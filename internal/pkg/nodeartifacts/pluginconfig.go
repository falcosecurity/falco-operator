// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package nodeartifacts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"reflect"
	"slices"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// pluginConfigFileName is the name of the shared plugin configuration file every Plugin CR on
// this node contributes an entry to.
const pluginConfigFileName = "plugins-config"

// PluginConfigKey identifies this manager's shared plugin configuration, not a parent CR.
// Each Falco pod has its own manager and files; instances in different namespaces do not share them.
var PluginConfigKey = Key{Kind: KindPluginConfig, Name: "plugins-config"}

// pluginConfig is a single plugin's entry in the shared plugins-config file.
type pluginConfig struct {
	InitConfig  *initConfig `yaml:"init_config,omitempty"`
	LibraryPath string      `yaml:"library_path"`
	Name        string      `yaml:"name"`
	OpenParams  string      `yaml:"open_params,omitempty"`
}

// initConfig wraps apiextensionsv1.JSON to provide proper YAML marshaling.
type initConfig struct {
	*apiextensionsv1.JSON
}

// pluginsConfig is the shared plugins-config aggregate: every Plugin CR on this node contributes
// one entry, serialized together into a single YAML file Falco loads.
type pluginsConfig struct {
	Configs     []pluginConfig `yaml:"plugins"`
	LoadPlugins []string       `yaml:"load_plugins,omitempty"`
}

// ResolveConfigName returns the canonical plugin name used by Falco and referenced in a
// Rulesfile's dependency list. Prefers spec.config.name (explicit override) over the CR's
// metadata.name, which may be an arbitrary Kubernetes identifier.
func ResolveConfigName(plugin *artifactv1alpha1.Plugin) string {
	if plugin.Spec.Config != nil && plugin.Spec.Config.Name != "" {
		return plugin.Spec.Config.Name
	}
	return plugin.Name
}

// AddPluginConfig ensures plugin's entry is present and current in the shared plugins-config
// aggregate file, then registers the resulting config name as provided.
//
// Handles a config-name rename (plugin.Spec.Config.Name differing from the name last seen for
// this CR) by removing the old entry first; if the old name is still required elsewhere, returns
// *BlockedError and leaves both the in-memory aggregate and disk untouched, so the rename can be
// retried on the next reconcile without having lost the old entry in the interim.
//
// The file this aggregate is written to is a single shared, node-level singleton (keyed by
// PluginConfigKey in the installed-artifact cache), not per-Plugin-CR; whether the write can be
// skipped as unchanged is decided from that cache entry, not from anything the caller passes in.
// fetcher prepares the serialized aggregate into a FetchResult (content hash, perm).
func (m *Manager) AddPluginConfig(ctx context.Context, plugin *artifactv1alpha1.Plugin,
	fetcher artifact.ArtifactFetcher) (artifact.StoreAction, *artifact.File, error) {
	m.mu.Lock()
	action, file, err := m.addPluginConfigLocked(ctx, plugin, fetcher)
	m.mu.Unlock()
	if err != nil {
		return action, file, err
	}
	// Best-effort: try to learn Falco's loaded versions sooner than the next periodic poll.
	// The response may still describe the runtime before this write; the periodic sink path
	// (see compat.VersionsWatcher.SetSink, wired in cmd/artifact/main.go) refreshes it later.
	// Must run after, never inside,
	// the locked section above: sync.Mutex isn't reentrant, and RefreshFalcoVersions locks too.
	if _, refreshErr := m.RefreshFalcoVersions(ctx); refreshErr != nil {
		log.FromContext(ctx).V(1).Info("post-install Falco versions refresh failed; will retry on next periodic poll", "err", refreshErr)
	}
	return action, file, nil
}

// StorePlugin checks installed ownership before replacing a plugin's binary.
func (m *Manager) StorePlugin(ctx context.Context, plugin *artifactv1alpha1.Plugin,
	result artifact.FetchResult) (artifact.StoreAction, *artifact.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkPluginOwnershipLocked(plugin); err != nil {
		return artifact.StoreActionNone, nil, err
	}
	return m.storeLocked(ctx, plugin.Namespace, plugin.Name, priority.DefaultPriority, artifact.TypePlugin, artifact.MediumOCI, result)
}

// RemovePluginConfig removes the installed entry by CR identity, never by desired spec.
func (m *Manager) RemovePluginConfig(ctx context.Context, fetcher artifact.ArtifactFetcher, plugin *artifactv1alpha1.Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removePluginConfigLocked(ctx, fetcher, plugin)
}

func (m *Manager) removePluginConfigLocked(ctx context.Context, fetcher artifact.ArtifactFetcher, plugin *artifactv1alpha1.Plugin) error {
	configName := m.installedPluginNameLocked(plugin)
	if configName == "" {
		return nil
	}
	if blocked := m.blockedByOthersLocked(configName); blocked != nil {
		return blocked
	}
	updated := m.pluginsConfig.clone()
	updated.removeByName(configName)
	owners := maps.Clone(m.pluginConfigOwners)
	delete(owners, configName)
	_, _, err := m.writePluginsConfigLocked(ctx, fetcher, updated, owners)
	return err
}

// addPluginConfigLocked updates the aggregate and provider registry. Caller holds m.mu.
func (m *Manager) addPluginConfigLocked(ctx context.Context, plugin *artifactv1alpha1.Plugin,
	fetcher artifact.ArtifactFetcher) (artifact.StoreAction, *artifact.File, error) {
	configName := ResolveConfigName(plugin)
	if err := m.checkPluginOwnershipLocked(plugin); err != nil {
		return artifact.StoreActionNone, nil, err
	}
	oldName := m.installedPluginNameLocked(plugin)
	updated := m.pluginsConfig.clone()
	if oldName != "" && oldName != configName {
		updated.removeByName(oldName)
	}
	updated.addConfig(artifact.DefaultArtifactDirs().Plugin, plugin)
	owners := maps.Clone(m.pluginConfigOwners)
	if oldName != configName {
		delete(owners, oldName)
	}
	owners[configName] = pluginOwner(plugin)
	return m.writePluginsConfigLocked(ctx, fetcher, updated, owners)
}

// writePluginsConfigLocked publishes the in-memory aggregate only after its file is installed.
func (m *Manager) writePluginsConfigLocked(ctx context.Context, fetcher artifact.ArtifactFetcher,
	config *pluginsConfig, owners map[string]corev1.ObjectReference) (artifact.StoreAction, *artifact.File, error) {
	pluginConfigString, err := config.toString()
	if err != nil {
		return artifact.StoreActionNone, nil, fmt.Errorf("convert plugin config to string: %w", err)
	}
	result, err := fetcher.FetchInline(ctx, []byte(pluginConfigString))
	if err != nil {
		return artifact.StoreActionNone, nil, fmt.Errorf("prepare plugin config content: %w", err)
	}
	current := artifact.FindInstalled(m.installed[PluginConfigKey], artifact.MediumInline)
	action, file, err := m.store.Store(ctx, current, pluginConfigFileName, priority.MaxPriority, artifact.TypeConfig, artifact.MediumInline, result)
	if file != nil || err == nil {
		m.upsertInstalledLocked(PluginConfigKey, action, artifact.MediumInline, file)
	}
	if err != nil {
		if file != nil && file.ContentHash == result.ContentHash {
			m.publishPluginConfigLocked(config, owners)
		}
		return action, file, err
	}
	m.publishPluginConfigLocked(config, owners)
	return action, file, nil
}

func (m *Manager) installedPluginNameLocked(plugin *artifactv1alpha1.Plugin) string {
	owner := pluginOwner(plugin)
	for _, config := range m.pluginsConfig.Configs {
		if m.pluginConfigOwners[config.Name] == owner {
			return config.Name
		}
	}
	return ""
}

func (m *Manager) checkPluginOwnershipLocked(plugin *artifactv1alpha1.Plugin) error {
	owner := pluginOwner(plugin)
	name := ResolveConfigName(plugin)
	for _, config := range m.pluginsConfig.Configs {
		existing := m.pluginConfigOwners[config.Name]
		if existing != owner && (config.Name == name || (existing.Namespace == owner.Namespace && existing.Name == owner.Name)) {
			return fmt.Errorf("installed plugin %q belongs to %s/%s (UID %s)", config.Name, existing.Namespace, existing.Name, existing.UID)
		}
		if existing == owner && config.Name != name {
			if blocked := m.blockedByOthersLocked(config.Name); blocked != nil {
				return blocked
			}
		}
	}
	return nil
}

func pluginOwner(plugin *artifactv1alpha1.Plugin) corev1.ObjectReference {
	return corev1.ObjectReference{Namespace: plugin.Namespace, Name: plugin.Name, UID: plugin.UID}
}

func (m *Manager) publishPluginConfigLocked(config *pluginsConfig, owners map[string]corev1.ObjectReference) {
	changed := false
	for _, name := range m.pluginsConfig.LoadPlugins {
		if !slices.Contains(config.LoadPlugins, name) {
			value := provided{Key: PluginConfigKey, Removed: true}
			changed = changed || m.provides[name] != value
			m.provides[name] = value
		}
	}
	for _, name := range config.LoadPlugins {
		previous := m.provides[name]
		value := provided{Key: PluginConfigKey, Version: previous.Version}
		m.provides[name] = value
		changed = changed || previous != value
	}
	m.pluginsConfig, m.pluginConfigOwners = config, owners
	if changed {
		m.notifySubscribersLocked()
	}
}

// restorePluginsConfig retains observed entries owned by the current assigned Plugins.
// New or changed settings are applied only by the normal plugin reconciler.
func (m *Manager) restorePluginsConfig(ctx context.Context, plugins []*artifactv1alpha1.Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	file := artifact.FindInstalled(m.installed[PluginConfigKey], artifact.MediumInline)
	if file == nil {
		return nil
	}
	data, err := m.store.Read(ctx, file.Path)
	if errors.Is(err, fs.ErrNotExist) {
		delete(m.installed, PluginConfigKey)
		return nil
	}
	if err != nil {
		return fmt.Errorf("read installed plugin configuration: %w", err)
	}
	observed := &pluginsConfig{}
	if err := yaml.Unmarshal(data, observed); err != nil {
		log.FromContext(ctx).Error(err, "Invalid installed plugin configuration; rebuilding from current Plugins")
		observed = &pluginsConfig{}
	}
	owners := make(map[string]corev1.ObjectReference, len(plugins))
	ambiguous := make(map[string]bool)
	for _, plugin := range plugins {
		name, owner := ResolveConfigName(plugin), pluginOwner(plugin)
		if existing, ok := owners[name]; ok && existing != owner {
			ambiguous[name] = true
			log.FromContext(ctx).Info("Multiple Plugins request the same config name; deferring ownership to reconciliation", "name", name)
		}
		owners[name] = owner
	}
	retained := &pluginsConfig{}
	retainedOwners := make(map[string]corev1.ObjectReference)
	for _, config := range observed.Configs {
		owner, wanted := owners[config.Name]
		if !wanted || ambiguous[config.Name] || !slices.Contains(observed.LoadPlugins, config.Name) {
			continue
		}
		if _, duplicate := retainedOwners[config.Name]; duplicate {
			continue
		}
		retained.Configs = append(retained.Configs, config)
		retained.LoadPlugins = append(retained.LoadPlugins, config.Name)
		retainedOwners[config.Name] = owner
	}
	// Seed the observed output before publishing its replacement, so pruned names
	// cannot be resurrected by a delayed Falco versions response.
	m.pluginsConfig = observed
	_, _, err = m.writePluginsConfigLocked(ctx, &artifact.Fetcher{}, retained, retainedOwners)
	return err
}

// UnmarshalYAML reads an installed init_config using the same JSON model as the CR.
func (c *initConfig) UnmarshalYAML(node *yaml.Node) error {
	var value any
	if err := node.Decode(&value); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	c.JSON = &apiextensionsv1.JSON{Raw: data}
	return nil
}

// MarshalYAML implements yaml.Marshaler to serialize the JSON content as nested YAML.
func (c *initConfig) MarshalYAML() (any, error) {
	if c == nil || c.JSON == nil || len(c.Raw) == 0 {
		return nil, nil
	}
	var data any
	if err := json.Unmarshal(c.Raw, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func (p *pluginConfig) isSame(other *pluginConfig) bool {
	if p.LibraryPath != other.LibraryPath {
		return false
	}
	if p.OpenParams != other.OpenParams {
		return false
	}
	if p.InitConfig == nil && other.InitConfig == nil {
		return true
	}
	if p.InitConfig == nil || other.InitConfig == nil {
		return false
	}
	return reflect.DeepEqual(p.InitConfig.JSON, other.InitConfig.JSON)
}

// clone isolates slice mutations while a proposed configuration is being written.
// Entries' nested init configs are only read, never modified by addConfig/removeByName.
func (pc *pluginsConfig) clone() *pluginsConfig {
	return &pluginsConfig{Configs: slices.Clone(pc.Configs), LoadPlugins: slices.Clone(pc.LoadPlugins)}
}

func (pc *pluginsConfig) addConfig(pluginDir string, plugin *artifactv1alpha1.Plugin) {
	config := pluginConfig{
		LibraryPath: artifact.ArtifactPath(
			artifact.ArtifactDirs{Plugin: pluginDir},
			plugin.Name, priority.DefaultPriority, artifact.MediumOCI, artifact.TypePlugin,
		),
		Name: plugin.Name,
	}

	if plugin.Spec.Config != nil {
		if plugin.Spec.Config.InitConfig != nil && len(plugin.Spec.Config.InitConfig.Raw) > 0 {
			config.InitConfig = &initConfig{JSON: plugin.Spec.Config.InitConfig.DeepCopy()}
		}
		if plugin.Spec.Config.LibraryPath != "" {
			config.LibraryPath = plugin.Spec.Config.LibraryPath
		}
		if plugin.Spec.Config.Name != "" {
			config.Name = plugin.Spec.Config.Name
		}
		if plugin.Spec.Config.OpenParams != "" {
			config.OpenParams = plugin.Spec.Config.OpenParams
		}
	}

	// If an entry with the same name already exists and is identical, skip the update
	// to avoid unnecessary writes to the config file mounted in the pod.
	for i, c := range pc.Configs {
		if c.Name == config.Name {
			if c.isSame(&config) {
				return
			}
			pc.Configs[i] = config
			return
		}
	}
	pc.Configs = append(pc.Configs, config)

	// Add to LoadPlugins if not already present (use config.Name for consistency).
	if slices.Contains(pc.LoadPlugins, config.Name) {
		return
	}
	pc.LoadPlugins = append(pc.LoadPlugins, config.Name)
}

func (pc *pluginsConfig) removeByName(name string) {
	for i, c := range pc.Configs {
		if c.Name == name {
			pc.Configs = append(pc.Configs[:i], pc.Configs[i+1:]...)
			break
		}
	}

	for i, c := range pc.LoadPlugins {
		if c == name {
			pc.LoadPlugins = append(pc.LoadPlugins[:i], pc.LoadPlugins[i+1:]...)
			break
		}
	}
}

func (pc *pluginsConfig) toString() (string, error) {
	data, err := yaml.Marshal(pc)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
