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
	"fmt"
	"reflect"
	"slices"

	"gopkg.in/yaml.v3"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// pluginConfigFileName is the name of the shared plugin configuration file every Plugin CR on
// this node contributes an entry to.
const pluginConfigFileName = "plugins-config"

// ResolveConfigName returns the canonical plugin name used by Falco and referenced in a
// Rulesfile's dependency list. Prefers spec.config.name (explicit override) over the CR's
// metadata.name, which may be an arbitrary Kubernetes identifier.
func ResolveConfigName(plugin *artifactv1alpha1.Plugin) string {
	if plugin.Spec.Config != nil && plugin.Spec.Config.Name != "" {
		return plugin.Spec.Config.Name
	}
	return plugin.Name
}

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

// pluginsConfig is the shared plugins-config aggregate: every Plugin CR on this node contributes
// one entry, serialized together into a single YAML file Falco loads.
type pluginsConfig struct {
	Configs     []pluginConfig `yaml:"plugins"`
	LoadPlugins []string       `yaml:"load_plugins,omitempty"`
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
			config.InitConfig = &initConfig{JSON: plugin.Spec.Config.InitConfig}
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
			pc.Configs = append(pc.Configs[:i], pc.Configs[i+1:]...)
			break
		}
	}
	pc.Configs = append(pc.Configs, config)

	// Add to LoadPlugins if not already present (use config.Name for consistency).
	if slices.Contains(pc.LoadPlugins, config.Name) {
		return
	}
	pc.LoadPlugins = append(pc.LoadPlugins, config.Name)
}

func (pc *pluginsConfig) removeConfig(plugin *artifactv1alpha1.Plugin) {
	pc.removeByName(ResolveConfigName(plugin))
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

func (pc *pluginsConfig) isEmpty() bool {
	return len(pc.Configs) == 0 && len(pc.LoadPlugins) == 0
}

// AddPluginConfig ensures plugin's entry is present and current in the shared plugins-config
// aggregate file, then registers the resulting config name as provided.
//
// Handles a config-name rename (plugin.Spec.Config.Name differing from the name last seen for
// this CR) by removing the old entry first; if the old name is still required elsewhere, returns
// *BlockedError and leaves both the in-memory aggregate and disk untouched, so the rename can be
// retried on the next reconcile without having lost the old entry in the interim.
//
// current is the caller's previously-tracked config file (nil if none), matching
// ArtifactStore.Store's convention; passed through so an unchanged write can be skipped.
// fetcher prepares the serialized aggregate into a FetchResult (content hash, perm).
//
// Falco reloads via a full process restart on SIGHUP, so a write landing during a restart's
// teardown/re-init window can be missed entirely. PluginConfigRetrier (pluginconfigretrier.go)
// is the backstop for this: it periodically compares what this node intends loaded against what
// Falco actually reports (Manager.PluginLoadMismatch) and forces a fresh write
// (Manager.ForceRewritePluginConfig) if a mismatch persists past a grace period.
func (m *Manager) AddPluginConfig(ctx context.Context, plugin *artifactv1alpha1.Plugin,
	current *artifact.File, fetcher artifact.ArtifactFetcher) (artifact.StoreAction, *artifact.File, error) {
	action, file, err := m.addPluginConfigLocked(ctx, plugin, current, fetcher)
	if err != nil {
		return action, file, err
	}
	// Best-effort: try to learn Falco's confirmed version sooner than the next periodic poll. A
	// fetch that's too early (Falco hasn't reloaded yet) is harmless; the periodic sink path
	// (see compat.VersionsWatcher.SetSink, wired in cmd/artifact/main.go) backstops this
	// regardless, so a failure or stale read here is never fatal. Must run after, never inside,
	// the locked section above: sync.Mutex isn't reentrant, and RefreshFalcoVersions locks too.
	if _, refreshErr := m.RefreshFalcoVersions(ctx); refreshErr != nil {
		log.FromContext(ctx).V(1).Info("post-install Falco versions refresh failed; will retry on next periodic poll", "err", refreshErr)
	}
	return action, file, nil
}

func (m *Manager) addPluginConfigLocked(ctx context.Context, plugin *artifactv1alpha1.Plugin,
	current *artifact.File, fetcher artifact.ArtifactFetcher) (artifact.StoreAction, *artifact.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	configName := ResolveConfigName(plugin)
	if oldName, ok := m.crToConfigName[plugin.Name]; ok && oldName != configName {
		if blockedBy := m.blockedByOthers(oldName); len(blockedBy) > 0 {
			return artifact.StoreActionNone, nil, &BlockedError{Name: oldName, BlockedBy: blockedBy}
		}
		m.pluginsConfig.removeByName(oldName)
		delete(m.provides, oldName)
	}
	m.crToConfigName[plugin.Name] = configName

	m.pluginsConfig.addConfig(artifact.DefaultArtifactDirs().Plugin, plugin)

	action, file, err := m.writePluginsConfig(ctx, current, fetcher)
	if err != nil {
		return artifact.StoreActionNone, nil, err
	}
	version := m.provides[configName].Version
	m.provides[configName] = provided{Key: PluginConfigKey, Version: version}
	return action, file, nil
}

// RemovePluginConfig removes plugin's entry from the shared config file, resolved from its
// current spec, and forgets its rename tracking. Equivalent to calling RemovePluginConfigByName
// with plugin.Name and ResolveConfigName(plugin); provided for callers that still have the
// Plugin object.
func (m *Manager) RemovePluginConfig(ctx context.Context, fetcher artifact.ArtifactFetcher, plugin *artifactv1alpha1.Plugin) error {
	return m.RemovePluginConfigByName(ctx, fetcher, plugin.Name, ResolveConfigName(plugin))
}

// RemovePluginConfigByName removes a plugin's config entry (identified by its resolved config
// name, in case Spec.Config.Name differs from pluginCRName or the parent Plugin object no longer
// exists) from the shared YAML file, and forgets rename tracking for pluginCRName.
//
// The file itself is always rewritten (even down to an explicitly-empty "plugins: []"), never
// deleted, even when this was the last configured plugin. Falco's own file-watch on this path
// does not reliably survive the underlying file being removed and later recreated (observed in
// practice: a plugin removed and re-added to the same running Falco pod never got picked back up;
// the config directory reload that dropped the file never fired again for a subsequently
// recreated one). Keeping the file present for the node's entire lifetime, and only ever changing
// its content via the same atomic rename-based write Store already uses for every other update
// (which Falco does reliably pick up), avoids that class of missed reload entirely.
//
// Refused, atomically with the check, when a Rulesfile on this node still declares configName as
// a dependency; see BlockedError.
func (m *Manager) RemovePluginConfigByName(ctx context.Context, fetcher artifact.ArtifactFetcher, pluginCRName, configName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if blockedBy := m.blockedByOthers(configName); len(blockedBy) > 0 {
		return &BlockedError{Name: configName, BlockedBy: blockedBy}
	}

	m.pluginsConfig.removeByName(configName)

	if _, _, err := m.writePluginsConfig(ctx, nil, fetcher); err != nil {
		return err
	}

	delete(m.provides, configName)
	delete(m.crToConfigName, pluginCRName)
	return nil
}

// writePluginsConfig serializes the current in-memory aggregate and stores it, skipping the
// write when current's content hash already matches what's on disk. Caller must hold m.mu.
func (m *Manager) writePluginsConfig(ctx context.Context, current *artifact.File, fetcher artifact.ArtifactFetcher) (artifact.StoreAction, *artifact.File, error) {
	pluginConfigString, err := m.pluginsConfig.toString()
	if err != nil {
		return artifact.StoreActionNone, nil, fmt.Errorf("convert plugin config to string: %w", err)
	}
	result, err := fetcher.FetchInline(ctx, []byte(pluginConfigString))
	if err != nil {
		return artifact.StoreActionNone, nil, fmt.Errorf("prepare plugin config content: %w", err)
	}
	if current != nil {
		if ok, verifyErr := m.store.Verify(ctx, &artifact.File{Path: current.Path, ContentHash: result.ContentHash}); verifyErr == nil && ok {
			return artifact.StoreActionUnchanged, nil, nil
		}
	}
	return m.store.Store(ctx, current, pluginConfigFileName, priority.MaxPriority, artifact.TypeConfig, artifact.MediumInline, result)
}
