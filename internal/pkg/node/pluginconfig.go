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

package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

// AddPluginConfig ensures plugin's entry is present and current in the shared plugins-config
// aggregate file, then registers the resulting config name as provided.
//
// Handles a config-name rename (plugin.Spec.Config.Name differing from the name last seen for
// this CR) by removing the old entry first; if the old name is still required elsewhere, returns
// *BlockedError and leaves both the in-memory aggregate and disk untouched, so the rename can be
// retried on the next reconcile without having lost the old entry in the interim.
//
// The file this aggregate is written to is a single shared, node-level singleton (the node's
// pluginsConfigFile), not per-Plugin-CR; whether the write can be skipped as unchanged is decided
// from that record, not from anything the caller passes in.
func (n *Node) AddPluginConfig(ctx context.Context, plugin *artifactv1alpha1.Plugin,
) (artifact.StoreAction, *artifact.File, error) {
	n.mu.Lock()
	action, file, err := n.addPluginConfigLocked(ctx, plugin)
	n.mu.Unlock()
	if err != nil {
		return action, file, err
	}
	// Best-effort: try to learn Falco's loaded versions sooner than the next periodic poll.
	// The response may still describe the runtime before this write; the versions watcher refreshes it
	// later. This runs after, never inside, the locked section above: the refresh takes the lock too.
	if _, refreshErr := n.refreshFalcoVersions(ctx); refreshErr != nil {
		log.FromContext(ctx).V(1).Info("post-install Falco versions refresh failed; will retry on next periodic poll", "err", refreshErr)
	}
	return action, file, nil
}

// RemovePluginConfig removes the installed entry by CR identity, never by desired spec.
func (n *Node) RemovePluginConfig(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	owner := pluginOwner(plugin)
	return n.withdrawClaimLocked(ctx, &owner)
}

// withdrawClaimLocked removes owner's entry from the shared file and releases the provider name it
// registered. Removal needs only what installation recorded: the owner identifies the entry, and
// nothing about the CR that created it is consulted. Caller holds mu.
func (n *Node) withdrawClaimLocked(ctx context.Context, owner *ownerRef) error {
	configName := n.claimedNameLocked(owner)
	if configName == "" {
		return nil
	}
	if blocked := n.blockedByOthersLocked(configName); blocked != nil {
		return blocked
	}
	updated := n.pluginsConfig.clone()
	updated.removeByName(configName)
	owners := n.ownersLocked()
	delete(owners, configName)
	_, _, err := n.writePluginsConfigLocked(ctx, updated, owners)
	return err
}

// addPluginConfigLocked updates the aggregate and provider registry. Caller holds mu.
func (n *Node) addPluginConfigLocked(ctx context.Context, plugin *artifactv1alpha1.Plugin) (artifact.StoreAction, *artifact.File, error) {
	claimed := pluginClaim(plugin)
	if err := n.checkClaimLocked(claimed); err != nil {
		return artifact.StoreActionNone, nil, err
	}
	oldName := n.claimedNameLocked(&claimed.Owner)
	updated := n.pluginsConfig.clone()
	if oldName != "" && oldName != claimed.Name {
		updated.removeByName(oldName)
	}
	if err := updated.addConfig(n.dirs.Plugin, plugin); err != nil {
		return artifact.StoreActionNone, nil, err
	}
	owners := n.ownersLocked()
	if oldName != claimed.Name {
		delete(owners, oldName)
	}
	owners[claimed.Name] = claimed.Owner
	return n.writePluginsConfigLocked(ctx, updated, owners)
}

// writePluginsConfigLocked publishes the in-memory aggregate only after its file is installed.
func (n *Node) writePluginsConfigLocked(ctx context.Context,
	config *pluginsConfig, owners map[string]ownerRef) (artifact.StoreAction, *artifact.File, error) {
	pluginConfigString, err := config.toString()
	if err != nil {
		return artifact.StoreActionNone, nil, fmt.Errorf("convert plugin config to string: %w", err)
	}
	result, err := n.fetcher.FetchInline(ctx, []byte(pluginConfigString))
	if err != nil {
		return artifact.StoreActionNone, nil, fmt.Errorf("prepare plugin config content: %w", err)
	}
	action, file, err := n.disk.Store(ctx, n.pluginsConfigFile, pluginConfigFileName, priority.MaxPriority,
		artifact.KindConfig, artifact.MediumInline, result)
	switch action {
	case artifact.StoreActionAdded, artifact.StoreActionUpdated, artifact.StoreActionPriorityChanged:
		if file != nil {
			n.pluginsConfigFile = file
		}
	case artifact.StoreActionNone, artifact.StoreActionUnchanged, artifact.StoreActionRemoved:
	}
	if err != nil {
		if file != nil && file.ContentHash == result.ContentHash {
			n.publishPluginConfigLocked(config, owners)
		}
		return action, file, err
	}
	n.publishPluginConfigLocked(config, owners)
	return action, file, nil
}

func (n *Node) publishPluginConfigLocked(config *pluginsConfig, owners map[string]ownerRef) {
	changed := false
	for _, name := range n.pluginsConfig.LoadPlugins {
		if !slices.Contains(config.LoadPlugins, name) {
			value := provided{Removed: true}
			changed = changed || n.provides[name] != value
			n.provides[name] = value
		}
	}
	for _, name := range config.LoadPlugins {
		previous := n.provides[name]
		value := provided{Version: previous.Version}
		n.provides[name] = value
		changed = changed || previous != value
	}
	n.pluginsConfig = config
	n.setOwnersLocked(owners)
	if changed {
		n.notifySubscribersLocked()
	}
}

// readPluginsConfigLocked parses the installed shared plugins-config file, as found. It returns nil when
// there is none. A file that does not parse counts as empty: it is logged, and rebuilt from the current
// Plugins by their reconciles. Caller holds mu.
func (n *Node) readPluginsConfigLocked(ctx context.Context) (*pluginsConfig, error) {
	file := n.pluginsConfigFile
	if file == nil {
		return nil, nil
	}
	data, err := n.disk.Read(ctx, file.Path)
	if errors.Is(err, fs.ErrNotExist) {
		n.pluginsConfigFile = nil
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read installed plugin configuration: %w", err)
	}
	observed := &pluginsConfig{}
	if err := yaml.Unmarshal(data, observed); err != nil {
		log.FromContext(ctx).Error(err, "Invalid installed plugin configuration; rebuilding from current Plugins")
		observed = &pluginsConfig{}
	}
	return observed, nil
}

// observePluginsConfig reads the installed shared plugins-config into memory as found, owned by nobody. It is
// warm sync's step when no ArtifactNode says which Plugins the entries belong to: nothing is written and
// nothing is pruned, since pruning against an empty assignment would destroy working configuration. The
// node controller decides from there. When it removes a plugin's binary as an orphan, the entry loading
// the binary goes with it (see releaseEntriesLoadingLocked), and a Plugin assigned later takes over the
// entry of its name (see checkClaimLocked). Without this, the node would believe the file empty, and
// remove a binary while the file on disk still tells Falco to load it.
func (n *Node) observePluginsConfig(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	observed, err := n.readPluginsConfigLocked(ctx)
	if err != nil || observed == nil {
		return err
	}
	n.publishPluginConfigLocked(observed, n.ownersLocked())
	return nil
}

// restorePluginsConfig retains observed entries owned by the current assigned Plugins, and those an installed
// Rulesfile still requires.
// New or changed settings are applied only by the normal plugin reconciler.
func (n *Node) restorePluginsConfig(ctx context.Context, plugins []*artifactv1alpha1.Plugin) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	observed, err := n.readPluginsConfigLocked(ctx)
	if err != nil || observed == nil {
		return err
	}
	owners := make(map[string]ownerRef, len(plugins))
	ambiguous := make(map[string]bool)
	for _, plugin := range plugins {
		name, owner := resolveConfigName(plugin), pluginOwner(plugin)
		if existing, ok := owners[name]; ok && existing != owner {
			ambiguous[name] = true
			log.FromContext(ctx).Info("Multiple Plugins request the same config name; deferring ownership to reconciliation", "name", name)
		}
		owners[name] = owner
	}
	retained := &pluginsConfig{}
	retainedOwners := make(map[string]ownerRef)
	for _, config := range observed.Configs {
		if slices.Contains(retained.LoadPlugins, config.Name) || !slices.Contains(observed.LoadPlugins, config.Name) {
			continue
		}
		owner, wanted := owners[config.Name]
		if !wanted || ambiguous[config.Name] {
			// An entry no assigned Plugin owns goes, unless an installed Rulesfile still requires it: pruning
			// it here would reload Falco without a plugin its rules need, which the removal of that plugin
			// refuses to do. It stays as found, owned by nobody, so that the removal of its binary is what
			// decides, and is blocked as it would have been before the restart (see releaseEntriesLoadingLocked).
			if n.blockedByOthersLocked(config.Name) == nil {
				continue
			}
			retained.Configs = append(retained.Configs, config)
			retained.LoadPlugins = append(retained.LoadPlugins, config.Name)
			continue
		}
		retained.Configs = append(retained.Configs, config)
		retained.LoadPlugins = append(retained.LoadPlugins, config.Name)
		retainedOwners[config.Name] = owner
	}
	// Seed the observed output before publishing its replacement, so pruned names
	// cannot be resurrected by a delayed Falco versions response.
	n.pluginsConfig = observed
	_, _, err = n.writePluginsConfigLocked(ctx, retained, retainedOwners)
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

// addConfig stages plugin's entry into the aggregate. It returns an error only because naming the
// plugin's binary can fail for an unregistered kind; the alternative, an entry with a made-up
// library_path, is the kind of silent wrong answer the registry exists to remove.
func (pc *pluginsConfig) addConfig(pluginDir string, plugin *artifactv1alpha1.Plugin) error {
	libraryPath, err := artifact.ArtifactPath(
		artifact.ArtifactDirs{Plugin: pluginDir},
		plugin.Name, priority.DefaultPriority, artifact.MediumOCI, artifact.KindPlugin,
	)
	if err != nil {
		return err
	}

	config := pluginConfig{
		LibraryPath: libraryPath,
		Name:        plugin.Name,
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

	// An entry of the same name is replaced, unless it is identical: nothing then changes, which avoids a write
	// to the config file mounted in the pod.
	index := slices.IndexFunc(pc.Configs, func(c pluginConfig) bool { return c.Name == config.Name })
	switch {
	case index < 0:
		pc.Configs = append(pc.Configs, config)
	case !pc.Configs[index].isSame(&config):
		pc.Configs[index] = config
	}

	// The name is loaded, whether its entry is new or was already there: a file taken over as found (see
	// observePluginsConfig) can hold an entry that load_plugins does not name, which Falco would never load.
	if !slices.Contains(pc.LoadPlugins, config.Name) {
		pc.LoadPlugins = append(pc.LoadPlugins, config.Name)
	}
	return nil
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
