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
	"fmt"
	"path/filepath"

	"k8s.io/apimachinery/pkg/types"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// resolveConfigName returns the canonical plugin name used by Falco and referenced in a
// Rulesfile's dependency list. Prefers spec.config.name (explicit override) over the CR's
// metadata.name, which may be an arbitrary Kubernetes identifier.
func resolveConfigName(plugin *artifactv1alpha1.Plugin) string {
	if plugin.Spec.Config != nil && plugin.Spec.Config.Name != "" {
		return plugin.Spec.Config.Name
	}
	return plugin.Name
}

// claimedNameLocked is the shared file's entry owner currently holds, or "" if it holds none.
// Caller holds mu.
func (n *Node) claimedNameLocked(owner *ownerRef) string {
	for _, config := range n.pluginsConfig.Configs {
		if held := n.ownerOfLocked(config.Name); held != nil && *held == *owner {
			return config.Name
		}
	}
	return ""
}

// checkClaimLocked reports whether c.Owner may hold the shared file's entry called c.Name. It is the
// ownership half of the aggregate: entries are keyed by the Falco-visible config name, which one
// CR can rename and another can collide with, so claiming one is checked against who holds it
// rather than against the artifact's own key. Caller holds mu.
func (n *Node) checkClaimLocked(c *claim) error {
	name, owner := c.Name, &c.Owner
	for _, config := range n.pluginsConfig.Configs {
		held := n.ownerOfLocked(config.Name)
		if held == nil {
			// Nobody holds the entry: warm sync observed it on disk with no ArtifactNode to attribute it to.
			// The claimant takes it over, and its reconcile rewrites it from its own spec.
			continue
		}
		existing := *held
		if existing != *owner && (config.Name == name || existing.Name == owner.Name) {
			return fmt.Errorf("installed plugin %q belongs to %s (UID %s)", config.Name, existing.Name, existing.UID)
		}
		if existing == *owner && config.Name != name {
			if blocked := n.blockedByOthersLocked(config.Name); blocked != nil {
				return blocked
			}
		}
	}
	return nil
}

// withdrawClaimOfLocked releases the shared-config entry the plugin key holds, if any. It goes by key, not by
// incarnation: the node holds one claim per plugin, and whoever removes the plugin's files releases it,
// whichever incarnation of the plugin made it (the one that installed it, or the one warm sync attributed
// it to after a restart). Caller holds mu.
func (n *Node) withdrawClaimOfLocked(ctx context.Context, key artifact.Ref) error {
	record := n.artifacts[key]
	if record == nil || record.configName == "" {
		return nil
	}
	owner := ownerRef{Name: key.Name, UID: record.ownerUID}
	return n.withdrawClaimLocked(ctx, &owner)
}

// TakeOver makes uid the incarnation of key that owns what the node holds for it. It is for an artifact deleted
// and recreated under the same name whose previous incarnation left something that cannot be removed first: the
// new one continues from it. Only a plugin's claim on the shared plugin configuration records an incarnation.
func (n *Node) TakeOver(key artifact.Ref, uid types.UID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if record := n.artifacts[key]; record != nil && record.configName != "" {
		record.ownerUID = uid
	}
}

// releaseEntriesLoadingLocked withdraws from the shared plugin configuration the entries that load one of
// files, which are about to be removed for key, so that Falco is never left loading a file that is not there.
//
// An entry nobody owns is one warm sync observed on disk with no ArtifactNode to attribute it to: it goes
// with its file, as the entry of key itself does. An entry another artifact owns stays, and the removal is
// refused: that artifact's reconcile is what decides about its entry. Withdrawing is blocked, with a
// *BlockedError, while a Rulesfile on this node still requires the name. Caller holds mu.
func (n *Node) releaseEntriesLoadingLocked(ctx context.Context, key artifact.Ref, files []artifactv1alpha1.InstalledArtifact) error {
	var names []string
	for _, config := range n.pluginsConfig.Configs {
		if !loadsOneOf(config.LibraryPath, files) {
			continue
		}
		if owner := n.ownerOfLocked(config.Name); owner != nil && owner.Name != key.Name {
			return fmt.Errorf("plugin %s still has a configured library: entry %q of %s loads it",
				key.Name, config.Name, owner.Name)
		}
		names = append(names, config.Name)
	}
	if len(names) == 0 {
		return nil
	}
	for _, name := range names {
		if blocked := n.blockedByOthersLocked(name); blocked != nil {
			return blocked
		}
	}
	updated := n.pluginsConfig.clone()
	owners := n.ownersLocked()
	for _, name := range names {
		updated.removeByName(name)
		delete(owners, name)
	}
	_, _, err := n.writePluginsConfigLocked(ctx, updated, owners)
	return err
}

// loadsOneOf reports whether libraryPath is the path of one of files.
func loadsOneOf(libraryPath string, files []artifactv1alpha1.InstalledArtifact) bool {
	for _, file := range files {
		if filepath.Clean(libraryPath) == filepath.Clean(file.Path) {
			return true
		}
	}
	return false
}

// pluginClaim is the shared-file entry a Plugin CR claims: the name Falco sees it under, and the
// object that owns it.
func pluginClaim(plugin *artifactv1alpha1.Plugin) *claim {
	return &claim{Name: resolveConfigName(plugin), Owner: pluginOwner(plugin)}
}

// ownerRef identifies the incarnation of a Plugin that holds an entry of the shared plugins-config file. The node
// serves one namespace, so name and uid are all it takes.
type ownerRef struct {
	Name string
	UID  types.UID
}

func pluginOwner(plugin *artifactv1alpha1.Plugin) ownerRef {
	return ownerRef{Name: plugin.Name, UID: plugin.UID}
}
