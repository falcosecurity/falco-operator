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
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/event"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
)

// provided is what's currently known about a capability/plugin name: where it comes from and its version once
// confirmed by Falco. Version is "" until Falco has reported it.
type provided struct {
	// ObservedOnly means only Falco knows the name: it is none of the plugins in the node's plugins-config, but a
	// capability Falco reports for itself (engine_version_semver, plugin_api_version) or a plugin loaded outside
	// the operator. Such a name goes as soon as Falco stops reporting it; a configured one stays, unconfirmed.
	ObservedOnly bool
	Version      string
	// Removed records an explicit configuration removal. Keep it until an explicit
	// registration so a pre-reload (or delayed) observation cannot resurrect the provider.
	Removed bool
}

// checkRequirement reports whether name is currently provided at a version satisfying
// minVersion. found=false means name isn't known to be provided yet, covering both "Falco
// hasn't been observed" and "this capability was never reported." Callers should treat this as
// an expected, temporary state that resolves once compat.VersionsWatcher's next observation
// arrives, not as an error to retry-with-backoff.
func (n *Node) checkRequirement(name, minVersion string) (providedVersion string, found, satisfied bool, err error) {
	n.mu.Lock()
	p, ok := n.provides[name]
	n.mu.Unlock()
	// A structural entry with no confirmed version (e.g. registered via AddPluginConfig or the warm sync
	// before Falco reports anything for it) is treated the same as not found.
	if !ok || p.Version == "" {
		return "", false, false, nil
	}
	satisfied, err = versionSatisfies(name, p.Version, minVersion)
	return p.Version, true, satisfied, err
}

// checkDependency checks primary then alternatives against one locked provider snapshot.
// The first observed candidate determines the result, even when its version is incompatible.
// A configured candidate awaiting observation blocks fallback until its version is known.
func (n *Node) checkDependency(dependency commonv1alpha1.ArtifactMetaDependency) (matchedName, providedVersion string, satisfied bool, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.checkDependencyLocked(dependency, "")
}

// refreshFalcoVersions fetches Falco's current /versions snapshot and merges it into the dependency registry.
func (n *Node) refreshFalcoVersions(ctx context.Context) (*compat.Versions, error) {
	versions, err := n.falcoFetcher.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	n.OnFalcoVersionsObserved(versions)
	return versions, nil
}

// Events returns a new channel that receives one GenericEvent each time OnFalcoVersionsObserved
// changes the version this Node reports for any name; e.g. a name transitioning from
// not-yet-confirmed to confirmed, a version bumping, or a confirmed name disappearing. Each call returns an
// independent channel, so every subscriber sees every event.
//
// Notifications reflect the effective registry, including explicit plugin removal, rather than
// only differences between Falco observations.
func (n *Node) Events() <-chan event.GenericEvent {
	ch := make(chan event.GenericEvent, 100)
	n.mu.Lock()
	n.subscribers = append(n.subscribers, ch)
	n.mu.Unlock()
	return ch
}

// OnFalcoVersionsObserved reconciles a complete Falco capability snapshot with the provides
// registry. Configured entries (a plugin registered via AddPluginConfig) get their Version filled in
// or updated. Explicitly removed entries stay unavailable until registered again. Names not already
// tracked (Falco's own engine_version_semver/plugin_api_version, or any plugin name Falco reports
// that the operator didn't configure) get an ObservedOnly entry. Used as the versions watcher's sink
// (wired in New) and by refreshFalcoVersions; safe to call directly with
// any successfully observed snapshot. Missing configured entries stay registered but lose their
// confirmed Version; missing ObservedOnly entries are removed.
//
// Notifies Events() subscribers whenever any name's Version changes value, including "" -> a
// confirmed version and a confirmed version becoming unavailable.
func (n *Node) OnFalcoVersionsObserved(v *compat.Versions) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.falcoSeen = true
	observed := v.All()
	changed := false
	for name, existing := range n.provides {
		if _, ok := observed[name]; ok {
			continue
		}
		if existing.ObservedOnly {
			delete(n.provides, name)
			changed = true
		} else if existing.Version != "" {
			// Keep the desired registration, but do not treat an unloaded plugin as available.
			existing.Version = ""
			n.provides[name] = existing
			changed = true
		}
	}
	for name, version := range observed {
		existing, ok := n.provides[name]
		if existing.Removed {
			continue
		}
		if !ok {
			n.provides[name] = provided{ObservedOnly: true, Version: version}
			changed = true
			continue
		}
		if existing.Version != version {
			existing.Version = version
			n.provides[name] = existing
			changed = true
		}
	}
	if changed {
		n.notifySubscribersLocked()
	}
}

// checkDependencyLocked follows Falco's candidate order and major-version compatibility.
// excludedName simulates a plugin removal without changing the registry. Caller holds mu.
func (n *Node) checkDependencyLocked(dependency commonv1alpha1.ArtifactMetaDependency, excludedName string) (
	matchedName, providedVersion string, satisfied bool, err error,
) {
	if err := compat.ValidatePluginDependency(dependency); err != nil {
		return "", "", false, err
	}
	for i := 0; i <= len(dependency.Alternatives); i++ {
		name, version := dependency.Name, dependency.Version
		if i > 0 {
			name, version = dependency.Alternatives[i-1].Name, dependency.Alternatives[i-1].Version
		}
		if name == excludedName {
			continue
		}
		p, found := n.provides[name]
		if !found || p.Removed {
			continue
		}
		if p.Version == "" {
			// Configured is not absent: Falco may already have loaded this candidate since
			// our last observation. Do not install rules (or allow removal) via a later
			// alternative while the earlier candidate's compatibility is still unknown.
			return name, "", false, nil
		}
		satisfied, err = compat.PluginVersionCompatible(p.Version, version)
		return name, p.Version, satisfied, err
	}
	return "", "", false, nil
}

// notifySubscribersLocked sends a non-blocking GenericEvent to every subscriber. If a subscriber
// already has a pending event, the controller will pick it up on its next work cycle, making the
// duplicate a no-op. Caller must hold mu.
func (n *Node) notifySubscribersLocked() {
	for _, ch := range n.subscribers {
		select {
		case ch <- event.GenericEvent{}:
		default:
		}
	}
}

// blockedByOthersLocked reports installed Rulesfiles with known dependencies that would
// lose their only satisfier if name stopped being provided. Caller must hold mu.
func (n *Node) blockedByOthersLocked(name string) *BlockedError {
	blocked := &BlockedError{Name: name}
	blockedKeys := make(map[artifact.Ref]struct{})
	for key, record := range n.artifacts {
		if _, seen := blockedKeys[key]; seen {
			continue
		}
		if n.recordBlocksRemovalLocked(record, name) {
			blocked.BlockedBy = append(blocked.BlockedBy, key)
			blockedKeys[key] = struct{}{}
		}
	}
	if len(blocked.BlockedBy) == 0 {
		return nil
	}
	return blocked
}

// recordBlocksRemovalLocked reports whether any of this artifact's installed sources requires name
// and would have no satisfier left without it. Caller must hold mu.
func (n *Node) recordBlocksRemovalLocked(record *nodeArtifact, name string) bool {
	for _, revisions := range record.requires {
		for _, revision := range revisions {
			if revision.Metadata == nil {
				continue
			}
			for _, dependency := range revision.Metadata.Dependencies {
				if dependency.Name != name && !slices.ContainsFunc(dependency.Alternatives,
					func(candidate commonv1alpha1.ArtifactMetaDependencyVariant) bool { return candidate.Name == name }) {
					continue
				}
				if _, _, satisfied, err := n.checkDependencyLocked(dependency, name); err != nil || !satisfied {
					return true
				}
			}
		}
	}
	return false
}

// versionSatisfies applies one special case: plugin_api_version compares by major-version
// compatibility; other capabilities require at-least. Plugin dependencies are checked
// separately by checkDependencyLocked.
func versionSatisfies(name, available, required string) (bool, error) {
	if name == compat.CapabilityPluginAPIVersion {
		return compat.SemverMajorCompatible(available, required)
	}
	return compat.SemverAtLeast(available, required)
}
