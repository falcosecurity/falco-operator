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
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/event"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
)

// provided is what's currently known about a capability/plugin name: which Key registered it
// (informational only, kept for observability) and its version once confirmed by Falco. Version
// is "" until Falco has reported it.
type provided struct {
	Key     Key
	Version string
	// Removed records an explicit configuration removal. Keep it until an explicit
	// registration so a pre-reload (or delayed) observation cannot resurrect the provider.
	Removed bool
}

// CheckRequirement reports whether name is currently provided at a version satisfying
// minVersion. found=false means name isn't known to be provided yet, covering both "Falco
// hasn't been observed" and "this capability was never reported." Callers should treat this as
// an expected, temporary state that resolves once compat.VersionsWatcher's next observation
// arrives, not as an error to retry-with-backoff.
func (m *Manager) CheckRequirement(name, minVersion string) (providedVersion string, found, satisfied bool, err error) {
	m.mu.Lock()
	p, ok := m.provides[name]
	m.mu.Unlock()
	// A structural entry with no confirmed version (e.g. registered via AddPluginConfig/WarmSync
	// before Falco reports anything for it) is treated the same as not found.
	if !ok || p.Version == "" {
		return "", false, false, nil
	}
	satisfied, err = versionSatisfies(name, p.Version, minVersion)
	return p.Version, true, satisfied, err
}

// CheckDependency checks primary then alternatives against one locked provider snapshot.
// The first observed candidate determines the result, even when its version is incompatible.
// A configured candidate awaiting observation blocks fallback until its version is known.
func (m *Manager) CheckDependency(dependency commonv1alpha1.ArtifactMetaDependency) (matchedName, providedVersion string, satisfied bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.checkDependencyLocked(dependency, "")
}

// RefreshFalcoVersions fetches Falco's current /versions snapshot and updates the provider registry.
func (m *Manager) RefreshFalcoVersions(ctx context.Context) (*compat.Versions, error) {
	versions, err := m.falcoFetcher.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	m.OnFalcoVersionsObserved(versions)
	return versions, nil
}

// Events returns a new channel that receives one GenericEvent each time OnFalcoVersionsObserved
// changes the version this Manager reports for any name; e.g. a name transitioning from
// not-yet-confirmed to confirmed, a version bumping, or a confirmed name disappearing. Each call returns an
// independent channel, so every subscriber sees every event.
//
// Notifications reflect the effective registry, including explicit plugin removal, rather than
// only differences between Falco observations.
func (m *Manager) Events() <-chan event.GenericEvent {
	ch := make(chan event.GenericEvent, 100)
	m.mu.Lock()
	m.subscribers = append(m.subscribers, ch)
	m.mu.Unlock()
	return ch
}

// OnFalcoVersionsObserved reconciles a complete Falco capability snapshot with the provides
// registry. Existing (operator-tracked) entries (e.g. a plugin already registered via
// AddPluginConfig) get their Version filled in or updated, preserving their
// original Key. Explicitly removed entries stay unavailable until registered again.
// Names not already tracked (Falco's own engine_version_semver/
// plugin_api_version, or any plugin name Falco reports that the operator didn't configure) get a
// new entry under KindFalco. Used as compat.VersionsWatcher's sink (wired in
// cmd/artifact/main.go) and by RefreshFalcoVersions' own merge step; safe to call directly with
// any successfully observed snapshot. Missing operator-tracked entries retain their Key but
// lose their confirmed Version; missing observation-only entries are removed.
//
// Notifies Events() subscribers whenever any name's Version changes value, including "" -> a
// confirmed version and a confirmed version becoming unavailable.
func (m *Manager) OnFalcoVersionsObserved(v *compat.Versions) {
	m.mu.Lock()
	defer m.mu.Unlock()
	observed := v.All()
	changed := false
	for name, existing := range m.provides {
		if _, ok := observed[name]; ok {
			continue
		}
		if existing.Key.Kind == KindFalco {
			delete(m.provides, name)
			changed = true
		} else if existing.Version != "" {
			// Keep the desired registration, but do not treat an unloaded plugin as available.
			existing.Version = ""
			m.provides[name] = existing
			changed = true
		}
	}
	for name, version := range observed {
		existing, ok := m.provides[name]
		if existing.Removed {
			continue
		}
		if !ok {
			m.provides[name] = provided{Key: Key{Kind: KindFalco, Name: name}, Version: version}
			changed = true
			continue
		}
		if existing.Version != version {
			existing.Version = version
			m.provides[name] = existing
			changed = true
		}
	}
	if changed {
		m.notifySubscribersLocked()
	}
}

// checkDependencyLocked follows Falco's candidate order and major-version compatibility.
// excludedName simulates a plugin removal without changing the registry. Caller holds m.mu.
func (m *Manager) checkDependencyLocked(dependency commonv1alpha1.ArtifactMetaDependency, excludedName string) (
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
		p, found := m.provides[name]
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
// duplicate a no-op. Caller must hold m.mu.
func (m *Manager) notifySubscribersLocked() {
	for _, ch := range m.subscribers {
		select {
		case ch <- event.GenericEvent{}:
		default:
		}
	}
}

// blockedByOthersLocked reports installed Rulesfiles with known dependencies that would
// lose their only satisfier if name stopped being provided. Caller must hold m.mu.
func (m *Manager) blockedByOthersLocked(name string) *BlockedError {
	blocked := &BlockedError{Name: name}
	blockedKeys := make(map[Key]struct{})
	for slot, revisions := range m.rulesfiles {
		if _, blocked := blockedKeys[slot.Key]; blocked {
			continue
		}
		for _, revision := range revisions {
			if revision.Metadata == nil {
				continue
			}
			for _, dependency := range revision.Metadata.Dependencies {
				if dependency.Name != name && !slices.ContainsFunc(dependency.Alternatives,
					func(candidate commonv1alpha1.ArtifactMetaDependencyVariant) bool { return candidate.Name == name }) {
					continue
				}
				if _, _, satisfied, err := m.checkDependencyLocked(dependency, name); err != nil || !satisfied {
					blocked.BlockedBy = append(blocked.BlockedBy, slot.Key)
					blockedKeys[slot.Key] = struct{}{}
					break
				}
			}
			if _, ok := blockedKeys[slot.Key]; ok {
				break
			}
		}
	}
	if len(blocked.BlockedBy) == 0 {
		return nil
	}
	return blocked
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
