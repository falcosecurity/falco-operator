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

// Package nodeartifacts coordinates on-disk writes across the artifact-operator sidecar's
// three per-node reconcilers (Plugin, Rulesfile, Config), which write into the same Falco
// config directories. This package controls what combination of files can be on disk; Falco
// reloads are triggered explicitly by ReloadCoordinator (reloadcoordinator.go) after writes
// settle, not by Falco's own file-watch.
package nodeartifacts

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/event"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// Kind identifies which artifact type a registry Key belongs to.
type Kind string

const (
	// KindRulesfile identifies a Rulesfile CR's dependency-registry entry.
	KindRulesfile Kind = "Rulesfile"
	// KindPluginConfig identifies the single shared plugins-config aggregate file's
	// registry entry. Every Plugin CR on a node contributes one entry to that file (see
	// controllers/artifact/plugin/controller.go's PluginsConfig).
	KindPluginConfig Kind = "PluginConfig"
	// KindFalco identifies capabilities reported directly by Falco itself
	// (engine_version_semver, plugin_api_version); a reserved provider identity distinct
	// from anything the operator itself writes to disk.
	KindFalco Kind = "Falco"
)

// Key identifies an entry in the dependency registry.
type Key struct {
	Kind Kind
	Name string
}

// PluginConfigKey is the single registry key for the shared plugins-config aggregate file.
var PluginConfigKey = Key{Kind: KindPluginConfig, Name: "plugins-config"}

// RequirementGroup is an ordered plugin dependency: the primary followed by its alternatives.
// Like Falco, both installation and removal checks use the first observed candidate and require
// a compatible version; an incompatible candidate cannot be bypassed by a later alternative.
type RequirementGroup []Requirement

// Requirement is a plugin name and its required version. Compatible versions must have the
// same major and be at least as recent as the requirement.
type Requirement = puller.Dependency

// BlockedError is returned by RemovePluginConfigByName when removing a name would leave some
// other artifact's dependency unsatisfied. It is an expected, retriable condition: callers
// should log, record an event, and return without erroring, relying on a watch to re-trigger
// once unblocked.
type BlockedError struct {
	Name      string
	BlockedBy []Key
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("%q is still required by %v", e.Name, e.BlockedBy)
}

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

// Manager coordinates disk writes across the artifact-operator sidecar's per-node reconcilers.
// It delegates file I/O to the wrapped artifact.ArtifactStore and owns everything needed to
// decide and perform those writes: a mutex, the provides/requires dependency registry, Falco's
// reported capabilities (kept fresh by a background poller and refreshed after a plugin
// install, see RefreshFalcoVersions), and the shared plugins-config aggregate with its
// CR-name-to-config-name rename tracking for Plugin CRs (see pluginconfig.go). The zero value
// is not usable; construct with NewManager.
type Manager struct {
	mu             sync.Mutex
	store          artifact.ArtifactStore
	falcoFetcher   compat.VersionsFetcher
	provides       map[string]provided
	requires       map[Key][]RequirementGroup
	pluginsConfig  *pluginsConfig
	crToConfigName map[string]string
	subscribers    []chan event.GenericEvent
}

// NewManager returns a Manager wrapping store. store performs the actual file I/O; falcoFetcher
// is used for the post-install refresh in AddPluginConfig (see RefreshFalcoVersions). The
// periodic background refresh path goes through compat.VersionsWatcher.SetSink instead, fed by
// the same underlying fetcher from the caller.
func NewManager(store artifact.ArtifactStore, falcoFetcher compat.VersionsFetcher) *Manager {
	return &Manager{
		store:          store,
		falcoFetcher:   falcoFetcher,
		provides:       make(map[string]provided),
		requires:       make(map[Key][]RequirementGroup),
		pluginsConfig:  &pluginsConfig{},
		crToConfigName: make(map[string]string),
	}
}

// Store is a lock-wrapped passthrough to the underlying ArtifactStore.Store. Use for writes
// that don't affect the cross-artifact dependency graph (plugin binaries, rulesfile media
// files, config files). The lock keeps these writes mutually exclusive with
// RemovePluginConfigByName's check-then-write critical section.
func (m *Manager) Store(ctx context.Context, current *artifact.File, name string, artifactPriority int32,
	artifactType artifact.Type, medium artifact.Medium, result artifact.FetchResult) (artifact.StoreAction, *artifact.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Store(ctx, current, name, artifactPriority, artifactType, medium, result)
}

// Remove is a lock-wrapped passthrough to the underlying ArtifactStore.Remove. Use for removals
// that don't themselves affect the dependency graph (see RemovePluginConfigByName for the one
// that does).
func (m *Manager) Remove(ctx context.Context, installed []artifactv1alpha1.InstalledArtifact) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Remove(ctx, installed)
}

// Verify is a read-only passthrough to the underlying ArtifactStore.Verify; it doesn't touch
// the registry, so no locking is needed for correctness.
func (m *Manager) Verify(ctx context.Context, f *artifact.File) (bool, error) {
	return m.store.Verify(ctx, f)
}

// Sync replaces key's registered requirement groups. A nil or empty requires clears the entry.
// Used to register/refresh what a Rulesfile currently depends on; call it on every reconcile
// with a resolved ArtifactMeta, since dependencies can change independently of rendered file
// content. Also used by WarmSync at startup.
func (m *Manager) Sync(key Key, requires []RequirementGroup) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(requires) == 0 {
		delete(m.requires, key)
		return
	}
	m.requires[key] = requires
}

// SyncProvides registers that key currently provides name (e.g. the shared plugin-config file
// now has an entry loading a plugin under this name). Used incrementally: the shared
// plugins-config aggregate is built up across every Plugin CR's own reconcile, each
// contributing one name to the same PluginConfigKey.
func (m *Manager) SyncProvides(key Key, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Preserves any version already confirmed for this name.
	version := m.provides[name].Version
	m.provides[name] = provided{Key: key, Version: version}
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
	// A structural entry with no confirmed version (e.g. registered via SyncProvides/WarmSync
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
func (m *Manager) CheckDependency(primary Requirement, alternatives []Requirement) (matchedName, providedVersion string, satisfied bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.checkDependencyLocked(append(RequirementGroup{primary}, alternatives...), "")
}

// checkDependencyLocked follows Falco's candidate order and major-version compatibility.
// excludedName simulates a plugin removal without changing the registry. Caller holds m.mu.
func (m *Manager) checkDependencyLocked(group RequirementGroup, excludedName string) (matchedName, providedVersion string, satisfied bool, err error) {
	if err := compat.ValidatePluginDependency(group); err != nil {
		return "", "", false, err
	}
	for _, req := range group {
		if req.Name == excludedName {
			continue
		}
		p, found := m.provides[req.Name]
		if !found || p.Removed {
			continue
		}
		if p.Version == "" {
			// Configured is not absent: Falco may already have loaded this candidate since
			// our last observation. Do not install rules (or allow removal) via a later
			// alternative while the earlier candidate's compatibility is still unknown.
			return req.Name, "", false, nil
		}
		satisfied, err = compat.PluginVersionCompatible(p.Version, req.Version)
		return req.Name, p.Version, satisfied, err
	}
	return "", "", false, nil
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

// RefreshFalcoVersions fetches Falco's current /versions snapshot and reconciles it with the
// provides registry (see OnFalcoVersionsObserved). Returns the fetched snapshot so callers that
// also want to inspect it directly (e.g. compat.VersionsWatcher, for its own change-diffing) can
// do so without a second fetch.
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
// Events reacts to the Manager's own bookkeeping rather than compat.VersionsWatcher's diff of
// Falco's raw /versions response, which is not a reliable proxy for this: a plugin's config can
// be removed and re-added, clearing then repopulating this Manager's provides entry, while
// Falco's reported version for that name never changes and the watcher's diff never fires.
func (m *Manager) Events() <-chan event.GenericEvent {
	ch := make(chan event.GenericEvent, 100)
	m.mu.Lock()
	m.subscribers = append(m.subscribers, ch)
	m.mu.Unlock()
	return ch
}

// notifySubscribers sends a non-blocking GenericEvent to every subscriber. If a subscriber
// already has a pending event, the controller will pick it up on its next work cycle, making the
// duplicate a no-op. Caller must hold m.mu.
func (m *Manager) notifySubscribers() {
	for _, ch := range m.subscribers {
		select {
		case ch <- event.GenericEvent{}:
		default:
		}
	}
}

// OnFalcoVersionsObserved reconciles a complete Falco capability snapshot with the provides
// registry. Existing (operator-tracked) entries (e.g. a plugin already registered via
// AddPluginConfig/SyncProvides) get their Version filled in or updated, preserving their
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
		m.notifySubscribers()
	}
}

// blockedByOthers reports which currently-registered RequirementGroups would lose their only
// satisfier if name stopped being provided. An empty result means it's safe to stop providing
// name. Caller must hold m.mu.
func (m *Manager) blockedByOthers(name string) []Key {
	var blockedBy []Key
	for key, groups := range m.requires {
		for _, group := range groups {
			if !slices.ContainsFunc(group, func(req Requirement) bool { return req.Name == name }) {
				continue
			}
			if _, _, satisfied, err := m.checkDependencyLocked(group, name); err != nil || !satisfied {
				blockedBy = append(blockedBy, key)
				break
			}
		}
	}
	return blockedBy
}

// RequirementGroupsFromDependencies converts ArtifactMeta.Dependencies (as populated by the
// instance operator on a Rulesfile's status) into the form Sync expects: each dependency's
// primary plus its alternatives, retaining versions and order. Returns nil for empty input.
func RequirementGroupsFromDependencies(deps []commonv1alpha1.ArtifactMetaDependency) []RequirementGroup {
	if len(deps) == 0 {
		return nil
	}
	groups := make([]RequirementGroup, 0, len(deps))
	for _, d := range deps {
		group := RequirementGroup{{Name: d.Name, Version: d.Version}}
		for _, alt := range d.Alternatives {
			group = append(group, Requirement{Name: alt.Name, Version: alt.Version})
		}
		groups = append(groups, group)
	}
	return groups
}
