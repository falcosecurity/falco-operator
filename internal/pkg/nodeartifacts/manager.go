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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// Kind identifies which artifact type a registry Key belongs to.
type Kind string

const (
	// KindRulesfile identifies a Rulesfile CR's dependency-registry and installed-cache entry.
	KindRulesfile Kind = "Rulesfile"
	// KindPlugin identifies a Plugin CR's installed-cache entry (its binary).
	KindPlugin Kind = "Plugin"
	// KindConfig identifies a Config CR's installed-cache entry.
	KindConfig Kind = "Config"
	// KindPluginConfig identifies the single shared plugins-config aggregate file's
	// registry and installed-cache entry. Every Plugin CR on a node contributes one entry to
	// that file (see pluginconfig.go).
	KindPluginConfig Kind = "PluginConfig"
	// KindFalco identifies capabilities reported directly by Falco itself
	// (engine_version_semver, plugin_api_version); a reserved provider identity distinct
	// from anything the operator itself writes to disk.
	KindFalco Kind = "Falco"
)

// Key identifies an entry in the dependency registry.
type Key struct {
	Kind      Kind
	Namespace string
	Name      string
}

// KeyFromObj builds the Key for kind identifying obj, the Plugin/Rulesfile/Config CR that owns
// it. Not applicable during deletion handling, where the parent object may already be gone and
// only its owner-reference name (never its namespace) survives: those call sites build a Key
// literal from the ArtifactNode's own namespace directly instead.
func KeyFromObj(kind Kind, obj metav1.Object) Key {
	return Key{Kind: kind, Namespace: obj.GetNamespace(), Name: obj.GetName()}
}

// PluginConfigKey is the single registry key for the shared plugins-config aggregate file. Its
// Namespace is deliberately left empty: the file itself is a per-node singleton (Falco is one
// process per node with one config file location) that aggregates every Plugin CR's entry
// regardless of namespace, so it doesn't belong to any one namespace the way a per-CR Key does.
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
	mu           sync.Mutex
	store        artifact.ArtifactStore
	falcoFetcher compat.VersionsFetcher
	provides     map[string]provided
	requires     map[Key][]RequirementGroup
	// installed tracks the on-disk files for each artifact (keyed by Kind+Name): the
	// authoritative source Store/Remove/FindInstalled read and write, and the only thing a
	// filesystem decision (skip vs. rewrite, what to remove) is ever based on. A controller's
	// own ArtifactNode status is a write-through mirror of this for observability only; it is
	// never read back to make a decision, since the informer-cached status a reconcile sees can
	// lag behind what's actually happened. Seeded from disk by WarmSync at startup (see
	// reconcileDiskState); updated on every Store/Remove call thereafter.
	installed      map[Key][]artifactv1alpha1.InstalledArtifact
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
		installed:      make(map[Key][]artifactv1alpha1.InstalledArtifact),
		pluginsConfig:  &pluginsConfig{},
		crToConfigName: make(map[string]string),
	}
}

// kindForArtifactType maps an artifact.Type to the Kind its installed-cache entries use.
func kindForArtifactType(t artifact.Type) Kind {
	switch t {
	case artifact.TypePlugin:
		return KindPlugin
	case artifact.TypeConfig:
		return KindConfig
	default:
		return KindRulesfile
	}
}

// Store is a lock-wrapped wrapper around the underlying ArtifactStore.Store. It derives "current"
// from the installed cache itself (keyed by namespace+artifactType+name) rather than accepting it
// from the caller, so there is exactly one place a Store decision can come from; on success it
// updates the cache with the result. Use for writes that don't affect the cross-artifact
// dependency graph (plugin binaries, rulesfile media files, config files). The lock keeps these
// writes mutually exclusive with RemovePluginConfigByName's check-then-write critical section.
func (m *Manager) Store(ctx context.Context, namespace, name string, artifactPriority int32,
	artifactType artifact.Type, medium artifact.Medium, result artifact.FetchResult) (artifact.StoreAction, *artifact.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := Key{Kind: kindForArtifactType(artifactType), Namespace: namespace, Name: name}
	current := artifact.FindInstalled(m.installed[key], medium)
	action, file, err := m.store.Store(ctx, current, name, artifactPriority, artifactType, medium, result)
	if err != nil {
		return action, file, err
	}
	m.upsertInstalledLocked(key, action, medium, file)
	return action, file, nil
}

// Remove is a lock-wrapped wrapper around the underlying ArtifactStore.Remove. key identifies
// which cache entry installed's mediums belong to; on success, each removed medium is cleared
// from that entry. Use for removals that don't themselves affect the dependency graph (see
// RemovePluginConfigByName for the one that does).
func (m *Manager) Remove(ctx context.Context, key Key, installed []artifactv1alpha1.InstalledArtifact) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.store.Remove(ctx, installed); err != nil {
		return err
	}
	entry := m.installed[key]
	for _, a := range installed {
		artifact.ClearInstalled(&entry, artifact.Medium(a.Medium))
	}
	if len(entry) == 0 {
		delete(m.installed, key)
	} else {
		m.installed[key] = entry
	}
	return nil
}

// upsertInstalledLocked applies a Store result to key's cache entry. Caller must hold m.mu.
func (m *Manager) upsertInstalledLocked(key Key, action artifact.StoreAction, medium artifact.Medium, file *artifact.File) {
	entry := m.installed[key]
	artifact.UpdateInstalledStatus(&entry, action, medium, file)
	m.installed[key] = entry
}

// FindInstalled returns the cached File for key's medium, or nil if none is known. This is the
// only source a filesystem decision should read "what's currently installed" from.
func (m *Manager) FindInstalled(key Key, medium artifact.Medium) *artifact.File {
	m.mu.Lock()
	defer m.mu.Unlock()
	return artifact.FindInstalled(m.installed[key], medium)
}

// UpdateInstalledSpecHash sets SpecHash on key's cache entry for medium; no-op if not found.
// Store's own dedup only knows about content, not the parent spec, so a caller whose Store call
// returned StoreActionUnchanged despite the parent spec changing (e.g. a new OCI tag resolving to
// identical content) still needs to persist that spec hash separately, exactly as it would in
// status; this keeps the cache the caller reads "current" from equally up to date.
func (m *Manager) UpdateInstalledSpecHash(key Key, medium artifact.Medium, specHash string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.installed[key]
	artifact.UpdateInstalledSpecHash(&entry, medium, specHash)
	m.installed[key] = entry
}

// SyncInstalledStatus mirrors key's cache entry for medium into status: upserts it if the cache
// has one, clears it if the cache doesn't. Call this after every ensure/skip decision a
// controller makes for a medium (including a "verified on disk, nothing to do" shortcut that
// never called Store), not only after a Store call that actually changed something.
//
// This exists because the cache — not status — is the source of a Store decision (see Store's
// doc comment): a decision can conclude "already correct" from cache state a previous reconcile
// established, even if that reconcile's own status patch never landed (an SSA conflict, or the
// cache being seeded straight from disk by WarmSync with no ArtifactNode status write at all).
// Gating a status write on the StoreAction (e.g. skipping it for StoreActionUnchanged, as the old
// per-medium status helpers did) leaves status permanently behind the cache in that case, since
// nothing will ever revisit it once the medium reads as settled. Syncing unconditionally instead
// makes status self-healing on every reconcile, regardless of which of this reconcile's own
// actions (if any) actually touched disk.
func (m *Manager) SyncInstalledStatus(key Key, medium artifact.Medium, status *[]artifactv1alpha1.InstalledArtifact) {
	if entry := m.FindInstalled(key, medium); entry != nil {
		artifact.SetInstalled(status, *entry)
	} else {
		artifact.ClearInstalled(status, medium)
	}
}

// SyncAllInstalledStatus calls SyncInstalledStatus for every medium in mediums. Every controller's
// Reconcile defer resyncs its artifact type's full set of mediums from the cache right before
// patching status, regardless of which medium (if any) this particular reconcile itself touched:
// see SyncInstalledStatus's doc comment for why a per-medium gate isn't enough to keep status from
// falling behind the cache after an SSA conflict between overlapping reconciles.
func (m *Manager) SyncAllInstalledStatus(key Key, mediums []artifact.Medium, status *[]artifactv1alpha1.InstalledArtifact) {
	for _, medium := range mediums {
		m.SyncInstalledStatus(key, medium, status)
	}
}

// GetInstalled returns a copy of the cached installed artifacts for key, or nil if none are
// known. Used to obtain the full list to pass to Remove (e.g. on deletion) and by WarmSync.
func (m *Manager) GetInstalled(key Key) []artifactv1alpha1.InstalledArtifact {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.installed[key]
	if src == nil {
		return nil
	}
	out := make([]artifactv1alpha1.InstalledArtifact, len(src))
	copy(out, src)
	return out
}

// SeedInstalled bulk-sets the installed cache for key, replacing any existing entry. Used only
// by WarmSync at startup to populate the cache from disk ground truth before the manager starts
// serving reconciles; every update after that goes through Store/Remove.
func (m *Manager) SeedInstalled(key Key, artifacts []artifactv1alpha1.InstalledArtifact) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(artifacts) == 0 {
		delete(m.installed, key)
		return
	}
	m.installed[key] = artifacts
}

// Verify is a read-only passthrough to the underlying ArtifactStore.Verify; it doesn't touch
// the registry, so no locking is needed for correctness.
func (m *Manager) Verify(ctx context.Context, f *artifact.File) (bool, error) {
	return m.store.Verify(ctx, f)
}

// ScanAll is a read-only passthrough to the underlying ArtifactStore.ScanAll; it doesn't touch
// the registry, so no locking is needed for correctness.
func (m *Manager) ScanAll(ctx context.Context, artifactType artifact.Type) (map[string][]artifactv1alpha1.InstalledArtifact, error) {
	return m.store.ScanAll(ctx, artifactType)
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
func (m *Manager) checkDependencyLocked(group RequirementGroup, excludedName string) (
	matchedName, providedVersion string, satisfied bool, err error,
) {
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
