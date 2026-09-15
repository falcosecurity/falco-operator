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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
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

// Manager coordinates disk writes across the artifact-operator sidecar's per-node reconcilers.
// It delegates file I/O to the wrapped artifact.ArtifactStore and owns everything needed to
// decide and perform those writes: a mutex, installed dependencies and providers, Falco's
// reported capabilities (kept fresh by a background poller and refreshed after a plugin
// install, see RefreshFalcoVersions), and the shared plugins-config aggregate with its
// installed ownership for Plugin CRs (see pluginconfig.go). The zero value
// is not usable; construct with NewManager.
type Manager struct {
	mu           sync.Mutex
	store        artifact.ArtifactStore
	falcoFetcher compat.VersionsFetcher
	provides     map[string]provided
	rulesfiles   map[rulesfileSourceKey][]rulesfileRevision
	// installed tracks the on-disk files for each artifact (keyed by Kind+Namespace+Name): the
	// authoritative source all store methods, Remove and FindInstalled use, and the only thing a
	// filesystem decision (skip vs. rewrite, what to remove) is ever based on. A controller's
	// own ArtifactNode status is a write-through mirror of this for observability only; it is
	// never read back to make a decision, since the informer-cached status a reconcile sees can
	// lag behind what's actually happened. Seeded from disk by WarmSync at startup (see
	// seedInstalledCacheFromDisk); updated on every write/removal thereafter.
	installed          map[Key][]artifactv1alpha1.InstalledArtifact
	pluginsConfig      *pluginsConfig
	pluginConfigOwners map[string]corev1.ObjectReference
	subscribers        []chan event.GenericEvent
}

// NewManager returns a Manager wrapping store. store performs the actual file I/O; falcoFetcher
// is used for the post-install refresh in AddPluginConfig (see RefreshFalcoVersions). The
// periodic background refresh path goes through compat.VersionsWatcher.SetSink instead, fed by
// the same underlying fetcher from the caller.
func NewManager(store artifact.ArtifactStore, falcoFetcher compat.VersionsFetcher) *Manager {
	return &Manager{
		store:              store,
		falcoFetcher:       falcoFetcher,
		provides:           make(map[string]provided),
		rulesfiles:         make(map[rulesfileSourceKey][]rulesfileRevision),
		installed:          make(map[Key][]artifactv1alpha1.InstalledArtifact),
		pluginsConfig:      &pluginsConfig{},
		pluginConfigOwners: make(map[string]corev1.ObjectReference),
	}
}

// KeyFromObj builds the Key for kind identifying obj, the Plugin/Rulesfile/Config CR that owns
// it. Not applicable during deletion handling, where the parent object may already be gone and
// only its owner-reference name (never its namespace) survives: those call sites build a Key
// literal from the ArtifactNode's own namespace directly instead.
func KeyFromObj(kind Kind, obj metav1.Object) Key {
	return Key{Kind: kind, Namespace: obj.GetNamespace(), Name: obj.GetName()}
}

// Remove deletes the installed files and releases their dependencies on success.
func (m *Manager) Remove(ctx context.Context, key Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removeLocked(ctx, key, slices.Clone(m.installed[key]))
}

// FindInstalled returns the cached File for key's medium, or nil if none is known. This is the
// only source a filesystem decision should read "what's currently installed" from.
func (m *Manager) FindInstalled(key Key, medium artifact.Medium) *artifact.File {
	m.mu.Lock()
	defer m.mu.Unlock()
	return artifact.FindInstalled(m.installed[key], medium)
}

// RemoveIfInstalled removes key's medium from disk and the cache when something is currently
// installed for it, returning the removed file's path (removed=true), or a no-op
// (removed=false) when nothing is installed for medium.
func (m *Manager) RemoveIfInstalled(ctx context.Context, key Key, medium artifact.Medium) (path string, removed bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing := artifact.FindInstalled(m.installed[key], medium)
	if existing == nil {
		if key.Kind != KindRulesfile {
			return "", false, nil
		}
		slot := rulesfileSourceKey{Key: key, Medium: medium}
		delete(m.rulesfiles, slot)
		return "", false, nil
	}
	var installed []artifactv1alpha1.InstalledArtifact
	for _, file := range m.installed[key] {
		if file.Medium == string(medium) {
			installed = append(installed, file)
		}
	}
	if err := m.removeLocked(ctx, key, installed); err != nil {
		return "", false, err
	}
	return existing.Path, true, nil
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
// This exists because the cache — not status — is the source of a write decision (see
// storeLocked): a decision can conclude "already correct" from cache state a previous reconcile
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
// known. Mutating the returned list does not update the installed cache.
func (m *Manager) GetInstalled(key Key) []artifactv1alpha1.InstalledArtifact {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.installed[key]
	if src == nil {
		return nil
	}
	out := make([]artifactv1alpha1.InstalledArtifact, len(src))
	for i := range src {
		src[i].DeepCopyInto(&out[i])
	}
	return out
}

// SeedInstalled bulk-sets the installed cache for key, replacing any existing entry. Used only
// by WarmSync at startup to populate the cache from disk ground truth before the manager starts
// serving reconciles; every update after that goes through the store/removal methods.
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

// storeLocked tracks the on-disk result, including partial moves. Caller holds m.mu.
func (m *Manager) storeLocked(ctx context.Context, namespace, name string, artifactPriority int32,
	artifactType artifact.Type, medium artifact.Medium, result artifact.FetchResult) (artifact.StoreAction, *artifact.File, error) {
	key := Key{Kind: kindForArtifactType(artifactType), Namespace: namespace, Name: name}
	current := artifact.FindInstalled(m.installed[key], medium)
	action, file, err := m.store.Store(ctx, current, name, artifactPriority, artifactType, medium, result)
	if file != nil || err == nil {
		m.upsertInstalledLocked(key, action, medium, file)
	}
	return action, file, err
}

// removeLocked releases dependencies only after the files have been removed. Caller holds m.mu.
func (m *Manager) removeLocked(ctx context.Context, key Key, installed []artifactv1alpha1.InstalledArtifact) error {
	if key.Kind == KindPluginConfig {
		return fmt.Errorf("shared plugin configuration cannot be removed as an artifact")
	}
	if key.Kind == KindPlugin && m.pluginFilesReferencedLocked(installed) {
		return fmt.Errorf("plugin %s/%s still has a configured library", key.Namespace, key.Name)
	}
	if err := m.store.Remove(ctx, installed); err != nil {
		return err
	}
	entry := m.installed[key]
	for _, a := range installed {
		entry = slices.DeleteFunc(entry, func(file artifactv1alpha1.InstalledArtifact) bool { return file.Path == a.Path })
	}
	for slot := range m.rulesfiles {
		if slot.Key == key && artifact.FindInstalled(entry, slot.Medium) == nil {
			delete(m.rulesfiles, slot)
		}
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
	if file != nil {
		// A priority move can replace a path already tracked as a legacy duplicate.
		seen := false
		entry = slices.DeleteFunc(entry, func(installed artifactv1alpha1.InstalledArtifact) bool {
			if installed.Path != file.Path {
				return false
			}
			if seen {
				return true
			}
			seen = true
			return false
		})
	}
	m.installed[key] = entry
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
