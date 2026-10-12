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
	"maps"
	"slices"

	"k8s.io/apimachinery/pkg/types"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// nodeArtifact is everything the node knows about one artifact. There is one of these per
// artifact, and nothing else in the node is keyed by artifact identity.
type nodeArtifact struct {
	// configName is the entry this artifact owns in the shared plugins-config file, and ownerUID
	// the incarnation of it that made the claim. Only a Plugin has these. Ownership is keyed by
	// the Falco-visible config name, which a CR can rename and another can collide with, so it is
	// recorded here rather than inferred from the artifact's own key.
	configName string
	ownerUID   types.UID
	// requires is what each installed source asks of Falco: the metadata that was in force when
	// that source's file was written. It lives beside the file it describes, so nothing has to
	// correlate the two, but each entry keeps the content hash it was recorded against, because
	// a later reconcile has to confirm the metadata still describes the bytes on disk.
	requires map[artifact.Medium][]rulesfileRevision
	// installed is the on-disk file for each of the artifact's sources: the authoritative source
	// every store method, removal and lookup reads, and the only thing a filesystem decision
	// (skip vs. rewrite, what to remove) is ever based on. A controller's own ArtifactNode status
	// is a write-through mirror of this for observability only; it is never read back to make a
	// decision, since the informer-cached status a reconcile sees can lag behind what has
	// actually happened. Seeded from disk by the warm sync at startup (see seedInstalledFromDisk);
	// updated on every write and removal thereafter.
	installed []artifactv1alpha1.InstalledArtifact
}

// ownerOfLocked returns the artifact that owns the shared-file entry called name, or nil. Caller
// holds mu.
func (n *Node) ownerOfLocked(name string) *ownerRef {
	for key, record := range n.artifacts {
		if record.configName != name {
			continue
		}
		return &ownerRef{Name: key.Name, UID: record.ownerUID}
	}
	return nil
}

// ownersLocked is who currently holds each entry of the shared plugins-config file, gathered from
// the records. It is a copy: a caller edits it and commits the result through a write, so that the
// records only change once the file has landed. Caller holds mu.
func (n *Node) ownersLocked() map[string]ownerRef {
	owners := make(map[string]ownerRef)
	for key, record := range n.artifacts {
		if record.configName == "" {
			continue
		}
		owners[record.configName] = ownerRef{Name: key.Name, UID: record.ownerUID}
	}
	return owners
}

// setOwnersLocked makes the records' claims match owners exactly. Caller holds mu.
func (n *Node) setOwnersLocked(owners map[string]ownerRef) {
	for key, record := range n.artifacts {
		if record.configName == "" {
			continue
		}
		owner, held := owners[record.configName]
		if held && owner.Name == key.Name && owner.UID == record.ownerUID {
			continue
		}
		record.configName, record.ownerUID = "", ""
		n.dropIfEmptyLocked(key, record)
	}
	for name, owner := range owners {
		key := artifact.Ref{Kind: artifact.KindPlugin, Name: owner.Name}
		record := n.artifacts[key]
		if record == nil {
			record = &nodeArtifact{}
			n.artifacts[key] = record
		}
		record.configName, record.ownerUID = name, owner.UID
	}
}

// requiresLocked returns what key's source for medium requires. Caller holds mu.
func (n *Node) requiresLocked(key artifact.Ref, medium artifact.Medium) []rulesfileRevision {
	if record := n.artifacts[key]; record != nil {
		return record.requires[medium]
	}
	return nil
}

// setRequiresLocked records what key's source for medium requires, or drops it when revisions is
// empty. Caller holds mu.
func (n *Node) setRequiresLocked(key artifact.Ref, medium artifact.Medium, revisions []rulesfileRevision) {
	record := n.artifacts[key]
	if record == nil {
		if len(revisions) == 0 {
			return
		}
		record = &nodeArtifact{}
		n.artifacts[key] = record
	}
	if len(revisions) == 0 {
		delete(record.requires, medium)
		return
	}
	if record.requires == nil {
		record.requires = map[artifact.Medium][]rulesfileRevision{}
	}
	record.requires[medium] = revisions
}

// filesLocked returns the installed files recorded for key, or nil. Caller holds mu.
func (n *Node) filesLocked(key artifact.Ref) []artifactv1alpha1.InstalledArtifact {
	if record := n.artifacts[key]; record != nil {
		return record.installed
	}
	return nil
}

// setFilesLocked records key's installed files, dropping the record entirely once it holds
// nothing. Caller holds mu.
func (n *Node) setFilesLocked(key artifact.Ref, files []artifactv1alpha1.InstalledArtifact) {
	record := n.artifacts[key]
	if len(files) == 0 {
		if record != nil {
			record.installed = nil
			n.dropIfEmptyLocked(key, record)
		}
		return
	}
	if record == nil {
		record = &nodeArtifact{}
		n.artifacts[key] = record
	}
	record.installed = files
}

// dropIfEmptyLocked forgets a record that no longer holds anything, so that the presence of a key
// keeps meaning the node holds something for it. Caller holds mu.
func (n *Node) dropIfEmptyLocked(key artifact.Ref, record *nodeArtifact) {
	if len(record.installed) == 0 && len(record.requires) == 0 && record.configName == "" {
		delete(n.artifacts, key)
	}
}

// installedKeys returns the artifacts that have files installed on this node.
func (n *Node) installedKeys() []artifact.Ref {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Collect(maps.Keys(n.artifacts))
}

// hasInstalled reports whether any file is installed on this node for the artifact.
func (n *Node) hasInstalled(key artifact.Ref) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.artifacts[key] != nil
}

// FindInstalled returns the cached File for key's medium, or nil if none is known. This is the
// only source a filesystem decision should read "what's currently installed" from.
func (n *Node) FindInstalled(key artifact.Ref, medium artifact.Medium) *artifact.File {
	n.mu.Lock()
	defer n.mu.Unlock()
	return artifact.FindInstalled(n.filesLocked(key), medium)
}

// removeIfInstalled removes key's medium from disk and the cache when something is currently
// installed for it, returning the removed file's path (removed=true), or a no-op
// (removed=false) when nothing is installed for medium.
func (n *Node) removeIfInstalled(ctx context.Context, key artifact.Ref, medium artifact.Medium) (path string, removed bool, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	existing := artifact.FindInstalled(n.filesLocked(key), medium)
	if existing == nil {
		if key.Kind != artifact.KindRulesfile {
			return "", false, nil
		}
		n.setRequiresLocked(key, medium, nil)
		return "", false, nil
	}
	var installed []artifactv1alpha1.InstalledArtifact
	for _, file := range n.filesLocked(key) {
		if file.Medium == string(medium) {
			installed = append(installed, file)
		}
	}
	if err := n.removeLocked(ctx, key, installed); err != nil {
		return "", false, err
	}
	return existing.Path, true, nil
}

// UpdateInstalledSpecHash sets SpecHash on key's cache entry for medium; no-op if not found.
// Store's own dedup only knows about content, not the parent spec, so a caller whose Store call
// returned StoreActionUnchanged despite the parent spec changing (e.g. a new OCI tag resolving to
// identical content) still needs to persist that spec hash separately, exactly as it would in
// status; this keeps the cache the caller reads "current" from equally up to date.
func (n *Node) UpdateInstalledSpecHash(key artifact.Ref, medium artifact.Medium, specHash string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	entry := n.filesLocked(key)
	artifact.UpdateInstalledSpecHash(&entry, medium, specHash)
	n.setFilesLocked(key, entry)
}

// syncInstalledStatus mirrors the node's record of key's file for medium into status: it upserts the
// entry when the node holds a file, and clears it when it does not.
//
// It runs on every reconcile, whatever the reconcile did. The record, not status, is what a write
// decision reads (see storeLocked), so a reconcile can find a file "already correct" although the
// status that should list it never landed: a patch that failed, or a record seeded from disk by the
// warm sync. Syncing only when a store changed something would leave such a status behind for good.
func (n *Node) syncInstalledStatus(key artifact.Ref, medium artifact.Medium, status *[]artifactv1alpha1.InstalledArtifact) {
	if entry := n.FindInstalled(key, medium); entry != nil {
		artifact.SetInstalled(status, *entry)
	} else {
		artifact.ClearInstalled(status, medium)
	}
}

// GetInstalled returns a copy of the cached installed artifacts for key, or nil if none are
// known. Mutating the returned list does not update the installed cache.
func (n *Node) GetInstalled(key artifact.Ref) []artifactv1alpha1.InstalledArtifact {
	n.mu.Lock()
	defer n.mu.Unlock()
	src := n.filesLocked(key)
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
// by the warm sync at startup to populate the cache from disk ground truth before the manager starts
// serving reconciles; every update after that goes through the store/removal methods.
func (n *Node) SeedInstalled(key artifact.Ref, artifacts []artifactv1alpha1.InstalledArtifact) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(artifacts) == 0 {
		n.setFilesLocked(key, nil)
		return
	}
	n.setFilesLocked(key, artifacts)
}

// seedPluginsConfigFile records the shared plugins-config file found on disk. Like SeedInstalled, it is used only by
// the warm sync at startup.
func (n *Node) seedPluginsConfigFile(file artifactv1alpha1.InstalledArtifact) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pluginsConfigFile = artifact.FindInstalled([]artifactv1alpha1.InstalledArtifact{file}, artifact.Medium(file.Medium))
}

// Verify is a read-only passthrough to the underlying ArtifactStore.Verify; it doesn't touch
// the registry, so no locking is needed for correctness.
func (n *Node) Verify(ctx context.Context, f *artifact.File) (bool, error) {
	return n.disk.Verify(ctx, f)
}

// ScanAll is a read-only passthrough to the underlying ArtifactStore.ScanAll; it doesn't touch
// the registry, so no locking is needed for correctness.
func (n *Node) ScanAll(ctx context.Context, kind artifact.Kind) (map[string][]artifactv1alpha1.InstalledArtifact, error) {
	return n.disk.ScanAll(ctx, kind)
}

// storeLocked tracks the on-disk result, including partial moves. Caller holds mu.
func (n *Node) storeLocked(ctx context.Context, name string, artifactPriority int32,
	kind artifact.Kind, medium artifact.Medium, result artifact.FetchResult) (artifact.StoreAction, *artifact.File, error) {
	info, err := artifact.InfoForKind(kind)
	if err != nil {
		return artifact.StoreActionNone, nil, err
	}
	key := artifact.Ref{Kind: info.Kind, Name: name}
	current := artifact.FindInstalled(n.filesLocked(key), medium)
	action, file, err := n.disk.Store(ctx, current, name, artifactPriority, kind, medium, result)
	if file != nil || err == nil {
		n.upsertInstalledLocked(key, action, medium, file)
	}
	return action, file, err
}

// removeLocked releases dependencies only after the files have been removed. Caller holds mu.
func (n *Node) removeLocked(ctx context.Context, key artifact.Ref, installed []artifactv1alpha1.InstalledArtifact) error {
	if key.Kind == artifact.KindPlugin {
		if err := n.releaseEntriesLoadingLocked(ctx, key, installed); err != nil {
			return err
		}
	}
	if err := n.disk.Remove(ctx, installed); err != nil {
		return err
	}
	entry := n.filesLocked(key)
	for _, removed := range installed {
		entry = slices.DeleteFunc(entry, func(file artifactv1alpha1.InstalledArtifact) bool { return file.Path == removed.Path })
	}
	if record := n.artifacts[key]; record != nil {
		for medium := range record.requires {
			if artifact.FindInstalled(entry, medium) == nil {
				delete(record.requires, medium)
			}
		}
	}
	if len(entry) == 0 {
		entry = nil
	}
	n.setFilesLocked(key, entry)
	return nil
}

// upsertInstalledLocked applies a Store result to key's cache entry. Caller must hold mu.
func (n *Node) upsertInstalledLocked(key artifact.Ref, action artifact.StoreAction, medium artifact.Medium, file *artifact.File) {
	entry := n.filesLocked(key)
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
	n.setFilesLocked(key, entry)
}
