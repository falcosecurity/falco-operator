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
	"fmt"
	"slices"

	apiequality "k8s.io/apimachinery/pkg/api/equality"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// rulesfileSourceKey ties dependencies to one installed source, not the desired whole bundle.
type rulesfileSourceKey struct {
	Key
	Medium artifact.Medium
}

type rulesfileRevision struct {
	ContentHash string
	Metadata    *commonv1alpha1.ArtifactMeta
}

// StoreRulesfile writes one source and updates its dependencies under the plugin-removal lock.
// Failed content writes preserve the previous dependencies.
func (m *Manager) StoreRulesfile(ctx context.Context, namespace, name string, artifactPriority int32,
	medium artifact.Medium, result artifact.FetchResult, metadata *commonv1alpha1.ArtifactMeta, enforce bool,
) (artifact.StoreAction, *artifact.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	metadata = metadata.DeepCopy()
	if metadata == nil {
		if enforce {
			return artifact.StoreActionNone, nil, fmt.Errorf("rulesfile metadata is unavailable")
		}
	} else if err := m.checkDependenciesLocked(metadata.Dependencies, enforce); err != nil {
		return artifact.StoreActionNone, nil, err
	}
	key := Key{Kind: KindRulesfile, Namespace: namespace, Name: name}
	revision := rulesfileRevision{ContentHash: result.ContentHash, Metadata: metadata}
	action, file, err := m.storeLocked(ctx, namespace, name, artifactPriority, artifact.TypeRulesfile, medium, result)
	if err != nil {
		return action, file, err
	}
	return action, file, m.commitRulesfileLocked(ctx, key, medium, revision)
}

// SyncRulesfileDependencies rechecks a verified source with matching known metadata identity.
// A false result without an error requires fetching the source before storing its metadata.
func (m *Manager) SyncRulesfileDependencies(ctx context.Context, key Key, medium artifact.Medium, metadata *commonv1alpha1.ArtifactMeta, enforce bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	metadata = metadata.DeepCopy()
	if metadata == nil || (medium == artifact.MediumOCI && metadata.Digest == "") {
		return false, nil
	}
	current := artifact.FindInstalled(m.installed[key], medium)
	if current == nil {
		return false, nil
	}
	if !slices.ContainsFunc(m.rulesfiles[rulesfileSourceKey{Key: key, Medium: medium}], func(revision rulesfileRevision) bool {
		return revision.ContentHash == current.ContentHash && revision.Metadata != nil && revision.Metadata.Digest == metadata.Digest
	}) {
		return false, nil
	}
	intact, err := m.store.Verify(ctx, current)
	if err != nil || !intact {
		return false, err
	}
	if err := m.checkDependenciesLocked(metadata.Dependencies, enforce); err != nil {
		return false, err
	}
	revision := rulesfileRevision{ContentHash: current.ContentHash, Metadata: metadata}
	if err := m.commitRulesfileLocked(ctx, key, medium, revision); err != nil {
		return false, err
	}
	return true, nil
}

// checkDependenciesLocked uses the same candidate order and version policy as reconciliation.
func (m *Manager) checkDependenciesLocked(dependencies []commonv1alpha1.ArtifactMetaDependency, enforce bool) error {
	if !enforce {
		return nil
	}
	for _, dependency := range dependencies {
		name, _, satisfied, err := m.checkDependencyLocked(dependency, "")
		if err != nil {
			return err
		}
		if !satisfied {
			if name == "" {
				name = dependency.Name
			}
			return &DependencyError{Name: name}
		}
	}
	return nil
}

// commitRulesfileLocked protects every remaining file until duplicate cleanup succeeds.
func (m *Manager) commitRulesfileLocked(ctx context.Context, key Key, medium artifact.Medium,
	revision rulesfileRevision,
) error {
	slot := rulesfileSourceKey{Key: key, Medium: medium}
	current := artifact.FindInstalled(m.installed[key], medium)
	var committed []rulesfileRevision
	if revision.Metadata == nil {
		// Missing metadata cannot erase known dependencies for these same installed bytes.
		for _, previous := range m.rulesfiles[slot] {
			if previous.ContentHash == revision.ContentHash && previous.Metadata != nil {
				committed = appendUniqueRulesfileRevision(committed, previous)
			}
		}
	}
	if len(committed) == 0 {
		committed = []rulesfileRevision{revision}
	}
	pending := slices.Clone(committed)
	for _, file := range m.installed[key] {
		if file.Medium != string(medium) || current == nil || file.Path == current.Path {
			continue
		}
		for _, previous := range m.rulesfiles[slot] {
			if previous.ContentHash == file.ContentHash {
				pending = appendUniqueRulesfileRevision(pending, previous)
			}
		}
	}
	m.rulesfiles[slot] = pending
	if err := m.removeDuplicatePathsLocked(ctx, key, medium); err != nil {
		return err
	}
	m.rulesfiles[slot] = committed
	return nil
}

func (m *Manager) removeDuplicatePathsLocked(ctx context.Context, key Key, medium artifact.Medium) error {
	current := artifact.FindInstalled(m.installed[key], medium)
	var duplicates []artifactv1alpha1.InstalledArtifact
	for _, file := range m.installed[key] {
		if file.Medium == string(medium) && current != nil && file.Path != current.Path {
			duplicates = append(duplicates, file)
		}
	}
	if len(duplicates) == 0 {
		return nil
	}
	return m.removeLocked(ctx, key, duplicates)
}

func appendUniqueRulesfileRevision(revisions []rulesfileRevision, revision rulesfileRevision) []rulesfileRevision {
	if slices.ContainsFunc(revisions, func(existing rulesfileRevision) bool {
		return existing.ContentHash == revision.ContentHash && apiequality.Semantic.DeepEqual(existing.Metadata, revision.Metadata)
	}) {
		return revisions
	}
	return append(revisions, revision)
}
