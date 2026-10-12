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
	"slices"

	apiequality "k8s.io/apimachinery/pkg/api/equality"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

type rulesfileRevision struct {
	ContentHash string
	Metadata    *commonv1alpha1.ArtifactMeta
}

// StoreRulesfile writes one source and updates its dependencies under the plugin-removal lock.
// Failed content writes preserve the previous dependencies.
func (n *Node) StoreRulesfile(ctx context.Context, name string, artifactPriority int32,
	medium artifact.Medium, result artifact.FetchResult, metadata *commonv1alpha1.ArtifactMeta, enforce bool,
) (artifact.StoreAction, *artifact.File, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	metadata = metadata.DeepCopy()
	if metadata == nil {
		if enforce {
			return artifact.StoreActionNone, nil, fmt.Errorf("rulesfile metadata is unavailable")
		}
	} else if err := n.checkDependenciesLocked(metadata.Dependencies, enforce); err != nil {
		return artifact.StoreActionNone, nil, err
	}
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: name}
	revision := rulesfileRevision{ContentHash: result.ContentHash, Metadata: metadata}
	action, file, err := n.storeLocked(ctx, name, artifactPriority, artifact.KindRulesfile, medium, result)
	if err != nil {
		return action, file, err
	}
	return action, file, n.commitRulesfileLocked(ctx, key, medium, revision)
}

// syncRulesfileDependencies rechecks a verified source with matching known metadata identity.
// A false result without an error requires fetching the source before storing its metadata.
func (n *Node) syncRulesfileDependencies(ctx context.Context, key artifact.Ref, medium artifact.Medium, metadata *commonv1alpha1.ArtifactMeta, enforce bool) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	metadata = metadata.DeepCopy()
	if metadata == nil || (medium == artifact.MediumOCI && metadata.Digest == "") {
		return false, nil
	}
	current := artifact.FindInstalled(n.filesLocked(key), medium)
	if current == nil {
		return false, nil
	}
	if !slices.ContainsFunc(n.requiresLocked(key, medium), func(revision rulesfileRevision) bool {
		return revision.ContentHash == current.ContentHash && revision.Metadata != nil && revision.Metadata.Digest == metadata.Digest
	}) {
		return false, nil
	}
	intact, err := n.disk.Verify(ctx, current)
	if err != nil || !intact {
		return false, err
	}
	if err := n.checkDependenciesLocked(metadata.Dependencies, enforce); err != nil {
		return false, err
	}
	revision := rulesfileRevision{ContentHash: current.ContentHash, Metadata: metadata}
	if err := n.commitRulesfileLocked(ctx, key, medium, revision); err != nil {
		return false, err
	}
	return true, nil
}

// checkDependenciesLocked uses the same candidate order and version policy as reconciliation.
func (n *Node) checkDependenciesLocked(dependencies []commonv1alpha1.ArtifactMetaDependency, enforce bool) error {
	if !enforce {
		return nil
	}
	for _, dependency := range dependencies {
		name, _, satisfied, err := n.checkDependencyLocked(dependency, "")
		if err != nil {
			return err
		}
		if !satisfied {
			if name == "" {
				name = dependency.Name
			}
			return &dependencyError{Name: name}
		}
	}
	return nil
}

// commitRulesfileLocked protects every remaining file until duplicate cleanup succeeds.
func (n *Node) commitRulesfileLocked(ctx context.Context, key artifact.Ref, medium artifact.Medium,
	revision rulesfileRevision,
) error {
	current := artifact.FindInstalled(n.filesLocked(key), medium)
	var committed []rulesfileRevision
	if revision.Metadata == nil {
		// Missing metadata cannot erase known dependencies for these same installed bytes.
		for _, previous := range n.requiresLocked(key, medium) {
			if previous.ContentHash == revision.ContentHash && previous.Metadata != nil {
				committed = appendUniqueRulesfileRevision(committed, previous)
			}
		}
	}
	if len(committed) == 0 {
		committed = []rulesfileRevision{revision}
	}
	pending := slices.Clone(committed)
	for _, file := range n.filesLocked(key) {
		if file.Medium != string(medium) || current == nil || file.Path == current.Path {
			continue
		}
		for _, previous := range n.requiresLocked(key, medium) {
			if previous.ContentHash == file.ContentHash {
				pending = appendUniqueRulesfileRevision(pending, previous)
			}
		}
	}
	n.setRequiresLocked(key, medium, pending)
	if err := n.removeDuplicatePathsLocked(ctx, key, medium); err != nil {
		return err
	}
	n.setRequiresLocked(key, medium, committed)
	return nil
}

func (n *Node) removeDuplicatePathsLocked(ctx context.Context, key artifact.Ref, medium artifact.Medium) error {
	current := artifact.FindInstalled(n.filesLocked(key), medium)
	var duplicates []artifactv1alpha1.InstalledArtifact
	for _, file := range n.filesLocked(key) {
		if file.Medium == string(medium) && current != nil && file.Path != current.Path {
			duplicates = append(duplicates, file)
		}
	}
	if len(duplicates) == 0 {
		return nil
	}
	return n.removeLocked(ctx, key, duplicates)
}

func appendUniqueRulesfileRevision(revisions []rulesfileRevision, revision rulesfileRevision) []rulesfileRevision {
	if slices.ContainsFunc(revisions, func(existing rulesfileRevision) bool {
		return existing.ContentHash == revision.ContentHash && apiequality.Semantic.DeepEqual(existing.Metadata, revision.Metadata)
	}) {
		return revisions
	}
	return append(revisions, revision)
}

// seedRulesfileRequirements records what an installed rulesfile source asks of the node, recovered
// from the file itself rather than from any CR.
//
// It is what a restart needs. The requires side of the dependency graph is otherwise written only
// when a rulesfile is installed, so after a restart it is empty until every rulesfile has
// reconciled, and in that window blockedByOthersLocked finds nothing, so removing a plugin an
// installed rulesfile depends on is not blocked. Warm sync calls this for every rulesfile it
// recovers from disk, which closes that window.
func (n *Node) seedRulesfileRequirements(key artifact.Ref, medium artifact.Medium,
	contentHash string, metadata *commonv1alpha1.ArtifactMeta,
) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.setRequiresLocked(key, medium, []rulesfileRevision{{ContentHash: contentHash, Metadata: metadata}})
}
