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

package artifactnode

import (
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// candidate is an artifact that selects a node and so may be assigned to it.
type candidate struct {
	ref     artifactv1alpha1.NodeArtifactRef
	created metav1.Time
}

// candidatesForNode returns the artifacts among the given ones whose selector selects a node with
// nodeLabels. Artifacts being deleted are not candidates. An artifact whose selector is invalid is
// never assigned and is reported as "Kind/name" in invalid, without affecting the others.
func candidatesForNode(
	nodeLabels map[string]string,
	rulesfiles []artifactv1alpha1.Rulesfile,
	plugins []artifactv1alpha1.Plugin,
	configs []artifactv1alpha1.Config,
) (cands []candidate, invalid []string) {
	add := func(obj artifactv1alpha1.Artifact) {
		if !obj.GetDeletionTimestamp().IsZero() {
			return
		}
		kind := obj.GetArtifactKind()
		selected, err := selects(obj.GetSelector(), nodeLabels)
		if err != nil {
			invalid = append(invalid, string(kind)+"/"+obj.GetName())
			return
		}
		if !selected {
			return
		}
		cands = append(cands, candidate{
			ref:     artifactv1alpha1.NodeArtifactRef{Kind: kind, Name: obj.GetName(), UID: string(obj.GetUID())},
			created: obj.GetCreationTimestamp(),
		})
	}
	for i := range rulesfiles {
		add(&rulesfiles[i])
	}
	for i := range plugins {
		add(&plugins[i])
	}
	for i := range configs {
		add(&configs[i])
	}
	return cands, invalid
}

// selects reports whether sel selects a node with nodeLabels. A nil selector selects every node,
// as it does in controllerhelper.ListMatchingNodes.
func selects(sel *metav1.LabelSelector, nodeLabels map[string]string) (bool, error) {
	if sel == nil {
		return true, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return false, err
	}
	return selector.Matches(labels.Set(nodeLabels)), nil
}

// selectArtifacts picks which candidates to list in an ArtifactNode's spec, at most limit of them.
//
// Artifacts already listed in existing keep their slot over newcomers, even when a newcomer is older,
// so a full node never evicts an installed artifact. Within each group the order is creation time,
// then kind, then name, which makes the outcome deterministic. An existing entry that is no longer a
// candidate is dropped and does not consume a slot, and a recreated artifact (same kind and name, new
// uid) keeps its slot and is listed with the new uid.
//
// selected is sorted by kind and name, the canonical order of a spec. dropped holds the candidates
// that did not fit, in the order they lost out.
func selectArtifacts(
	existing []artifactv1alpha1.NodeArtifactRef, cands []candidate, limit int,
) (selected, dropped []artifactv1alpha1.NodeArtifactRef) {
	listed := make(map[artifact.Ref]struct{}, len(existing))
	for _, r := range existing {
		listed[artifact.RefOfAssignment(r)] = struct{}{}
	}

	ranked := slices.Clone(cands)
	slices.SortFunc(ranked, func(a, b candidate) int {
		_, aListed := listed[artifact.RefOfAssignment(a.ref)]
		_, bListed := listed[artifact.RefOfAssignment(b.ref)]
		if aListed != bListed {
			if aListed {
				return -1
			}
			return 1
		}
		if c := a.created.Compare(b.created.Time); c != 0 {
			return c
		}
		return compareRefs(a.ref, b.ref)
	})

	fit := max(0, min(limit, len(ranked)))
	for _, c := range ranked[:fit] {
		selected = append(selected, c.ref)
	}
	for _, c := range ranked[fit:] {
		dropped = append(dropped, c.ref)
	}
	sortRefs(selected)
	return selected, dropped
}

// sameArtifacts reports whether a and b list the same artifacts, regardless of order. Two entries are
// the same only when kind, name and uid all match.
func sameArtifacts(a, b []artifactv1alpha1.NodeArtifactRef) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = slices.Clone(a), slices.Clone(b)
	sortRefs(a)
	sortRefs(b)
	return slices.Equal(a, b)
}

func sortRefs(refs []artifactv1alpha1.NodeArtifactRef) {
	slices.SortFunc(refs, compareRefs)
}

func compareRefs(a, b artifactv1alpha1.NodeArtifactRef) int {
	return artifact.RefOfAssignment(a).Compare(artifact.RefOfAssignment(b))
}
