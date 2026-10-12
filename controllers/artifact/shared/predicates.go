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

package shared

import (
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// ParentChanged accepts the updates of an artifact that can change what the artifact operator does with it: a new
// generation, the start of its deletion, and a change of the status fields the instance operator writes for the
// nodes (observed generation and artifact metadata). The rest of its status is the aggregate of what the nodes
// report, which the instance operator rewrites as they report: waking every node's reconcile for it would cost a
// reconcile per node per write. Creations and deletions are always accepted.
func ParentChanged() predicate.Predicate {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		if e.ObjectOld == nil || e.ObjectNew == nil {
			return true
		}
		if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() ||
			!e.ObjectOld.GetDeletionTimestamp().Equal(e.ObjectNew.GetDeletionTimestamp()) {
			return true
		}
		return !apiequality.Semantic.DeepEqual(statusForNodes(e.ObjectOld), statusForNodes(e.ObjectNew))
	}}
}

// nodeStatus is the part of an artifact's status that the instance operator writes for the nodes to read. Its
// fields are exported only because apiequality compares no unexported field.
type nodeStatus struct {
	ObservedGeneration int64
	ArtifactMeta       *commonv1alpha1.ArtifactMeta
	SourcesHash        string
}

// statusForNodes returns the part of obj's status the artifact operator reads. An object of another type has
// none, so only its generation and deletion count.
func statusForNodes(obj client.Object) nodeStatus {
	a, ok := obj.(artifactv1alpha1.Artifact)
	if !ok {
		return nodeStatus{}
	}
	return nodeStatus{*a.GetStatusObservedGeneration(), a.GetArtifactMeta(), a.GetArtifactMetaSourcesHash()}
}
