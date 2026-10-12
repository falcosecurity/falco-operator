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

package controllerhelper

import (
	"context"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// AssignedArtifact returns the assignment of the artifact in the ArtifactNode's spec, or nil when the spec does not
// list it.
func AssignedArtifact(artifactNode *artifactv1alpha1.ArtifactNode, kind artifact.Kind, name string) *artifactv1alpha1.NodeArtifactRef {
	for i := range artifactNode.Spec.Artifacts {
		if r := &artifactNode.Spec.Artifacts[i]; r.Kind == kind && r.Name == name {
			return r
		}
	}
	return nil
}

// ArtifactNodeSidecarFinalizer is the finalizer the artifact operator puts on its node's ArtifactNode,
// so that a deleted ArtifactNode still gets every installed artifact removed before it goes away.
const ArtifactNodeSidecarFinalizer = "artifactnode.artifact.falcosecurity.dev/sidecar"

// GetArtifactNode returns the ArtifactNode of nodeName in namespace, or nil when it does not exist,
// or is not visible to a cache scoped to the node's own ArtifactNode.
func GetArtifactNode(ctx context.Context, cl client.Client, namespace, nodeName string) (*artifactv1alpha1.ArtifactNode, error) {
	artifactNode := &artifactv1alpha1.ArtifactNode{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: nodeName}, artifactNode); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return artifactNode, nil
}

// EnqueueNames adds a request for each of names in namespace to q.
func EnqueueNames(q workqueue.TypedRateLimitingInterface[reconcile.Request], namespace string, names []string) {
	for _, name := range names {
		q.Add(reconcile.Request{NamespacedName: client.ObjectKey{Namespace: namespace, Name: name}})
	}
}

// ArtifactView is what an ArtifactNode says about one artifact: its assignment and its published entry. The
// handlers that wake artifacts on an ArtifactNode change compare views to tell which artifacts it concerns.
type ArtifactView struct {
	Assigned *artifactv1alpha1.NodeArtifactRef
	Reported *artifactv1alpha1.NodeArtifactStatus
}

// Equal reports whether both views hold the same assignment and the same entry. The comparison is on the
// pointed-to values: Semantic.DeepEqual refuses structs that have unexported fields.
func (v ArtifactView) Equal(other ArtifactView) bool {
	return v.SameAssignment(other) && equalPtr(v.Reported, other.Reported)
}

// SameAssignment reports whether both views hold the same assignment, whatever their entries.
func (v ArtifactView) SameAssignment(other ArtifactView) bool {
	return equalPtr(v.Assigned, other.Assigned)
}

func equalPtr[T any](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return apiequality.Semantic.DeepEqual(*a, *b)
}

func viewsOf(artifactNode *artifactv1alpha1.ArtifactNode, kind artifact.Kind) map[string]ArtifactView {
	views := map[string]ArtifactView{}
	if artifactNode == nil {
		return views
	}
	for i := range artifactNode.Spec.Artifacts {
		if r := &artifactNode.Spec.Artifacts[i]; r.Kind == kind {
			v := views[r.Name]
			v.Assigned = r
			views[r.Name] = v
		}
	}
	for i := range artifactNode.Status.Artifacts {
		if e := &artifactNode.Status.Artifacts[i]; e.Kind == kind {
			v := views[e.Name]
			v.Reported = e
			views[e.Name] = v
		}
	}
	return views
}

// ChangedArtifacts returns the names of the artifacts of kind whose views in oldArtifactNode and newArtifactNode
// differ by same, such as ArtifactView.Equal. A nil ArtifactNode stands for one that does not exist. An artifact
// present on one side only is compared with an empty view, so it counts as changed exactly when same says the side
// it is on differs from nothing.
func ChangedArtifacts(
	kind artifact.Kind, oldArtifactNode, newArtifactNode *artifactv1alpha1.ArtifactNode, same func(o, n ArtifactView) bool,
) []string {
	oldViews, newViews := viewsOf(oldArtifactNode, kind), viewsOf(newArtifactNode, kind)
	var changed []string
	for name, o := range oldViews {
		if !same(o, newViews[name]) {
			changed = append(changed, name)
		}
	}
	for name, n := range newViews {
		if _, seen := oldViews[name]; !seen && !same(ArtifactView{}, n) {
			changed = append(changed, name)
		}
	}
	return changed
}
