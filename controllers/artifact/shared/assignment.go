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
	"context"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

// AssignmentState is what the node's spec says about one artifact, as seen by the artifact operator.
type AssignmentState int

const (
	// NotAssigned means the node's spec does not list the artifact, or there is no ArtifactNode for the node, or it
	// is being deleted. The reconciler removes what the node holds for the artifact. The artifact operator selects
	// its ArtifactNode by name, so the object is missing only when it was really deleted.
	NotAssigned AssignmentState = iota
	// AssignmentPending means the spec lists the artifact for another incarnation of it (another uid). The
	// operator has not caught up with the artifact's recreation yet, so the reconciler waits.
	AssignmentPending
	// Assigned means the spec lists this incarnation of the artifact for the node.
	Assigned
)

// AssignmentRetryDelay is how long a reconciler waits when the spec lists another incarnation of its
// artifact. The operator updates the spec within milliseconds of the artifact's recreation.
const AssignmentRetryDelay = 250 * time.Millisecond

// ResolveAssignment reports whether the node's ArtifactNode assigns parent, an artifact of kind, to it.
func ResolveAssignment(
	ctx context.Context, cl client.Client, namespace, nodeName string, kind artifact.Kind, parent client.Object,
) (AssignmentState, error) {
	ref, err := listedRef(ctx, cl, namespace, nodeName, kind, parent.GetName())
	switch {
	case err != nil || ref == nil:
		return NotAssigned, err
	case ref.UID != string(parent.GetUID()):
		return AssignmentPending, nil
	default:
		return Assigned, nil
	}
}

// IsListed reports whether the spec of the node's ArtifactNode, when it exists and is not being deleted, lists
// the artifact of kind named name, whatever its uid.
func IsListed(ctx context.Context, cl client.Client, namespace, nodeName string, kind artifact.Kind, name string) (bool, error) {
	ref, err := listedRef(ctx, cl, namespace, nodeName, kind, name)
	return ref != nil, err
}

// listedRef returns the entry of the artifact of kind named name in the spec of the node's ArtifactNode, or nil
// when the spec does not list it, or there is no ArtifactNode for the node, or it is being deleted.
func listedRef(
	ctx context.Context, cl client.Client, namespace, nodeName string, kind artifact.Kind, name string,
) (*artifactv1alpha1.NodeArtifactRef, error) {
	artifactNode, err := controllerhelper.GetArtifactNode(ctx, cl, namespace, nodeName)
	if err != nil || artifactNode == nil || !artifactNode.DeletionTimestamp.IsZero() {
		return nil, err
	}
	return controllerhelper.AssignedArtifact(artifactNode, kind, name), nil
}

// AssignmentHandler is the artifact operator's counterpart of the instance operator's ArtifactNodeHandler: it enqueues the
// artifacts of kind whose assignment in the node's spec was added, removed or changed. It ignores status,
// which the sidecar itself writes, so its own updates do not echo back into reconciles.
//
// dependsOn lists other kinds whose published status matters to this one: when an entry of one of them
// changes, every assigned artifact of kind is enqueued. A rulesfile depends on the plugins it requires.
func AssignmentHandler(kind artifact.Kind, dependsOn ...artifact.Kind) handler.EventHandler {
	return handler.Funcs{
		CreateFunc: func(_ context.Context, e event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			if artifactNode, ok := e.Object.(*artifactv1alpha1.ArtifactNode); ok {
				controllerhelper.EnqueueNames(q, artifactNode.Namespace, assignedNames(artifactNode, kind))
			}
		},
		UpdateFunc: func(_ context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			oldArtifactNode, oldOK := e.ObjectOld.(*artifactv1alpha1.ArtifactNode)
			newArtifactNode, newOK := e.ObjectNew.(*artifactv1alpha1.ArtifactNode)
			if !oldOK || !newOK {
				return
			}
			names := changedAssignments(kind, oldArtifactNode, newArtifactNode)
			if dependencyChanged(dependsOn, oldArtifactNode, newArtifactNode) {
				names = append(names, assignedNames(newArtifactNode, kind)...)
			}
			controllerhelper.EnqueueNames(q, newArtifactNode.Namespace, names)
		},
	}
}

// assignedRequests returns a request for every artifact of kind the node's ArtifactNode assigns, and none when
// there is no ArtifactNode.
func assignedRequests(ctx context.Context, cl client.Client, namespace, nodeName string, kind artifact.Kind) []reconcile.Request {
	artifactNode, err := controllerhelper.GetArtifactNode(ctx, cl, namespace, nodeName)
	if err != nil {
		log.FromContext(ctx).Error(err, "unable to get the ArtifactNode", "node", nodeName)
		return nil
	}
	if artifactNode == nil {
		return nil
	}
	var reqs []reconcile.Request
	for _, name := range assignedNames(artifactNode, kind) {
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Namespace: namespace, Name: name}})
	}
	return reqs
}

func assignedNames(artifactNode *artifactv1alpha1.ArtifactNode, kind artifact.Kind) []string {
	var names []string
	for i := range artifactNode.Spec.Artifacts {
		if r := &artifactNode.Spec.Artifacts[i]; r.Kind == kind {
			names = append(names, r.Name)
		}
	}
	return names
}

// changedAssignments returns the artifacts of kind whose assignment differs between two ArtifactNodes.
func changedAssignments(kind artifact.Kind, oldArtifactNode, newArtifactNode *artifactv1alpha1.ArtifactNode) []string {
	return controllerhelper.ChangedArtifacts(kind, oldArtifactNode, newArtifactNode, controllerhelper.ArtifactView.SameAssignment)
}

// dependencyChanged reports whether the state of an artifact of one of kinds changed between two ArtifactNodes in a
// way a dependent artifact acts on: an entry that appeared, went or was replaced by another incarnation, a change of
// its installed files, or its Programmed condition changing status. Other changes to its conditions (a message, a
// reason, a condition a dependent never reads) do not count: every dependent artifact on the node would be woken
// for each of them.
func dependencyChanged(kinds []artifact.Kind, oldArtifactNode, newArtifactNode *artifactv1alpha1.ArtifactNode) bool {
	for _, kind := range kinds {
		reportedSame := func(o, n controllerhelper.ArtifactView) bool { return sameHolding(o.Reported, n.Reported) }
		if len(controllerhelper.ChangedArtifacts(kind, oldArtifactNode, newArtifactNode, reportedSame)) > 0 {
			return true
		}
	}
	return false
}

// sameHolding reports whether two status entries name the same incarnation of an artifact, with the same installed
// files and the same Programmed status, whatever the rest of their conditions.
func sameHolding(a, b *artifactv1alpha1.NodeArtifactStatus) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.UID == b.UID && apiequality.Semantic.DeepEqual(a.InstalledArtifacts, b.InstalledArtifacts) &&
		programmedStatus(a) == programmedStatus(b)
}

func programmedStatus(entry *artifactv1alpha1.NodeArtifactStatus) metav1.ConditionStatus {
	if c := apimeta.FindStatusCondition(entry.Conditions, commonv1alpha1.ConditionProgrammed.String()); c != nil {
		return c.Status
	}
	return ""
}
