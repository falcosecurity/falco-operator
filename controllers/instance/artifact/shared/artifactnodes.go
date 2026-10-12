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
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

// ListAllArtifactNodes lists every ArtifactNode of namespace from the informer cache, those being deleted included.
// The objects are not copied out of the cache and must not be modified.
func ListAllArtifactNodes(ctx context.Context, cl client.Client, namespace string) ([]artifactv1alpha1.ArtifactNode, error) {
	list := &artifactv1alpha1.ArtifactNodeList{}
	if err := cl.List(ctx, list, client.InNamespace(namespace), client.UnsafeDisableDeepCopy); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// ArtifactNodesByNode indexes items by node name, leaving out the ones being deleted: those are not expected to
// report any more.
func ArtifactNodesByNode(items []artifactv1alpha1.ArtifactNode) map[string]*artifactv1alpha1.ArtifactNode {
	artifactNodes := make(map[string]*artifactv1alpha1.ArtifactNode, len(items))
	for i := range items {
		artifactNode := &items[i]
		if !artifactNode.DeletionTimestamp.IsZero() {
			continue
		}
		artifactNodes[artifactNode.Spec.NodeName] = artifactNode
	}
	return artifactNodes
}

// AnyHoldsArtifact reports whether any of items, those being deleted included, lists the artifact in its spec or
// holds a status entry for it. A parent being deleted must outlive node cleanup: while a node's spec lists the
// artifact or the node reports on it, files for it may still be on that node. The entry is withdrawn only after
// the last file is removed, so an entry that is gone means the node is clean.
//
// items normally come from the informer cache. A cache that has not yet seen an entry can only make the parent go a
// moment early, and the node controller removes the files regardless, since it acts on the ArtifactNode and not the
// parent.
func AnyHoldsArtifact(items []artifactv1alpha1.ArtifactNode, kind artifact.Kind, name string) bool {
	for i := range items {
		if holdsArtifact(&items[i], kind, name) {
			return true
		}
	}
	return false
}

// DesiredNodes returns the nodes an artifact of kind is expected to be reported on: the ones its selector selects
// that run a Falco pod (matching), and the ones among artifactNodes (see ArtifactNodesByNode) whose spec still
// lists it.
//
// The second group matters while a Falco pod is being replaced. The assignment controller keeps the node's
// ArtifactNode, with its assignment and what its artifact operator reported, for a grace period, so that the
// parents reading it do not flap. A parent that dropped the node the moment its pod went would flap regardless.
func DesiredNodes(
	artifactNodes map[string]*artifactv1alpha1.ArtifactNode, kind artifact.Kind, obj client.Object, matching []corev1.Node,
) map[string]struct{} {
	desired := make(map[string]struct{}, len(matching))
	for i := range matching {
		desired[matching[i].Name] = struct{}{}
	}
	for _, node := range artifactNodes {
		if controllerhelper.AssignedArtifact(node, kind, obj.GetName()) != nil {
			desired[node.Spec.NodeName] = struct{}{}
		}
	}
	return desired
}

// NodeConditionsOnDeletion returns the per-node conditions of obj, an artifact of kind that is being deleted, from
// the nodes among items whose spec still lists it or that report on it. During a Plugin's deletion this is how a
// DeletionBlocked condition published by the node's sidecar reaches the parent.
//
// ArtifactNodes being deleted count like the others, as they do for AnyHoldsArtifact: the sidecar of such a node
// may still be removing the artifact, and what it reports is why the parent cannot go yet.
func NodeConditionsOnDeletion(items []artifactv1alpha1.ArtifactNode, kind artifact.Kind, obj client.Object) []controllerhelper.NodeConditionSet {
	var holding []controllerhelper.NodeConditionSet
	for i := range items {
		if artifactNode := &items[i]; holdsArtifact(artifactNode, kind, obj.GetName()) {
			// Setting the deletion timestamp of an object that has finalizers bumps its generation, and no node
			// reports on a deleted artifact's new generation: what the nodes last reported stands for it.
			// The conditions are the cache's, so they are copied before being restamped.
			conditions := slices.Clone(conditionsFromArtifactNode(artifactNode, kind, obj))
			for j := range conditions {
				conditions[j].ObservedGeneration = obj.GetGeneration()
			}
			holding = append(holding, controllerhelper.NodeConditionSet{NodeName: artifactNode.Spec.NodeName, Conditions: conditions})
		}
	}
	return holding
}

// holdsArtifact reports whether the node lists the artifact in its spec or holds a status entry for it.
func holdsArtifact(artifactNode *artifactv1alpha1.ArtifactNode, kind artifact.Kind, name string) bool {
	if controllerhelper.AssignedArtifact(artifactNode, kind, name) != nil {
		return true
	}
	for j := range artifactNode.Status.Artifacts {
		if e := &artifactNode.Status.Artifacts[j]; e.Kind == kind && e.Name == name {
			return true
		}
	}
	return false
}

// NodeConditionsFromArtifactNodes returns one entry for every node in desired, with the conditions that node's sidecar
// published for the artifact obj of the given kind. A node whose ArtifactNode is missing reports none,
// which the aggregate treats as pending.
//
// For a node that has an ArtifactNode, the artifact's status is:
//   - its published entry, when the entry is for this incarnation of the artifact (same uid). An entry
//     of a deleted artifact of the same name is not credited to its replacement;
//   - a Programmed=False NodeCapacityExceeded, when the ArtifactNode's spec does not list the artifact and lists the
//     maximum number of others, so the artifact was left out;
//   - otherwise nothing, which the aggregate treats as pending.
//
// A node that is not in desired but reports that it cannot remove the artifact yet (DeletionBlocked), as one the
// selector stopped matching does while a Rulesfile there still requires a plugin, is returned as a leftover, so
// that the artifact shows what it left behind.
func NodeConditionsFromArtifactNodes(
	artifactNodes map[string]*artifactv1alpha1.ArtifactNode, desired map[string]struct{}, kind artifact.Kind, obj client.Object,
) []controllerhelper.NodeConditionSet {
	out := make([]controllerhelper.NodeConditionSet, 0, len(desired))
	for name := range desired {
		entry := controllerhelper.NodeConditionSet{NodeName: name}
		if artifactNode, ok := artifactNodes[name]; ok {
			entry.Conditions = conditionsFromArtifactNode(artifactNode, kind, obj)
		}
		out = append(out, entry)
	}
	for name, artifactNode := range artifactNodes {
		if _, expected := desired[name]; expected {
			continue
		}
		conditions := conditionsFromArtifactNode(artifactNode, kind, obj)
		if apimeta.IsStatusConditionTrue(conditions, commonv1alpha1.ConditionDeletionBlocked.String()) {
			out = append(out, controllerhelper.NodeConditionSet{NodeName: name, Conditions: conditions, Leftover: true})
		}
	}
	return out
}

func conditionsFromArtifactNode(artifactNode *artifactv1alpha1.ArtifactNode, kind artifact.Kind, obj client.Object) []metav1.Condition {
	name := obj.GetName()
	for i := range artifactNode.Status.Artifacts {
		entry := &artifactNode.Status.Artifacts[i]
		if entry.Kind != kind || entry.Name != name {
			continue
		}
		if entry.UID == string(obj.GetUID()) {
			return entry.Conditions
		}
		break // a previous incarnation of the artifact
	}
	if controllerhelper.AssignedArtifact(artifactNode, kind, name) == nil && len(artifactNode.Spec.Artifacts) >= artifactv1alpha1.MaxNodeArtifacts {
		return []metav1.Condition{{
			Type:   commonv1alpha1.ConditionProgrammed.String(),
			Status: metav1.ConditionFalse,
			Reason: artifact.ReasonNodeCapacityExceeded,
			Message: fmt.Sprintf("The node already lists the maximum of %d artifacts, so this artifact is not assigned to it",
				artifactv1alpha1.MaxNodeArtifacts),
			ObservedGeneration: obj.GetGeneration(),
		}}
	}
	return nil
}

// ArtifactNodeHandler enqueues the artifacts of kind that an ArtifactNode event concerns. The spec of an
// ArtifactNode lists up to a hundred artifacts, so enqueueing every artifact it mentions on every
// update would wake a hundred reconciles for one node's change. It enqueues only the artifacts whose own
// part of the ArtifactNode changed: their assignment in the spec or their entry in the status.
//
// It also wakes every artifact of kind in the namespace when an ArtifactNode reaches or leaves its cap. An
// artifact that is desired on a node but not listed in its spec has nothing in the ArtifactNode to change, yet its result
// there switches to NodeCapacityExceeded and back at that moment.
//
// newList returns an empty list of the parent kind, used for that case.
func ArtifactNodeHandler(cl client.Client, kind artifact.Kind, newList func() client.ObjectList) handler.EventHandler {
	return handler.Funcs{
		CreateFunc: func(_ context.Context, e event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			if artifactNode, ok := e.Object.(*artifactv1alpha1.ArtifactNode); ok {
				controllerhelper.EnqueueNames(q, artifactNode.Namespace, changedArtifacts(kind, nil, artifactNode))
			}
		},
		UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			oldArtifactNode, oldOK := e.ObjectOld.(*artifactv1alpha1.ArtifactNode)
			newArtifactNode, newOK := e.ObjectNew.(*artifactv1alpha1.ArtifactNode)
			if !oldOK || !newOK {
				return
			}
			controllerhelper.EnqueueNames(q, newArtifactNode.Namespace, changedArtifacts(kind, oldArtifactNode, newArtifactNode))
			if atCap(oldArtifactNode) != atCap(newArtifactNode) {
				for _, req := range controllerhelper.EnqueueAllOfType(ctx, cl, newList(), client.InNamespace(newArtifactNode.Namespace)) {
					q.Add(req)
				}
			}
		},
		DeleteFunc: func(_ context.Context, e event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			if artifactNode, ok := e.Object.(*artifactv1alpha1.ArtifactNode); ok {
				controllerhelper.EnqueueNames(q, artifactNode.Namespace, changedArtifacts(kind, artifactNode, nil))
			}
		},
	}
}

func atCap(artifactNode *artifactv1alpha1.ArtifactNode) bool {
	return len(artifactNode.Spec.Artifacts) >= artifactv1alpha1.MaxNodeArtifacts
}

// changedArtifacts returns the names of the artifacts of kind whose assignment or entry differs between
// oldArtifactNode and newArtifactNode. A nil ArtifactNode stands for one that does not exist.
func changedArtifacts(kind artifact.Kind, oldArtifactNode, newArtifactNode *artifactv1alpha1.ArtifactNode) []string {
	return controllerhelper.ChangedArtifacts(kind, oldArtifactNode, newArtifactNode, controllerhelper.ArtifactView.Equal)
}

// lostNodeGrace is how long a node must have been unreachable before the artifacts it holds stop keeping a
// deleted artifact alive. It outlasts a reboot or a network blip, after which the node's sidecar finishes the
// removal itself.
const lostNodeGrace = 5 * time.Minute

// lostNodes returns the nodes that have been unreachable for longer than lostNodeGrace at now, and how long until
// the next unreachable node joins them (zero when there is none).
//
// A node is unreachable while it carries the node.kubernetes.io/unreachable NoExecute taint, which the node
// lifecycle controller adds, with the time, when the kubelet stops reporting. A Falco pod on such a node stays
// Running, since a DaemonSet pod tolerates the taint, so the node keeps its ArtifactNode, and its sidecar, which
// cannot reach the API server either, never withdraws its status entries. Without this, one node that is down
// would keep every deleted artifact it held from ever going. A sidecar that comes back finds the artifact gone
// from the spec of its ArtifactNode and removes what it installed, which needs nothing of the artifact itself.
func lostNodes(ctx context.Context, cl client.Client, now time.Time) (lost map[string]struct{}, recheck time.Duration, err error) {
	nodes, err := controllerhelper.ListMatchingNodes(ctx, cl, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("list Nodes: %w", err)
	}
	lost = map[string]struct{}{}
	for i := range nodes {
		since, unreachable := unreachableSince(&nodes[i])
		if !unreachable {
			continue
		}
		if left := lostNodeGrace - now.Sub(since); left > 0 {
			if recheck == 0 || left < recheck {
				recheck = left
			}
			continue
		}
		lost[nodes[i].Name] = struct{}{}
	}
	return lost, recheck, nil
}

// unreachableSince returns since when node carries the unreachable NoExecute taint. A taint without a time, which
// only one added by hand can be, does not count: there is no telling how long the node has been away.
func unreachableSince(node *corev1.Node) (time.Time, bool) {
	for i := range node.Spec.Taints {
		taint := &node.Spec.Taints[i]
		if taint.Key == corev1.TaintNodeUnreachable && taint.Effect == corev1.TaintEffectNoExecute && taint.TimeAdded != nil {
			return taint.TimeAdded.Time, true
		}
	}
	return time.Time{}, false
}

// holderNotLost returns the node of one of items that lists the artifact in its spec or holds a status entry for
// it and is not in lost, or "" when every holder is.
func holderNotLost(items []artifactv1alpha1.ArtifactNode, kind artifact.Kind, name string, lost map[string]struct{}) string {
	for i := range items {
		if _, isLost := lost[items[i].Spec.NodeName]; !isLost && holdsArtifact(&items[i], kind, name) {
			return items[i].Spec.NodeName
		}
	}
	return ""
}

// reachabilityChanged accepts the updates of a Node in which it became unreachable, became reachable again, or the
// time since which it is unreachable changed: what lostNodes answers from.
func reachabilityChanged() predicate.Predicate {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		oldNode, oldOK := e.ObjectOld.(*corev1.Node)
		newNode, newOK := e.ObjectNew.(*corev1.Node)
		if !oldOK || !newOK {
			return false
		}
		oldSince, oldUnreachable := unreachableSince(oldNode)
		newSince, newUnreachable := unreachableSince(newNode)
		return oldUnreachable != newUnreachable || !oldSince.Equal(newSince)
	}}
}
