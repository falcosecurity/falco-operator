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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

const falcoInstanceLabel = "app.kubernetes.io/instance"

// ClearFinalizersIfNodeOrPodGone checks whether the per-node artifact operator that
// owns obj's finalizers can still perform cleanup. When either the Kubernetes Node no
// longer exists or no Running Falco pod is present on it, all finalizers are removed
// via a Patch so the API server can complete the pending deletion.
//
// This covers both a deleted Kubernetes Node and a Falco pod disappearing from a
// still-existing node. In either case no per-node artifact operator remains to remove
// its finalizer, and there is no remaining node-side cleanup to perform. Without this
// call the ArtifactNode would remain stuck in Terminating indefinitely, blocking its
// parent artifact cleanup.
func ClearFinalizersIfNodeOrPodGone(
	ctx context.Context,
	cl client.Client,
	nodeName string,
	runningFalcoNodes map[string]struct{},
	obj client.Object,
) error {
	if len(obj.GetFinalizers()) == 0 {
		return nil
	}

	reason := "Falco pod gone"
	if _, podRunning := runningFalcoNodes[nodeName]; podRunning {
		node := &corev1.Node{}
		err := cl.Get(ctx, client.ObjectKey{Name: nodeName}, node)
		if err == nil {
			return nil // Node and per-node artifact operator still exist; let it clean up normally.
		}
		if !k8serrors.IsNotFound(err) {
			return err
		}
		reason = "Node gone"
	}

	log.FromContext(ctx).Info("Force-clearing finalizers on orphaned node object",
		"node", nodeName, "object", obj.GetName(), "reason", reason)
	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object)) //nolint:forcetypeassert // client.Object always satisfies this
	obj.SetFinalizers(nil)
	if pErr := cl.Patch(ctx, obj, patch); pErr != nil && !k8serrors.IsNotFound(pErr) {
		return pErr
	}
	return nil
}

// ListMatchingNodes returns all nodes matching the given label selector.
// A nil selector matches all nodes.
func ListMatchingNodes(ctx context.Context, cl client.Client, sel *metav1.LabelSelector) ([]corev1.Node, error) {
	nodeList := &corev1.NodeList{}
	var listOpts []client.ListOption
	if sel != nil {
		selector, err := metav1.LabelSelectorAsSelector(sel)
		if err != nil {
			return nil, fmt.Errorf("invalid node selector: %w", err)
		}
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: selector})
	}
	if err := cl.List(ctx, nodeList, listOpts...); err != nil {
		return nil, err
	}
	return nodeList.Items, nil
}

// ListMatchingFalcoNodes returns the subset of nodes that (a) match sel and (b) have at least
// one Running Falco pod scheduled on them across all Falco CRs in namespace. In DaemonSet mode
// every matching node has a Falco pod, so the result equals ListMatchingNodes. In Deployment mode
// only the node(s) hosting a scheduled Falco pod are returned. Nodes excluded by taints or
// tolerations that prevent Falco from running there are correctly omitted in both modes.
func ListMatchingFalcoNodes(ctx context.Context, cl client.Client, sel *metav1.LabelSelector, namespace string) ([]corev1.Node, error) {
	nodes, err := ListMatchingNodes(ctx, cl, sel)
	if err != nil {
		return nil, err
	}

	falcoNodes, err := ListFalcoRunningNodeNames(ctx, cl, namespace)
	if err != nil {
		return nil, err
	}
	return FilterNodesByName(nodes, falcoNodes), nil
}

// FilterNodesByName returns the nodes whose names are present in desired. The returned
// slice does not alias nodes, so callers can safely retain the original list for other
// purposes such as multi-platform cache pre-fetching.
func FilterNodesByName(nodes []corev1.Node, desired map[string]struct{}) []corev1.Node {
	filtered := make([]corev1.Node, 0, len(nodes))
	for i := range nodes {
		if _, ok := desired[nodes[i].Name]; ok {
			filtered = append(filtered, nodes[i])
		}
	}
	return filtered
}

// ListFalcoRunningNodeNames lists all Falco CRs in namespace and returns the set of node names
// that currently have a Running pod for any of them.
func ListFalcoRunningNodeNames(ctx context.Context, cl client.Client, namespace string) (map[string]struct{}, error) {
	falcoList := &instancev1alpha1.FalcoList{}
	if err := cl.List(ctx, falcoList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list Falco CRs for node filtering: %w", err)
	}

	running := make(map[string]struct{})
	for i := range falcoList.Items {
		name := falcoList.Items[i].Name
		podList := &corev1.PodList{}
		if err := cl.List(ctx, podList,
			client.InNamespace(namespace),
			client.MatchingLabels{falcoInstanceLabel: name},
		); err != nil {
			return nil, fmt.Errorf("list pods for Falco %q: %w", name, err)
		}
		for j := range podList.Items {
			pod := &podList.Items[j]
			if pod.Status.Phase == corev1.PodRunning && pod.Spec.NodeName != "" {
				running[pod.Spec.NodeName] = struct{}{}
			}
		}
	}
	return running, nil
}

// FalcoPodChangePredicate accepts exactly the Pod events that can change the result of
// ListFalcoRunningNodeNames: a labeled Pod appearing or disappearing, or an update to its
// Falco instance label, node assignment, or phase. In particular, checking both sides of an
// update ensures that removing the instance label still triggers stale ArtifactNode cleanup.
func FalcoPodChangePredicate() predicate.Predicate {
	hasFalcoInstance := func(obj client.Object) bool {
		_, ok := obj.GetLabels()[falcoInstanceLabel]
		return ok
	}

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return hasFalcoInstance(e.Object)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return hasFalcoInstance(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldInstance, oldTracked := e.ObjectOld.GetLabels()[falcoInstanceLabel]
			newInstance, newTracked := e.ObjectNew.GetLabels()[falcoInstanceLabel]
			if !oldTracked && !newTracked {
				return false
			}
			if oldTracked != newTracked || oldInstance != newInstance {
				return true
			}

			oldPod, oldOK := e.ObjectOld.(*corev1.Pod)
			newPod, newOK := e.ObjectNew.(*corev1.Pod)
			if !oldOK || !newOK {
				return true
			}
			return oldPod.Spec.NodeName != newPod.Spec.NodeName ||
				oldPod.Status.Phase != newPod.Status.Phase
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return hasFalcoInstance(e.Object)
		},
	}
}

// IsBeingDeleted re-fetches obj and reports whether it now has a DeletionTimestamp set, or is
// gone entirely, which is treated the same way since there is nothing left to create against.
//
// Use this as a final check immediately before creating a child object, after any slow,
// network-bound work (OCI registry calls, blob pulls) that ran since the initial
// DeletionTimestamp check at the top of Reconcile (that earlier check can go stale if an
// external delete lands while the reconcile is busy).
func IsBeingDeleted(ctx context.Context, cl client.Client, obj client.Object) (bool, error) {
	fresh := obj.DeepCopyObject().(client.Object) //nolint:forcetypeassert // client.Object always satisfies this
	if err := cl.Get(ctx, client.ObjectKeyFromObject(obj), fresh); err != nil {
		if k8serrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	return !fresh.GetDeletionTimestamp().IsZero(), nil
}

// NodeMatchesSelector checks if a selector matches the node labels.
func NodeMatchesSelector(ctx context.Context, cl client.Client, nodeName string, labelSelector *metav1.LabelSelector) (bool, error) {
	logger := log.FromContext(ctx)

	// If the labelSelector is nil, return true.
	if labelSelector == nil {
		logger.V(2).Info("LabelSelector is nil, returning true")
		return true, nil
	}

	// Fetch the partial object metadata for the node.
	node := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
	}
	logger.V(2).Info("Fetching node", "node", nodeName)
	if err := cl.Get(ctx, client.ObjectKey{Name: nodeName}, node); err != nil {
		logger.Error(err, "unable to fetch node")
		return false, err
	}

	// Convert the LabelSelector to a Selector.
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		logger.Error(err, "invalid label selector", "labelSelector", labelSelector)
		return false, err
	}

	// Check if the node matches the selector.
	logger.V(2).Info("Checking node labelSelector", "node", nodeName, "labelSelector", labelSelector)
	if selector.Matches(labels.Set(node.Labels)) {
		logger.V(2).Info("Node matches labelSelector", "node", nodeName)
		return true, nil
	} else {
		logger.V(2).Info("Node does not match labelSelector", "node", nodeName)
		return false, nil
	}
}
