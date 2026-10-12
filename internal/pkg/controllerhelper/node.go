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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

// FalcoInstanceLabel is the label a Falco pod carries with the name of its Falco CR as value. It is what a pod is
// recognized as a Falco pod by, whoever created it.
const FalcoInstanceLabel = "app.kubernetes.io/instance"

// appNameLabel is the label that tells a Falco pod from another workload whose instance label happens to carry the
// same value, such as a pod of a Helm release named like the Falco CR. The operator gives a Falco pod its Falco CR's
// name in both labels. A pod that carries only the instance label still counts as a Falco pod; one whose name label
// says something else does not.
const appNameLabel = "app.kubernetes.io/name"

// ListMatchingNodes returns all nodes matching the given label selector.
// A nil selector matches all nodes. The nodes are not copied out of the informer cache, which on a large cluster
// is a copy of every node for every reconcile: callers must not modify them.
func ListMatchingNodes(ctx context.Context, cl client.Client, sel *metav1.LabelSelector) ([]corev1.Node, error) {
	nodeList := &corev1.NodeList{}
	listOpts := []client.ListOption{client.UnsafeDisableDeepCopy}
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
	counts, err := countFalcoRunningPods(ctx, cl, namespace)
	if err != nil {
		return nil, err
	}
	running := make(map[string]struct{}, len(counts))
	for node := range counts {
		running[node] = struct{}{}
	}
	return running, nil
}

// CountFalcoRunningPodsOnNode returns how many Running pods of any Falco CR in namespace run on nodeName. More
// than one is not supported: their sidecars would share one ArtifactNode. A pod being deleted does not count (see
// falcoPodRunning). It reads the pods of that node alone, through the index.PodNodeName field
// index, so that a per-node reconcile does not go through every pod of the namespace: every artifact change
// reconciles every node.
func CountFalcoRunningPodsOnNode(ctx context.Context, cl client.Client, namespace, nodeName string) (int, error) {
	counts, err := countFalcoRunningPods(ctx, cl, namespace, client.MatchingFields{index.PodNodeName: nodeName})
	if err != nil {
		return 0, fmt.Errorf("count Falco pods on node %q: %w", nodeName, err)
	}
	return counts[nodeName], nil
}

// countFalcoRunningPods counts, per node, the Running pods of every Falco CR in namespace among those that
// podFilter selects; a pod being deleted does not count (see falcoPodRunning). It is the one place that decides
// which pods count as a running Falco pod, for ListFalcoRunningNodeNames and CountFalcoRunningPodsOnNode alike.
// Only names, phases and timestamps are read, so nothing is copied out of the informer cache.
func countFalcoRunningPods(
	ctx context.Context, cl client.Client, namespace string, podFilter ...client.ListOption,
) (map[string]int, error) {
	falcoList := &instancev1alpha1.FalcoList{}
	if err := cl.List(ctx, falcoList, client.InNamespace(namespace), client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list Falco CRs for node filtering: %w", err)
	}

	running := make(map[string]int)
	for i := range falcoList.Items {
		name := falcoList.Items[i].Name
		podList := &corev1.PodList{}
		opts := append([]client.ListOption{
			client.InNamespace(namespace),
			client.MatchingLabels{FalcoInstanceLabel: name},
			client.UnsafeDisableDeepCopy,
		}, podFilter...)
		if err := cl.List(ctx, podList, opts...); err != nil {
			return nil, fmt.Errorf("list pods for Falco %q: %w", name, err)
		}
		for j := range podList.Items {
			if pod := &podList.Items[j]; isFalcoPod(pod, name) && falcoPodRunning(pod) {
				running[pod.Spec.NodeName]++
			}
		}
	}
	return running, nil
}

// isFalcoPod reports whether pod, which carries the instance label of the Falco CR called falcoName, is a pod of
// that Falco and not of another workload labeled alike: see appNameLabel.
func isFalcoPod(pod *corev1.Pod, falcoName string) bool {
	appName, labeled := pod.Labels[appNameLabel]
	return !labeled || appName == falcoName
}

// falcoPodRunning reports whether pod is a Falco pod with a sidecar at work: scheduled, Running, and not
// being deleted. A pod being deleted is on its way out, whatever its phase still says: it is the old pod of
// a replacement, and counting it would make the replacement look like a second sidecar on the node.
func falcoPodRunning(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodRunning && pod.Spec.NodeName != "" && pod.DeletionTimestamp.IsZero()
}

// FalcoPodChangePredicate accepts exactly the Pod events that can change the result of
// ListFalcoRunningNodeNames: a labeled Pod appearing or disappearing, or an update to its
// Falco instance or name label, node assignment, phase, or its deletion starting (falcoPodRunning stops
// counting a pod the moment its deletionTimestamp is set, whatever its phase still says). In
// particular, checking both sides of an update ensures that removing the instance label still
// triggers stale ArtifactNode cleanup.
func FalcoPodChangePredicate() predicate.Predicate {
	hasFalcoInstance := func(obj client.Object) bool {
		_, ok := obj.GetLabels()[FalcoInstanceLabel]
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
			oldInstance, oldTracked := e.ObjectOld.GetLabels()[FalcoInstanceLabel]
			newInstance, newTracked := e.ObjectNew.GetLabels()[FalcoInstanceLabel]
			if !oldTracked && !newTracked {
				return false
			}
			if oldTracked != newTracked || oldInstance != newInstance ||
				e.ObjectOld.GetLabels()[appNameLabel] != e.ObjectNew.GetLabels()[appNameLabel] {
				return true
			}

			oldPod, oldOK := e.ObjectOld.(*corev1.Pod)
			newPod, newOK := e.ObjectNew.(*corev1.Pod)
			if !oldOK || !newOK {
				return true
			}
			return oldPod.Spec.NodeName != newPod.Spec.NodeName ||
				oldPod.Status.Phase != newPod.Status.Phase ||
				oldPod.DeletionTimestamp.IsZero() != newPod.DeletionTimestamp.IsZero()
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return hasFalcoInstance(e.Object)
		},
	}
}
