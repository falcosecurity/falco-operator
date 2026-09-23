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

// Package controllerhelper provides shared helpers for the artifact and instance controllers.
package controllerhelper

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// maxFailingNodesListed caps how many node names AggregateConditions lists in a False condition's
// message; the remainder is summarized as "(+N more)".
const maxFailingNodesListed = 5

const reasonPending = "Pending"

// NodeConditionSet pairs a node name with its observed conditions.
type NodeConditionSet struct {
	NodeName   string
	Conditions []metav1.Condition
}

// AggregateConditions merges per-node condition sets into a single aggregate slice
// written to the parent artifact status.
//
// Aggregation rules per condition type:
//   - False wins over Unknown wins over True.
//   - When the result is False, the message includes the names of up to 5 failing nodes.
//   - Missing or stale reports are Unknown, not successful observations.
//   - An empty input produces a single Programmed=Unknown condition.
func AggregateConditions(nodeSets []NodeConditionSet, generation int64) []metav1.Condition {
	now := metav1.Now()

	if len(nodeSets) == 0 {
		return []metav1.Condition{{
			Type:               string(commonv1alpha1.ConditionProgrammed),
			Status:             metav1.ConditionUnknown,
			Reason:             "NoNodesAssigned",
			Message:            "No nodes are assigned to this artifact.",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		}}
	}

	nodeSets = slices.Clone(nodeSets)
	sort.Slice(nodeSets, func(i, j int) bool { return nodeSets[i].NodeName < nodeSets[j].NodeName })

	type entry struct {
		reported     int
		worstStatus  metav1.ConditionStatus
		reason       string
		message      string
		failingNodes []string
	}
	byType := map[string]*entry{
		commonv1alpha1.ConditionProgrammed.String(): {worstStatus: metav1.ConditionTrue},
	}

	for _, ns := range nodeSets {
		for _, c := range ns.Conditions {
			if c.ObservedGeneration != generation {
				c.Status = metav1.ConditionUnknown
				c.Reason = reasonPending
				c.Message = fmt.Sprintf("Waiting for node %q to report %s for generation %d", ns.NodeName, c.Type, generation)
			}
			e, exists := byType[c.Type]
			if !exists {
				e = &entry{worstStatus: metav1.ConditionTrue}
				byType[c.Type] = e
			}
			e.reported++
			switch c.Status {
			case metav1.ConditionFalse:
				// Collects every failing node, regardless of arrival order.
				e.failingNodes = append(e.failingNodes, ns.NodeName)
				if e.worstStatus != metav1.ConditionFalse {
					// On first failure, capture reason from this node; the message is extended
					// with the full failing-node list after the loop.
					e.worstStatus = metav1.ConditionFalse
					e.reason = c.Reason
					e.message = c.Message
				}
			case metav1.ConditionUnknown:
				if e.worstStatus == metav1.ConditionTrue {
					e.worstStatus = metav1.ConditionUnknown
					e.reason = c.Reason
					e.message = c.Message
				}
			case metav1.ConditionTrue:
				if e.reason == "" {
					// Capture reason/message from the first True condition.
					e.reason = c.Reason
					e.message = c.Message
				}
			}
		}
	}

	result := make([]metav1.Condition, 0, len(byType))
	for condType, e := range byType {
		if e.reported < len(nodeSets) && e.worstStatus != metav1.ConditionFalse {
			e.worstStatus = metav1.ConditionUnknown
			e.reason = reasonPending
			e.message = fmt.Sprintf("Waiting for %s status from %d of %d assigned nodes",
				condType, len(nodeSets)-e.reported, len(nodeSets))
		}
		message := e.message
		if e.worstStatus == metav1.ConditionFalse {
			message = appendFailingNodes(message, e.failingNodes)
		}
		result = append(result, metav1.Condition{
			Type:               condType,
			Status:             e.worstStatus,
			Reason:             e.reason,
			Message:            message,
			ObservedGeneration: generation,
			LastTransitionTime: now,
		})
	}

	// Stable ordering for deterministic SSA patches.
	sort.Slice(result, func(i, j int) bool { return result[i].Type < result[j].Type })
	return result
}

// appendFailingNodes appends up to maxFailingNodesListed failing node names (sorted) to message,
// summarizing any remainder as "(+N more)".
func appendFailingNodes(message string, failingNodes []string) string {
	names := make([]string, len(failingNodes))
	copy(names, failingNodes)
	sort.Strings(names)

	shown := names
	var suffix string
	if len(shown) > maxFailingNodesListed {
		shown = shown[:maxFailingNodesListed]
		suffix = fmt.Sprintf(" (+%d more)", len(names)-maxFailingNodesListed)
	}
	nodesPart := fmt.Sprintf("failing nodes: %s%s", strings.Join(shown, ", "), suffix)

	if message == "" {
		return nodesPart
	}
	return fmt.Sprintf("%s (%s)", message, nodesPart)
}

// LogConditionTransitions logs each condition type in newConds whose Status or Reason differs from current.
// Must be called before ApplyAggregateConditions, which overwrites current in place: this is the only point
// where a condition transition (e.g. Programmed flipping to False) is recorded in logs, so callers can find it
// by grepping later.
func LogConditionTransitions(ctx context.Context, current, newConds []metav1.Condition) {
	logger := log.FromContext(ctx)
	for i := range newConds {
		next := &newConds[i]
		prev := apimeta.FindStatusCondition(current, next.Type)
		if prev != nil && prev.Status == next.Status && prev.Reason == next.Reason {
			continue
		}
		prevStatus, prevReason := "absent", ""
		if prev != nil {
			prevStatus, prevReason = string(prev.Status), prev.Reason
		}
		logger.Info("Condition transition",
			"type", next.Type,
			"from", prevStatus, "fromReason", prevReason,
			"to", string(next.Status), "toReason", next.Reason,
		)
	}
}

// ApplyAggregateConditions merges newConds into current using apimeta.SetStatusCondition, which preserves
// LastTransitionTime for conditions whose Status is unchanged, and removes condition types no longer present
// in newConds.
func ApplyAggregateConditions(current *[]metav1.Condition, newConds []metav1.Condition) {
	for i := range newConds {
		apimeta.SetStatusCondition(current, newConds[i])
	}
	newSet := make(map[string]bool, len(newConds))
	for _, c := range newConds {
		newSet[c.Type] = true
	}
	var toRemove []string
	for _, c := range *current {
		if !newSet[c.Type] {
			toRemove = append(toRemove, c.Type)
		}
	}
	for _, t := range toRemove {
		apimeta.RemoveStatusCondition(current, t)
	}
}

// NodeConditionsForAssignments includes every desired node, even when its ArtifactNode has
// not reached the informer cache or has not reported status. Terminating and stale assignments
// do not contribute their old conditions to the desired state.
func NodeConditionsForAssignments(nodeList *artifactv1alpha1.ArtifactNodeList, desired map[string]struct{}) []NodeConditionSet {
	byNode := make(map[string][]metav1.Condition, len(nodeList.Items))
	for i := range nodeList.Items {
		node := &nodeList.Items[i]
		if node.DeletionTimestamp.IsZero() {
			byNode[node.Spec.NodeName] = node.Status.Conditions
		}
	}
	sets := make([]NodeConditionSet, 0, len(desired))
	for name := range desired {
		sets = append(sets, NodeConditionSet{NodeName: name, Conditions: byNode[name]})
	}
	return sets
}

// ComputeAggregateConditions merges the supplied node reports, logs transitions, and applies
// the result in place. Callers supply every expected node, including ones without a report.
// It does not patch status; the caller decides whether a write is needed.
func ComputeAggregateConditions(
	ctx context.Context,
	obj client.Object,
	conditions *[]metav1.Condition,
	nodeSets []NodeConditionSet,
) {
	aggregated := AggregateConditions(nodeSets, obj.GetGeneration())
	LogConditionTransitions(ctx, *conditions, aggregated)
	ApplyAggregateConditions(conditions, aggregated)
}

// UpdateAggregateConditions computes aggregate conditions from nodeList and patches status only when
// conditions change. Callers must publish other status changes separately. conditions is passed as an
// addressable pointer (e.g. &plugin.Status.Conditions) because each aggregator controller's Status struct
// (Plugin, Rulesfile, Config) is differently typed.
func UpdateAggregateConditions(
	ctx context.Context,
	cl client.Client,
	scheme *runtime.Scheme,
	obj client.Object,
	conditions *[]metav1.Condition,
	nodeList *artifactv1alpha1.ArtifactNodeList,
	fieldManager string,
) error {
	// During deletion, report on the remaining children, including Terminating ones.
	sets := make([]NodeConditionSet, len(nodeList.Items))
	for i := range nodeList.Items {
		sets[i] = NodeConditionSet{
			NodeName:   nodeList.Items[i].Spec.NodeName,
			Conditions: nodeList.Items[i].Status.Conditions,
		}
	}
	condSnap := slices.Clone(*conditions)
	ComputeAggregateConditions(ctx, obj, conditions, sets)
	if apiequality.Semantic.DeepEqual(condSnap, *conditions) {
		return nil
	}
	return PatchStatusSSA(ctx, cl, scheme, obj, fieldManager)
}
