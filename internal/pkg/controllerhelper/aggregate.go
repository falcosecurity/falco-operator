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

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
)

// maxFailingNodesListed caps how many node names AggregateConditions lists in a False condition's
// message; the remainder is summarized as "and others".
//
// Aggregated messages carry no counts and no name of a node that is merely late: a message that changes
// each time one more node reports would make every such report a write to the parent's status.
const maxFailingNodesListed = 5

// NodeConditionSet pairs a node name with its observed conditions.
type NodeConditionSet struct {
	NodeName   string
	Conditions []metav1.Condition
	// Leftover marks a node the artifact is no longer assigned to but that still holds it. No report is expected
	// from it, so it does not count towards the other conditions: only its DeletionBlocked is aggregated.
	Leftover bool
}

// AggregateConditions merges per-node condition sets into a single aggregate slice
// written to the parent artifact status.
//
// Aggregation rules per condition type:
//   - False wins over Unknown wins over True.
//   - When the result is False, the message includes the names of up to 5 failing nodes.
//   - Missing or stale reports are Unknown, not successful observations.
//   - With no node expected to report, Programmed is Unknown.
//   - DeletionBlocked is the exception to all of the above: it says a node cannot let go of the artifact, which
//     is true of the artifact as soon as it is true of one node, whatever generation that node last saw and
//     whether or not the others have reported. A single True is True, and names the nodes.
func AggregateConditions(nodeConditions []NodeConditionSet, generation int64) []metav1.Condition {
	now := metav1.Now()

	all := slices.Clone(nodeConditions)
	sort.Slice(all, func(i, j int) bool { return all[i].NodeName < all[j].NodeName })
	blocked := deletionBlocked(all, generation, now)
	nodeConditions = slices.DeleteFunc(slices.Clone(all), func(ns NodeConditionSet) bool { return ns.Leftover })

	if len(nodeConditions) == 0 {
		result := []metav1.Condition{{
			Type:               string(commonv1alpha1.ConditionProgrammed),
			Status:             metav1.ConditionUnknown,
			Reason:             common.ReasonNoNodesAssigned,
			Message:            "No nodes are assigned to this artifact.",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		}}
		if blocked != nil {
			result = append([]metav1.Condition{*blocked}, result...)
		}
		return result
	}

	type entry struct {
		reported     int
		worstStatus  metav1.ConditionStatus
		reason       string
		message      string
		failingNodes []string
		// causesDiffer is whether the failing nodes do not all fail for the reason and message kept above.
		causesDiffer bool
	}
	byType := map[string]*entry{
		commonv1alpha1.ConditionProgrammed.String(): {worstStatus: metav1.ConditionTrue},
	}

	for _, ns := range nodeConditions {
		for _, c := range ns.Conditions {
			if blocked != nil && c.Type == blocked.Type {
				continue
			}
			if c.ObservedGeneration != generation {
				c.Status = metav1.ConditionUnknown
				c.Reason = common.ReasonPending
				c.Message = fmt.Sprintf("Waiting for nodes to report %s for generation %d", c.Type, generation)
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
				} else if c.Reason != e.reason || c.Message != e.message {
					e.causesDiffer = true
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
		if e.reported < len(nodeConditions) && e.worstStatus != metav1.ConditionFalse {
			e.worstStatus = metav1.ConditionUnknown
			e.reason = common.ReasonPending
			e.message = fmt.Sprintf("Waiting for %s status from all assigned nodes", condType)
		}
		message := e.message
		if e.worstStatus == metav1.ConditionFalse {
			message = appendNodes(message, "failing nodes", e.failingNodes)
			if e.causesDiffer {
				// One message cannot carry every node's cause, and must not pass one node's off as all of theirs.
				message += "; this is the cause on the first of them, the others differ: see each node's ArtifactNode"
			}
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

	if blocked != nil {
		result = append(result, *blocked)
	}

	// Stable ordering for deterministic SSA patches.
	sort.Slice(result, func(i, j int) bool { return result[i].Type < result[j].Type })
	return result
}

// deletionBlocked returns the aggregate DeletionBlocked condition of sorted, which is True as soon as one node
// reports it True, with that node's reason and message and the names of the nodes reporting it. It returns nil
// when none does.
func deletionBlocked(sorted []NodeConditionSet, generation int64, now metav1.Time) *metav1.Condition {
	var blocked *metav1.Condition
	var nodes []string
	for _, ns := range sorted {
		c := apimeta.FindStatusCondition(ns.Conditions, commonv1alpha1.ConditionDeletionBlocked.String())
		if c == nil || c.Status != metav1.ConditionTrue {
			continue
		}
		nodes = append(nodes, ns.NodeName)
		if blocked == nil {
			blocked = &metav1.Condition{
				Type: c.Type, Status: c.Status, Reason: c.Reason, Message: c.Message,
				ObservedGeneration: generation, LastTransitionTime: now,
			}
		}
	}
	if blocked != nil {
		blocked.Message = appendNodes(blocked.Message, "blocked on nodes", nodes)
	}
	return blocked
}

// appendNodes appends up to maxFailingNodesListed node names (sorted) to message under label,
// summarizing any remainder as "and others".
func appendNodes(message, label string, nodes []string) string {
	names := make([]string, len(nodes))
	copy(names, nodes)
	sort.Strings(names)

	shown := names
	var suffix string
	if len(shown) > maxFailingNodesListed {
		shown = shown[:maxFailingNodesListed]
		suffix = ", and others"
	}
	nodesPart := fmt.Sprintf("%s: %s%s", label, strings.Join(shown, ", "), suffix)

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
	newTypes := make(map[string]bool, len(newConds))
	for _, c := range newConds {
		newTypes[c.Type] = true
	}
	var toRemove []string
	for _, c := range *current {
		if !newTypes[c.Type] {
			toRemove = append(toRemove, c.Type)
		}
	}
	for _, t := range toRemove {
		apimeta.RemoveStatusCondition(current, t)
	}
}

// ComputeAggregateConditions merges the supplied node reports, logs transitions, and applies
// the result in place. Callers supply every expected node, including ones without a report.
// It does not patch status; the caller decides whether a write is needed.
func ComputeAggregateConditions(
	ctx context.Context,
	obj client.Object,
	conditions *[]metav1.Condition,
	nodeConditions []NodeConditionSet,
) {
	aggregated := AggregateConditions(nodeConditions, obj.GetGeneration())
	LogConditionTransitions(ctx, *conditions, aggregated)
	ApplyAggregateConditions(conditions, aggregated)
}
