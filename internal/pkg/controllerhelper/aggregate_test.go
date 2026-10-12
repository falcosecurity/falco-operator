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

package controllerhelper_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func TestAggregateConditions_EmptyInput(t *testing.T) {
	result := controllerhelper.AggregateConditions(nil, 3)
	require.Len(t, result, 1)
	assert.Equal(t, string(commonv1alpha1.ConditionProgrammed), result[0].Type)
	assert.Equal(t, metav1.ConditionUnknown, result[0].Status)
	assert.Equal(t, "NoNodesAssigned", result[0].Reason)
	assert.Equal(t, int64(3), result[0].ObservedGeneration)
}

func TestAggregateConditions_SingleNodeTrue(t *testing.T) {
	artifactNodes := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok"},
		}},
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 1)
	assert.Equal(t, metav1.ConditionTrue, result[0].Status)
	assert.Equal(t, "Programmed", result[0].Reason)
	assert.Equal(t, "ok", result[0].Message)
}

func TestAggregateConditions_FalseWinsOverTrue(t *testing.T) {
	artifactNodes := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok"},
		}},
		{NodeName: "node2", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "disk full"},
		}},
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 1)
	assert.Equal(t, metav1.ConditionFalse, result[0].Status)
	assert.Equal(t, "ProgramFailed", result[0].Reason)
	assert.Equal(t, "disk full (failing nodes: node2)", result[0].Message)
}

func TestAggregateConditions_FalseListsFailingNodesSortedRegardlessOfArrivalOrder(t *testing.T) {
	artifactNodes := []controllerhelper.NodeConditionSet{
		{NodeName: "node-c", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "disk full"},
		}},
		{NodeName: "node-a", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "disk full"},
		}},
		{NodeName: "node-b", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "disk full"},
		}},
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 1)
	assert.Equal(t, "disk full (failing nodes: node-a, node-b, node-c)", result[0].Message)
}

func TestAggregateConditions_FalseListsExactlyFiveFailingNodesWithoutOverflowSuffix(t *testing.T) {
	artifactNodes := make([]controllerhelper.NodeConditionSet, 5)
	for i := range artifactNodes {
		artifactNodes[i] = controllerhelper.NodeConditionSet{
			NodeName: fmt.Sprintf("node-%d", i+1),
			Conditions: []metav1.Condition{
				{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "boom"},
			},
		}
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 1)
	assert.Equal(t, "boom (failing nodes: node-1, node-2, node-3, node-4, node-5)", result[0].Message)
	assert.NotContains(t, result[0].Message, "others")
}

func TestAggregateConditions_FalseSummarizesBeyondFiveFailingNodes(t *testing.T) {
	artifactNodes := make([]controllerhelper.NodeConditionSet, 7)
	for i := range artifactNodes {
		artifactNodes[i] = controllerhelper.NodeConditionSet{
			NodeName: fmt.Sprintf("node-%d", i+1),
			Conditions: []metav1.Condition{
				{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "boom"},
			},
		}
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 1)
	assert.Equal(t, "boom (failing nodes: node-1, node-2, node-3, node-4, node-5, and others)", result[0].Message)
}

func TestAggregateConditions_FalseWithEmptyBaseMessageOmitsLeadingParen(t *testing.T) {
	artifactNodes := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed"},
		}},
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 1)
	assert.Equal(t, "failing nodes: node1", result[0].Message)
}

func TestAggregateConditions_UnknownWinsOverTrue(t *testing.T) {
	artifactNodes := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue},
		}},
		{NodeName: "node2", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionUnknown, Reason: "Pending", Message: "waiting"},
		}},
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 1)
	assert.Equal(t, metav1.ConditionUnknown, result[0].Status)
	assert.Equal(t, "Pending", result[0].Reason)
}

func TestAggregateConditions_FalseWinsOverUnknown(t *testing.T) {
	artifactNodes := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionUnknown, Reason: "Pending"},
		}},
		{NodeName: "node2", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed"},
		}},
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 1)
	assert.Equal(t, metav1.ConditionFalse, result[0].Status)
	assert.Equal(t, "ProgramFailed", result[0].Reason)
}

func TestAggregateConditions_MultipleTypesSortedDeterministically(t *testing.T) {
	artifactNodes := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Zeta", ObservedGeneration: 1, Status: metav1.ConditionTrue},
			{Type: "Alpha", ObservedGeneration: 1, Status: metav1.ConditionTrue},
		}},
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 3)
	assert.Equal(t, "Alpha", result[0].Type)
	assert.Equal(t, "Programmed", result[1].Type)
	assert.Equal(t, metav1.ConditionUnknown, result[1].Status)
	assert.Equal(t, "Zeta", result[2].Type)
}

func TestAggregateConditions_FirstTrueReasonCapturedWhenAllTrue(t *testing.T) {
	artifactNodes := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue, Reason: "FirstReason"},
		}},
		{NodeName: "node2", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue, Reason: "SecondReason"},
		}},
	}
	result := controllerhelper.AggregateConditions(artifactNodes, 1)
	require.Len(t, result, 1)
	// The first True condition's reason/message is kept; later True conditions of the
	// same type don't overwrite it.
	assert.Equal(t, "FirstReason", result[0].Reason)
}

func TestLogConditionTransitions(t *testing.T) {
	// logged runs LogConditionTransitions against a capturing logger and returns one string per
	// log line, message and key-values flattened together.
	logged := func(t *testing.T, current, next []metav1.Condition) []string {
		t.Helper()
		var lines []string
		logger := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{})
		controllerhelper.LogConditionTransitions(log.IntoContext(context.Background(), logger), current, next)
		return lines
	}

	t.Run("no previous condition of this type", func(t *testing.T) {
		lines := logged(t, nil, []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"},
		})
		require.Len(t, lines, 1)
		assert.Contains(t, lines[0], `"from"="absent"`)
		assert.Contains(t, lines[0], `"to"="True"`)
	})

	t.Run("status changed", func(t *testing.T) {
		current := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionFalse, Reason: "ProgramFailed"}}
		next := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"}}
		lines := logged(t, current, next)
		require.Len(t, lines, 1)
		assert.Contains(t, lines[0], `"from"="False"`)
		assert.Contains(t, lines[0], `"to"="True"`)
	})

	t.Run("reason changed only", func(t *testing.T) {
		current := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionFalse, Reason: "ReasonA"}}
		next := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionFalse, Reason: "ReasonB"}}
		lines := logged(t, current, next)
		require.Len(t, lines, 1)
		assert.Contains(t, lines[0], `"fromReason"="ReasonA"`)
		assert.Contains(t, lines[0], `"toReason"="ReasonB"`)
	})

	t.Run("unchanged: no transition logged", func(t *testing.T) {
		current := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"}}
		next := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"}}
		assert.Empty(t, logged(t, current, next))
	})
}

func TestApplyAggregateConditions(t *testing.T) {
	t.Run("adds new conditions", func(t *testing.T) {
		var current []metav1.Condition
		controllerhelper.ApplyAggregateConditions(&current, []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"},
		})
		require.Len(t, current, 1)
		assert.Equal(t, "Programmed", current[0].Type)
	})

	t.Run("removes condition types no longer present", func(t *testing.T) {
		current := []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"},
			{Type: "Stale", Status: metav1.ConditionTrue, Reason: "WillBeRemoved"},
		}
		controllerhelper.ApplyAggregateConditions(&current, []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"},
		})
		require.Len(t, current, 1)
		assert.Equal(t, "Programmed", current[0].Type)
	})

	t.Run("preserves LastTransitionTime when status is unchanged", func(t *testing.T) {
		fixed := metav1.NewTime(metav1.Now().Add(-time.Hour))
		current := []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed", LastTransitionTime: fixed},
		}
		controllerhelper.ApplyAggregateConditions(&current, []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"},
		})
		require.Len(t, current, 1)
		assert.True(t, current[0].LastTransitionTime.Equal(&fixed))
	})
}

func TestAggregateConditions_WaitsForEveryAssignedNode(t *testing.T) {
	for _, tt := range []struct {
		name       string
		conditions []metav1.Condition
		ready      bool
	}{
		{name: "new assignment has no status"},
		{
			name: "new assignment has only resolved references",
			conditions: []metav1.Condition{{
				Type: "ResolvedRefs", Status: metav1.ConditionTrue,
				Reason: "ReferenceResolved", ObservedGeneration: 2,
			}},
		},
		{
			name: "both assignments have programmed status",
			conditions: []metav1.Condition{{
				Type: "Programmed", Status: metav1.ConditionTrue,
				Reason: "Programmed", ObservedGeneration: 2,
			}},
			ready: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parent := &artifactv1alpha1.Config{ObjectMeta: metav1.ObjectMeta{Generation: 2}}
			nodeConditions := []controllerhelper.NodeConditionSet{
				{NodeName: "existing-node", Conditions: []metav1.Condition{{
					Type: "Programmed", Status: metav1.ConditionTrue,
					Reason: "Programmed", ObservedGeneration: 2,
				}}},
				{NodeName: "new-node", Conditions: tt.conditions},
			}
			controllerhelper.ComputeAggregateConditions(t.Context(), parent, &parent.Status.Conditions, nodeConditions)
			assert.Equal(t, tt.ready, apimeta.IsStatusConditionTrue(parent.Status.Conditions, "Programmed"),
				"Programmed must not certify an assigned node which has not reported installation")
		})
	}
}

func TestAggregateConditions_StaleReportsCannotCertifyCurrentGeneration(t *testing.T) {
	for _, status := range []metav1.ConditionStatus{metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionUnknown} {
		t.Run(string(status), func(t *testing.T) {
			artifactNodes := []controllerhelper.NodeConditionSet{{
				NodeName:   "old-node",
				Conditions: []metav1.Condition{{Type: "Programmed", Status: status, Reason: "Old", ObservedGeneration: 1}},
			}}
			got := controllerhelper.AggregateConditions(artifactNodes, 2)
			require.Len(t, got, 1)
			require.Equal(t, metav1.ConditionUnknown, got[0].Status)
			require.Equal(t, "Pending", got[0].Reason)
			require.EqualValues(t, 2, got[0].ObservedGeneration)
			require.Equal(t, status, artifactNodes[0].Conditions[0].Status, "aggregation must not mutate child status")
		})
	}
}

// A message that changes each time one more node reports would make each report a write to the parent's status.
func TestAggregateConditions_PendingMessagesDoNotChangeAsMoreNodesReport(t *testing.T) {
	messages := func(reported int, generation int64) []string {
		nodes := make([]controllerhelper.NodeConditionSet, 4)
		for i := range nodes {
			nodes[i].NodeName = fmt.Sprintf("node-%d", i)
			if i < reported {
				nodes[i].Conditions = []metav1.Condition{
					{Type: "Programmed", ObservedGeneration: generation, Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok"},
				}
			}
		}
		aggregated := controllerhelper.AggregateConditions(nodes, 2)
		got := make([]string, 0, len(aggregated))
		for _, c := range aggregated {
			got = append(got, c.Type+"/"+c.Message)
		}
		return got
	}

	assert.Equal(t, messages(0, 2), messages(3, 2), "nodes that have not reported yet")
	assert.Equal(t, messages(1, 1), messages(3, 1), "nodes that report an older generation")
}

func TestAggregateConditions_FailingNodesBeyondTheListedOnesDoNotChangeTheMessage(t *testing.T) {
	failing := func(n int) string {
		nodes := make([]controllerhelper.NodeConditionSet, n)
		for i := range nodes {
			nodes[i] = controllerhelper.NodeConditionSet{
				NodeName: fmt.Sprintf("node-%03d", i),
				Conditions: []metav1.Condition{
					{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "boom"},
				},
			}
		}
		return controllerhelper.AggregateConditions(nodes, 1)[0].Message
	}

	assert.Equal(t, failing(6), failing(500))
}

// DeletionBlocked says a node cannot let go of the artifact: one node saying so is enough, whatever generation it
// last saw and whether or not the others have reported.
func TestAggregateConditions_OneBlockedNodeBlocksTheArtifact(t *testing.T) {
	blocked := metav1.Condition{
		Type: commonv1alpha1.ConditionDeletionBlocked.String(), Status: metav1.ConditionTrue,
		Reason: "PluginConfigStillRequired", Message: "required by rules", ObservedGeneration: 1,
	}
	programmed := metav1.Condition{
		Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: "Programmed", ObservedGeneration: 2,
	}

	result := controllerhelper.AggregateConditions([]controllerhelper.NodeConditionSet{
		{NodeName: "node-b", Conditions: []metav1.Condition{programmed, blocked}},
		{NodeName: "node-a", Conditions: []metav1.Condition{programmed}},
	}, 2)

	got := apimeta.FindStatusCondition(result, blocked.Type)
	require.NotNil(t, got)
	assert.Equal(t, metav1.ConditionTrue, got.Status)
	assert.Equal(t, "PluginConfigStillRequired", got.Reason)
	assert.Equal(t, "required by rules (blocked on nodes: node-b)", got.Message)
	assert.Equal(t, int64(2), got.ObservedGeneration)
	assert.True(t, apimeta.IsStatusConditionTrue(result, programmed.Type))
}

// A node the artifact is no longer assigned to is not expected to report: it adds its DeletionBlocked and nothing
// else, alone or beside the assigned nodes.
func TestAggregateConditions_ALeftoverNodeOnlyAddsItsBlock(t *testing.T) {
	blocked := metav1.Condition{
		Type: commonv1alpha1.ConditionDeletionBlocked.String(), Status: metav1.ConditionTrue, Reason: "PluginConfigStillRequired",
	}
	programmed := metav1.Condition{
		Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: "Programmed", ObservedGeneration: 2,
	}
	leftover := controllerhelper.NodeConditionSet{NodeName: "node-x", Conditions: []metav1.Condition{blocked}, Leftover: true}

	beside := controllerhelper.AggregateConditions([]controllerhelper.NodeConditionSet{
		{NodeName: "node-a", Conditions: []metav1.Condition{programmed}}, leftover,
	}, 2)
	assert.True(t, apimeta.IsStatusConditionTrue(beside, programmed.Type), "the leftover node is not waited for")
	assert.True(t, apimeta.IsStatusConditionTrue(beside, blocked.Type))

	alone := controllerhelper.AggregateConditions([]controllerhelper.NodeConditionSet{leftover}, 2)
	assert.Equal(t, common.ReasonNoNodesAssigned, apimeta.FindStatusCondition(alone, programmed.Type).Reason)
	assert.True(t, apimeta.IsStatusConditionTrue(alone, blocked.Type))
}

// Nodes failing for different reasons are not all given the cause of the first one.
func TestAggregateConditions_FailingNodesWithDifferentCausesSaySo(t *testing.T) {
	failing := func(reason, message string) []metav1.Condition {
		return []metav1.Condition{{
			Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse,
			Reason: reason, Message: message, ObservedGeneration: 1,
		}}
	}

	same := controllerhelper.AggregateConditions([]controllerhelper.NodeConditionSet{
		{NodeName: "node-a", Conditions: failing("StoreFailed", "disk full")},
		{NodeName: "node-b", Conditions: failing("StoreFailed", "disk full")},
	}, 1)
	assert.Equal(t, "disk full (failing nodes: node-a, node-b)", same[0].Message)

	different := controllerhelper.AggregateConditions([]controllerhelper.NodeConditionSet{
		{NodeName: "node-a", Conditions: failing("StoreFailed", "disk full")},
		{NodeName: "node-b", Conditions: failing("FetchFailed", "registry unreachable")},
	}, 1)
	assert.Equal(t, "StoreFailed", different[0].Reason)
	assert.Equal(t, "disk full (failing nodes: node-a, node-b); this is the cause on the first of them, "+
		"the others differ: see each node's ArtifactNode", different[0].Message)
}
