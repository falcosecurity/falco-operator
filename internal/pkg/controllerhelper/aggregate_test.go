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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
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
	sets := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok"},
		}},
	}
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 1)
	assert.Equal(t, metav1.ConditionTrue, result[0].Status)
	assert.Equal(t, "Programmed", result[0].Reason)
	assert.Equal(t, "ok", result[0].Message)
}

func TestAggregateConditions_FalseWinsOverTrue(t *testing.T) {
	sets := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok"},
		}},
		{NodeName: "node2", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "disk full"},
		}},
	}
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 1)
	assert.Equal(t, metav1.ConditionFalse, result[0].Status)
	assert.Equal(t, "ProgramFailed", result[0].Reason)
	assert.Equal(t, "disk full (failing nodes: node2)", result[0].Message)
}

func TestAggregateConditions_FalseListsFailingNodesSortedRegardlessOfArrivalOrder(t *testing.T) {
	sets := []controllerhelper.NodeConditionSet{
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
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 1)
	assert.Equal(t, "disk full (failing nodes: node-a, node-b, node-c)", result[0].Message)
}

func TestAggregateConditions_FalseListsExactlyFiveFailingNodesWithoutOverflowSuffix(t *testing.T) {
	sets := make([]controllerhelper.NodeConditionSet, 5)
	for i := range sets {
		sets[i] = controllerhelper.NodeConditionSet{
			NodeName: fmt.Sprintf("node-%d", i+1),
			Conditions: []metav1.Condition{
				{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "boom"},
			},
		}
	}
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 1)
	assert.Equal(t, "boom (failing nodes: node-1, node-2, node-3, node-4, node-5)", result[0].Message)
	assert.NotContains(t, result[0].Message, "more")
}

func TestAggregateConditions_FalseSummarizesBeyondFiveFailingNodes(t *testing.T) {
	sets := make([]controllerhelper.NodeConditionSet, 7)
	for i := range sets {
		sets[i] = controllerhelper.NodeConditionSet{
			NodeName: fmt.Sprintf("node-%d", i+1),
			Conditions: []metav1.Condition{
				{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed", Message: "boom"},
			},
		}
	}
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 1)
	assert.Equal(t, "boom (failing nodes: node-1, node-2, node-3, node-4, node-5 (+2 more))", result[0].Message)
}

func TestAggregateConditions_FalseWithEmptyBaseMessageOmitsLeadingParen(t *testing.T) {
	sets := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed"},
		}},
	}
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 1)
	assert.Equal(t, "failing nodes: node1", result[0].Message)
}

func TestAggregateConditions_UnknownWinsOverTrue(t *testing.T) {
	sets := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue},
		}},
		{NodeName: "node2", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionUnknown, Reason: "Pending", Message: "waiting"},
		}},
	}
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 1)
	assert.Equal(t, metav1.ConditionUnknown, result[0].Status)
	assert.Equal(t, "Pending", result[0].Reason)
}

func TestAggregateConditions_FalseWinsOverUnknown(t *testing.T) {
	sets := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionUnknown, Reason: "Pending"},
		}},
		{NodeName: "node2", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionFalse, Reason: "ProgramFailed"},
		}},
	}
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 1)
	assert.Equal(t, metav1.ConditionFalse, result[0].Status)
	assert.Equal(t, "ProgramFailed", result[0].Reason)
}

func TestAggregateConditions_MultipleTypesSortedDeterministically(t *testing.T) {
	sets := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Zeta", ObservedGeneration: 1, Status: metav1.ConditionTrue},
			{Type: "Alpha", ObservedGeneration: 1, Status: metav1.ConditionTrue},
		}},
	}
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 3)
	assert.Equal(t, "Alpha", result[0].Type)
	assert.Equal(t, "Programmed", result[1].Type)
	assert.Equal(t, metav1.ConditionUnknown, result[1].Status)
	assert.Equal(t, "Zeta", result[2].Type)
}

func TestAggregateConditions_FirstTrueReasonCapturedWhenAllTrue(t *testing.T) {
	sets := []controllerhelper.NodeConditionSet{
		{NodeName: "node1", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue, Reason: "FirstReason"},
		}},
		{NodeName: "node2", Conditions: []metav1.Condition{
			{Type: "Programmed", ObservedGeneration: 1, Status: metav1.ConditionTrue, Reason: "SecondReason"},
		}},
	}
	result := controllerhelper.AggregateConditions(sets, 1)
	require.Len(t, result, 1)
	// The first True condition's reason/message is kept; later True conditions of the
	// same type don't overwrite it.
	assert.Equal(t, "FirstReason", result[0].Reason)
}

func TestLogConditionTransitions(t *testing.T) {
	ctx := context.Background()

	// Exercises every branch of LogConditionTransitions, which has no return value to assert on.
	t.Run("no previous condition of this type", func(t *testing.T) {
		controllerhelper.LogConditionTransitions(ctx, nil, []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"},
		})
	})

	t.Run("status changed", func(t *testing.T) {
		current := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionFalse, Reason: "ProgramFailed"}}
		next := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"}}
		controllerhelper.LogConditionTransitions(ctx, current, next)
	})

	t.Run("reason changed only", func(t *testing.T) {
		current := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionFalse, Reason: "ReasonA"}}
		next := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionFalse, Reason: "ReasonB"}}
		controllerhelper.LogConditionTransitions(ctx, current, next)
	})

	t.Run("unchanged: no transition logged", func(t *testing.T) {
		current := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"}}
		next := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed"}}
		controllerhelper.LogConditionTransitions(ctx, current, next)
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

func TestUpdateAggregateConditions(t *testing.T) {
	newScheme := func(t *testing.T) *runtime.Scheme {
		t.Helper()
		s := runtime.NewScheme()
		require.NoError(t, artifactv1alpha1.AddToScheme(s))
		return s
	}

	t.Run("empty node list produces NoNodesAssigned", func(t *testing.T) {
		s := newScheme(t)
		plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
		cl := fake.NewClientBuilder().WithScheme(s).WithObjects(plugin).WithStatusSubresource(plugin).Build()

		err := controllerhelper.UpdateAggregateConditions(
			context.Background(), cl, s, plugin, &plugin.Status.Conditions, &artifactv1alpha1.ArtifactNodeList{}, "test-manager",
		)
		require.NoError(t, err)

		got := &artifactv1alpha1.Plugin{}
		require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
		require.Len(t, got.Status.Conditions, 1)
		assert.Equal(t, "NoNodesAssigned", got.Status.Conditions[0].Reason)
	})

	t.Run("aggregates node conditions onto the parent status", func(t *testing.T) {
		s := newScheme(t)
		plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
		cl := fake.NewClientBuilder().WithScheme(s).WithObjects(plugin).WithStatusSubresource(plugin).Build()

		nodeList := &artifactv1alpha1.ArtifactNodeList{
			Items: []artifactv1alpha1.ArtifactNode{
				{
					Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "node-1"},
					Status: artifactv1alpha1.ArtifactNodeStatus{
						Conditions: []metav1.Condition{
							{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok"},
						},
					},
				},
			},
		}

		err := controllerhelper.UpdateAggregateConditions(
			context.Background(), cl, s, plugin, &plugin.Status.Conditions, nodeList, "test-manager",
		)
		require.NoError(t, err)

		got := &artifactv1alpha1.Plugin{}
		require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
		cond := apimeta.FindStatusCondition(got.Status.Conditions, "Programmed")
		require.NotNil(t, cond)
		assert.Equal(t, metav1.ConditionTrue, cond.Status)
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
			nodes := &artifactv1alpha1.ArtifactNodeList{Items: []artifactv1alpha1.ArtifactNode{
				{
					Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "existing-node"},
					Status: artifactv1alpha1.ArtifactNodeStatus{Conditions: []metav1.Condition{{
						Type: "Programmed", Status: metav1.ConditionTrue,
						Reason: "Programmed", ObservedGeneration: 2,
					}}},
				},
				{
					Spec:   artifactv1alpha1.ArtifactNodeSpec{NodeName: "new-node"},
					Status: artifactv1alpha1.ArtifactNodeStatus{Conditions: tt.conditions},
				},
			}}
			controllerhelper.ComputeAggregateConditions(t.Context(), parent, &parent.Status.Conditions,
				controllerhelper.NodeConditionsForAssignments(nodes, map[string]struct{}{"existing-node": {}, "new-node": {}}))
			assert.Equal(t, tt.ready, apimeta.IsStatusConditionTrue(parent.Status.Conditions, "Programmed"),
				"Programmed must not certify an assigned node which has not reported installation")
		})
	}
}

func TestAggregateConditions_StaleReportsCannotCertifyCurrentGeneration(t *testing.T) {
	for _, status := range []metav1.ConditionStatus{metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionUnknown} {
		t.Run(string(status), func(t *testing.T) {
			sets := []controllerhelper.NodeConditionSet{{
				NodeName:   "old-node",
				Conditions: []metav1.Condition{{Type: "Programmed", Status: status, Reason: "Old", ObservedGeneration: 1}},
			}}
			got := controllerhelper.AggregateConditions(sets, 2)
			require.Len(t, got, 1)
			require.Equal(t, metav1.ConditionUnknown, got[0].Status)
			require.Equal(t, "Pending", got[0].Reason)
			require.EqualValues(t, 2, got[0].ObservedGeneration)
			require.Equal(t, status, sets[0].Conditions[0].Status, "aggregation must not mutate child status")
		})
	}
}

func TestNodeConditionsForAssignments(t *testing.T) {
	now := metav1.Now()
	ready := []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue, ObservedGeneration: 1}}
	nodes := &artifactv1alpha1.ArtifactNodeList{Items: []artifactv1alpha1.ArtifactNode{
		{Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "ready"}, Status: artifactv1alpha1.ArtifactNodeStatus{Conditions: ready}},
		{ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now}, Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "terminating"},
			Status: artifactv1alpha1.ArtifactNodeStatus{Conditions: ready}},
		{Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "no-longer-assigned"}, Status: artifactv1alpha1.ArtifactNodeStatus{Conditions: ready}},
	}}
	sets := controllerhelper.NodeConditionsForAssignments(nodes, map[string]struct{}{"ready": {}, "terminating": {}, "not-cached-yet": {}})
	require.Len(t, sets, 3)
	for _, set := range sets {
		if set.NodeName == "ready" {
			require.Equal(t, ready, set.Conditions)
		} else {
			require.Empty(t, set.Conditions)
		}
	}
	got := controllerhelper.AggregateConditions(sets, 1)
	require.Equal(t, metav1.ConditionUnknown, apimeta.FindStatusCondition(got, "Programmed").Status)
	require.Empty(t, controllerhelper.NodeConditionsForAssignments(nodes, map[string]struct{}{}))
}
