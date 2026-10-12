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

package shared_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

const nsTestNamespace = "ns"

// Shorthands for the testutil ArtifactNode builders, which the tests below use on nearly every line.
var (
	withRefs    = testutil.WithAssigned
	withEntries = testutil.WithReported
	ref         = testutil.NodeArtifactRef
	entryOf     = testutil.NodeArtifactStatus
	cond        = testutil.ProgrammedCondition
)

// nodeAArtifactNode is the ArtifactNode of node-a in the test namespace.
func nodeAArtifactNode(mods ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	return testutil.NewArtifactNode(nsTestNamespace, "node-a", mods...)
}

func nsArtifact() *artifactv1alpha1.Rulesfile {
	return &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "rf", Namespace: nsTestNamespace, UID: types.UID("uid-rf"), Generation: 3},
	}
}

func TestAssignedRequestsOfNode(t *testing.T) {
	artifactNode := nodeAArtifactNode(withRefs(ref("Plugin", "p1", "u1"), ref("Rulesfile", "rf", "u2"), ref("Plugin", "p2", "u3")))
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(artifactNode).Build()
	tests := []struct {
		name     string
		cl       client.Client
		nodeName string
		want     []reconcile.Request
	}{
		{
			name: "the artifacts of the kind", cl: cl, nodeName: "node-a",
			want: []reconcile.Request{
				{NamespacedName: types.NamespacedName{Namespace: nsTestNamespace, Name: "p1"}},
				{NamespacedName: types.NamespacedName{Namespace: nsTestNamespace, Name: "p2"}},
			},
		},
		{name: "no ArtifactNode", cl: cl, nodeName: "node-b"},
		{name: "the ArtifactNode cannot be read", cl: fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build(), nodeName: "node-a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shared.AssignedRequestsOfNode(t.Context(), tt.cl, nsTestNamespace, tt.nodeName, "Plugin")

			assert.Equal(t, tt.want, got)
		})
	}
}

func assignmentHandler(t *testing.T, kind artifact.Kind, dependsOn ...artifact.Kind) func(old, updated *artifactv1alpha1.ArtifactNode) []string {
	t.Helper()
	h := shared.AssignmentHandler(kind, dependsOn...)
	return func(old, updated *artifactv1alpha1.ArtifactNode) []string {
		q := testutil.NewQueue()
		h.Update(context.Background(), event.UpdateEvent{ObjectOld: old, ObjectNew: updated}, q)
		return testutil.DrainQueue(t, q)
	}
}

func TestAssignmentHandler_EnqueuesOnlyAssignmentChanges(t *testing.T) {
	update := assignmentHandler(t, "Rulesfile")
	old := nodeAArtifactNode(
		withRefs(ref("Rulesfile", "kept", "u"), ref("Rulesfile", "removed", "u"), ref("Rulesfile", "recreated", "old")))
	updated := nodeAArtifactNode(
		withRefs(ref("Rulesfile", "kept", "u"), ref("Rulesfile", "recreated", "new"), ref("Rulesfile", "added", "u")))

	assert.ElementsMatch(t, []string{"removed", "recreated", "added"}, update(old, updated))
}

func TestAssignmentHandler_IgnoresStatusAndOtherKinds(t *testing.T) {
	update := assignmentHandler(t, "Rulesfile")
	old := nodeAArtifactNode(withRefs(ref("Rulesfile", "rf", "u")), withEntries(entryOf("Rulesfile", "rf", "u")))
	updated := nodeAArtifactNode(withRefs(ref("Rulesfile", "rf", "u")),
		withEntries(entryOf("Rulesfile", "rf", "u", cond(metav1.ConditionTrue, 1))))

	assert.Empty(t, update(old, updated), "the sidecar's own status write must not wake its reconciler")

	otherKind := nodeAArtifactNode(withRefs(ref("Rulesfile", "rf", "u"), ref("Plugin", "p", "u")))
	assert.Empty(t, update(old, otherKind), "a plugin's assignment concerns the plugin controller")
}

func TestAssignmentHandler_WakesEveryAssignedArtifactWhenADependencyChanges(t *testing.T) {
	update := assignmentHandler(t, "Rulesfile", "Plugin")
	listed := withRefs(ref("Rulesfile", "rf-a", "u"), ref("Rulesfile", "rf-b", "u"), ref("Plugin", "p", "u"))
	old := nodeAArtifactNode(listed, withEntries(entryOf("Plugin", "p", "u")))
	updated := nodeAArtifactNode(listed, withEntries(entryOf("Plugin", "p", "u", cond(metav1.ConditionTrue, 1))))

	assert.ElementsMatch(t, []string{"rf-a", "rf-b"}, update(old, updated),
		"a rulesfile re-checks its plugin requirements when a plugin's state changes")

	newPlugin := nodeAArtifactNode(listed, withEntries(entryOf("Plugin", "p", "u"), entryOf("Plugin", "q", "u")))
	assert.ElementsMatch(t, []string{"rf-a", "rf-b"}, update(old, newPlugin), "a plugin reporting for the first time counts")

	unchanged := nodeAArtifactNode(listed, withEntries(entryOf("Plugin", "p", "u")))
	assert.Empty(t, update(old, unchanged))

	programmed := nodeAArtifactNode(listed, withEntries(entryOf("Plugin", "p", "u", cond(metav1.ConditionTrue, 1))))
	reworded := programmed.DeepCopy()
	reworded.Status.Artifacts[0].Conditions[0].Message = "reworded"
	reworded.Status.Artifacts[0].Conditions = append(reworded.Status.Artifacts[0].Conditions,
		metav1.Condition{Type: "ConfigProgrammed", Status: metav1.ConditionTrue, Reason: "ConfigProgrammed"})
	assert.Empty(t, update(programmed, reworded),
		"a plugin whose Programmed status stays the same has not changed for its dependents, whatever else its conditions say")
}

func TestAssignmentHandler_CreateEnqueuesEveryAssignmentOfTheKind(t *testing.T) {
	h := shared.AssignmentHandler("Rulesfile")
	q := testutil.NewQueue()

	h.Create(context.Background(), event.CreateEvent{
		Object: nodeAArtifactNode(withRefs(ref("Rulesfile", "rf-a", "u"), ref("Plugin", "p", "u"))),
	}, q)

	assert.Equal(t, []string{"rf-a"}, testutil.DrainQueue(t, q), "at startup every assigned artifact is reconciled once")
}

func TestAssignmentHandler_IgnoresNonArtifactNodeObjects(t *testing.T) {
	h := shared.AssignmentHandler("Rulesfile")
	q := testutil.NewQueue()

	assert.NotPanics(t, func() {
		h.Create(context.Background(), event.CreateEvent{Object: &artifactv1alpha1.Rulesfile{}}, q)
		h.Update(context.Background(), event.UpdateEvent{ObjectOld: &artifactv1alpha1.Rulesfile{}, ObjectNew: &artifactv1alpha1.Rulesfile{}}, q)
	})
	assert.Zero(t, q.Len())
}

func TestResolveAssignmentAndIsListed(t *testing.T) {
	now := metav1.Now()
	terminating := func(n *artifactv1alpha1.ArtifactNode) {
		n.DeletionTimestamp = &now
		n.Finalizers = []string{"test/finalizer"}
	}
	rf := nsArtifact() // rulesfile "rf", uid "uid-rf"
	tests := []struct {
		name         string
		artifactNode *artifactv1alpha1.ArtifactNode
		wantState    shared.AssignmentState
		wantListed   bool
	}{
		{name: "no ArtifactNode", wantState: shared.NotAssigned},
		{
			name:         "listed for this incarnation",
			artifactNode: nodeAArtifactNode(withRefs(ref("Rulesfile", "rf", "uid-rf"))),
			wantState:    shared.Assigned, wantListed: true,
		},
		{
			name:         "listed for another incarnation",
			artifactNode: nodeAArtifactNode(withRefs(ref("Rulesfile", "rf", "uid-old"))),
			wantState:    shared.AssignmentPending, wantListed: true,
		},
		{
			name:         "not listed",
			artifactNode: nodeAArtifactNode(withRefs(ref("Rulesfile", "other", "u"))),
			wantState:    shared.NotAssigned,
		},
		{
			name:         "another kind of the same name is not this artifact",
			artifactNode: nodeAArtifactNode(withRefs(ref("Plugin", "rf", "uid-rf"))),
			wantState:    shared.NotAssigned,
		},
		{
			name:         "listed, but the ArtifactNode is being deleted",
			artifactNode: nodeAArtifactNode(withRefs(ref("Rulesfile", "rf", "uid-rf")), terminating),
			wantState:    shared.NotAssigned,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme))
			if tt.artifactNode != nil {
				builder = builder.WithObjects(tt.artifactNode)
			}
			cl := builder.Build()

			state, err := shared.ResolveAssignment(t.Context(), cl, nsTestNamespace, "node-a", "Rulesfile", rf)
			require.NoError(t, err)
			listed, err := shared.IsListed(t.Context(), cl, nsTestNamespace, "node-a", "Rulesfile", "rf")
			require.NoError(t, err)

			assert.Equal(t, tt.wantState, state)
			assert.Equal(t, tt.wantListed, listed)
		})
	}

	t.Run("the ArtifactNode cannot be read", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build() // scheme without the type

		_, err := shared.ResolveAssignment(t.Context(), cl, nsTestNamespace, "node-a", "Rulesfile", rf)
		require.Error(t, err)
		_, err = shared.IsListed(t.Context(), cl, nsTestNamespace, "node-a", "Rulesfile", "rf")
		require.Error(t, err)
	})
}
