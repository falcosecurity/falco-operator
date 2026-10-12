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
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/instance/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
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

// artifactNodeOf is the ArtifactNode of node in the test namespace.
func artifactNodeOf(node string, mods ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	return testutil.NewArtifactNode(nsTestNamespace, node, mods...)
}

func nsArtifact() *artifactv1alpha1.Rulesfile {
	return &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "rf", Namespace: nsTestNamespace, UID: types.UID("uid-rf"), Generation: 3},
	}
}

func TestListAllArtifactNodes(t *testing.T) {
	now := metav1.Now()
	terminating := artifactNodeOf("node-c")
	terminating.DeletionTimestamp = &now
	terminating.Finalizers = []string{"test/finalizer"}
	elsewhere := artifactNodeOf("node-z")
	elsewhere.Namespace = "other"
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(
		artifactNodeOf("node-a"), artifactNodeOf("node-b"), terminating, elsewhere).Build()

	items, err := shared.ListAllArtifactNodes(t.Context(), cl, nsTestNamespace)

	require.NoError(t, err)
	assert.Len(t, items, 3, "this namespace's ArtifactNodes, the one being deleted included")
	byNode := shared.ArtifactNodesByNode(items)
	assert.Len(t, byNode, 2, "indexed without the one being deleted")
	assert.Contains(t, byNode, "node-a")
	assert.Contains(t, byNode, "node-b")
}

func TestListAllArtifactNodes_Error(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build() // scheme without the type

	_, err := shared.ListAllArtifactNodes(t.Context(), cl, nsTestNamespace)

	require.Error(t, err)
}

func TestNodeConditionsFromArtifactNodes(t *testing.T) {
	rf := nsArtifact()
	desired := func(nodes ...string) map[string]struct{} {
		out := map[string]struct{}{}
		for _, n := range nodes {
			out[n] = struct{}{}
		}
		return out
	}
	conditionsOf := func(artifactNodes []controllerhelper.NodeConditionSet) []metav1.Condition {
		require.Len(t, artifactNodes, 1)
		return artifactNodes[0].Conditions
	}

	t.Run("a desired node without an ArtifactNode is pending", func(t *testing.T) {
		got := shared.NodeConditionsFromArtifactNodes(nil, desired("node-a"), artifact.KindRulesfile, rf)
		require.Len(t, got, 1)
		assert.Equal(t, "node-a", got[0].NodeName)
		assert.Empty(t, got[0].Conditions, "no report yet: the aggregate treats a missing report as pending")
	})

	t.Run("a node that is not desired is not reported", func(t *testing.T) {
		artifactNodes := map[string]*artifactv1alpha1.ArtifactNode{"node-b": artifactNodeOf("node-b",
			withEntries(entryOf("Rulesfile", "rf", "uid-rf", cond(metav1.ConditionTrue, 3))))}
		got := shared.NodeConditionsFromArtifactNodes(artifactNodes, desired("node-a"), artifact.KindRulesfile, rf)
		require.Len(t, got, 1)
		assert.Equal(t, "node-a", got[0].NodeName)
		assert.Empty(t, got[0].Conditions, "node-b's report is not credited to node-a")
	})

	t.Run("the entry of the artifact is used", func(t *testing.T) {
		artifactNodes := map[string]*artifactv1alpha1.ArtifactNode{"node-a": artifactNodeOf("node-a",
			withEntries(entryOf("Rulesfile", "rf", "uid-rf", cond(metav1.ConditionTrue, 3))))}
		got := shared.NodeConditionsFromArtifactNodes(artifactNodes, desired("node-a"), artifact.KindRulesfile, rf)
		assert.Equal(t, []metav1.Condition{cond(metav1.ConditionTrue, 3)}, conditionsOf(got))
	})

	t.Run("an ArtifactNode without an entry for the artifact is pending", func(t *testing.T) {
		artifactNodes := map[string]*artifactv1alpha1.ArtifactNode{"node-a": artifactNodeOf("node-a",
			withEntries(entryOf("Rulesfile", "other", "uid-other", cond(metav1.ConditionTrue, 3))))}
		got := shared.NodeConditionsFromArtifactNodes(artifactNodes, desired("node-a"), artifact.KindRulesfile, rf)
		assert.Empty(t, conditionsOf(got))
	})

	t.Run("an entry of the same name but another kind is not this artifact's", func(t *testing.T) {
		artifactNodes := map[string]*artifactv1alpha1.ArtifactNode{"node-a": artifactNodeOf("node-a",
			withEntries(entryOf("Plugin", "rf", "uid-rf", cond(metav1.ConditionTrue, 3))))}
		got := shared.NodeConditionsFromArtifactNodes(artifactNodes, desired("node-a"), artifact.KindRulesfile, rf)
		assert.Empty(t, conditionsOf(got))
	})

	t.Run("an entry of a previous incarnation of the artifact is ignored", func(t *testing.T) {
		artifactNodes := map[string]*artifactv1alpha1.ArtifactNode{"node-a": artifactNodeOf("node-a",
			withEntries(entryOf("Rulesfile", "rf", "old-uid", cond(metav1.ConditionTrue, 3))))}
		got := shared.NodeConditionsFromArtifactNodes(artifactNodes, desired("node-a"), artifact.KindRulesfile, rf)
		assert.Empty(t, conditionsOf(got), "the deleted artifact's success must not be credited to its replacement")
	})

	t.Run("an artifact left out of a full node reports the capacity failure", func(t *testing.T) {
		full := make([]artifactv1alpha1.NodeArtifactRef, artifactv1alpha1.MaxNodeArtifacts)
		for i := range full {
			full[i] = ref("Rulesfile", fmt.Sprintf("other-%03d", i), "u")
		}
		artifactNodes := map[string]*artifactv1alpha1.ArtifactNode{"node-a": artifactNodeOf("node-a", withRefs(full...))}
		got := conditionsOf(shared.NodeConditionsFromArtifactNodes(artifactNodes, desired("node-a"), artifact.KindRulesfile, rf))
		require.Len(t, got, 1)
		assert.Equal(t, "Programmed", got[0].Type)
		assert.Equal(t, metav1.ConditionFalse, got[0].Status)
		assert.Equal(t, artifact.ReasonNodeCapacityExceeded, got[0].Reason)
		assert.Equal(t, int64(3), got[0].ObservedGeneration, "stamped with the artifact's generation so it is not read as stale")
	})

	t.Run("a node that is not full and does not list the artifact yet is pending", func(t *testing.T) {
		artifactNodes := map[string]*artifactv1alpha1.ArtifactNode{"node-a": artifactNodeOf("node-a", withRefs(ref("Rulesfile", "other", "u")))}
		got := shared.NodeConditionsFromArtifactNodes(artifactNodes, desired("node-a"), artifact.KindRulesfile, rf)
		assert.Empty(t, conditionsOf(got), "the assignment controller has not caught up")
	})

	t.Run("a full node that lists the artifact reports its entry", func(t *testing.T) {
		full := make([]artifactv1alpha1.NodeArtifactRef, artifactv1alpha1.MaxNodeArtifacts)
		for i := range full {
			full[i] = ref("Rulesfile", fmt.Sprintf("other-%03d", i), "u")
		}
		full[0] = ref("Rulesfile", "rf", "uid-rf")
		artifactNodes := map[string]*artifactv1alpha1.ArtifactNode{"node-a": artifactNodeOf("node-a", withRefs(full...),
			withEntries(entryOf("Rulesfile", "rf", "uid-rf", cond(metav1.ConditionTrue, 3))))}
		got := conditionsOf(shared.NodeConditionsFromArtifactNodes(artifactNodes, desired("node-a"), artifact.KindRulesfile, rf))
		assert.Equal(t, []metav1.Condition{cond(metav1.ConditionTrue, 3)}, got)
	})

	t.Run("nodes are handled independently", func(t *testing.T) {
		artifactNodes := map[string]*artifactv1alpha1.ArtifactNode{"node-a": artifactNodeOf("node-a",
			withEntries(entryOf("Rulesfile", "rf", "uid-rf", cond(metav1.ConditionTrue, 3))))}
		got := shared.NodeConditionsFromArtifactNodes(artifactNodes, desired("node-a", "node-b"), artifact.KindRulesfile, rf)
		require.Len(t, got, 2)
		byNode := map[string][]metav1.Condition{}
		for _, g := range got {
			byNode[g.NodeName] = g.Conditions
		}
		assert.Equal(t, metav1.ConditionTrue, byNode["node-a"][0].Status, "node-a reported")
		assert.Empty(t, byNode["node-b"], "node-b has no ArtifactNode yet")
	})
}

func newRulesfileHandlerFixture(
	t *testing.T, rulesfiles ...string,
) (enqueued func() []string, update func(old, updated *artifactv1alpha1.ArtifactNode)) {
	t.Helper()
	objs := make([]client.Object, 0, len(rulesfiles))
	for _, name := range rulesfiles {
		objs = append(objs, &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: nsTestNamespace}})
	}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(objs...).Build()
	h := shared.ArtifactNodeHandler(cl, artifact.KindRulesfile, func() client.ObjectList { return &artifactv1alpha1.RulesfileList{} })
	q := testutil.NewQueue()
	update = func(old, updated *artifactv1alpha1.ArtifactNode) {
		h.Update(context.Background(), event.UpdateEvent{ObjectOld: old, ObjectNew: updated}, q)
	}
	enqueued = func() []string { return testutil.DrainQueue(t, q) }
	return enqueued, update
}

func TestArtifactNodeHandler_UpdateEnqueuesOnlyArtifactsWhoseEntryChanged(t *testing.T) {
	queued, update := newRulesfileHandlerFixture(t, "rf-a", "rf-b", "rf-c")
	programmed := func(s metav1.ConditionStatus) metav1.Condition { return cond(s, 1) }
	old := artifactNodeOf("node-a", withEntries(
		entryOf("Rulesfile", "rf-a", "u", programmed(metav1.ConditionFalse)),
		entryOf("Rulesfile", "rf-b", "u", programmed(metav1.ConditionTrue))))
	updated := artifactNodeOf("node-a", withEntries(
		entryOf("Rulesfile", "rf-a", "u", programmed(metav1.ConditionTrue)),  // changed
		entryOf("Rulesfile", "rf-b", "u", programmed(metav1.ConditionTrue)))) // unchanged

	update(old, updated)

	assert.Equal(t, []string{"rf-a"}, queued(), "one node update wakes about one artifact, not every artifact on the node")
}

func TestArtifactNodeHandler_IgnoresOtherKinds(t *testing.T) {
	queued, update := newRulesfileHandlerFixture(t, "rf-a")
	old := artifactNodeOf("node-a", withEntries(entryOf("Plugin", "p", "u")))
	updated := artifactNodeOf("node-a", withEntries(entryOf("Plugin", "p", "u", cond(metav1.ConditionTrue, 1))))

	update(old, updated)

	assert.Empty(t, queued(), "a plugin's entry concerns the plugin aggregator")
}

func TestArtifactNodeHandler_EnqueuesWhenAnArtifactIsAssignedOrUnassigned(t *testing.T) {
	queued, update := newRulesfileHandlerFixture(t, "rf-a")
	old := artifactNodeOf("node-a", withRefs(ref("Rulesfile", "gone", "u")))
	updated := artifactNodeOf("node-a", withRefs(ref("Rulesfile", "rf-a", "u")))

	update(old, updated)

	assert.ElementsMatch(t, []string{"gone", "rf-a"}, queued())
}

func TestArtifactNodeHandler_IgnoresUpdatesThatChangeNothingItReadsFrom(t *testing.T) {
	queued, update := newRulesfileHandlerFixture(t, "rf-a")
	old := artifactNodeOf("node-a", withRefs(ref("Rulesfile", "rf-a", "u")))
	updated := artifactNodeOf("node-a", withRefs(ref("Rulesfile", "rf-a", "u")))
	updated.ResourceVersion = "2"
	updated.Labels = map[string]string{"x": "y"}

	update(old, updated)

	assert.Empty(t, queued())
}

func TestArtifactNodeHandler_CreateAndDeleteEnqueueEverythingTheArtifactNodeMentions(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).Build()
	h := shared.ArtifactNodeHandler(cl, artifact.KindRulesfile, func() client.ObjectList { return &artifactv1alpha1.RulesfileList{} })
	artifactNode := artifactNodeOf("node-a", withRefs(ref("Rulesfile", "listed", "u")), withEntries(entryOf("Rulesfile", "reported", "u")))

	q := testutil.NewQueue()
	h.Create(context.Background(), event.CreateEvent{Object: artifactNode}, q)
	assert.ElementsMatch(t, []string{"listed", "reported"}, testutil.DrainQueue(t, q))

	h.Delete(context.Background(), event.DeleteEvent{Object: artifactNode}, q)
	assert.ElementsMatch(t, []string{"listed", "reported"}, testutil.DrainQueue(t, q))
}

func TestArtifactNodeHandler_ACrossingOfTheCapWakesEveryArtifact(t *testing.T) {
	// An artifact that is desired on a node but not listed has no entry to change, so it would never be
	// woken by the diff. When the node reaches its cap those artifacts must learn they were left out.
	queued, update := newRulesfileHandlerFixture(t, "rf-a", "rf-b", "rf-c")
	almostFull := make([]artifactv1alpha1.NodeArtifactRef, artifactv1alpha1.MaxNodeArtifacts-1)
	for i := range almostFull {
		almostFull[i] = ref("Secret", fmt.Sprintf("x-%03d", i), "u") // other kinds: nothing of ours changes
	}
	full := append(append([]artifactv1alpha1.NodeArtifactRef{}, almostFull...), ref("Secret", "last", "u"))

	update(artifactNodeOf("node-a", withRefs(almostFull...)), artifactNodeOf("node-a", withRefs(full...)))

	assert.ElementsMatch(t, []string{"rf-a", "rf-b", "rf-c"}, queued())
}

func TestArtifactNodeHandler_NonArtifactNodeObjectsAreIgnored(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).Build()
	h := shared.ArtifactNodeHandler(cl, artifact.KindRulesfile, func() client.ObjectList { return &artifactv1alpha1.RulesfileList{} })
	q := testutil.NewQueue()

	assert.NotPanics(t, func() {
		h.Create(context.Background(), event.CreateEvent{Object: &artifactv1alpha1.Rulesfile{}}, q)
		h.Update(context.Background(), event.UpdateEvent{ObjectOld: &artifactv1alpha1.Rulesfile{}, ObjectNew: &artifactv1alpha1.Rulesfile{}}, q)
	})
	assert.Empty(t, testutil.DrainQueue(t, q))
}

const otherName = "other"

func TestAnyHoldsArtifact(t *testing.T) {
	type nodes = []*artifactv1alpha1.ArtifactNode
	now := metav1.Now()
	terminating := artifactNodeOf("node-a", withEntries(entryOf("Rulesfile", "rf", "u")))
	terminating.DeletionTimestamp = &now

	for name, tc := range map[string]struct {
		artifactNodes nodes
		want          bool
	}{
		"no ArtifactNodes":                   {nil, false},
		"an ArtifactNode that knows nothing": {nodes{artifactNodeOf("node-a")}, false},
		"the spec still lists it":            {nodes{artifactNodeOf("node-a", withRefs(ref("Rulesfile", "rf", "u")))}, true},
		"a status entry remains":             {nodes{artifactNodeOf("node-a", withEntries(entryOf("Rulesfile", "rf", "u")))}, true},
		"on another node": {
			nodes{artifactNodeOf("node-a"), artifactNodeOf("node-b", withEntries(entryOf("Rulesfile", "rf", "u")))}, true,
		},
		"an ArtifactNode being deleted": {nodes{terminating}, true},
		"another kind of the same name": {
			nodes{artifactNodeOf("node-a", withRefs(ref("Plugin", "rf", "u")), withEntries(entryOf("Plugin", "rf", "u")))}, false,
		},
		"another artifact": {nodes{artifactNodeOf("node-a", withRefs(ref("Rulesfile", otherName, "u")))}, false},
	} {
		t.Run(name, func(t *testing.T) {
			items := make([]artifactv1alpha1.ArtifactNode, 0, len(tc.artifactNodes))
			for _, n := range tc.artifactNodes {
				items = append(items, *n)
			}

			assert.Equal(t, tc.want, shared.AnyHoldsArtifact(items, artifact.KindRulesfile, "rf"))
		})
	}
}

// The conditions a node's sidecar publishes while the artifact goes, a DeletionBlocked for a Plugin a Rulesfile
// still requires, reach the parent from every node that lists it or reports on it, terminating ones included.
func TestNodeConditionsOnDeletion(t *testing.T) {
	// The generation is the one the deletion itself bumped: no node reports on it.
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "pl", Namespace: nsTestNamespace, UID: types.UID("uid-pl"), Generation: 2},
	}
	blocked := metav1.Condition{
		Type: "DeletionBlocked", Status: metav1.ConditionTrue, Reason: "PluginConfigStillRequired", Message: "m", ObservedGeneration: 1,
	}
	now := metav1.Now()
	terminating := artifactNodeOf("node-b", withEntries(entryOf("Plugin", "pl", "uid-pl", blocked)))
	terminating.DeletionTimestamp = &now
	items := []artifactv1alpha1.ArtifactNode{
		*artifactNodeOf("node-a", withEntries(entryOf("Plugin", "pl", "uid-pl", blocked))),
		*terminating,
		*artifactNodeOf("node-c"),
	}

	got := shared.NodeConditionsOnDeletion(items, artifact.KindPlugin, plugin)

	byNode := map[string][]metav1.Condition{}
	for _, set := range got {
		byNode[set.NodeName] = set.Conditions
	}
	assert.Len(t, byNode, 2, "only the nodes holding the plugin count")
	for _, node := range []string{"node-a", "node-b"} {
		cond := apimeta.FindStatusCondition(byNode[node], "DeletionBlocked")
		require.NotNil(t, cond, "node %s", node)
		assert.Equal(t, int64(2), cond.ObservedGeneration, "what the node last reported stands for the deleted artifact")
	}
	assert.Equal(t, int64(1), items[0].Status.Artifacts[0].Conditions[0].ObservedGeneration, "the cache's objects are not modified")
}

// A node the selector stopped matching that cannot remove a plugin yet is not desired any more, and still tells
// the parent what it left behind.
func TestNodeConditionsFromArtifactNodes_ADeselectedNodeStillReportsABlockedRemoval(t *testing.T) {
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "pl", Namespace: nsTestNamespace, UID: types.UID("uid-pl"), Generation: 1},
	}
	blocked := metav1.Condition{Type: "DeletionBlocked", Status: metav1.ConditionTrue, Reason: "PluginConfigStillRequired"}
	artifactNodes := shared.ArtifactNodesByNode([]artifactv1alpha1.ArtifactNode{
		*artifactNodeOf("node-x", withEntries(entryOf("Plugin", "pl", "uid-pl", blocked))),
		*artifactNodeOf("node-old", withEntries(entryOf("Plugin", "pl", "uid-previous", blocked))),
		*artifactNodeOf("node-clean"),
	})

	got := shared.NodeConditionsFromArtifactNodes(artifactNodes, map[string]struct{}{}, artifact.KindPlugin, plugin)

	require.Len(t, got, 1, "neither a clean node nor one blocked on another incarnation counts")
	assert.Equal(t, "node-x", got[0].NodeName)
	assert.True(t, got[0].Leftover)
}

func TestDesiredNodes(t *testing.T) {
	rf := nsArtifact()
	matching := []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}}

	for name, tc := range map[string]struct {
		artifactNodes []*artifactv1alpha1.ArtifactNode
		want          []string
	}{
		"only the nodes that run Falco and are selected": {nil, []string{"node-a"}},
		"a node whose ArtifactNode still lists the artifact, though Falco is away": {
			[]*artifactv1alpha1.ArtifactNode{artifactNodeOf("node-b", withRefs(ref("Rulesfile", "rf", "uid-rf")))}, []string{"node-a", "node-b"}},
		"an ArtifactNode that lists another artifact adds nothing": {
			[]*artifactv1alpha1.ArtifactNode{artifactNodeOf("node-b", withRefs(ref("Rulesfile", "other", "u")))}, []string{"node-a"}},
		"an entry that is only reported adds nothing: the artifact is no longer assigned": {
			[]*artifactv1alpha1.ArtifactNode{artifactNodeOf("node-b", withEntries(entryOf("Rulesfile", "rf", "uid-rf")))}, []string{"node-a"}},
		"a listing of another kind of the same name adds nothing": {
			[]*artifactv1alpha1.ArtifactNode{artifactNodeOf("node-b", withRefs(ref("Plugin", "rf", "u")))}, []string{"node-a"}},
		"a node counted twice is one node": {
			[]*artifactv1alpha1.ArtifactNode{artifactNodeOf("node-a", withRefs(ref("Rulesfile", "rf", "uid-rf")))}, []string{"node-a"}},
	} {
		t.Run(name, func(t *testing.T) {
			items := make([]artifactv1alpha1.ArtifactNode, 0, len(tc.artifactNodes))
			for _, an := range tc.artifactNodes {
				items = append(items, *an)
			}

			got := shared.DesiredNodes(shared.ArtifactNodesByNode(items), artifact.KindRulesfile, rf, matching)

			assert.ElementsMatch(t, tc.want, slices.Collect(maps.Keys(got)))
		})
	}
}

func TestDesiredNodes_ATerminatingArtifactNodeIsNotExpectedToReport(t *testing.T) {
	now := metav1.Now()
	terminating := artifactNodeOf("node-b", withRefs(ref("Rulesfile", "rf", "uid-rf")))
	terminating.DeletionTimestamp = &now

	got := shared.DesiredNodes(shared.ArtifactNodesByNode([]artifactv1alpha1.ArtifactNode{*terminating}),
		artifact.KindRulesfile, nsArtifact(), nil)

	assert.Empty(t, got)
}

// The aggregators are woken when a node becomes unreachable or reachable again, and by nothing else about its
// taints: the grace of a lost node is counted from the moment it became unreachable.
func TestReachabilityChanged(t *testing.T) {
	node := func(taints ...corev1.Taint) *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{Taints: taints}}
	}
	since := func(d time.Duration) corev1.Taint {
		return corev1.Taint{
			Key: corev1.TaintNodeUnreachable, Effect: corev1.TaintEffectNoExecute,
			TimeAdded: &metav1.Time{Time: time.Unix(0, 0).Add(d)},
		}
	}
	other := corev1.Taint{Key: "dedicated", Effect: corev1.TaintEffectNoSchedule}
	p := shared.ReachabilityChanged()
	for name, tt := range map[string]struct {
		old, updated *corev1.Node
		want         bool
	}{
		"became unreachable":             {node(), node(since(time.Minute)), true},
		"became reachable again":         {node(since(time.Minute)), node(), true},
		"unreachable since another time": {node(since(time.Minute)), node(since(time.Hour)), true},
		"still unreachable":              {node(since(time.Minute)), node(since(time.Minute), other), false},
		"another taint":                  {node(), node(other), false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, p.Update(event.UpdateEvent{ObjectOld: tt.old, ObjectNew: tt.updated}))
		})
	}
	assert.False(t, p.Update(event.UpdateEvent{ObjectOld: &corev1.Pod{}, ObjectNew: &corev1.Pod{}}), "not a Node")
}
