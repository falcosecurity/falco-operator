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

package artifactnode

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestReconcile(t *testing.T) {
	nodeLabel := controllerhelper.ArtifactNodeLabels(testutil.TestNodeName)
	rfListing := listing(ref("Rulesfile", "rf1", "uid-rf1"))
	withTeamLabel := func(s *artifactv1alpha1.ArtifactNode) { s.Labels["team"] = "sec" }
	unlabeled := func(s *artifactv1alpha1.ArtifactNode) { s.Labels = nil }
	badSelector := testRulesfile("bad", func(rf *artifactv1alpha1.Rulesfile) {
		rf.Spec.Selector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "Bogus"}}}
	})
	otherPool := func(rf *artifactv1alpha1.Rulesfile) { rf.Spec.Selector = selecting("gpu") }
	noPod := func(extra ...client.Object) []client.Object {
		return append([]client.Object{testNode(), testutil.NewTestFalco(), testRulesfile("rf1")}, extra...)
	}
	noNode := func(extra ...client.Object) []client.Object {
		return append([]client.Object{testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), testRulesfile("rf1")}, extra...)
	}
	reportsRf := reporting(artifactv1alpha1.NodeArtifactStatus{Kind: "Rulesfile", Name: "rf1", UID: "uid-rf1"})

	tests := []struct {
		name       string
		objs       []client.Object
		wantExists bool
		wantSpec   []artifactv1alpha1.NodeArtifactRef
		wantLabels map[string]string // checked when set
		wantWrites writes
		wantEvents int
	}{
		{
			name:       "creates the ArtifactNode with every kind, sorted",
			objs:       hosted(testRulesfile("rf1"), testPlugin("p1"), testConfig("c1")),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Config", "c1", "uid-c1"), ref("Plugin", "p1", "uid-p1"), ref("Rulesfile", "rf1", "uid-rf1")},
			wantLabels: nodeLabel,
			wantWrites: writes{creates: 1},
		},
		{name: "does not create one when no artifact exists", objs: hosted()},
		{name: "does not create one when no artifact selects the node", objs: hosted(testRulesfile("rf1", otherPool))},
		{name: "does not create one when no Falco pod runs on the node", objs: noPod()},
		{
			name:       "an invalid selector does not block the other artifacts",
			objs:       hosted(badSelector, testRulesfile("good")),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "good", "uid-good")},
			wantWrites: writes{creates: 1},
		},
		{
			name:       "lists a newly selecting artifact",
			objs:       hosted(testRulesfile("rf1"), testPlugin("p1"), existingArtifactNode(rfListing)),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Plugin", "p1", "uid-p1"), ref("Rulesfile", "rf1", "uid-rf1")},
			wantWrites: writes{patches: 1},
		},
		{
			name: "drops an artifact that stopped selecting the node",
			objs: hosted(testRulesfile("rf1"), testPlugin("p1", func(p *artifactv1alpha1.Plugin) { p.Spec.Selector = selecting("gpu") }),
				existingArtifactNode(listing(ref("Plugin", "p1", "uid-p1"), ref("Rulesfile", "rf1", "uid-rf1")))),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
			wantWrites: writes{patches: 1},
		},
		{
			name: "drops an artifact being deleted",
			objs: hosted(terminating(testRulesfile("gone")), testRulesfile("live"),
				existingArtifactNode(listing(ref("Rulesfile", "gone", "uid-gone"), ref("Rulesfile", "live", "uid-live")))),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "live", "uid-live")},
			wantWrites: writes{patches: 1},
		},
		{
			name:       "lists a recreated artifact with its new uid",
			objs:       hosted(testRulesfile("rf1"), existingArtifactNode(listing(ref("Rulesfile", "rf1", "old-uid")))),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
			wantWrites: writes{patches: 1},
		},
		{
			name:       "writes nothing once converged",
			objs:       hosted(testRulesfile("rf1"), existingArtifactNode(rfListing)),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
		},
		{
			name:       "repairs a missing node label",
			objs:       hosted(testRulesfile("rf1"), existingArtifactNode(rfListing, unlabeled)),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
			wantLabels: nodeLabel,
			wantWrites: writes{patches: 1},
		},
		{
			name: "repairs the node label and leaves another label alone",
			objs: hosted(testRulesfile("rf1"), existingArtifactNode(rfListing, unlabeled, func(s *artifactv1alpha1.ArtifactNode) {
				s.Labels = map[string]string{"team": "sec"}
			})),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
			wantLabels: map[string]string{"team": "sec", controllerhelper.LabelArtifactNode: nodeLabel[controllerhelper.LabelArtifactNode]},
			wantWrites: writes{patches: 1},
		},
		{
			name:       "does not write for a label somebody else added",
			objs:       hosted(testRulesfile("rf1"), existingArtifactNode(rfListing, withTeamLabel)),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
			wantLabels: map[string]string{"team": "sec", controllerhelper.LabelArtifactNode: nodeLabel[controllerhelper.LabelArtifactNode]},
		},
		{
			name:       "empties the spec of an ArtifactNode nothing selects it for, before deleting it",
			objs:       hosted(existingArtifactNode(rfListing)),
			wantExists: true,
			wantWrites: writes{patches: 1},
		},
		{
			name:       "deletes an ArtifactNode whose spec is empty and whose status is empty",
			objs:       hosted(existingArtifactNode(listing())),
			wantWrites: writes{deletes: 1},
		},
		{
			name:       "keeps an ArtifactNode the sidecar still reports on, with an empty spec",
			objs:       hosted(existingArtifactNode(rfListing, reportsRf)),
			wantExists: true,
			wantWrites: writes{patches: 1},
		},
		{
			name:       "writes nothing while the sidecar still reports on an ArtifactNode with an empty spec",
			objs:       hosted(existingArtifactNode(listing(), reportsRf)),
			wantExists: true,
		},
		{
			name:       "leaves an ArtifactNode that is being deleted alone",
			objs:       hosted(testRulesfile("rf1"), terminating(existingArtifactNode(rfListing))),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
		},
		{
			name:       "deletes the ArtifactNode of a node that is gone, at once",
			objs:       noNode(existingArtifactNode(rfListing)),
			wantWrites: writes{deletes: 1},
		},
		{
			name:       "releases the sidecar's finalizer of a node that is gone",
			objs:       noNode(existingArtifactNode(rfListing, sidecarFinalized())),
			wantWrites: writes{patches: 1, deletes: 1},
		},
		{
			name:       "warns when several Falco pods share the node, and carries on",
			objs:       hosted(testutil.NewFalcoPod("falco-pod-2", testutil.TestNodeName), testRulesfile("rf1"), existingArtifactNode(rfListing)),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
			wantEvents: 1,
		},
		{
			name: "a Falco pod being replaced is not a second sidecar",
			objs: hosted(terminating(testutil.NewFalcoPod("falco-pod-old", testutil.TestNodeName)), testRulesfile("rf1"),
				existingArtifactNode(rfListing)),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
		},
		{
			name:       "several Falco pods still get the assignment before the ArtifactNode exists, with only a log to warn",
			objs:       hosted(testutil.NewFalcoPod("falco-pod-2", testutil.TestNodeName), testRulesfile("rf1")),
			wantExists: true,
			wantSpec:   []artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")},
			wantWrites: writes{creates: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl, w := newReconciler(t, tt.objs...)
			rec := events.NewFakeRecorder(10)
			r.recorder = rec

			result, err := reconcileNode(t, r)

			require.NoError(t, err)
			assert.Equal(t, ctrl.Result{}, result)
			assert.Equal(t, tt.wantWrites, *w)
			assert.Len(t, drainEvents(rec), tt.wantEvents)
			got, exists := getArtifactNode(t, cl)
			require.Equal(t, tt.wantExists, exists)
			if !exists {
				return
			}
			assert.Equal(t, len(tt.wantSpec) == 0, len(got.Spec.Artifacts) == 0)
			if len(tt.wantSpec) > 0 {
				assert.Equal(t, tt.wantSpec, got.Spec.Artifacts)
			}
			if tt.wantLabels != nil {
				assert.Equal(t, tt.wantLabels, got.Labels)
			}
		})
	}
}

// An ArtifactNode lists at most artifactv1alpha1.MaxNodeArtifacts artifacts: the newest one beyond that is left
// unassigned, and the ones already listed keep their slot.
func TestReconcile_ListsAtMostTheSchemaCap(t *testing.T) {
	artifacts := make([]client.Object, 0, artifactv1alpha1.MaxNodeArtifacts+1)
	for i := range artifactv1alpha1.MaxNodeArtifacts + 1 {
		artifacts = append(artifacts, testRulesfile(fmt.Sprintf("rf-%03d", i), func(rf *artifactv1alpha1.Rulesfile) {
			rf.CreationTimestamp = at(i)
		}))
	}
	r, cl, _ := newReconciler(t, hosted(artifacts...)...)

	_, err := reconcileNode(t, r)

	require.NoError(t, err)
	got, _ := getArtifactNode(t, cl)
	require.Len(t, got.Spec.Artifacts, artifactv1alpha1.MaxNodeArtifacts)
	assert.NotContains(t, got.Spec.Artifacts, ref("Rulesfile", "rf-100", "uid-rf-100"), "the newest is the one left out")
}

// A Falco pod is replaced by an update, a restart or a reschedule, and there is a moment with none on the node.
// The ArtifactNode is kept for a grace period that starts at the first absence and is forgotten as soon as a
// pod is back.
func TestReconcile_TheGraceForAMissingFalcoPod(t *testing.T) {
	const (
		podUp   = "up"
		podDown = "down"
	)
	type step struct {
		pod         string        // podUp or podDown creates or deletes the pod before this reconcile
		advance     time.Duration // moves the clock before this reconcile
		wantRequeue time.Duration
		wantExists  bool
	}
	held := existingArtifactNode(listing(ref("Rulesfile", "rf1", "uid-rf1")))
	heldBySidecar := existingArtifactNode(listing(ref("Rulesfile", "rf1", "uid-rf1")), sidecarFinalized())

	tests := []struct {
		name  string
		node  *artifactv1alpha1.ArtifactNode
		steps []step
	}{
		{
			name: "kept for the whole grace, then deleted",
			node: held,
			steps: []step{
				{wantRequeue: falcoAbsentGrace, wantExists: true},
				{advance: falcoAbsentGrace},
			},
		},
		{
			name: "the sidecar's finalizer is released with the deletion",
			node: heldBySidecar,
			steps: []step{
				{wantRequeue: falcoAbsentGrace, wantExists: true},
				{advance: falcoAbsentGrace},
			},
		},
		{
			name: "counts down from the first absence",
			node: held,
			steps: []step{
				{wantRequeue: falcoAbsentGrace, wantExists: true},
				{advance: 30 * time.Second, wantRequeue: falcoAbsentGrace - 30*time.Second, wantExists: true},
			},
		},
		{
			name: "a pod that returns restarts the grace",
			node: held,
			steps: []step{
				{pod: podDown, wantRequeue: falcoAbsentGrace, wantExists: true},
				{pod: podUp, advance: falcoAbsentGrace - time.Second, wantExists: true},
				{pod: podDown, advance: time.Second, wantRequeue: falcoAbsentGrace, wantExists: true},
				{advance: falcoAbsentGrace - time.Second, wantRequeue: time.Second, wantExists: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl, _ := newReconciler(t, testNode(), testutil.NewTestFalco(), testRulesfile("rf1"), tt.node.DeepCopy())
			clock := useClock(r)
			pod := testutil.NewRunningFalcoPod()
			for i, s := range tt.steps {
				switch s.pod {
				case podUp:
					require.NoError(t, cl.Create(t.Context(), pod))
				case podDown:
					// Deleting a pod that was never there is how a test says "no pod" at the start.
					_ = cl.Delete(t.Context(), pod)
				}
				clock.advance(s.advance)

				result, err := reconcileNode(t, r)

				require.NoError(t, err, "step %d", i)
				assert.Equal(t, s.wantRequeue, result.RequeueAfter, "step %d", i)
				_, exists := getArtifactNode(t, cl)
				assert.Equal(t, s.wantExists, exists, "step %d", i)
			}
		})
	}
}

// Nothing is assigned any more, but Falco runs on the node: its artifact operator removes what it installed and
// then releases the finalizer itself, so the controller only deletes the ArtifactNode, after emptying its spec.
func TestReconcile_ARunningSidecarReleasesItsOwnFinalizer(t *testing.T) {
	r, cl, _ := newReconciler(t, hosted(existingArtifactNode(listing(ref("Rulesfile", "rf", "uid-rf")), sidecarFinalized()))...)

	_, err := reconcileNode(t, r) // empties the spec
	require.NoError(t, err)
	_, err = reconcileNode(t, r) // nothing assigned, nothing reported: deleted

	require.NoError(t, err)
	got, found := getArtifactNode(t, cl)
	require.True(t, found, "the sidecar has not cleaned yet")
	assert.NotNil(t, got.DeletionTimestamp)
	assert.Empty(t, got.Spec.Artifacts)
	assert.Contains(t, got.Finalizers, controllerhelper.ArtifactNodeSidecarFinalizer)
}

// Several Falco pods on one node are warned about once per change of their number, not on every reconcile of
// the node, which every artifact or pod event in the namespace triggers.
func TestReconcile_SeveralFalcoPodsOnANodeAreWarnedAboutOncePerChange(t *testing.T) {
	r, cl := build(t, nil, hosted(testRulesfile("rf1"), testutil.NewFalcoPod("falco-pod-2", testutil.TestNodeName))...)
	recorder := r.recorder.(*events.FakeRecorder)
	warnings := func() int {
		n := 0
		for {
			select {
			case e := <-recorder.Events:
				if strings.Contains(e, ReasonMultipleSidecars) {
					n++
				}
			default:
				return n
			}
		}
	}
	reconcileTimes := func(n int) {
		for range n {
			_, err := reconcileNode(t, r)
			require.NoError(t, err)
		}
	}

	reconcileTimes(3)
	assert.Equal(t, 1, warnings(), "two pods: one warning however often the node is reconciled")

	require.NoError(t, cl.Create(t.Context(), testutil.NewFalcoPod("falco-pod-3", testutil.TestNodeName)))
	reconcileTimes(2)
	assert.Equal(t, 1, warnings(), "a third pod is a change, warned about once")

	for _, name := range []string{"falco-pod-2", "falco-pod-3"} {
		require.NoError(t, cl.Delete(t.Context(), testutil.NewFalcoPod(name, testutil.TestNodeName)))
	}
	reconcileTimes(1)
	require.NoError(t, cl.Create(t.Context(), testutil.NewFalcoPod("falco-pod-4", testutil.TestNodeName)))
	reconcileTimes(2)
	assert.Equal(t, 1, warnings(), "back to one pod and up again is reported again")
}

// A deletion at the end of the grace that is rejected because the cache lagged is retried at once: the grace has
// already run out, and a retry must not start it again.
func TestReconcile_ARejectedDeletionDoesNotRestartTheGrace(t *testing.T) {
	deletes := 0
	funcs := interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		deletes++
		if deletes == 1 {
			return errConflict
		}
		return c.Delete(ctx, obj, opts...)
	}}
	r, cl := build(t, &funcs, testNode(), testutil.NewTestFalco(), testRulesfile("rf1"),
		existingArtifactNode(listing(ref("Rulesfile", "rf1", "uid-rf1"))))
	clock := useClock(r)

	result, err := reconcileNode(t, r)
	require.NoError(t, err)
	require.Equal(t, falcoAbsentGrace, result.RequeueAfter)

	clock.advance(falcoAbsentGrace)
	result, err = reconcileNode(t, r)
	require.NoError(t, err)
	require.Equal(t, controllerhelper.StaleCacheRetryDelay, result.RequeueAfter, "the rejected deletion is retried shortly")

	result, err = reconcileNode(t, r)
	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)
	assert.Equal(t, 2, deletes)
	_, exists := getArtifactNode(t, cl)
	assert.False(t, exists, "the retry deletes the ArtifactNode without another grace")
}

// A write rejected because the cache lagged is expected: it is retried shortly, and never an error. An object that
// is gone leaves nothing to do.
func TestReconcile_RejectedWritesAreRetriedWithoutError(t *testing.T) {
	noNode := func(extra ...client.Object) []client.Object {
		return append([]client.Object{testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), testRulesfile("rf1")}, extra...)
	}
	tests := []struct {
		name        string
		funcs       interceptor.Funcs
		objs        []client.Object
		wantRequeue time.Duration
	}{
		{
			"the patch conflicts", testutil.FailPatch(errConflict), hosted(testRulesfile("rf1"), existingArtifactNode()),
			controllerhelper.StaleCacheRetryDelay,
		},
		{
			"the create finds the ArtifactNode there", testutil.FailCreate(errExists), hosted(testRulesfile("rf1")),
			controllerhelper.StaleCacheRetryDelay,
		},
		{
			"the delete's uid precondition fails", testutil.FailDelete(errConflict), hosted(existingArtifactNode(listing())),
			controllerhelper.StaleCacheRetryDelay,
		},
		{
			"releasing the finalizer conflicts", testutil.FailPatch(errConflict),
			noNode(existingArtifactNode(listing(ref("Rulesfile", "rf1", "uid-rf1")), sidecarFinalized())), controllerhelper.StaleCacheRetryDelay,
		},
		{"the patch finds the ArtifactNode gone", testutil.FailPatch(errNotFound), hosted(testRulesfile("rf1"), existingArtifactNode()), 0},
		{"the create finds the namespace gone", testutil.FailCreate(errNotFound), hosted(testRulesfile("rf1")), 0},
		{"the delete finds the ArtifactNode gone", testutil.FailDelete(errNotFound), hosted(existingArtifactNode(listing())), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := build(t, &tt.funcs, tt.objs...)

			result, err := reconcileNode(t, r)

			require.NoError(t, err)
			assert.Equal(t, tt.wantRequeue, result.RequeueAfter)
		})
	}
}

func TestReconcile_ReturnsAPIErrors(t *testing.T) {
	noNode := []client.Object{testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), testRulesfile("rf1"),
		existingArtifactNode(listing(ref("Rulesfile", "rf1", "uid-rf1")), sidecarFinalized())}
	tests := []struct {
		name  string
		funcs interceptor.Funcs
		objs  []client.Object
	}{
		{"getting the ArtifactNode", failGet[*artifactv1alpha1.ArtifactNode](errBoom), hosted(testRulesfile("rf1"))},
		{"getting the Node", failGet[*corev1.Node](errBoom), hosted(testRulesfile("rf1"))},
		{"listing the Falcos", failList[*instancev1alpha1.FalcoList](errBoom), hosted(testRulesfile("rf1"))},
		{"listing the Falco pods", failList[*corev1.PodList](errBoom), hosted(testRulesfile("rf1"))},
		{"listing the Rulesfiles", failList[*artifactv1alpha1.RulesfileList](errBoom), hosted(testRulesfile("rf1"))},
		{"listing the Plugins", failList[*artifactv1alpha1.PluginList](errBoom), hosted(testRulesfile("rf1"))},
		{"listing the Configs", failList[*artifactv1alpha1.ConfigList](errBoom), hosted(testRulesfile("rf1"))},
		{"creating", testutil.FailCreate(errBoom), hosted(testRulesfile("rf1"))},
		{"patching", testutil.FailPatch(errBoom), hosted(testRulesfile("rf1"), existingArtifactNode())},
		{"deleting", testutil.FailDelete(errBoom), hosted(existingArtifactNode(listing()))},
		{"releasing the sidecar's finalizer", testutil.FailPatch(errBoom), noNode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := build(t, &tt.funcs, tt.objs...)

			_, err := reconcileNode(t, r)

			require.ErrorIs(t, err, errBoom)
		})
	}
}

// capacityRulesfiles returns one Rulesfile more than an ArtifactNode can list, rf-000 the oldest and rf-100 the
// newest, and the refs of the first n of them.
func capacityRulesfiles(n int) ([]client.Object, []artifactv1alpha1.NodeArtifactRef) {
	artifacts := make([]client.Object, 0, artifactv1alpha1.MaxNodeArtifacts+1)
	refs := make([]artifactv1alpha1.NodeArtifactRef, 0, n)
	for i := range artifactv1alpha1.MaxNodeArtifacts + 1 {
		name := fmt.Sprintf("rf-%03d", i)
		artifacts = append(artifacts, testRulesfile(name, func(rf *artifactv1alpha1.Rulesfile) { rf.CreationTimestamp = at(i) }))
		if i < n {
			refs = append(refs, ref("Rulesfile", name, "uid-"+name))
		}
	}
	return artifacts, refs
}

// The spec patch carries the resourceVersion only when some artifact did not fit: then the slots depend on what is
// listed. Otherwise the list follows from the artifacts alone, and a precondition would only have the patch conflict
// with every status write of the node's artifact operator.
func TestReconcile_PatchCarriesTheResourceVersionOnlyWhenCapped(t *testing.T) {
	capped, firstRefs := capacityRulesfiles(artifactv1alpha1.MaxNodeArtifacts - 1)
	for name, tc := range map[string]struct {
		objs   []client.Object
		wantRV bool
	}{
		"every artifact fits":        {hosted(testRulesfile("rf1"), existingArtifactNode()), false},
		"some artifact does not fit": {hosted(append(capped, existingArtifactNode(listing(firstRefs...)))...), true},
	} {
		t.Run(name, func(t *testing.T) {
			var body []byte
			funcs := interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					var err error
					body, err = patch.Data(obj)
					require.NoError(t, err)
					return c.Patch(ctx, obj, patch, opts...)
				},
			}
			r, cl := build(t, &funcs, tc.objs...)
			before, _ := getArtifactNode(t, cl)

			_, err := reconcileNode(t, r)

			require.NoError(t, err)
			require.NotEmpty(t, body, "the spec changed, so it is patched")
			var got struct {
				Metadata struct {
					ResourceVersion string `json:"resourceVersion"`
				} `json:"metadata"`
			}
			require.NoError(t, json.Unmarshal(body, &got))
			if tc.wantRV {
				assert.Equal(t, before.ResourceVersion, got.Metadata.ResourceVersion)
			} else {
				assert.Empty(t, got.Metadata.ResourceVersion)
			}
		})
	}
}

// A decision based on a cache older than the server is safe either way. When every artifact fits, it writes the
// list that follows from the artifacts, which is right whatever the cache showed. When some do not fit, a stale view
// of which artifacts hold a slot could take one away, so the write conflicts and is retried instead.
func TestReconcile_AStaleCacheCannotTakeASlotAway(t *testing.T) {
	// staleAs makes the client read the ArtifactNode as it was at resourceVersion "1", listing spec, until the
	// returned flag is cleared.
	staleAs := func(spec []artifactv1alpha1.NodeArtifactRef) (*interceptor.Funcs, *bool) {
		stale := true
		get := func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if artifactNode, ok := obj.(*artifactv1alpha1.ArtifactNode); ok && stale {
				artifactNode.ResourceVersion = "1"
				artifactNode.Spec.Artifacts = spec
			}
			return nil
		}
		return &interceptor.Funcs{Get: get}, &stale
	}

	t.Run("every artifact fits: the right list is written", func(t *testing.T) {
		newer := existingArtifactNode(listing(ref("Rulesfile", "rf1", "uid-rf1"), ref("Rulesfile", "rf2", "uid-rf2")))
		funcs, stale := staleAs([]artifactv1alpha1.NodeArtifactRef{ref("Rulesfile", "rf1", "uid-rf1")})
		r, cl := build(t, funcs, hosted(testRulesfile("rf1"), testRulesfile("rf2"), testRulesfile("rf3"), newer)...)

		result, err := reconcileNode(t, r)

		require.NoError(t, err)
		assert.Zero(t, result.RequeueAfter)
		*stale = false // read what the server actually holds
		stored, _ := getArtifactNode(t, cl)
		assert.Equal(t, []artifactv1alpha1.NodeArtifactRef{
			ref("Rulesfile", "rf1", "uid-rf1"), ref("Rulesfile", "rf2", "uid-rf2"), ref("Rulesfile", "rf3", "uid-rf3"),
		}, stored.Spec.Artifacts)
	})

	t.Run("some artifact does not fit: the newer slots survive", func(t *testing.T) {
		// The server gave the last slot to rf-100. The cache does not show it yet, so a decision based on it would give
		// the slot to rf-099, the oldest artifact without one, and take it from rf-100.
		artifacts, firstRefs := capacityRulesfiles(artifactv1alpha1.MaxNodeArtifacts - 1)
		serverSpec := append(slices.Clone(firstRefs), ref("Rulesfile", "rf-100", "uid-rf-100"))
		funcs, stale := staleAs(firstRefs)
		r, cl := build(t, funcs, hosted(append(artifacts, existingArtifactNode(listing(serverSpec...)))...)...)

		result, err := reconcileNode(t, r)

		require.NoError(t, err, "a stale write is expected and must not fail the reconcile")
		assert.Equal(t, controllerhelper.StaleCacheRetryDelay, result.RequeueAfter)
		*stale = false // read what the server actually holds
		stored, _ := getArtifactNode(t, cl)
		assert.Contains(t, stored.Spec.Artifacts, ref("Rulesfile", "rf-100", "uid-rf-100"), "the slot is not taken away")
	})
}

// A terminating ArtifactNode whose node no longer runs a Falco pod has nobody left to release the artifact
// operator's finalizer: that operator went with the pod. This controller is the only other actor that can
// remove it, and if it does not, neither the ArtifactNode nor the namespace holding it ever finishes deleting.
func TestReconcile_ReleasesTheFinalizerOfAnAbandonedTerminatingArtifactNode(t *testing.T) {
	abandoned := func() *artifactv1alpha1.ArtifactNode {
		an := existingArtifactNode()
		now := metav1.Now()
		an.DeletionTimestamp = &now
		an.Finalizers = []string{controllerhelper.ArtifactNodeSidecarFinalizer}
		return an
	}

	t.Run("no Falco pod on the node: the finalizer is released", func(t *testing.T) {
		// testNode() and testutil.NewTestFalco() but deliberately no testutil.NewRunningFalcoPod().
		r, cl, _ := newReconciler(t, testNode(), testutil.NewTestFalco(), abandoned())

		_, err := reconcileNode(t, r)

		require.NoError(t, err)
		_, exists := getArtifactNode(t, cl)
		assert.False(t, exists, "releasing the last finalizer lets the terminating ArtifactNode go")
	})

	t.Run("a Falco pod still runs: the artifact operator releases it itself", func(t *testing.T) {
		r, cl, w := newReconciler(t, testNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), abandoned())

		_, err := reconcileNode(t, r)

		require.NoError(t, err)
		got, exists := getArtifactNode(t, cl)
		require.True(t, exists)
		assert.Contains(t, got.Finalizers, controllerhelper.ArtifactNodeSidecarFinalizer,
			"the artifact operator is there to remove what it installed first")
		assert.Equal(t, writes{}, *w, "a terminating ArtifactNode is not otherwise this controller's business")
	})
}

// The deletion names the ArtifactNode the decision was made about, by uid: one deleted and created again since the
// cache was read is another object, and survives. The fake client does not enforce a uid precondition, so the
// request itself is checked.
func TestReconcile_DeletesOnlyTheArtifactNodeItSaw(t *testing.T) {
	var precondition *types.UID
	funcs := interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		options := &client.DeleteOptions{}
		options.ApplyOptions(opts)
		if options.Preconditions != nil {
			precondition = options.Preconditions.UID
		}
		return c.Delete(ctx, obj, opts...)
	}}
	seen := existingArtifactNode()
	seen.UID = "seen"
	// No Node: the ArtifactNode of a node that is gone is deleted at once.
	r, _ := build(t, &funcs, seen)

	_, err := reconcileNode(t, r)

	require.NoError(t, err)
	require.NotNil(t, precondition, "the delete carries a uid precondition")
	assert.Equal(t, seen.UID, *precondition)
}

// An ArtifactNode a v0.5.0 release candidate left behind is named after an artifact and a node, and carries the
// finalizer of an artifact operator that no longer exists. The controller deletes it, as it does the ArtifactNode
// of a node that is gone, and releases that finalizer, or it would stay Terminating for good.
func TestReconcile_ReleasesAnArtifactNodeLeftByAReleaseCandidate(t *testing.T) {
	const legacyName = "plugin--container--" + testutil.TestNodeName
	for _, finalizer := range legacyArtifactNodeFinalizers {
		t.Run(finalizer, func(t *testing.T) {
			legacy := &artifactv1alpha1.ArtifactNode{
				ObjectMeta: metav1.ObjectMeta{Name: legacyName, Namespace: testutil.TestNamespace, Finalizers: []string{finalizer}},
				Spec:       artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
			}
			r, cl, _ := newReconciler(t, testNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), legacy)
			req := reconcile.Request{NamespacedName: key(testutil.TestNamespace, legacyName)}

			for range 2 {
				_, err := r.Reconcile(t.Context(), req)
				require.NoError(t, err)
			}

			err := cl.Get(t.Context(), req.NamespacedName, &artifactv1alpha1.ArtifactNode{})
			assert.True(t, k8serrors.IsNotFound(err), "the object is gone: %v", err)
		})
	}
}

func keysOf(reqs []reconcile.Request) []types.NamespacedName {
	keys := make([]types.NamespacedName, len(reqs))
	for i, req := range reqs {
		keys[i] = req.NamespacedName
	}
	return keys
}

func TestFalcoPodRequests(t *testing.T) {
	unscheduled := testutil.NewFalcoPod("pending", "")
	tests := []struct {
		name string
		obj  client.Object
		want []types.NamespacedName
	}{
		{
			"a pod on a node maps to that node's ArtifactNode", testutil.NewRunningFalcoPod(),
			[]types.NamespacedName{key(testutil.TestNamespace, testutil.TestNodeName)},
		},
		{"a pod that is not scheduled yet maps to nothing", unscheduled, []types.NamespacedName{}},
		{"an object that is not a pod maps to nothing", testNode(), []types.NamespacedName{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.want, keysOf(falcoPodRequests(t.Context(), tt.obj)))
		})
	}
}

func TestRequestsForNamespace(t *testing.T) {
	const other = "other"
	objs := []client.Object{
		testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), testutil.NewFalcoPod("falco-pod-2", "node-b"),
		artifactNodeOf(testutil.TestNamespace, "node-c"), // no Falco pod any more, but still has an ArtifactNode
		artifactNodeOf(other, "node-d"),                  // another namespace
	}
	tests := []struct {
		name  string
		funcs interceptor.Funcs
		want  []types.NamespacedName
	}{
		{
			name: "nodes running Falco and nodes that already have an ArtifactNode, in that namespace only",
			want: []types.NamespacedName{
				key(testutil.TestNamespace, testutil.TestNodeName), key(testutil.TestNamespace, "node-b"), key(testutil.TestNamespace, "node-c"),
			},
		},
		{
			name:  "the nodes with an ArtifactNode are still enqueued when listing the Falcos fails",
			funcs: failList[*instancev1alpha1.FalcoList](errBoom),
			want:  []types.NamespacedName{key(testutil.TestNamespace, "node-c")},
		},
		{
			name:  "the nodes running Falco are still enqueued when listing the ArtifactNodes fails",
			funcs: failList[*artifactv1alpha1.ArtifactNodeList](errBoom),
			want:  []types.NamespacedName{key(testutil.TestNamespace, testutil.TestNodeName), key(testutil.TestNamespace, "node-b")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := build(t, &tt.funcs, objs...)

			assert.ElementsMatch(t, tt.want, keysOf(r.requestsForNamespace(t.Context(), testutil.TestNamespace)))
		})
	}
}

func TestRequestsForNode(t *testing.T) {
	const other = "other"
	objs := []client.Object{
		testutil.NewTestFalco(),                          // Falco runs in the test namespace
		artifactNodeOf(other, testutil.TestNodeName),     // this node's ArtifactNode in another namespace
		artifactNodeOf("third", "node-z"),                // another node's
		artifactNodeOf(testutil.TestNamespace, "node-y"), // another node's, in a namespace that runs Falco
	}
	tests := []struct {
		name  string
		funcs interceptor.Funcs
		want  []types.NamespacedName
	}{
		{
			name: "namespaces running Falco and namespaces that already have an ArtifactNode for the node",
			want: []types.NamespacedName{key(testutil.TestNamespace, testutil.TestNodeName), key(other, testutil.TestNodeName)},
		},
		{
			name:  "the namespaces with an ArtifactNode are still enqueued when listing the Falcos fails",
			funcs: failList[*instancev1alpha1.FalcoList](errBoom),
			want:  []types.NamespacedName{key(other, testutil.TestNodeName)},
		},
		{
			name:  "the namespaces running Falco are still enqueued when listing the ArtifactNodes fails",
			funcs: failList[*artifactv1alpha1.ArtifactNodeList](errBoom),
			want:  []types.NamespacedName{key(testutil.TestNamespace, testutil.TestNodeName)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := build(t, &tt.funcs, objs...)

			assert.ElementsMatch(t, tt.want, keysOf(r.requestsForNode(t.Context(), testutil.TestNodeName)))
		})
	}
}

func TestArtifactNodeChanged(t *testing.T) {
	withStatus := func(generation int64, entries ...string) *artifactv1alpha1.ArtifactNode {
		n := &artifactv1alpha1.ArtifactNode{}
		n.Name, n.Generation = "node", generation
		for _, name := range entries {
			n.Status.Artifacts = append(n.Status.Artifacts, artifactv1alpha1.NodeArtifactStatus{Kind: "Rulesfile", Name: name, UID: "u"})
		}
		return n
	}
	relabeled := withStatus(1)
	relabeled.Labels = map[string]string{"artifact.falcosecurity.dev/node": "other"}

	tests := []struct {
		name string
		old  client.Object
		new  client.Object
		want bool
	}{
		{"the sidecar withdrawing its last entry", withStatus(1, "a"), withStatus(1), true},
		{"the sidecar withdrawing one of several entries", withStatus(1, "a", "b"), withStatus(1, "a"), false},
		{"the sidecar rewriting the same status", withStatus(1, "a"), withStatus(1, "a"), false},
		{"the sidecar starting to report", withStatus(1), withStatus(1, "a"), false},
		{"nothing changed, with an empty status", withStatus(1), withStatus(1), false},
		{"a spec change", withStatus(1), withStatus(2), true},
		{"a label change", withStatus(1), relabeled, true},
		{"an update of an object that is not an ArtifactNode", testNode(), testNode(), false},
	}
	p := artifactNodeChanged()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, p.Update(event.UpdateEvent{ObjectOld: tt.old, ObjectNew: tt.new}))
		})
	}

	t.Run("creation and deletion are accepted", func(t *testing.T) {
		assert.True(t, p.Create(event.CreateEvent{Object: withStatus(1)}))
		assert.True(t, p.Delete(event.DeleteEvent{Object: withStatus(1)}))
	})
}

func TestToRequests(t *testing.T) {
	assert.Empty(t, toRequests(nil))
	assert.ElementsMatch(t,
		[]reconcile.Request{{NamespacedName: key("ns", "a")}, {NamespacedName: key("ns", "b")}},
		toRequests(map[types.NamespacedName]struct{}{key("ns", "a"): {}, key("ns", "b"): {}}))
}
