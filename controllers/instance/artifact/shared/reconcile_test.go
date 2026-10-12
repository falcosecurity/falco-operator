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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/instance/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// The tests aggregate Configs, the kind with the least of its own; what Plugins and Rulesfiles add is switched on
// through the Aggregation's fields.

const configName = "cfg"

var errBoom = errors.New("boom")

func newConfig() *artifactv1alpha1.Config {
	return &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: configName, UID: "uid", Generation: 2},
		Status:     artifactv1alpha1.ConfigStatus{ObservedGeneration: 1},
	}
}

func selectedNode() *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName}}
}

func newClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Config{}, &artifactv1alpha1.ArtifactNode{}).
		Build()
}

// aggregation aggregates Configs through cl, counting the status writes in patches.
func aggregation(cl client.Client, patches *int) shared.Aggregation[*artifactv1alpha1.Config] {
	return shared.Aggregation[*artifactv1alpha1.Config]{
		Client:       cl,
		Scheme:       cl.Scheme(),
		FieldManager: "test-aggregator",
		Kind:         artifact.KindConfig,
		New:          func() *artifactv1alpha1.Config { return &artifactv1alpha1.Config{} },
		PatchStatus: func(ctx context.Context, c *artifactv1alpha1.Config) error {
			*patches++
			return controllerhelper.PatchStatusSSA(ctx, cl, cl.Scheme(), c, "test-aggregator")
		},
		StatusValue: func(c *artifactv1alpha1.Config) any { return *c.Status.DeepCopy() },
	}
}

func get(t *testing.T, cl client.Client) *artifactv1alpha1.Config {
	t.Helper()
	c := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(newConfig()), c))
	return c
}

func TestReconcile_TheArtifactIsGone(t *testing.T) {
	var patches int
	result, err := shared.Reconcile(t.Context(), testutil.Request(configName), aggregation(newClient(t), &patches))

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Zero(t, patches)
}

func TestReconcile_ReturnsAnErrorReadingTheArtifact(t *testing.T) {
	cl := newClient(t)
	a := aggregation(cl, new(int))
	a.Client = errorOnGet{cl}

	_, err := shared.Reconcile(t.Context(), testutil.Request(configName), a)

	require.ErrorIs(t, err, errBoom)
}

// errorOnGet is a client whose reads fail.
type errorOnGet struct{ client.Client }

func (errorOnGet) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errBoom
}

// A Config on a node running Falco: it gets the in-use finalizer, and its status is stamped with its generation and
// the aggregate of what its nodes report, in a single write.
func TestReconcile_WritesTheAggregate(t *testing.T) {
	cl := newClient(t, newConfig(), selectedNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod())
	var patches int

	result, err := shared.Reconcile(t.Context(), testutil.Request(configName), aggregation(cl, &patches))

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, 1, patches)
	got := get(t, cl)
	assert.Contains(t, got.Finalizers, controllerhelper.NodeObjectsInUseFinalizer)
	assert.Equal(t, int64(2), got.Status.ObservedGeneration)
	assert.NotNil(t, apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
}

// The finalizer is held while a selected node runs Falco, or, with HoldForSelectedNodes, while any node is
// selected at all.
// A selector the API server admits but that is no valid label selector selects no node. The status says so, once.
func TestReconcile_AnInvalidSelectorIsReported(t *testing.T) {
	config := newConfig()
	config.Spec.Selector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "zone", Operator: "NoSuchOperator"},
	}}
	config.Status.Conditions = []metav1.Condition{
		{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: "Programmed", LastTransitionTime: metav1.Now()},
		{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: "Resolved", LastTransitionTime: metav1.Now()},
	}
	cl := newClient(t, config, selectedNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod())
	var patches int

	for range 2 {
		result, err := shared.Reconcile(t.Context(), testutil.Request(configName), aggregation(cl, &patches))
		require.NoError(t, err, "retrying cannot fix the selector")
		assert.Equal(t, ctrl.Result{}, result)
	}

	assert.Equal(t, 1, patches, "the second reconcile finds nothing to change")
	got := get(t, cl)
	require.Len(t, got.Status.Conditions, 1, "no node reports on it any more")
	testutil.RequireCondition(t, got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String(),
		metav1.ConditionFalse, artifact.ReasonInvalidSelector)
}

// An artifact with no node says which of the two reasons applies, and a second reconcile changes nothing.
func TestReconcile_SaysWhyNoNodeIsAssigned(t *testing.T) {
	for name, tc := range map[string]struct {
		objects []client.Object
		want    string
	}{
		"the selector matches no node":              {nil, "its selector matches no node"},
		"no Falco pod runs on the nodes it matches": {[]client.Object{selectedNode()}, "no Falco pod runs on the nodes"},
	} {
		t.Run(name, func(t *testing.T) {
			cl := newClient(t, append(tc.objects, newConfig())...)
			var patches int

			for range 2 {
				_, err := shared.Reconcile(t.Context(), testutil.Request(configName), aggregation(cl, &patches))
				require.NoError(t, err)
			}

			assert.Equal(t, 1, patches)
			programmed := apimeta.FindStatusCondition(get(t, cl).Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
			require.NotNil(t, programmed)
			assert.Equal(t, "NoNodesAssigned", programmed.Reason)
			assert.Contains(t, programmed.Message, tc.want)
		})
	}
}

func TestReconcile_HoldsTheFinalizer(t *testing.T) {
	for name, tt := range map[string]struct {
		falcoRunning, holdForSelected, want bool
	}{
		"a selected node without Falco":                          {want: false},
		"a selected node without Falco, held for selected nodes": {holdForSelected: true, want: true},
		"a selected node running Falco":                          {falcoRunning: true, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			objs := []client.Object{newConfig(), selectedNode()}
			if tt.falcoRunning {
				objs = append(objs, testutil.NewTestFalco(), testutil.NewRunningFalcoPod())
			}
			cl := newClient(t, objs...)
			a := aggregation(cl, new(int))
			a.HoldForSelectedNodes = tt.holdForSelected

			_, err := shared.Reconcile(t.Context(), testutil.Request(configName), a)

			require.NoError(t, err)
			assert.Equal(t, tt.want, controllerutil.ContainsFinalizer(get(t, cl), controllerhelper.NodeObjectsInUseFinalizer))
		})
	}
}

// With metadata, the generation is stamped in the same write as the metadata, before the aggregate is written.
func TestReconcile_WritesTheMetadataFirst(t *testing.T) {
	cl := newClient(t, newConfig())
	var patches int
	a := aggregation(cl, &patches)
	a.Metadata = func(context.Context, *artifactv1alpha1.Config) error { return nil }

	_, err := shared.Reconcile(t.Context(), testutil.Request(configName), a)

	require.NoError(t, err)
	assert.Equal(t, 2, patches)
	assert.Equal(t, int64(2), get(t, cl).Status.ObservedGeneration)
}

// A metadata failure is the cause of Programmed=False, and, with ResetObservedGenerationOnMetadataFailure, makes the
// nodes wait for a complete rebuild. The generation observed so far is one the aggregator wrote itself, as it is in
// a cluster: a server-side apply drops only a field its manager owns.
func TestReconcile_AMetadataFailure(t *testing.T) {
	for name, tt := range map[string]struct {
		reset    bool
		wantSeen int64
	}{
		"keeps the generation observed so far": {reset: false, wantSeen: 2},
		"resets the generation observed":       {reset: true, wantSeen: 0},
	} {
		t.Run(name, func(t *testing.T) {
			cl := newClient(t, newConfig())
			a := aggregation(cl, new(int))
			_, err := shared.Reconcile(t.Context(), testutil.Request(configName), a)
			require.NoError(t, err)
			require.Equal(t, int64(2), get(t, cl).Status.ObservedGeneration)

			a.Metadata = func(context.Context, *artifactv1alpha1.Config) error { return errBoom }
			a.MetadataFailedReason = "MetadataFailed"
			a.MetadataFailedMessage = "metadata: %s"
			a.ResetObservedGenerationOnMetadataFailure = tt.reset

			_, err = shared.Reconcile(t.Context(), testutil.Request(configName), a)

			require.ErrorIs(t, err, errBoom)
			got := get(t, cl)
			assert.Equal(t, tt.wantSeen, got.Status.ObservedGeneration)
			programmed := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
			require.NotNil(t, programmed)
			assert.Equal(t, metav1.ConditionFalse, programmed.Status)
			assert.Equal(t, "MetadataFailed", programmed.Reason)
			assert.Equal(t, "metadata: boom", programmed.Message)
		})
	}
}

// The pre-fetch covers every selected node, not only those running Falco, and its failure is returned once the
// status is written.
func TestReconcile_APrefetchFailureIsReturnedAfterTheStatus(t *testing.T) {
	cl := newClient(t, newConfig(), selectedNode())
	var prefetched []string
	a := aggregation(cl, new(int))
	a.Prefetch = func(_ context.Context, _ *artifactv1alpha1.Config, nodes []corev1.Node) error {
		for _, n := range nodes {
			prefetched = append(prefetched, n.Name)
		}
		return errBoom
	}

	_, err := shared.Reconcile(t.Context(), testutil.Request(configName), a)

	require.ErrorIs(t, err, errBoom)
	assert.Equal(t, []string{testutil.TestNodeName}, prefetched)
	assert.Equal(t, int64(2), get(t, cl).Status.ObservedGeneration, "the status is written despite the failure")
}

// deleting returns a client holding the Config, being deleted, and objs.
func deleting(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	config := newConfig()
	config.Finalizers = []string{controllerhelper.NodeObjectsInUseFinalizer}
	cl := newClient(t, append(objs, config)...)
	require.NoError(t, cl.Delete(t.Context(), newConfig()))
	return cl
}

// A Config being deleted is released once no node lists it or reports on it.
func TestReconcile_ReleasesADeletedArtifact(t *testing.T) {
	cl := deleting(t)

	_, err := shared.Reconcile(t.Context(), testutil.Request(configName), aggregation(cl, new(int)))

	require.NoError(t, err)
	err = cl.Get(t.Context(), client.ObjectKeyFromObject(newConfig()), &artifactv1alpha1.Config{})
	assert.True(t, k8serrors.IsNotFound(err), "with no node holding it, the finalizer is released")
}

func TestHandleDeletion(t *testing.T) {
	for name, tt := range map[string]struct {
		listed, withCache, aggregate bool
		wantReleased                 bool
	}{
		"a node lists it":                     {listed: true},
		"a node lists it, aggregating":        {listed: true, aggregate: true},
		"no node holds it":                    {wantReleased: true},
		"no node holds it, its cache evicted": {withCache: true, wantReleased: true},
	} {
		t.Run(name, func(t *testing.T) {
			var objs []client.Object
			if tt.listed {
				objs = append(objs, testutil.NewAssigningArtifactNode("Config", configName, "uid"))
			}
			cl := deleting(t, objs...)
			a := aggregation(cl, new(int))
			a.AggregateOnDeletion = tt.aggregate
			if tt.withCache {
				a.Cache = artifactcache.NewCache(t.TempDir())
			}

			_, err := shared.HandleDeletion(t.Context(), a, get(t, cl))
			require.NoError(t, err)

			err = cl.Get(t.Context(), client.ObjectKeyFromObject(newConfig()), &artifactv1alpha1.Config{})
			assert.Equal(t, tt.wantReleased, k8serrors.IsNotFound(err))
		})
	}
}

// A node that is down keeps its ArtifactNode, and its sidecar withdraws nothing. Once it has been unreachable for
// long enough it no longer keeps a deleted artifact from going; until then the reconcile looks again when the
// grace runs out.
func TestHandleDeletion_ALostNodeDoesNotHoldTheArtifact(t *testing.T) {
	unreachable := func(since *metav1.Time) *corev1.Node {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName},
			Spec: corev1.NodeSpec{Taints: []corev1.Taint{{
				Key: corev1.TaintNodeUnreachable, Effect: corev1.TaintEffectNoExecute, TimeAdded: since,
			}}},
		}
	}
	ago := func(d time.Duration) *metav1.Time { return &metav1.Time{Time: time.Now().Add(-d)} }
	for name, tt := range map[string]struct {
		node         *corev1.Node
		wantReleased bool
		wantRecheck  bool
	}{
		"reachable":                     {node: &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName}}},
		"unreachable for a moment":      {node: unreachable(ago(time.Minute)), wantRecheck: true},
		"unreachable past the grace":    {node: unreachable(ago(time.Hour)), wantReleased: true},
		"tainted by hand, with no time": {node: unreachable(nil)},
		"only unschedulable, not NoExecute": {node: func() *corev1.Node {
			n := unreachable(ago(time.Hour))
			n.Spec.Taints[0].Effect = corev1.TaintEffectNoSchedule
			return n
		}()},
	} {
		t.Run(name, func(t *testing.T) {
			// The node's spec no longer lists the artifact, as the assignment controller leaves it, but the entry its
			// sidecar published is still there.
			holding := testutil.NewReportingArtifactNode("Config", configName)
			cl := deleting(t, holding, tt.node)

			result, err := shared.HandleDeletion(t.Context(), aggregation(cl, new(int)), get(t, cl))

			require.NoError(t, err)
			assert.Equal(t, tt.wantRecheck, result.RequeueAfter > 0, "looks again when the grace runs out")
			err = cl.Get(t.Context(), client.ObjectKeyFromObject(newConfig()), &artifactv1alpha1.Config{})
			assert.Equal(t, tt.wantReleased, k8serrors.IsNotFound(err))
		})
	}
}

// Another node that is reachable and still holds the artifact keeps it, whatever the lost one does.
func TestHandleDeletion_AReachableHolderStillHoldsTheArtifact(t *testing.T) {
	lost := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName},
		Spec: corev1.NodeSpec{Taints: []corev1.Taint{{
			Key: corev1.TaintNodeUnreachable, Effect: corev1.TaintEffectNoExecute,
			TimeAdded: &metav1.Time{Time: time.Now().Add(-time.Hour)},
		}}},
	}
	other := testutil.NewArtifactNode(testutil.TestNamespace, "other-node",
		testutil.WithReported(testutil.NodeArtifactStatus("Config", configName, "uid")))
	cl := deleting(t, testutil.NewReportingArtifactNode("Config", configName), other, lost,
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node"}})

	result, err := shared.HandleDeletion(t.Context(), aggregation(cl, new(int)), get(t, cl))

	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter, "the reachable node's events wake the reconcile")
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(newConfig()), &artifactv1alpha1.Config{}))
}

func TestHandleDeletion_ReturnsAnErrorListingTheNodes(t *testing.T) {
	cl := deleting(t)
	a := aggregation(cl, new(int))
	a.Client = errorOnList{cl}

	_, err := shared.HandleDeletion(t.Context(), a, get(t, cl))
	require.ErrorIs(t, err, errBoom)
}

// errorOnList is a client whose lists fail.
type errorOnList struct{ client.Client }

func (errorOnList) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errBoom
}

func TestNewControllerManagedBy(t *testing.T) {
	scheme := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	mgr := testutil.NewUnstartedManager(t, scheme)

	err := shared.NewControllerManagedBy(mgr, mgr.GetClient(), "test-aggregator", artifact.KindConfig,
		&artifactv1alpha1.Config{}, func() client.ObjectList { return &artifactv1alpha1.ConfigList{} }, nil).
		Complete(reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}))

	require.NoError(t, err)
}

// Every read and write of the reconcile fails it with the error.
func TestReconcile_Errors(t *testing.T) {
	for name, tt := range map[string]struct {
		funcs        interceptor.Funcs
		metadataErr  error
		failPatchAt  int // fail the nth status write (from 1); 0 never
		withMetadata bool
	}{
		"listing the nodes":           {funcs: testutil.FailListOf(&corev1.NodeList{}, errBoom)},
		"listing the Falco instances": {funcs: testutil.FailListOf(&instancev1alpha1.FalcoList{}, errBoom)},
		// One listing serves the finalizer, the desired nodes and what they report.
		"listing the ArtifactNodes":  {funcs: testutil.FailListOf(&artifactv1alpha1.ArtifactNodeList{}, errBoom)},
		"writing the finalizer":      {funcs: testutil.FailPatch(errBoom)},
		"writing the aggregate":      {failPatchAt: 1},
		"writing the metadata":       {withMetadata: true, failPatchAt: 1},
		"writing a metadata failure": {metadataErr: errors.New("metadata"), failPatchAt: 1},
	} {
		t.Run(name, func(t *testing.T) {
			cl := interceptor.NewClient(newClient(t, newConfig(), selectedNode()).(client.WithWatch), tt.funcs)
			var patches int
			a := aggregation(cl, &patches)
			a.HoldForSelectedNodes = true // the selected node asks for the finalizer
			patch := a.PatchStatus
			a.PatchStatus = func(ctx context.Context, c *artifactv1alpha1.Config) error {
				if patches+1 == tt.failPatchAt {
					patches++
					return errBoom
				}
				return patch(ctx, c)
			}
			if tt.withMetadata || tt.metadataErr != nil {
				a.Metadata = func(context.Context, *artifactv1alpha1.Config) error { return tt.metadataErr }
				a.MetadataFailedMessage = "%s"
			}

			_, err := shared.Reconcile(t.Context(), testutil.Request(configName), a)

			require.ErrorIs(t, err, errBoom)
		})
	}
}

func TestHandleDeletion_ReturnsAnErrorAggregating(t *testing.T) {
	cl := deleting(t)
	a := aggregation(cl, new(int))
	a.AggregateOnDeletion = true
	a.Client = interceptor.NewClient(cl.(client.WithWatch), testutil.FailListOf(&artifactv1alpha1.ArtifactNodeList{}, errBoom))

	_, err := shared.HandleDeletion(t.Context(), a, get(t, cl))
	require.ErrorIs(t, err, errBoom)
}
