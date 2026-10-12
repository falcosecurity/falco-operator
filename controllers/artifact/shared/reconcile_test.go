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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
	"github.com/falcosecurity/falco-operator/internal/testutil"
	"github.com/falcosecurity/falco-operator/internal/testutil/nodetest"
)

var errBoom = errors.New("boom")

// cfgKey identifies the Config named "cfg" the tests install.
var cfgKey = artifact.Ref{Kind: artifact.KindConfig, Name: "cfg"}

// ensureEntry gives the node a status entry for the artifact, as it holds one from before an install.
func ensureEntry(t *testing.T, n *node.Node, key artifact.Ref, uid string, conditions []metav1.Condition) {
	t.Helper()
	obj := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: n.Namespace(), Name: key.Name, UID: types.UID(uid)}}
	n.PublishStatus(key.Kind, obj, &artifactv1alpha1.NodeArtifactStatus{Conditions: conditions})
}

func TestReconcileArtifact(t *testing.T) {
	const name = "cfg"
	config := func(mods ...func(*artifactv1alpha1.Config)) *artifactv1alpha1.Config {
		c := &artifactv1alpha1.Config{ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: name, UID: "uid-new"}}
		for _, mod := range mods {
			mod(c)
		}
		return c
	}
	deleting := func(c *artifactv1alpha1.Config) {
		now := metav1.Now()
		c.DeletionTimestamp = &now
		c.Finalizers = []string{"test/finalizer"}
	}
	listing := func(uid string) *artifactv1alpha1.ArtifactNode {
		artifactNode := testutil.NewTestArtifactNode()
		artifactNode.Spec.Artifacts = []artifactv1alpha1.NodeArtifactRef{{Kind: "Config", Name: name, UID: uid}}
		return artifactNode
	}
	failing := func(kind string) interceptor.Funcs {
		return interceptor.Funcs{Get: func(
			ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
		) error {
			switch obj.(type) {
			case *artifactv1alpha1.Config:
				if kind == "Config" {
					return errBoom
				}
			case *artifactv1alpha1.ArtifactNode:
				if kind == "ArtifactNode" {
					return errBoom
				}
			}
			return cl.Get(ctx, key, obj, opts...)
		}}
	}

	tests := []struct {
		name string
		// objects the API server holds.
		objects []client.Object
		funcs   interceptor.Funcs
		// held puts a file on the node; entryUID, when set, gives the publisher an entry with that uid.
		held         bool
		entryUID     string
		cleanupErr   error
		installError error

		wantResult    reconcile.Result
		wantErr       error
		wantCleanups  int
		wantInstalled bool
		wantHeld      bool
	}{
		{
			name:     "gone and still listed: nothing is removed",
			objects:  []client.Object{listing("uid-old")},
			held:     true,
			wantHeld: true,
		},
		{
			name:         "gone and no longer listed: what the node holds is removed",
			objects:      []client.Object{testutil.NewTestArtifactNode()},
			held:         true,
			wantCleanups: 1,
		},
		{
			name:         "gone and no ArtifactNode: what the node holds is removed",
			held:         true,
			wantCleanups: 1,
		},
		{
			name:    "gone and never held: nothing to do",
			objects: []client.Object{testutil.NewTestArtifactNode()},
		},
		{
			name:         "gone and cleanup fails",
			objects:      []client.Object{testutil.NewTestArtifactNode()},
			held:         true,
			cleanupErr:   errBoom,
			wantErr:      errBoom,
			wantCleanups: 1,
			wantHeld:     true,
		},
		{
			name:    "the artifact cannot be read",
			objects: []client.Object{config(), listing("uid-new")},
			funcs:   failing("Config"),
			wantErr: errBoom,
		},
		{
			name:         "being deleted and no longer listed: what the node holds is removed",
			objects:      []client.Object{config(deleting), testutil.NewTestArtifactNode()},
			held:         true,
			wantCleanups: 1,
		},
		{
			name:     "being deleted and still listed: nothing is removed",
			objects:  []client.Object{config(deleting), listing("uid-new")},
			held:     true,
			wantHeld: true,
		},
		{
			name:    "the ArtifactNode cannot be read",
			objects: []client.Object{config()},
			funcs:   failing("ArtifactNode"),
			wantErr: errBoom,
		},
		{
			name:         "not assigned and held: removed",
			objects:      []client.Object{config(), testutil.NewTestArtifactNode()},
			held:         true,
			wantCleanups: 1,
		},
		{
			name:    "not assigned and not held: nothing to do",
			objects: []client.Object{config(), testutil.NewTestArtifactNode()},
		},
		{
			name:         "no ArtifactNode: removed",
			objects:      []client.Object{config()},
			held:         true,
			wantCleanups: 1,
		},
		{
			name:         "not assigned, and cleanup fails",
			objects:      []client.Object{config(), testutil.NewTestArtifactNode()},
			held:         true,
			cleanupErr:   errBoom,
			wantErr:      errBoom,
			wantCleanups: 1,
			wantHeld:     true,
		},
		{
			name:         "not assigned, and cleanup is blocked: retried later",
			objects:      []client.Object{config(), testutil.NewTestArtifactNode()},
			held:         true,
			cleanupErr:   &node.BlockedError{},
			wantResult:   reconcile.Result{RequeueAfter: shared.BlockedRetryDelay},
			wantCleanups: 1,
			wantHeld:     true,
		},
		{
			name:       "assigned for another incarnation: waits for the operator",
			objects:    []client.Object{config(), listing("uid-old")},
			held:       true,
			wantResult: reconcile.Result{RequeueAfter: shared.AssignmentRetryDelay},
			wantHeld:   true,
		},
		{
			name:          "assigned: installs",
			objects:       []client.Object{config(), listing("uid-new")},
			wantInstalled: true,
		},
		{
			name:          "assigned, and the install result is passed on",
			objects:       []client.Object{config(), listing("uid-new")},
			installError:  errBoom,
			wantErr:       errBoom,
			wantInstalled: true,
		},
		{
			name:          "assigned with an entry of this incarnation: no cleanup",
			objects:       []client.Object{config(), listing("uid-new")},
			held:          true,
			entryUID:      "uid-new",
			wantInstalled: true,
			wantHeld:      true,
		},
		{
			name:          "assigned with an entry of an earlier incarnation: cleaned up first",
			objects:       []client.Object{config(), listing("uid-new")},
			held:          true,
			entryUID:      "uid-old",
			wantCleanups:  1,
			wantInstalled: true,
		},
		{
			name:          "assigned with an entry of an earlier incarnation that cannot go yet: takes it over",
			objects:       []client.Object{config(), listing("uid-new")},
			held:          true,
			entryUID:      "uid-old",
			cleanupErr:    &node.BlockedError{Name: name},
			wantCleanups:  1,
			wantInstalled: true,
			wantHeld:      true,
		},
		{
			name:         "assigned with an entry of an earlier incarnation, and cleanup fails: does not install",
			objects:      []client.Object{config(), listing("uid-new")},
			held:         true,
			entryUID:     "uid-old",
			cleanupErr:   errBoom,
			wantErr:      errBoom,
			wantCleanups: 1,
			wantHeld:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
				WithObjects(tt.objects...).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).WithInterceptorFuncs(tt.funcs).Build()
			m := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil)
			key := cfgKey
			if tt.held {
				nodetest.InstallConfig(t, cl, m, name)
			}
			if tt.entryUID != "" {
				ensureEntry(t, m, key, tt.entryUID, nil)
			}
			cleanups, installed := 0, false
			cleanup := func(ctx context.Context, n string) error {
				cleanups++
				assert.Equal(t, name, n)
				if tt.cleanupErr != nil {
					return tt.cleanupErr
				}
				err := m.Remove(ctx, key)
				return err
			}
			install := func(_ context.Context, parent artifactv1alpha1.Artifact, status *artifactv1alpha1.NodeArtifactStatus) (reconcile.Result, error) {
				installed = true
				assert.Equal(t, name, parent.GetName())
				// The flow continues from this incarnation's entry: no conditions yet, and whatever files the node holds.
				assert.Equal(t, []string{"Config", name, "uid-new"}, []string{string(status.Kind), status.Name, status.UID})
				assert.Empty(t, status.Conditions)
				return reconcile.Result{}, tt.installError
			}
			req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: testutil.TestNamespace, Name: name}}

			result, err := shared.ReconcileArtifactWith(t.Context(), cl, m, req, &artifactv1alpha1.Config{}, cleanup, install)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantResult, result)
			assert.Equal(t, tt.wantCleanups, cleanups, "cleanups")
			assert.Equal(t, tt.wantInstalled, installed, "installed")
			assert.Equal(t, tt.wantHeld, m.Holds(key), "held")
		})
	}
}

// An artifact that is no longer assigned and never had a file still has the entry reserved for it. The entry goes
// whatever the cleanup does about files: left behind, it would hold the artifact's finalizer for good.
func TestReconcileArtifact_WithdrawsTheEntryOfAnUnassignedArtifactThatNeverHadAFile(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	m := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil)
	ensureEntry(t, m, cfgKey, "uid", nil)
	require.True(t, m.Holds(cfgKey))
	nothingToRemove := func(context.Context, string) error { return nil }
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: testutil.TestNamespace, Name: cfgKey.Name}}

	_, err := shared.ReconcileArtifactWith(t.Context(), cl, m, req, &artifactv1alpha1.Config{}, nothingToRemove, nil)

	require.NoError(t, err)
	assert.False(t, m.Holds(cfgKey))
}

func TestReconcileArtifact_StartsFromTheEntryOfTheSameIncarnation(t *testing.T) {
	artifactNode := testutil.NewTestArtifactNode()
	artifactNode.Spec.Artifacts = []artifactv1alpha1.NodeArtifactRef{{Kind: "Config", Name: "cfg", UID: "uid"}}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(&artifactv1alpha1.Config{ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: "cfg", UID: "uid"}}, artifactNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	m := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil)
	condition := metav1.Condition{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Ok", LastTransitionTime: metav1.NewTime(time.Unix(1, 0))}
	ensureEntry(t, m, cfgKey, "uid", []metav1.Condition{condition})
	var got *artifactv1alpha1.NodeArtifactStatus

	_, err := shared.ReconcileArtifactWith(t.Context(), cl, m,
		reconcile.Request{NamespacedName: types.NamespacedName{Namespace: testutil.TestNamespace, Name: "cfg"}},
		&artifactv1alpha1.Config{}, func(context.Context, string) error { return nil },
		func(_ context.Context, _ artifactv1alpha1.Artifact, status *artifactv1alpha1.NodeArtifactStatus) (reconcile.Result, error) {
			got = status
			return reconcile.Result{}, nil
		})

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "Programmed", got.Conditions[0].Type)
}

func TestRemove(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil)
	nodetest.InstallConfig(t, cl, n, "cfg")
	require.NotEmpty(t, n.GetInstalled(cfgKey))

	require.NoError(t, shared.Remove(t.Context(), n, artifact.KindConfig, "cfg"))
	assert.Empty(t, n.GetInstalled(cfgKey), "what the node held is removed")
	require.NoError(t, shared.Remove(t.Context(), n, artifact.KindConfig, "cfg"), "a removal is idempotent")
}

func TestAssignedRequests(t *testing.T) {
	artifactNode := testutil.NewTestArtifactNode()
	artifactNode.Spec.Artifacts = []artifactv1alpha1.NodeArtifactRef{
		{Kind: "Config", Name: "a"}, {Kind: "Rulesfile", Name: "r"}, {Kind: "Config", Name: "b"},
	}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(artifactNode).Build()
	n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil)

	got := shared.AssignedRequests(cl, n, artifact.KindConfig)(t.Context(), nil)

	assert.ElementsMatch(t, []reconcile.Request{testutil.Request("a"), testutil.Request("b")}, got,
		"every artifact of the kind the node's ArtifactNode assigns, and nothing else")
}

// The gate takes the generation the instance operator processed only in enforce mode: in advise mode the artifact
// is programmed against its own generation.
// Programmed waits for the instance operator to observe the generation, except for an artifact that declares
// requirements on a node that only advises on them.
func TestApplyAndPublish(t *testing.T) {
	for _, tt := range []struct {
		enforce, declaresRequirements bool
		wantProgramed                 metav1.ConditionStatus
	}{
		{enforce: true, declaresRequirements: true, wantProgramed: metav1.ConditionUnknown},
		{enforce: false, declaresRequirements: true, wantProgramed: metav1.ConditionTrue},
		{enforce: true, declaresRequirements: false, wantProgramed: metav1.ConditionUnknown},
		{enforce: false, declaresRequirements: false, wantProgramed: metav1.ConditionUnknown},
	} {
		t.Run(fmt.Sprintf("enforce=%t/declaresRequirements=%t", tt.enforce, tt.declaresRequirements), func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
				WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
			n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil,
				nodetest.WithFetcher(testutil.NewFakeFetcher(cl)), nodetest.WithEnforceRequirements(tt.enforce))
			// Generation 2, of which the instance operator has processed only the first. A Plugin is a kind that
			// declares requirements, a Config one that does not.
			meta := metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: "a", UID: "uid", Generation: 2}
			var parent artifactv1alpha1.Artifact = &artifactv1alpha1.Config{
				ObjectMeta: meta,
				Spec:       artifactv1alpha1.ConfigSpec{Config: &apiextensionsv1.JSON{Raw: []byte(`{"a":"b"}`)}, Priority: 50},
				Status:     artifactv1alpha1.ConfigStatus{ObservedGeneration: 1},
			}
			if tt.declaresRequirements {
				parent = &artifactv1alpha1.Plugin{
					ObjectMeta: meta,
					Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}},
					Status:     artifactv1alpha1.PluginStatus{ObservedGeneration: 1},
				}
			}
			status := &artifactv1alpha1.NodeArtifactStatus{}

			result, err := shared.ApplyAndPublish(t.Context(), n, parent, status)

			require.NoError(t, err)
			assert.Equal(t, reconcile.Result{}, result)
			programmed := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionProgrammed.String())
			require.NotNil(t, programmed)
			assert.Equal(t, tt.wantProgramed, programmed.Status)
			entry, held := n.StatusEntry(parent.GetArtifactKind(), "a")
			require.True(t, held, "the status is published")
			assert.Equal(t, status.Conditions, entry.Conditions)
		})
	}
}

func TestRemove_ReportsWhatCannotBeRemoved(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	fs := fsfake.NewMockFileSystem()
	n := nodetest.NewTestNodeOn(t, cl, fs, nil)
	nodetest.InstallConfig(t, cl, n, "cfg")
	fs.RemoveErr = errBoom

	require.ErrorIs(t, shared.Remove(t.Context(), n, artifact.KindConfig, "cfg"), errBoom)
	assert.NotEmpty(t, n.GetInstalled(cfgKey), "what could not be removed is still held")
}

// A failed flow still publishes its status. A transient fetch failure requeues without an error; any other
// failure is returned.
func TestApplyAndPublish_Failures(t *testing.T) {
	for name, tt := range map[string]struct {
		fetchErr    error
		wantErr     error
		wantRequeue bool
	}{
		"a transient fetch failure requeues": {
			fetchErr:    &artifact.RetryableError{Err: errBoom, RetryAfter: time.Second},
			wantRequeue: true,
		},
		"any other failure is returned": {fetchErr: errBoom, wantErr: errBoom},
	} {
		t.Run(name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
				WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
			fetcher := testutil.NewFakeFetcher(cl)
			fetcher.OCIErr = tt.fetchErr
			n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil, nodetest.WithFetcher(fetcher))
			plugin := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: "p", UID: "uid", Generation: 1},
				Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}},
				Status:     artifactv1alpha1.PluginStatus{ObservedGeneration: 1},
			}
			status := &artifactv1alpha1.NodeArtifactStatus{}

			result, err := shared.ApplyAndPublish(t.Context(), n, plugin, status)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantRequeue, result.RequeueAfter > 0, "requeue")
			programmed := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionProgrammed.String())
			require.NotNil(t, programmed)
			assert.NotEqual(t, metav1.ConditionTrue, programmed.Status)
			_, held := n.StatusEntry(artifact.KindPlugin, "p")
			assert.True(t, held, "the status is published on the failure path too")
		})
	}
}

// Until the warm sync has run, the node does not know what it holds, so a reconcile waits for it.
func TestReconcileArtifact_WaitsForTheWarmSync(t *testing.T) {
	config := &artifactv1alpha1.Config{ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: "cfg", UID: "uid"}}
	artifactNode := testutil.NewTestArtifactNode()
	artifactNode.Spec.Artifacts = []artifactv1alpha1.NodeArtifactRef{{Kind: "Config", Name: "cfg", UID: "uid"}}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(config, artifactNode).WithStatusSubresource(artifactNode).Build()
	n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil)
	warmSync := node.NewWarmSyncRunnable(n)
	installs := 0
	install := func(context.Context, artifactv1alpha1.Artifact, *artifactv1alpha1.NodeArtifactStatus,
	) (reconcile.Result, error) { //nolint:unparam // the flow's result is not what this test is about
		installs++
		return reconcile.Result{}, nil
	}
	cleanup := func(context.Context, string) error { t.Fatal("nothing to clean up"); return nil }
	reconcileOnce := func(ctx context.Context) error {
		_, err := shared.ReconcileArtifactWith(ctx, cl, n, testutil.Request("cfg"), &artifactv1alpha1.Config{}, cleanup, install)
		return err
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, reconcileOnce(ctx), context.Canceled)
	assert.Zero(t, installs, "a reconcile ahead of the warm sync could install a file the scan then hides from every later removal")

	require.NoError(t, warmSync.Warmup(t.Context()))
	require.NoError(t, reconcileOnce(t.Context()))
	assert.Equal(t, 1, installs)
}

// TestApplyAndPublish_ClearsDeletionBlocked pins that a successful apply takes DeletionBlocked away.
// Nothing else ever clears it, so a plugin that was blocked from removal and is then assigned again
// would carry the condition forever; once its generation moves on, the stale condition makes
// ComputeProgrammedCondition report Programmed=Unknown/GenerationPending for good.
func TestApplyAndPublish_ClearsDeletionBlocked(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil, nodetest.WithFetcher(testutil.NewFakeFetcher(cl)))
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: "p", UID: "uid", Generation: 2},
		Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}},
		Status:     artifactv1alpha1.PluginStatus{ObservedGeneration: 2},
	}
	// What a blocked removal left behind, stamped with the generation of the time.
	status := &artifactv1alpha1.NodeArtifactStatus{Conditions: []metav1.Condition{{
		Type:               commonv1alpha1.ConditionDeletionBlocked.String(),
		Status:             metav1.ConditionTrue,
		Reason:             "PluginConfigStillRequired",
		Message:            `"p" is still required`,
		ObservedGeneration: 1,
		LastTransitionTime: metav1.Now(),
	}}}

	_, err := shared.ApplyAndPublish(t.Context(), n, plugin, status)

	require.NoError(t, err)
	assert.Nil(t, apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionDeletionBlocked.String()),
		"a successful apply means the artifact is installed, so it is not blocked from removal")
	programmed := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, programmed)
	assert.NotEqual(t, "GenerationPending", programmed.Reason,
		"a condition left by a removal must not pin Programmed on a generation nothing will re-evaluate")
}
