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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
	"github.com/falcosecurity/falco-operator/internal/testutil"
	"github.com/falcosecurity/falco-operator/internal/testutil/nodetest"
)

// What the node holds and its ArtifactNode does not assign is asked to be removed, and nothing is removed here.
func TestReconcile(t *testing.T) {
	const (
		rulesfile = artifact.KindRulesfile
		config    = artifact.KindConfig
		plugin    = artifact.KindPlugin
	)
	tests := []struct {
		name          string
		artifactNode  *artifactv1alpha1.ArtifactNode // nil: there is none
		installed     []string                       // config files on the disk
		reported      []artifact.Ref                 // entries without files
		wantRequested []string
		wantResult    ctrl.Result
		wantGone      bool // the ArtifactNode does not exist afterwards
		wantFinalizer bool // ... or holds the sidecar's finalizer
	}{
		{name: "an idle node with no ArtifactNode needs nothing"},
		{
			name:          "no ArtifactNode: everything installed is an orphan",
			installed:     []string{"b", "a"},
			wantRequested: []string{"Config/a", "Config/b"},
		},
		{
			name:          "no ArtifactNode: orphans of every kind",
			reported:      []artifact.Ref{key(plugin, "p"), key(rulesfile, "r"), key(config, "c")},
			wantRequested: []string{"Rulesfile/r", "Config/c", "Plugin/p"},
		},
		{
			name:          "everything installed is listed",
			artifactNode:  listing(configRef("a"), configRef("b")),
			installed:     []string{"a", "b"},
			wantFinalizer: true,
		},
		{
			name:          "what the spec does not list is asked for",
			artifactNode:  listing(configRef("kept")),
			installed:     []string{"kept", "gone"},
			wantRequested: []string{"Config/gone"},
			wantFinalizer: true,
		},
		{
			name:          "an entry that never had files is asked for like any other",
			artifactNode:  listing(),
			reported:      []artifact.Ref{key(rulesfile, "ghost")},
			wantRequested: []string{"Rulesfile/ghost"},
			wantFinalizer: true,
		},
		{
			name:          "an entry the ArtifactNode itself reports is asked for when it is not listed",
			artifactNode:  reporting(listing(), artifactv1alpha1.NodeArtifactStatus{Kind: "Rulesfile", Name: "left-over", UID: "u"}),
			wantRequested: []string{"Rulesfile/left-over"},
			wantFinalizer: true,
		},
		{
			name: "an artifact listed with another uid is still assigned",
			artifactNode: listing(artifactv1alpha1.NodeArtifactRef{
				Kind: "Config", Name: "recreated", UID: "new-uid",
			}),
			installed:     []string{"recreated"},
			wantFinalizer: true,
		},
		{
			name:          "the finalizer is put on an ArtifactNode that has none",
			artifactNode:  unfinalized(listing(configRef("a"))),
			installed:     []string{"a"},
			wantFinalizer: true,
		},
		{
			name:          "being deleted: everything is asked for, and the finalizer stays while something is left",
			artifactNode:  deleting(listing(configRef("assigned"))),
			installed:     []string{"assigned", "other"},
			wantRequested: []string{"Config/assigned", "Config/other"},
			wantResult:    ctrl.Result{RequeueAfter: finalizePollDelay},
			wantFinalizer: true,
		},
		{
			name:         "being deleted with nothing left: the finalizer is released",
			artifactNode: deleting(listing(configRef("assigned"))),
			wantGone:     true,
		},
		{
			name: "being deleted, and not held by the sidecar: left alone",
			artifactNode: deleting(func() *artifactv1alpha1.ArtifactNode {
				an := listing()
				an.Finalizers = []string{"someone-else/finalizer"}
				return an
			}()),
			installed:     []string{"installed"},
			wantFinalizer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if tt.artifactNode != nil {
				objs = append(objs, tt.artifactNode)
			}
			f := newFixture(t, nil, objs...)
			f.install(t, tt.installed...)
			for _, k := range tt.reported {
				f.report(k.Kind, k.Name)
			}

			result, err := f.reconcile(t)

			require.NoError(t, err)
			assert.Equal(t, tt.wantResult, result)
			assert.Equal(t, tt.wantRequested, f.requested())
			if tt.artifactNode == nil {
				return
			}
			_, exists := f.artifactNodeNow(t)
			assert.Equal(t, !tt.wantGone, exists)
			assert.Equal(t, tt.wantFinalizer, f.finalizerHeld(t))
		})
	}
}

// Removing many artifacts at once is what a wrongly short assignment would look like, so it must be visible.
func TestReconcile_AWideRemovalIsReported(t *testing.T) {
	tests := []struct {
		name       string
		stale      int
		wantEvents int
	}{
		{"just under the threshold", bulkRemovalThreshold - 1, 0},
		{"at the threshold", bulkRemovalThreshold, 1},
		{"well over it", 3 * bulkRemovalThreshold, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, nil, listing())
			for i := range tt.stale {
				f.install(t, fmt.Sprintf("c-%02d", i))
			}

			_, err := f.reconcile(t)

			require.NoError(t, err)
			require.Len(t, f.recorder.Events, tt.wantEvents)
			if tt.wantEvents > 0 {
				assert.Contains(t, <-f.recorder.Events, ReasonBulkRemoval)
			}
			assert.Len(t, f.requested(), tt.stale)
		})
	}
}

// What cannot be removed yet, plugins a Rulesfile requires, is still held and unlisted at every later reconcile.
// It is one removal, reported once.
func TestReconcile_AWideRemovalThatLingersIsReportedOnce(t *testing.T) {
	f := newFixture(t, nil, listing())
	for i := range bulkRemovalThreshold {
		f.install(t, fmt.Sprintf("c-%02d", i))
	}

	for range 3 {
		_, err := f.reconcile(t)
		require.NoError(t, err)
	}

	assert.Len(t, f.recorder.Events, 1)
}

// The per-artifact reconcilers remove what the spec no longer lists as soon as they see it, so a wide drop from the
// spec is reported even when the node holds little or none of it any more, and even when the ArtifactNode is already
// being deleted. It is reported once, not on every later reconcile.
func TestReconcile_AWideDropFromTheSpecIsReported(t *testing.T) {
	tests := []struct {
		name       string
		dropped    int
		held       int
		deleting   bool
		wantEvents int
	}{
		{"just under the threshold, nothing held", bulkRemovalThreshold - 1, 0, false, 0},
		{"at the threshold, nothing held", bulkRemovalThreshold, 0, false, 1},
		{"at the threshold, some held", bulkRemovalThreshold, 3, false, 1},
		{"at the threshold, being deleted", bulkRemovalThreshold, 0, true, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := make([]artifactv1alpha1.NodeArtifactRef, tt.dropped)
			for i := range refs {
				refs[i] = configRef(fmt.Sprintf("c-%02d", i))
			}
			f := newFixture(t, nil, listing(refs...))
			_, err := f.reconcile(t)
			require.NoError(t, err)
			require.Empty(t, f.recorder.Events)
			for i := range tt.held {
				f.install(t, refs[i].Name)
			}

			an, _ := f.artifactNodeNow(t)
			an.Spec.Artifacts = nil
			require.NoError(t, f.cl.Update(t.Context(), an))
			if tt.deleting {
				require.NoError(t, f.cl.Delete(t.Context(), an))
			}
			// The per-artifact reconcilers get to all but the held ones first.
			f.forget(t, refs[tt.held:]...)
			_, err = f.reconcile(t)
			require.NoError(t, err)
			require.Len(t, f.recorder.Events, tt.wantEvents)
			if tt.wantEvents > 0 {
				assert.Contains(t, <-f.recorder.Events, ReasonBulkRemoval)
			}

			f.forget(t, refs[:tt.held]...)
			_, err = f.reconcile(t)
			require.NoError(t, err)
			assert.Empty(t, f.recorder.Events)
		})
	}
}

// Deleting an ArtifactNode removes everything the node holds, although its spec still lists it all: nothing was
// dropped from the spec, and it is a bulk removal all the same. It is reported once, not on every poll.
func TestReconcile_TheDeletionOfAnArtifactNodeHoldingManyIsReported(t *testing.T) {
	tests := []struct {
		name       string
		held       int
		wantEvents int
	}{
		{"just under the threshold", bulkRemovalThreshold - 1, 0},
		{"at the threshold", bulkRemovalThreshold, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := make([]artifactv1alpha1.NodeArtifactRef, tt.held)
			for i := range refs {
				refs[i] = configRef(fmt.Sprintf("c-%02d", i))
			}
			f := newFixture(t, nil, listing(refs...))
			for i := range refs {
				f.install(t, refs[i].Name)
			}
			_, err := f.reconcile(t)
			require.NoError(t, err)
			require.Empty(t, f.recorder.Events, "everything held is assigned")

			an, _ := f.artifactNodeNow(t)
			require.NoError(t, f.cl.Delete(t.Context(), an))
			_, err = f.reconcile(t)
			require.NoError(t, err)
			require.Len(t, f.recorder.Events, tt.wantEvents)
			if tt.wantEvents > 0 {
				assert.Contains(t, <-f.recorder.Events, ReasonBulkRemoval)
			}

			_, err = f.reconcile(t)
			require.NoError(t, err)
			assert.Empty(t, f.recorder.Events, "the next poll does not warn again")
		})
	}
}

// While the ArtifactNode is being deleted the reconcilers do the removing, and the finalizer is released once they
// have. Every poll asks again for everything still held: the workqueue behind the removal channel coalesces the
// requests naming the same artifact, and asking again is what recovers a request a full channel refused.
func TestReconcile_TheEndOfADeletion(t *testing.T) {
	type step struct {
		install       []string
		uninstall     []string
		wantRequested []string
		wantResult    ctrl.Result
		wantGone      bool
	}
	poll := ctrl.Result{RequeueAfter: finalizePollDelay}
	tests := []struct {
		name  string
		start []string
		steps []step
	}{
		{
			name:  "asked on every poll, released when empty",
			start: []string{"a", "b"},
			steps: []step{
				{wantRequested: []string{"Config/a", "Config/b"}, wantResult: poll},
				// Nothing has been removed yet, so the same two are asked for again.
				{wantRequested: []string{"Config/a", "Config/b"}, wantResult: poll},
				{uninstall: []string{"a"}, wantRequested: []string{"Config/b"}, wantResult: poll},
				// Nothing is held any more: the finalizer goes and nothing is asked for.
				{uninstall: []string{"b"}, wantGone: true},
			},
		},
		{
			name:  "what shows up later is asked for too",
			start: []string{"a"},
			steps: []step{
				{wantRequested: []string{"Config/a"}, wantResult: poll},
				{install: []string{"b"}, wantRequested: []string{"Config/a", "Config/b"}, wantResult: poll},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, nil, deleting(listing()))
			f.install(t, tt.start...)

			for i, s := range tt.steps {
				f.install(t, s.install...)
				f.uninstall(t, s.uninstall...)

				result, err := f.reconcile(t)

				require.NoError(t, err, "step %d", i)
				assert.Equal(t, s.wantResult, result, "step %d", i)
				assert.Equal(t, s.wantRequested, f.requested(), "step %d", i)
				_, exists := f.artifactNodeNow(t)
				assert.Equal(t, !s.wantGone, exists, "step %d", i)
			}
		})
	}
}

// A finalizer write can conflict with the operator's own write of the object, which the cache had not shown yet: it
// is retried shortly and is not an error. An object that is gone leaves nothing to do.
func TestReconcile_RejectedFinalizerWritesAreRetriedWithoutError(t *testing.T) {
	tests := []struct {
		name        string
		funcs       interceptor.Funcs
		node        *artifactv1alpha1.ArtifactNode
		wantRequeue time.Duration
	}{
		{"adding the finalizer conflicts", testutil.FailPatch(errConflict), unfinalized(listing()), controllerhelper.StaleCacheRetryDelay},
		{"adding the finalizer finds the object gone", testutil.FailPatch(errNotFound), unfinalized(listing()), 0},
		{"releasing the finalizer conflicts", testutil.FailPatch(errConflict), deleting(listing()), controllerhelper.StaleCacheRetryDelay},
		{"releasing the finalizer finds the object gone", testutil.FailPatch(errNotFound), deleting(listing()), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, &tt.funcs, tt.node)

			result, err := f.reconcile(t)

			require.NoError(t, err)
			assert.Equal(t, tt.wantRequeue, result.RequeueAfter)
		})
	}
}

func TestReconcile_ReturnsAPIErrors(t *testing.T) {
	fullBuffer := func(f *fixture, kind artifact.Kind) {
		for range 2 * artifactv1alpha1.MaxNodeArtifacts {
			require.NoError(t, f.node.RequestRemoval(t.Context(), key(kind, "x")))
		}
	}
	tests := []struct {
		name         string
		funcs        interceptor.Funcs
		artifactNode *artifactv1alpha1.ArtifactNode
		installed    []string
		prepare      func(*fixture) // runs before the reconcile
		canceled     bool           // the context is already done
	}{
		{name: "getting the ArtifactNode", funcs: testutil.FailGet(errBoom)},
		{name: "adding the finalizer", funcs: testutil.FailPatch(errBoom), artifactNode: unfinalized(listing())},
		{name: "releasing the finalizer", funcs: testutil.FailPatch(errBoom), artifactNode: deleting(listing())},
		{
			name: "asking for a removal of what the spec does not list", artifactNode: listing(), installed: []string{"gone"}, canceled: true,
			prepare: func(f *fixture) { fullBuffer(f, artifact.KindConfig) },
		},
		{
			name: "asking for the removal of orphans", installed: []string{"orphan"}, canceled: true,
			prepare: func(f *fixture) { fullBuffer(f, artifact.KindConfig) },
		},
		{
			name: "asking for the removal of everything, for a deleted ArtifactNode", artifactNode: deleting(listing()), installed: []string{"gone"},
			canceled: true, prepare: func(f *fixture) { fullBuffer(f, artifact.KindConfig) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if tt.artifactNode != nil {
				objs = append(objs, tt.artifactNode)
			}
			f := newFixture(t, &tt.funcs, objs...)
			f.install(t, tt.installed...)
			if tt.prepare != nil {
				tt.prepare(f)
			}
			ctx := t.Context()
			if tt.canceled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			_, err := f.r.Reconcile(ctx, testutil.Request(testutil.TestNodeName))

			require.Error(t, err)
		})
	}
}

// The startup reconcile of a node with files and no ArtifactNode only finds the orphans once the warm sync has
// recovered them, so it waits for it.
func TestReconcile_WaitsForTheWarmSync(t *testing.T) {
	f := newFixture(t, nil)
	f.install(t, "orphan")
	warmSync := node.NewWarmSyncRunnable(f.node)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := f.r.Reconcile(ctx, testutil.Request(testutil.TestNodeName))
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, nodetest.RemovalsRequested(f.node))

	require.NoError(t, warmSync.Warmup(t.Context()))
	_, err = f.reconcile(t)
	require.NoError(t, err)
	assert.Equal(t, []string{"Config/orphan"}, nodetest.RemovalsRequested(f.node))
}
