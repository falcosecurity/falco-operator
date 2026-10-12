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

package node

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// newWarmupNode is the Node of a warm-sync test, over cl.
func newWarmupNode(t *testing.T, cl client.Client) *Node {
	t.Helper()
	n, err := New(&Config{
		Fetcher:        &artifact.Fetcher{},
		Client:         cl,
		NodeName:       "minikube",
		Namespace:      "ns",
		FalcoBaseURL:   compat.DefaultBaseURL,
		ReloadCooldown: DefaultReloadCooldown,
		Store:          &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
		FalcoFetcher:   compatfake.NewMockVersionsFetcher(nil),
	})
	require.NoError(t, err)
	return n
}

func TestWarmSyncRunnable_Warmup_Succeeds(t *testing.T) {
	sch := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(sch).Build()

	r := NewWarmSyncRunnable(newWarmupNode(t, cl))
	require.NoError(t, r.Warmup(context.Background()))
}

func TestWarmSyncRunnable_Warmup_WrapsError(t *testing.T) {
	// A scheme with no types registered makes the underlying warm sync List fail immediately,
	// exercising Warmup's error-wrapping path.
	cl := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()

	r := NewWarmSyncRunnable(newWarmupNode(t, cl))
	err := r.Warmup(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "warm-sync node artifacts")
}

func TestWarmSyncRunnable_Start_ReturnsOnCancel(t *testing.T) {
	r := NewWarmSyncRunnable(newWarmupNode(t, fake.NewClientBuilder().Build()))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestNode_WaitWarmSync_IsImmediateForANodeWithoutTheRunnable(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).Build()
	n := newWarmupNode(t, cl)

	require.NoError(t, n.WaitWarmSync(t.Context()), "no warm sync is going to run, so there is nothing to wait for")
	require.NoError(t, n.checkWarmSynced(nil))
}

func TestNode_WaitWarmSync_WaitsForTheRunnable(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).Build()
	n := newWarmupNode(t, cl)
	r := NewWarmSyncRunnable(n)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, n.WaitWarmSync(ctx), context.DeadlineExceeded, "the reconcilers must not run ahead of the warm sync")
	require.Error(t, n.checkWarmSynced(nil), "the pod must not be Ready ahead of the warm sync")

	require.NoError(t, r.Warmup(t.Context()))
	require.NoError(t, n.WaitWarmSync(t.Context()))
	require.NoError(t, n.checkWarmSynced(nil))
	require.NoError(t, r.Warmup(t.Context()), "running the warm sync again is harmless")
}

// TestWarmSyncRunnable_NeedLeaderElection pins the invariant Node.AddToManager states: every runnable it
// registers is per-node and needs no leader election. Without the method, controller-runtime puts Start in
// the leader-election group, so on a sidecar run with leader election on only one node would run it.
func TestWarmSyncRunnable_NeedLeaderElection(t *testing.T) {
	assert.False(t, NewWarmSyncRunnable(newTestNode()).NeedLeaderElection())
}

// AddToManager is what makes the node work in a sidecar: it registers the node's runnables with the manager, and
// the warm sync the reconcilers wait for.
func TestNode_AddToManager(t *testing.T) {
	n := newTestNode()
	// The dir watcher watches the artifact directories for real, and Falco's own do not exist on a machine
	// without Falco.
	n.dirs = artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
	mgr := testutil.NewUnstartedManager(t, testutil.Scheme(t, artifactv1alpha1.AddToScheme))

	require.NoError(t, n.AddToManager(mgr))

	assert.NotNil(t, n.dirWatcher)
	require.NotNil(t, n.warmSync)
	require.Error(t, n.checkWarmSynced(nil), "registered, and not run yet")
}
