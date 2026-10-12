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

package envtest

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	sidecarnode "github.com/falcosecurity/falco-operator/controllers/artifact/artifactnode"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/testutil"
	"github.com/falcosecurity/falco-operator/internal/testutil/nodetest"
)

// The controller wired to a real manager and API server, through the watches and predicates registered by
// SetupWithManager: the reconcile asked for at startup when there is no ArtifactNode, the finalizer put on one
// that appears, the removal of what its spec stops listing, and the end of a deletion.
func TestIntegration_TheNodeIsKeptInLineWithItsArtifactNode(t *testing.T) {
	ctx := t.Context()
	store := newTestNode(t)
	nodetest.InstallConfig(t, k8sClient, store, "orphan")

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:  k8sClient.Scheme(),
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	require.NoError(t, err)
	r := sidecarnode.NewReconciler(mgr.GetClient(), mgr.GetEventRecorder(sidecarnode.ControllerName), store)
	require.NoError(t, r.SetupWithManager(mgr))
	mgrCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(mgrCtx) }()

	// asked collects, until it has exactly these, what has been asked of the reconcilers, however often.
	var seen []string
	asked := func(want ...string) {
		t.Helper()
		require.Eventually(t, func() bool {
			seen = append(seen, nodetest.RemovalsRequested(store)...)
			return slices.Equal(slices.Compact(slices.Sorted(slices.Values(seen))), want)
		}, 15*time.Second, 50*time.Millisecond, "asked for %v, want %v", seen, want)
		seen = nil
	}
	artifactNodeKey := client.ObjectKeyFromObject(testutil.NewTestArtifactNode())
	current := func() (*artifactv1alpha1.ArtifactNode, bool) {
		an := &artifactv1alpha1.ArtifactNode{}
		err := k8sClient.Get(ctx, artifactNodeKey, an)
		if k8serrors.IsNotFound(err) {
			return nil, false
		}
		require.NoError(t, err)
		return an, true
	}

	// A node with files and no ArtifactNode has no event to start from: the reconcile asked for at startup.
	asked("Config/orphan")

	// An ArtifactNode appears, listing what is installed but the orphan: it gets the finalizer, and the orphan is
	// asked for again.
	an := testutil.NewTestArtifactNode()
	an.Spec.Artifacts = []artifactv1alpha1.NodeArtifactRef{{Kind: "Config", Name: "kept", UID: "u"}}
	require.NoError(t, k8sClient.Create(ctx, an))
	nodetest.InstallConfig(t, k8sClient, store, "kept")
	require.Eventually(t, func() bool {
		latest, ok := current()
		return ok && slices.Contains(latest.Finalizers, controllerhelper.ArtifactNodeSidecarFinalizer)
	}, 15*time.Second, 50*time.Millisecond, "the sidecar's finalizer")
	asked("Config/orphan")

	// Its spec stops listing what is installed.
	latest, _ := current()
	latest.Spec.Artifacts = nil
	require.NoError(t, k8sClient.Update(ctx, latest))
	asked("Config/kept", "Config/orphan")

	// It is deleted: everything is asked for, and it stays while anything is left on the node.
	require.NoError(t, k8sClient.Delete(ctx, latest))
	asked("Config/kept", "Config/orphan")
	require.Never(t, func() bool { _, ok := current(); return !ok }, time.Second, 50*time.Millisecond,
		"the finalizer must hold the ArtifactNode while files are left")

	for _, name := range []string{"kept", "orphan"} {
		err := store.Remove(ctx, artifact.Ref{Kind: artifact.KindConfig, Name: name})
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { _, ok := current(); return !ok }, 15*time.Second, 50*time.Millisecond,
		"once nothing is left the finalizer is released")

	// Each poll asked again for whatever was still held, so the channel holds repeats of the two. They are
	// harmless, since the workqueue coalesces the requests naming the same artifact. Draining them leaves the
	// question that matters: with the ArtifactNode gone and the node holding nothing, no more are asked for.
	nodetest.RemovalsRequested(store)
	require.Never(t, func() bool { return len(nodetest.RemovalsRequested(store)) > 0 }, time.Second, 50*time.Millisecond,
		"nothing more is asked for once the ArtifactNode is gone and the node holds nothing")
}
