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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/plugin"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// The publisher writes the node's status only when the status it holds differs from what it last wrote, so a
// steady-state reconcile must leave the ArtifactNode untouched on a real API server: an unconditional write
// would bump the resourceVersion on every reconcile and wake every watcher of the object.
func TestIntegration_Plugin_SteadyStateReconcileIsQuiet(t *testing.T) {
	ctx := context.Background()
	p := create(t, ctx, &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "quiet", Namespace: testutil.TestNamespace},
	})
	// The instance operator has processed the current generation.
	p.Status.ObservedGeneration = p.Generation
	require.NoError(t, k8sClient.Status().Update(ctx, p))
	artifactNode := create(t, ctx, &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.ArtifactNodeSpec{
			NodeName:  testutil.TestNodeName,
			Artifacts: []artifactv1alpha1.NodeArtifactRef{{Kind: "Plugin", Name: p.Name, UID: string(p.UID)}},
		},
	})
	n := newTestNode(t)
	r := plugin.NewPluginReconciler(k8sClient, events.NewFakeRecorder(100), n)

	_, err := r.Reconcile(ctx, testutil.Request(p.Name))
	require.NoError(t, err)
	testutil.RequirePublishedWhere(t, k8sClient, "Plugin", p.Name, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.FindStatusCondition(e.Conditions, commonv1alpha1.ConditionProgrammed.String()) != nil
	})

	settled := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(artifactNode), settled))
	for range 5 {
		_, err = r.Reconcile(ctx, testutil.Request(p.Name))
		require.NoError(t, err)
	}
	// The publisher coalesces for a moment: give it time to write, were it going to.
	require.Never(t, func() bool {
		cur := &artifactv1alpha1.ArtifactNode{}
		return k8sClient.Get(ctx, client.ObjectKeyFromObject(artifactNode), cur) != nil ||
			cur.ResourceVersion != settled.ResourceVersion
	}, 700*time.Millisecond, 50*time.Millisecond, "an unchanged status must not be written again")
}

// The reconciler wired to a real manager, through the watches registered by SetupWithManager: the Plugin, its
// assignment on the node, a change of Falco's versions, and the removal the node controller asks for.
func TestIntegration_Plugin_TheWatchesDriveTheReconciler(t *testing.T) {
	ctx := context.Background() // t.Context() ends before the cleanups that use it run
	n := newTestNode(t)
	r := plugin.NewPluginReconciler(k8sClient, events.NewFakeRecorder(100), n)
	versions := make(chan event.GenericEvent)
	testutil.StartManager(t, restConfig, k8sClient.Scheme(), func(mgr ctrl.Manager) error {
		r.Client = mgr.GetClient()
		return r.SetupWithManager(mgr, versions)
	})
	reported := func(name string) bool {
		artifactNode := &artifactv1alpha1.ArtifactNode{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: testutil.TestNamespace, Name: testutil.TestNodeName}, artifactNode); err != nil {
			return false
		}
		for _, e := range artifactNode.Status.Artifacts {
			if e.Kind == "Plugin" && e.Name == name {
				return true
			}
		}
		return false
	}

	p := create(t, ctx, &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "wired", Namespace: testutil.TestNamespace}})
	p.Status.ObservedGeneration = p.Generation
	require.NoError(t, k8sClient.Status().Update(ctx, p))

	// Assigned to the node: reconciled and reported.
	artifactNode := create(t, ctx, &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.ArtifactNodeSpec{
			NodeName:  testutil.TestNodeName,
			Artifacts: []artifactv1alpha1.NodeArtifactRef{{Kind: "Plugin", Name: p.Name, UID: string(p.UID)}},
		},
	})
	require.Eventually(t, func() bool { return reported(p.Name) }, 15*time.Second, 50*time.Millisecond)

	// Falco's versions changed: what the node assigns is reconciled again.
	select {
	case versions <- event.GenericEvent{Object: p}:
	case <-time.After(15 * time.Second):
		t.Fatal("the reconciler does not consume the versions channel")
	}

	// The node controller asks for the removal of what the node holds for an artifact nothing lists.
	orphan := artifact.Ref{Kind: artifact.KindPlugin, Name: "orphan"}
	orphanPlugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: orphan.Name, UID: "orphan-uid"},
		Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}},
	}
	require.NoError(t, n.ApplyArtifact(ctx, orphanPlugin, &artifactv1alpha1.NodeArtifactStatus{}))
	require.NotEmpty(t, n.GetInstalled(orphan))
	require.NoError(t, n.RequestRemoval(ctx, orphan))
	require.Eventually(t, func() bool { return len(n.GetInstalled(orphan)) == 0 }, 15*time.Second, 50*time.Millisecond,
		"the removal asked for reaches the reconciler")

	// The ArtifactNode stops listing the Plugin: its entry is withdrawn.
	latest := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(artifactNode), latest))
	latest.Spec.Artifacts = nil
	require.NoError(t, k8sClient.Update(ctx, latest))
	require.Eventually(t, func() bool { return !reported(p.Name) }, 15*time.Second, 50*time.Millisecond,
		"what the ArtifactNode stops listing is withdrawn")
}
