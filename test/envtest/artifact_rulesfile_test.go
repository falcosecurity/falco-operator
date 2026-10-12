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
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/rulesfile"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// The publisher writes the node's status only when the status it holds differs from what it last wrote, so a
// steady-state reconcile must leave the ArtifactNode untouched on a real API server: an unconditional write
// would bump the resourceVersion on every reconcile and wake every watcher of the object.
func TestIntegration_Rulesfile_SteadyStateReconcileIsQuiet(t *testing.T) {
	ctx := context.Background()
	rf := create(t, ctx, &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "quiet", Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.RulesfileSpec{
			InlineRules: &apiextensionsv1.JSON{Raw: []byte(`[{"rule":"r","desc":"d","condition":"always_true","output":"o","priority":"WARNING"}]`)},
		},
	})
	// The instance operator has processed the current generation.
	rf.Status.ObservedGeneration = rf.Generation
	require.NoError(t, k8sClient.Status().Update(ctx, rf))
	artifactNode := create(t, ctx, &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.ArtifactNodeSpec{
			NodeName:  testutil.TestNodeName,
			Artifacts: []artifactv1alpha1.NodeArtifactRef{{Kind: "Rulesfile", Name: rf.Name, UID: string(rf.UID)}},
		},
	})
	n := newTestNode(t)
	r := rulesfile.NewRulesfileReconciler(k8sClient, n)

	_, err := r.Reconcile(ctx, testutil.Request(rf.Name))
	require.NoError(t, err)
	testutil.RequirePublishedWhere(t, k8sClient, "Rulesfile", rf.Name, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.IsStatusConditionTrue(e.Conditions, commonv1alpha1.ConditionProgrammed.String())
	})

	settled := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(artifactNode), settled))
	for range 5 {
		_, err = r.Reconcile(ctx, testutil.Request(rf.Name))
		require.NoError(t, err)
	}
	// The publisher coalesces for a moment: give it time to write, were it going to.
	require.Never(t, func() bool {
		cur := &artifactv1alpha1.ArtifactNode{}
		return k8sClient.Get(ctx, client.ObjectKeyFromObject(artifactNode), cur) != nil ||
			cur.ResourceVersion != settled.ResourceVersion
	}, 700*time.Millisecond, 50*time.Millisecond, "an unchanged status must not be written again")
}

const wiredRules = "- rule: r\n  desc: d\n  condition: always_true\n  output: o\n  priority: WARNING\n"

// The reconciler wired to a real manager, through the watches registered by SetupWithManager: the Rulesfile, its
// assignment on the node, the ConfigMap it references, a change of Falco's versions, and the removal the node
// controller asks for.
func TestIntegration_Rulesfile_TheWatchesDriveTheReconciler(t *testing.T) {
	ctx := context.Background() // t.Context() ends before the cleanups that use it run
	n := newTestNode(t)
	r := rulesfile.NewRulesfileReconciler(k8sClient, n)
	versions := make(chan event.GenericEvent)
	testutil.StartManager(t, restConfig, k8sClient.Scheme(), func(mgr ctrl.Manager) error {
		r.Client = mgr.GetClient()
		return r.SetupWithManager(mgr, versions)
	})
	programmed := func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.IsStatusConditionTrue(e.Conditions, commonv1alpha1.ConditionProgrammed.String())
	}
	installedFiles := func(name string) int {
		return len(n.GetInstalled(artifact.Ref{Kind: artifact.KindRulesfile, Name: name}))
	}
	processed := func(rf *artifactv1alpha1.Rulesfile) {
		t.Helper()
		rf.Status.ObservedGeneration = rf.Generation
		require.NoError(t, k8sClient.Status().Update(ctx, rf))
	}

	inline := create(t, ctx, &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "wired", Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.RulesfileSpec{
			InlineRules: &apiextensionsv1.JSON{Raw: []byte(`[{"rule":"r","desc":"d","condition":"always_true","output":"o","priority":"WARNING"}]`)},
		},
	})
	processed(inline)
	mapped := create(t, ctx, &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "mapped", Namespace: testutil.TestNamespace},
		Spec:       artifactv1alpha1.RulesfileSpec{ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "wired-cm"}},
	})
	processed(mapped)

	// Assigned to the node: installed and reported.
	artifactNode := create(t, ctx, &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.ArtifactNodeSpec{
			NodeName: testutil.TestNodeName,
			Artifacts: []artifactv1alpha1.NodeArtifactRef{
				{Kind: "Rulesfile", Name: inline.Name, UID: string(inline.UID)},
				{Kind: "Rulesfile", Name: mapped.Name, UID: string(mapped.UID)},
			},
		},
	})
	testutil.RequirePublishedWhere(t, k8sClient, "Rulesfile", inline.Name, programmed)
	require.Equal(t, 1, installedFiles(inline.Name))

	// The ConfigMap it references appears.
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "wired-cm", Namespace: testutil.TestNamespace},
		Data:       map[string]string{commonv1alpha1.ConfigMapRulesKey: wiredRules},
	}
	require.NoError(t, k8sClient.Create(ctx, cm))
	t.Cleanup(func() { testutil.CleanupObject(t, ctx, k8sClient, cm) })
	testutil.RequirePublishedWhere(t, k8sClient, "Rulesfile", mapped.Name, programmed)

	// Falco's versions changed: what the node assigns is reconciled again.
	select {
	case versions <- event.GenericEvent{Object: inline}:
	case <-time.After(15 * time.Second):
		t.Fatal("the reconciler does not consume the versions channel")
	}

	// The node controller asks for the removal of what the node holds for an artifact nothing lists.
	orphan := artifact.Ref{Kind: artifact.KindRulesfile, Name: "orphan"}
	_, _, err := n.StoreRulesfile(ctx, orphan.Name, 50, artifact.MediumInline,
		artifact.FetchResult{Content: []byte(wiredRules), ContentHash: "hash", Perm: 0o644}, nil, false)
	require.NoError(t, err)
	require.NoError(t, n.RequestRemoval(ctx, orphan))
	require.Eventually(t, func() bool { return installedFiles(orphan.Name) == 0 }, 15*time.Second, 50*time.Millisecond,
		"the removal asked for reaches the reconciler")

	// The ArtifactNode stops listing the artifacts: their files go.
	latest := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(artifactNode), latest))
	latest.Spec.Artifacts = nil
	require.NoError(t, k8sClient.Update(ctx, latest))
	require.Eventually(t, func() bool { return installedFiles(inline.Name) == 0 && installedFiles(mapped.Name) == 0 },
		15*time.Second, 50*time.Millisecond, "what the ArtifactNode stops listing is removed")
}
