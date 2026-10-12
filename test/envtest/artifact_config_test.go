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

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/config"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// The publisher writes the node's status only when the status it holds differs from what it last wrote, so a
// steady-state reconcile must leave the ArtifactNode untouched on a real API server: an unconditional write
// would bump the resourceVersion on every reconcile and wake every watcher of the object.
func TestIntegration_Config_SteadyStateReconcileIsQuiet(t *testing.T) {
	ctx := context.Background()
	c := create(t, ctx, &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: "quiet", Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.ConfigSpec{
			Config:   &apiextensionsv1.JSON{Raw: []byte(`{"engine":{"kind":"modern_ebpf"}}`)},
			Priority: 50,
		},
	})
	// The instance operator has processed the current generation.
	c.Status.ObservedGeneration = c.Generation
	require.NoError(t, k8sClient.Status().Update(ctx, c))
	artifactNode := create(t, ctx, &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.ArtifactNodeSpec{
			NodeName:  testutil.TestNodeName,
			Artifacts: []artifactv1alpha1.NodeArtifactRef{{Kind: "Config", Name: c.Name, UID: string(c.UID)}},
		},
	})
	n := newTestNode(t)
	r := config.NewConfigReconciler(k8sClient, n)

	_, err := r.Reconcile(ctx, testutil.Request(c.Name))
	require.NoError(t, err)
	testutil.RequirePublishedWhere(t, k8sClient, "Config", c.Name, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.IsStatusConditionTrue(e.Conditions, commonv1alpha1.ConditionProgrammed.String())
	})

	settled := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(artifactNode), settled))
	for range 5 {
		_, err = r.Reconcile(ctx, testutil.Request(c.Name))
		require.NoError(t, err)
	}
	// The publisher coalesces for a moment: give it time to write, were it going to.
	require.Never(t, func() bool {
		cur := &artifactv1alpha1.ArtifactNode{}
		return k8sClient.Get(ctx, client.ObjectKeyFromObject(artifactNode), cur) != nil ||
			cur.ResourceVersion != settled.ResourceVersion
	}, 700*time.Millisecond, 50*time.Millisecond, "an unchanged status must not be written again")
}

// The reconciler wired to a real manager, through the watches registered by SetupWithManager: the Config, its
// assignment on the node, the ConfigMap it references, and the removal the node controller asks for.
func TestIntegration_Config_TheWatchesDriveTheReconciler(t *testing.T) {
	ctx := context.Background() // t.Context() ends before the cleanups that use it run
	n := newTestNode(t)
	r := config.NewConfigReconciler(k8sClient, n)
	testutil.StartManager(t, restConfig, k8sClient.Scheme(), func(mgr ctrl.Manager) error {
		r.Client = mgr.GetClient()
		return r.SetupWithManager(mgr)
	})
	programmed := func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.IsStatusConditionTrue(e.Conditions, commonv1alpha1.ConditionProgrammed.String())
	}
	installedFiles := func(name string) int {
		return len(n.GetInstalled(artifact.Ref{Kind: artifact.KindConfig, Name: name}))
	}
	processed := func(c *artifactv1alpha1.Config) {
		t.Helper()
		c.Status.ObservedGeneration = c.Generation
		require.NoError(t, k8sClient.Status().Update(ctx, c))
	}

	inline := create(t, ctx, &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: "wired", Namespace: testutil.TestNamespace},
		Spec:       artifactv1alpha1.ConfigSpec{Config: &apiextensionsv1.JSON{Raw: []byte(`{"engine":{"kind":"modern_ebpf"}}`)}, Priority: 50},
	})
	processed(inline)
	mapped := create(t, ctx, &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: "mapped", Namespace: testutil.TestNamespace},
		Spec:       artifactv1alpha1.ConfigSpec{ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "wired-cm"}, Priority: 50},
	})
	processed(mapped)

	// Assigned to the node: installed and reported.
	artifactNode := create(t, ctx, &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.ArtifactNodeSpec{
			NodeName: testutil.TestNodeName,
			Artifacts: []artifactv1alpha1.NodeArtifactRef{
				{Kind: "Config", Name: inline.Name, UID: string(inline.UID)},
				{Kind: "Config", Name: mapped.Name, UID: string(mapped.UID)},
			},
		},
	})
	testutil.RequirePublishedWhere(t, k8sClient, "Config", inline.Name, programmed)
	require.Equal(t, 1, installedFiles(inline.Name))

	// The ConfigMap it references appears.
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "wired-cm", Namespace: testutil.TestNamespace},
		Data:       map[string]string{commonv1alpha1.ConfigMapConfigKey: "engine:\n  kind: modern_ebpf\n"},
	}
	require.NoError(t, k8sClient.Create(ctx, cm))
	t.Cleanup(func() { testutil.CleanupObject(t, ctx, k8sClient, cm) })
	testutil.RequirePublishedWhere(t, k8sClient, "Config", mapped.Name, programmed)

	// The node controller asks for the removal of what the node holds for an artifact nothing lists.
	orphan := artifact.Ref{Kind: artifact.KindConfig, Name: "orphan"}
	require.NoError(t, n.ApplyArtifact(ctx, &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: orphan.Name, UID: "orphan-uid"},
		Spec:       artifactv1alpha1.ConfigSpec{Config: &apiextensionsv1.JSON{Raw: []byte(`{"a":"b"}`)}, Priority: 50},
	}, &artifactv1alpha1.NodeArtifactStatus{}))
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
