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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	instancenode "github.com/falcosecurity/falco-operator/controllers/instance/artifact/artifactnode"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// The controller wired to a real manager and API server: what selects a node, what happens when a node's labels
// change, and what happens when the artifacts go, all through the watches and predicates registered by
// SetupWithManager.
func TestIntegration_TheAssignmentFollowsTheClusterThroughTheWatches(t *testing.T) {
	ctx := t.Context()
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:  k8sClient.Scheme(),
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	require.NoError(t, err)
	// The controller asks for the Falco pods of one node through the field index the instance operator registers.
	for _, idx := range index.PodIndexes {
		require.NoError(t, mgr.GetFieldIndexer().IndexField(ctx, idx.Object, idx.Field, idx.ExtractValueFn))
	}
	require.NoError(t, instancenode.NewArtifactNodeReconciler(mgr.GetClient(), mgr.GetEventRecorder(instancenode.ControllerName)).SetupWithManager(mgr))
	mgrCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(mgrCtx) }()

	const nodeName = "integration-node"
	create := func(obj client.Object) {
		t.Helper()
		require.NoError(t, k8sClient.Create(ctx, obj))
	}
	spec := func() []artifactv1alpha1.NodeArtifactRef {
		artifactNode := &artifactv1alpha1.ArtifactNode{}
		err := k8sClient.Get(ctx, client.ObjectKey{Namespace: testutil.TestNamespace, Name: nodeName}, artifactNode)
		if k8serrors.IsNotFound(err) {
			return nil
		}
		require.NoError(t, err)
		return artifactNode.Spec.Artifacts
	}
	names := func() (names []string) {
		for _, r := range spec() {
			names = append(names, string(r.Kind)+"/"+r.Name)
		}
		return names
	}
	eventually := func(what string, cond func() bool) {
		t.Helper()
		require.Eventually(t, cond, 15*time.Second, 50*time.Millisecond, what)
	}

	// A node that runs Falco, and a Rulesfile that selects every node.
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Labels: map[string]string{"pool": "a"}}}
	create(node)
	create(&artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "integration-rf", Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.RulesfileSpec{
			InlineRules: &apiextensionsv1.JSON{Raw: []byte(`[{"rule":"r","desc":"d","condition":"always_true","output":"o","priority":"WARNING"}]`)},
		},
	})
	eventually("without a Falco pod on the node nothing is assigned", func() bool { return spec() == nil })

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "integration-pod",
			Namespace: testutil.TestNamespace,
			Labels:    map[string]string{"app.kubernetes.io/instance": "integration-falco"},
		},
		Spec: corev1.PodSpec{NodeName: nodeName},
	}
	pod.Spec.Containers = []corev1.Container{{Name: "falco", Image: "falco"}}
	create(pod)
	pod.Status.Phase = corev1.PodRunning
	require.NoError(t, k8sClient.Status().Update(ctx, pod))
	// A pod is a Falco pod only while its Falco exists. Creating the Falco over a pod that is already running is
	// no pod event: the Falco watch is what assigns the node.
	require.Never(t, func() bool { return spec() != nil }, time.Second, 50*time.Millisecond, "a pod of no Falco")
	create(&instancev1alpha1.Falco{ObjectMeta: metav1.ObjectMeta{Name: "integration-falco", Namespace: testutil.TestNamespace}})
	eventually("a running Falco pod gets the node its ArtifactNode", func() bool { return len(names()) == 1 })
	require.Equal(t, []string{"Rulesfile/integration-rf"}, names())

	// A Config for another pool is not assigned until the node's labels change.
	create(&artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: "integration-config", Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.ConfigSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"pool": "b"}},
			Config:   &apiextensionsv1.JSON{Raw: []byte(`{"a":1}`)},
		},
	})
	require.Never(t, func() bool { return len(names()) != 1 }, time.Second, 50*time.Millisecond, "a Config that selects another pool")

	node.Labels["pool"] = "b"
	require.NoError(t, k8sClient.Update(ctx, node))
	eventually("relabelling the node assigns the Config", func() bool { return len(names()) == 2 })

	// The artifacts go: the spec is emptied, then the ArtifactNode is deleted.
	require.NoError(t, k8sClient.DeleteAllOf(ctx, &artifactv1alpha1.Rulesfile{}, client.InNamespace(testutil.TestNamespace)))
	eventually("a deleted Rulesfile is dropped", func() bool { return len(names()) == 1 })
	require.NoError(t, k8sClient.DeleteAllOf(ctx, &artifactv1alpha1.Config{}, client.InNamespace(testutil.TestNamespace)))
	eventually("nothing assigned and nothing reported deletes the ArtifactNode", func() bool {
		err := k8sClient.Get(ctx, client.ObjectKey{Namespace: testutil.TestNamespace, Name: nodeName}, &artifactv1alpha1.ArtifactNode{})
		return k8serrors.IsNotFound(err)
	})
}
