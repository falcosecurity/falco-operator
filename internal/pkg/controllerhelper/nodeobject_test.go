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

package controllerhelper_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func TestNodeObjectName_ShortNameNoTruncation(t *testing.T) {
	got := controllerhelper.NodeObjectName("plugin", "container", "node-1")
	assert.Equal(t, "plugin--container--node-1", got)
}

func TestNodeObjectName_TruncatesLongArtifactName(t *testing.T) {
	longName := strings.Repeat("a", 300)
	got := controllerhelper.NodeObjectName("plugin", longName, "node-1")
	// Format is kind--<truncated-artifact-name>--nodeName--hash: the node name is preserved
	// verbatim in the middle, with a content hash appended at the end for uniqueness.
	assert.LessOrEqual(t, len(got), 253)
	assert.True(t, strings.HasPrefix(got, "plugin--"))
	assert.Contains(t, got, "--node-1--")
}

func TestNodeObjectName_ExtremeEdgeVeryLongNodeName(t *testing.T) {
	// nodeName alone exceeds the length budget, leaving no room even after dropping the artifact name.
	longNode := strings.Repeat("n", 300)
	got := controllerhelper.NodeObjectName("rulesfile", strings.Repeat("a", 300), longNode)
	assert.LessOrEqual(t, len(got), 253)
	assert.True(t, strings.HasPrefix(got, "rulesfile--"))
}

func TestNodeObjectName_DeterministicAndStable(t *testing.T) {
	a := controllerhelper.NodeObjectName("config", "my-config", "node-1")
	b := controllerhelper.NodeObjectName("config", "my-config", "node-1")
	assert.Equal(t, a, b)
}

func TestNodeObjectLabels(t *testing.T) {
	got := controllerhelper.NodeObjectLabels("plugin", "container", "node-1")
	assert.Equal(t, map[string]string{
		controllerhelper.LabelArtifactParent: "container",
		controllerhelper.LabelArtifactNode:   "node-1",
		controllerhelper.LabelArtifactKind:   "plugin",
	}, got)
}

func newOwnerRef(uid types.UID) metav1.OwnerReference {
	ctrlFlag := true
	return metav1.OwnerReference{
		APIVersion: "artifact.falcosecurity.dev/v1alpha1",
		Kind:       "Plugin",
		Name:       "container",
		UID:        uid,
		Controller: &ctrlFlag,
	}
}

func TestEnforceNodeObjectMeta_AlreadyCorrectIsNoOp(t *testing.T) {
	s := newNodeScheme(t)
	ref := newOwnerRef("uid-1")
	labels := map[string]string{"a": "1"}
	node := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "n1", Namespace: "default",
			Labels:          labels,
			OwnerReferences: []metav1.OwnerReference{ref},
		},
	}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(node).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
				t.Fatal("Patch should not be called when metadata already matches")
				return nil
			},
		}).
		Build()

	err := controllerhelper.EnforceNodeObjectMeta(context.Background(), cl, node, labels, &ref)
	require.NoError(t, err)
}

func TestEnforceNodeObjectMeta_MissingLabelIsMerged(t *testing.T) {
	s := newNodeScheme(t)
	ref := newOwnerRef("uid-1")
	node := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "n1", Namespace: "default",
			Labels:          map[string]string{"user-added": "keep-me"},
			OwnerReferences: []metav1.OwnerReference{ref},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node).Build()

	desired := map[string]string{"a": "1"}
	err := controllerhelper.EnforceNodeObjectMeta(context.Background(), cl, node, desired, &ref)
	require.NoError(t, err)

	got := &corev1.ConfigMap{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(node), got))
	assert.Equal(t, "1", got.Labels["a"])
	assert.Equal(t, "keep-me", got.Labels["user-added"], "pre-existing labels must be preserved, not overwritten")
}

func TestEnforceNodeObjectMeta_StaleOwnerRefIsReplaced(t *testing.T) {
	s := newNodeScheme(t)
	staleRef := newOwnerRef("stale-uid")
	node := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "n1", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{staleRef},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node).Build()

	freshRef := newOwnerRef("fresh-uid")
	err := controllerhelper.EnforceNodeObjectMeta(context.Background(), cl, node, nil, &freshRef)
	require.NoError(t, err)

	got := &corev1.ConfigMap{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(node), got))
	require.Len(t, got.OwnerReferences, 1, "the stale ref must be dropped, not kept alongside the fresh one")
	assert.Equal(t, types.UID("fresh-uid"), got.OwnerReferences[0].UID)
}

func TestEnforceNodeObjectMeta_OwnerRefOfDifferentKindIsPreserved(t *testing.T) {
	s := newNodeScheme(t)
	otherKindRef := newOwnerRef("other-uid")
	otherKindRef.Kind = "Rulesfile"
	node := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "n1", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{otherKindRef},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node).Build()

	pluginRef := newOwnerRef("plugin-uid")
	err := controllerhelper.EnforceNodeObjectMeta(context.Background(), cl, node, nil, &pluginRef)
	require.NoError(t, err)

	got := &corev1.ConfigMap{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(node), got))
	require.Len(t, got.OwnerReferences, 2, "an existing ref of a different Kind must be kept alongside the new one")
	kinds := []string{got.OwnerReferences[0].Kind, got.OwnerReferences[1].Kind}
	assert.Contains(t, kinds, "Rulesfile")
	assert.Contains(t, kinds, "Plugin")
}

func TestEnforceNodeObjectMeta_NoOwnerRefAtAllIsAdded(t *testing.T) {
	s := newNodeScheme(t)
	node := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "n1", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node).Build()

	ref := newOwnerRef("uid-1")
	err := controllerhelper.EnforceNodeObjectMeta(context.Background(), cl, node, nil, &ref)
	require.NoError(t, err)

	got := &corev1.ConfigMap{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(node), got))
	require.Len(t, got.OwnerReferences, 1)
	assert.Equal(t, types.UID("uid-1"), got.OwnerReferences[0].UID)
}

func TestEnforceNodeObjectMeta_PatchError(t *testing.T) {
	s := newNodeScheme(t)
	node := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "n1", Namespace: "default"}}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(node).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
				return fmt.Errorf("api server unavailable")
			},
		}).
		Build()

	ref := newOwnerRef("uid-1")
	err := controllerhelper.EnforceNodeObjectMeta(context.Background(), cl, node, nil, &ref)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api server unavailable")
}

func TestEnsureNodeObject_Creates(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default", UID: "plugin-uid"}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(plugin).Build()

	gvk := artifactv1alpha1.GroupVersion.WithKind("Plugin")
	err := controllerhelper.EnsureNodeObject(context.Background(), cl, plugin, gvk, "plugin", "node-1")
	require.NoError(t, err)

	created := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(),
		client.ObjectKey{Namespace: "default", Name: controllerhelper.NodeObjectName("plugin", "container", "node-1")}, created))
	assert.Equal(t, "node-1", created.Spec.NodeName)
	assert.Equal(t, "container", created.Labels[controllerhelper.LabelArtifactParent])
	require.Len(t, created.OwnerReferences, 1)
	assert.Equal(t, types.UID("plugin-uid"), created.OwnerReferences[0].UID)
}

func TestEnsureNodeObject_AlreadyExists_EnforcesMetadata(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default", UID: "plugin-uid"}}
	existing := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      controllerhelper.NodeObjectName("plugin", "container", "node-1"),
			Namespace: "default",
			// Object has no labels or owner ref; EnsureNodeObject adds them.
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "node-1"},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(plugin, existing).Build()

	gvk := artifactv1alpha1.GroupVersion.WithKind("Plugin")
	err := controllerhelper.EnsureNodeObject(context.Background(), cl, plugin, gvk, "plugin", "node-1")
	require.NoError(t, err)

	list := &artifactv1alpha1.ArtifactNodeList{}
	require.NoError(t, cl.List(context.Background(), list))
	require.Len(t, list.Items, 1, "must not create a second ArtifactNode for an existing one")
	assert.Equal(t, "container", list.Items[0].Labels[controllerhelper.LabelArtifactParent])
	require.Len(t, list.Items[0].OwnerReferences, 1)
}

func TestEnsureNodeObject_EnforceMetadataError(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default", UID: "plugin-uid"}}
	existing := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      controllerhelper.NodeObjectName("plugin", "container", "node-1"),
			Namespace: "default",
			// Object has no labels or owner ref; EnsureNodeObject issues a Patch to add them.
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "node-1"},
	}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin, existing).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
				return fmt.Errorf("patch error")
			},
		}).
		Build()

	gvk := artifactv1alpha1.GroupVersion.WithKind("Plugin")
	err := controllerhelper.EnsureNodeObject(context.Background(), cl, plugin, gvk, "plugin", "node-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "patch error")
}

func TestEnsureNodeObject_CreateError(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				return fmt.Errorf("create error")
			},
		}).
		Build()

	gvk := artifactv1alpha1.GroupVersion.WithKind("Plugin")
	err := controllerhelper.EnsureNodeObject(context.Background(), cl, plugin, gvk, "plugin", "node-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create error")
}

func TestEnsureNodeObject_GetError(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if _, ok := obj.(*artifactv1alpha1.ArtifactNode); ok {
					return fmt.Errorf("get error")
				}
				return nil
			},
		}).
		Build()

	gvk := artifactv1alpha1.GroupVersion.WithKind("Plugin")
	err := controllerhelper.EnsureNodeObject(context.Background(), cl, plugin, gvk, "plugin", "node-1")
	require.Error(t, err)
}
