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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

// newArtifactScheme returns a scheme with corev1 and artifactv1alpha1 registered, for tests
// that operate on ArtifactNode/Plugin objects.
func newArtifactScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	return s
}

func newArtifactNode(name, parentName string, ownerRefs ...metav1.OwnerReference) *artifactv1alpha1.ArtifactNode {
	return &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels: map[string]string{
				controllerhelper.LabelArtifactParent: parentName,
			},
			OwnerReferences: ownerRefs,
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "n1"},
	}
}

func controllerRef(kind, name string, uid types.UID) metav1.OwnerReference {
	ctrlFlag := true
	return metav1.OwnerReference{
		APIVersion: artifactv1alpha1.GroupVersion.String(),
		Kind:       kind,
		Name:       name,
		UID:        uid,
		Controller: &ctrlFlag,
	}
}

// --- GetVerifiedOwner ---

func TestGetVerifiedOwner_NoMatchingKindRef(t *testing.T) {
	s := newArtifactScheme(t)
	node := newArtifactNode("plugin--container--n1", "container",
		controllerRef("Rulesfile", "other", "uid-1")) // different Kind
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node).Build()

	out := &artifactv1alpha1.Plugin{}
	ok, err := controllerhelper.GetVerifiedOwner(context.Background(), cl, node, "Plugin", out)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestGetVerifiedOwner_OwnerNotFound(t *testing.T) {
	s := newArtifactScheme(t)
	node := newArtifactNode("plugin--container--n1", "container",
		controllerRef("Plugin", "container", "uid-1"))
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node).Build() // Plugin "container" never created

	out := &artifactv1alpha1.Plugin{}
	ok, err := controllerhelper.GetVerifiedOwner(context.Background(), cl, node, "Plugin", out)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestGetVerifiedOwner_GetOtherError(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
	node := newArtifactNode("plugin--container--n1", "container",
		controllerRef("Plugin", "container", "uid-1"))
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(node, plugin).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*artifactv1alpha1.Plugin); ok {
					return fmt.Errorf("api server unavailable")
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	out := &artifactv1alpha1.Plugin{}
	_, err := controllerhelper.GetVerifiedOwner(context.Background(), cl, node, "Plugin", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api server unavailable")
}

func TestGetVerifiedOwner_UIDMismatchTreatedAsOrphaned(t *testing.T) {
	s := newArtifactScheme(t)
	// Live Plugin has the same name as the ownerRef but a different UID, as if the owner was deleted and recreated.
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default", UID: "live-uid"},
	}
	node := newArtifactNode("plugin--container--n1", "container",
		controllerRef("Plugin", "container", "stale-uid"))
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node, plugin).Build()

	out := &artifactv1alpha1.Plugin{}
	ok, err := controllerhelper.GetVerifiedOwner(context.Background(), cl, node, "Plugin", out)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestGetVerifiedOwner_UIDMatchReturnsLiveOwner(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default", UID: "uid-1"},
	}
	node := newArtifactNode("plugin--container--n1", "container",
		controllerRef("Plugin", "container", "uid-1"))
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(node, plugin).Build()

	out := &artifactv1alpha1.Plugin{}
	ok, err := controllerhelper.GetVerifiedOwner(context.Background(), cl, node, "Plugin", out)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "container", out.Name)
}

// --- ListOwnedNodes ---

func newArtifactNodeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := newArtifactScheme(t)
	builder := fake.NewClientBuilder().WithScheme(s).WithIndex(
		&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer,
	)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	return builder.Build()
}

func TestListOwnedNodes_FindsMatchingItems(t *testing.T) {
	pluginNode := newArtifactNode("plugin--container--n1", "container",
		controllerRef("Plugin", "container", "uid-1"))
	rulesfileNode := newArtifactNode("rulesfile--myrules--n1", "myrules",
		controllerRef("Rulesfile", "myrules", "uid-2"))
	cl := newArtifactNodeClient(t, pluginNode, rulesfileNode)

	list, err := controllerhelper.ListOwnedNodes(context.Background(), cl, "default", "container", "Plugin")
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	assert.Equal(t, "plugin--container--n1", list.Items[0].Name)
}

func TestListOwnedNodes_EmptyResult(t *testing.T) {
	cl := newArtifactNodeClient(t)

	list, err := controllerhelper.ListOwnedNodes(context.Background(), cl, "default", "container", "Plugin")
	require.NoError(t, err)
	assert.Empty(t, list.Items)
}

func TestListOwnedNodes_ListError(t *testing.T) {
	s := newArtifactScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return fmt.Errorf("api server unavailable")
			},
		}).
		Build()

	_, err := controllerhelper.ListOwnedNodes(context.Background(), cl, "default", "container", "Plugin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listing ArtifactNodes owned by Plugin default/container")
	assert.Contains(t, err.Error(), "api server unavailable")
}

// --- DeleteStaleNodeObjects (also exercises deleteNodeObject's success/NotFound/error paths) ---

func TestDeleteStaleNodeObjects_NodeInDesiredIsKept(t *testing.T) {
	node := newArtifactNode("plugin--container--n1", "container")
	cl := newArtifactNodeClient(t, node)

	err := controllerhelper.DeleteStaleNodeObjects(context.Background(), cl,
		[]artifactv1alpha1.ArtifactNode{*node}, map[string]struct{}{"n1": {}})
	require.NoError(t, err)

	got := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(node), got), "node in the desired set must not be deleted")
}

func TestDeleteStaleNodeObjects_NodeNotInDesiredIsDeleted(t *testing.T) {
	k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}} // node still exists; ClearFinalizersIfNodeGone is a no-op
	node := newArtifactNode("plugin--container--n1", "container")
	cl := newArtifactNodeClient(t, node, k8sNode)

	err := controllerhelper.DeleteStaleNodeObjects(context.Background(), cl,
		[]artifactv1alpha1.ArtifactNode{*node}, map[string]struct{}{"other-node": {}})
	require.NoError(t, err)

	got := &artifactv1alpha1.ArtifactNode{}
	err = cl.Get(context.Background(), client.ObjectKeyFromObject(node), got)
	assert.True(t, k8serrors.IsNotFound(err), "node no longer matching the selector must be deleted")
}

func TestDeleteStaleNodeObjects_DeleteAlreadyNotFoundIsNotAnError(t *testing.T) {
	k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	node := newArtifactNode("plugin--container--n1", "container")
	cl := fake.NewClientBuilder().
		WithScheme(newArtifactScheme(t)).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithObjects(node, k8sNode).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				return k8serrors.NewNotFound(schema.GroupResource{Resource: "artifactnodes"}, "plugin--container--n1")
			},
		}).
		Build()

	err := controllerhelper.DeleteStaleNodeObjects(context.Background(), cl,
		[]artifactv1alpha1.ArtifactNode{*node}, map[string]struct{}{})
	require.NoError(t, err)
}

func TestDeleteStaleNodeObjects_ClearFinalizersError(t *testing.T) {
	node := newArtifactNode("plugin--container--n1", "container")
	node.Finalizers = []string{"pluginnode.artifact.falcosecurity.dev/finalizer"}
	cl := fake.NewClientBuilder().
		WithScheme(newArtifactScheme(t)).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithObjects(node). // no corev1.Node "n1" exists; ClearFinalizersIfNodeGone treats the ArtifactNode as gone and patches it
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Node); ok {
					return fmt.Errorf("api server unavailable")
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	err := controllerhelper.DeleteStaleNodeObjects(context.Background(), cl,
		[]artifactv1alpha1.ArtifactNode{*node}, map[string]struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api server unavailable")
}

func TestDeleteStaleNodeObjects_DeleteOtherErrorPropagates(t *testing.T) {
	k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	node := newArtifactNode("plugin--container--n1", "container")
	cl := fake.NewClientBuilder().
		WithScheme(newArtifactScheme(t)).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithObjects(node, k8sNode).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				return fmt.Errorf("server unavailable")
			},
		}).
		Build()

	err := controllerhelper.DeleteStaleNodeObjects(context.Background(), cl,
		[]artifactv1alpha1.ArtifactNode{*node}, map[string]struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server unavailable")
}

// --- DeleteNodeObjectsForParentDeletion ---

func TestDeleteNodeObjectsForParentDeletion_EmptyExisting(t *testing.T) {
	cl := newArtifactNodeClient(t)

	remaining, err := controllerhelper.DeleteNodeObjectsForParentDeletion(context.Background(), cl, nil)
	require.NoError(t, err)
	assert.False(t, remaining)
}

func TestDeleteNodeObjectsForParentDeletion_NodesPresentAreDeletedAndReportedRemaining(t *testing.T) {
	k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	node := newArtifactNode("plugin--container--n1", "container")
	cl := newArtifactNodeClient(t, node, k8sNode)

	remaining, err := controllerhelper.DeleteNodeObjectsForParentDeletion(context.Background(), cl,
		[]artifactv1alpha1.ArtifactNode{*node})
	require.NoError(t, err)
	// nodesRemaining reflects presence at the start of the call, not whether the Delete
	// this call issued has already taken effect server-side.
	assert.True(t, remaining)

	got := &artifactv1alpha1.ArtifactNode{}
	err = cl.Get(context.Background(), client.ObjectKeyFromObject(node), got)
	assert.True(t, k8serrors.IsNotFound(err), "the node must actually have been deleted")
}

func TestDeleteNodeObjectsForParentDeletion_AlreadyDeletingNodeIsNotDeletedAgain(t *testing.T) {
	node := newArtifactNode("plugin--container--n1", "container")
	node.Finalizers = []string{"pluginnode.artifact.falcosecurity.dev/finalizer"} // required for a non-nil DeletionTimestamp
	now := metav1.Now()
	node.DeletionTimestamp = &now
	k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	cl := fake.NewClientBuilder().
		WithScheme(newArtifactScheme(t)).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithObjects(node, k8sNode).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				t.Fatal("Delete must not be called again for a node already marked for deletion")
				return nil
			},
		}).
		Build()

	remaining, err := controllerhelper.DeleteNodeObjectsForParentDeletion(context.Background(), cl,
		[]artifactv1alpha1.ArtifactNode{*node})
	require.NoError(t, err)
	assert.True(t, remaining)
}

func TestDeleteNodeObjectsForParentDeletion_ClearFinalizersError(t *testing.T) {
	node := newArtifactNode("plugin--container--n1", "container")
	node.Finalizers = []string{"pluginnode.artifact.falcosecurity.dev/finalizer"}
	cl := fake.NewClientBuilder().
		WithScheme(newArtifactScheme(t)).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithObjects(node).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Node); ok {
					return fmt.Errorf("api server unavailable")
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	remaining, err := controllerhelper.DeleteNodeObjectsForParentDeletion(context.Background(), cl,
		[]artifactv1alpha1.ArtifactNode{*node})
	require.Error(t, err)
	assert.False(t, remaining)
	assert.Contains(t, err.Error(), "api server unavailable")
}

func TestDeleteNodeObjectsForParentDeletion_DeleteError(t *testing.T) {
	k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	node := newArtifactNode("plugin--container--n1", "container")
	cl := fake.NewClientBuilder().
		WithScheme(newArtifactScheme(t)).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		WithObjects(node, k8sNode).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				return fmt.Errorf("server unavailable")
			},
		}).
		Build()

	remaining, err := controllerhelper.DeleteNodeObjectsForParentDeletion(context.Background(), cl,
		[]artifactv1alpha1.ArtifactNode{*node})
	require.Error(t, err)
	assert.False(t, remaining)
	assert.Contains(t, err.Error(), "server unavailable")
}
