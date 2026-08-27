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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func TestPatchStatusSSA_UnresolvableGVKReturnsError(t *testing.T) {
	// A scheme with nothing registered can't resolve a GVK for any object.
	s := runtime.NewScheme()
	cl := fake.NewClientBuilder().WithScheme(newArtifactScheme(t)).Build()

	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
	err := controllerhelper.PatchStatusSSA(context.Background(), cl, s, plugin, "test-manager")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolving GVK")
}

// unconvertibleObject has a status field type (chan) that runtime.DefaultUnstructuredConverter
// cannot convert, triggering ToUnstructured's error path.
type unconvertibleObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Status            unconvertibleStatus `json:"status"`
}

type unconvertibleStatus struct {
	Bad chan int `json:"bad"`
}

func (o *unconvertibleObject) DeepCopyObject() runtime.Object {
	return &unconvertibleObject{TypeMeta: o.TypeMeta, ObjectMeta: *o.DeepCopy(), Status: o.Status}
}

func TestPatchStatusSSA_ToUnstructuredError(t *testing.T) {
	s := runtime.NewScheme()
	gvk := schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Unconvertible"}
	s.AddKnownTypeWithName(gvk, &unconvertibleObject{})

	obj := &unconvertibleObject{ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	err := controllerhelper.PatchStatusSSA(context.Background(), cl, s, obj, "test-manager")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "converting")
}

func TestPatchStatusSSA_NoStatusFieldIsANoOp(t *testing.T) {
	s := newArtifactScheme(t)
	require.NoError(t, corev1.AddToScheme(s))
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "default"}}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(context.Context, client.Client, string, runtime.ApplyConfiguration, ...client.SubResourceApplyOption) error {
				t.Fatal("Apply must not be called when the object has no status field")
				return nil
			},
		}).
		Build()

	err := controllerhelper.PatchStatusSSA(context.Background(), cl, s, cm, "test-manager")
	require.NoError(t, err)
}

func TestPatchStatusSSA_Success(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(plugin).WithStatusSubresource(plugin).Build()

	plugin.Status.Conditions = []metav1.Condition{
		{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed", Message: "ok"},
	}
	err := controllerhelper.PatchStatusSSA(context.Background(), cl, s, plugin, "test-manager")
	require.NoError(t, err)

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	require.Len(t, got.Status.Conditions, 1)
	assert.Equal(t, "Programmed", got.Status.Conditions[0].Type)
}

func TestPatchStatusSSA_ConflictError(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithStatusSubresource(plugin).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(context.Context, client.Client, string, runtime.ApplyConfiguration, ...client.SubResourceApplyOption) error {
				return k8serrors.NewConflict(schema.GroupResource{Group: "artifact.falcosecurity.dev", Resource: "plugins"}, "container", fmt.Errorf("stale resourceVersion"))
			},
		}).
		Build()

	err := controllerhelper.PatchStatusSSA(context.Background(), cl, s, plugin, "test-manager")
	require.Error(t, err)
	assert.True(t, k8serrors.IsConflict(err))
}

func TestPatchStatusSSA_NotFoundErrorIsSwallowed(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithStatusSubresource(plugin).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(context.Context, client.Client, string, runtime.ApplyConfiguration, ...client.SubResourceApplyOption) error {
				return k8serrors.NewNotFound(schema.GroupResource{Group: "artifact.falcosecurity.dev", Resource: "plugins"}, "container")
			},
		}).
		Build()

	err := controllerhelper.PatchStatusSSA(context.Background(), cl, s, plugin, "test-manager")
	require.NoError(t, err, "the object being gone before the patch landed must not surface as a reconcile error")
}

func TestPatchStatusSSA_GenericApplyError(t *testing.T) {
	s := newArtifactScheme(t)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithStatusSubresource(plugin).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(context.Context, client.Client, string, runtime.ApplyConfiguration, ...client.SubResourceApplyOption) error {
				return fmt.Errorf("apiserver unavailable")
			},
		}).
		Build()

	err := controllerhelper.PatchStatusSSA(context.Background(), cl, s, plugin, "test-manager")
	require.Error(t, err)
	assert.False(t, k8serrors.IsConflict(err))
	assert.Contains(t, err.Error(), "apiserver unavailable")
}
