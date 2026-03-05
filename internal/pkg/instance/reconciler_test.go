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

package instance

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, rbacv1.AddToScheme(s))
	return s
}

// newConfigMap creates a ConfigMap for use as a client.Object in tests.
func newConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}
}

// testSAGenerator is a simple ResourceGenerator used by TestEnsureResource.
func testSAGenerator(cm *corev1.ConfigMap) runtime.Object {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: cm.Name, Namespace: cm.Namespace},
	}
}

func TestEnsureResource(t *testing.T) {
	scheme := testScheme(t)
	opts := GenerateOptions{}

	tests := []struct {
		name     string
		existing []client.Object
		getErr   error
		applyErr error
		wantErr  string
	}{
		{
			name: "creates new resource",
		},
		{
			name:    "returns error when get fails",
			getErr:  fmt.Errorf("injected get error"),
			wantErr: "unable to fetch existing",
		},
		{
			name:     "returns error when apply fails",
			applyErr: fmt.Errorf("injected apply error"),
			wantErr:  "unable to apply",
		},
		{
			name: "proceeds when no managed fields found",
			existing: []client.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := newConfigMap()
			objs := append([]client.Object{obj}, tt.existing...)
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...)

			funcs := interceptor.Funcs{}
			if tt.getErr != nil {
				funcs.Get = func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, o client.Object, opts ...client.GetOption) error {
					if _, ok := o.(*unstructured.Unstructured); ok {
						return tt.getErr
					}
					return cl.Get(ctx, key, o, opts...)
				}
			}
			if tt.applyErr != nil {
				funcs.Apply = func(ctx context.Context, cl client.WithWatch, o runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					return tt.applyErr
				}
			}
			cl := builder.WithInterceptorFuncs(funcs).Build()

			recorder := events.NewFakeRecorder(10)
			err := EnsureResource(context.Background(), cl, recorder, obj, "test-manager", testSAGenerator, opts)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestEnsureFinalizer(t *testing.T) {
	scheme := testScheme(t)

	tests := []struct {
		name         string
		obj          *corev1.ConfigMap
		hasFinalizer bool
		patchErr     error
		wantUpdated  bool
		wantErr      string
	}{
		{
			name:        "adds finalizer when not present",
			obj:         newConfigMap(),
			wantUpdated: true,
		},
		{
			name: "no-op when finalizer already present",
			obj: func() *corev1.ConfigMap {
				cm := newConfigMap()
				cm.Finalizers = []string{"test-finalizer"}
				return cm
			}(),
			hasFinalizer: true,
			wantUpdated:  false,
		},
		{
			name:     "returns error when patch fails",
			obj:      newConfigMap(),
			patchErr: fmt.Errorf("injected patch error"),
			wantErr:  "injected patch error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.obj)
			if tt.patchErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						return tt.patchErr
					},
				})
			}
			cl := builder.Build()

			updated, err := EnsureFinalizer(context.Background(), cl, tt.obj, "test-finalizer")

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, updated)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantUpdated, updated)

			if tt.wantUpdated || tt.hasFinalizer {
				fetched := &corev1.ConfigMap{}
				require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(tt.obj), fetched))
				assert.Contains(t, fetched.Finalizers, "test-finalizer")
			}
		})
	}
}

func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name            string
		currentVersion  string
		podTemplateSpec *corev1.PodTemplateSpec
		containerName   string
		defaultVersion  string
		want            string
	}{
		{
			name:           "returns default when no version set and no pod template",
			defaultVersion: "0.41.0",
			containerName:  "falco",
			want:           "0.41.0",
		},
		{
			name:           "returns current version when set",
			currentVersion: "0.40.0",
			defaultVersion: "0.41.0",
			containerName:  "falco",
			want:           "0.40.0",
		},
		{
			name:           "extracts version from container image",
			currentVersion: "",
			defaultVersion: "0.41.0",
			containerName:  "falco",
			podTemplateSpec: &corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "falco", Image: "docker.io/falcosecurity/falco:0.38.0"},
					},
				},
			},
			want: "0.38.0",
		},
		{
			name:           "image version takes precedence over current version",
			currentVersion: "0.35.0",
			defaultVersion: "0.41.0",
			containerName:  "falco",
			podTemplateSpec: &corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "falco", Image: "custom-registry/falco:0.39.0"},
					},
				},
			},
			want: "0.39.0",
		},
		{
			name:           "ignores containers with different names",
			currentVersion: "0.40.0",
			defaultVersion: "0.41.0",
			containerName:  "falco",
			podTemplateSpec: &corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "sidecar", Image: "some-image:1.0.0"},
					},
				},
			},
			want: "0.40.0",
		},
		{
			name:           "falls back to current when image has no tag",
			currentVersion: "0.40.0",
			defaultVersion: "0.41.0",
			containerName:  "falco",
			podTemplateSpec: &corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "falco", Image: "docker.io/falcosecurity/falco"},
					},
				},
			},
			want: "0.40.0",
		},
		{
			name:           "works with metacollector container",
			currentVersion: "",
			defaultVersion: "0.1.1",
			containerName:  "metacollector",
			podTemplateSpec: &corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "metacollector", Image: "docker.io/falcosecurity/k8s-metacollector:0.2.0"},
					},
				},
			},
			want: "0.2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveVersion(tt.currentVersion, tt.podTemplateSpec, tt.containerName, tt.defaultVersion)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHandleDeletion(t *testing.T) {
	scheme := testScheme(t)
	finalizerName := "test-finalizer"

	clusterGVKs := []schema.GroupVersionKind{
		{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"},
		{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"},
	}

	tests := []struct {
		name                   string
		obj                    *corev1.ConfigMap
		skipObjInClient        bool
		createClusterResources bool
		deleteErr              error
		patchErr               error
		wantHandled            bool
		wantErr                string
	}{
		{
			name: "not marked for deletion returns early",
			obj: func() *corev1.ConfigMap {
				cm := newConfigMap()
				cm.Finalizers = []string{finalizerName}
				return cm
			}(),
			wantHandled: false,
		},
		{
			name: "no finalizer returns true",
			obj: func() *corev1.ConfigMap {
				cm := newConfigMap()
				now := metav1.Now()
				cm.DeletionTimestamp = &now
				return cm
			}(),
			skipObjInClient: true,
			wantHandled:     true,
		},
		{
			name: "removes cluster resources and finalizer",
			obj: func() *corev1.ConfigMap {
				cm := newConfigMap()
				cm.Finalizers = []string{finalizerName}
				now := metav1.Now()
				cm.DeletionTimestamp = &now
				return cm
			}(),
			createClusterResources: true,
			wantHandled:            true,
		},
		{
			name: "handles deletion when cluster resources do not exist",
			obj: func() *corev1.ConfigMap {
				cm := newConfigMap()
				cm.Finalizers = []string{finalizerName}
				now := metav1.Now()
				cm.DeletionTimestamp = &now
				return cm
			}(),
			createClusterResources: false,
			wantHandled:            true,
		},
		{
			name: "returns error when cluster resource deletion fails",
			obj: func() *corev1.ConfigMap {
				cm := newConfigMap()
				cm.Finalizers = []string{finalizerName}
				now := metav1.Now()
				cm.DeletionTimestamp = &now
				return cm
			}(),
			deleteErr: fmt.Errorf("injected delete error"),
			wantErr:   "injected delete error",
		},
		{
			name: "returns error when finalizer patch fails",
			obj: func() *corev1.ConfigMap {
				cm := newConfigMap()
				cm.Finalizers = []string{finalizerName}
				now := metav1.Now()
				cm.DeletionTimestamp = &now
				return cm
			}(),
			patchErr: fmt.Errorf("injected patch error"),
			wantErr:  "injected patch error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if !tt.skipObjInClient {
				objs = append(objs, tt.obj)
			}
			if tt.createClusterResources {
				resourceName := GenerateUniqueName("test", "default")
				objs = append(objs,
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: resourceName}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: resourceName}},
				)
			}

			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...)
			funcs := interceptor.Funcs{}
			if tt.deleteErr != nil {
				funcs.Delete = func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					if _, ok := obj.(*unstructured.Unstructured); ok {
						return tt.deleteErr
					}
					return cl.Delete(ctx, obj, opts...)
				}
			}
			if tt.patchErr != nil {
				funcs.Patch = func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					return tt.patchErr
				}
			}
			cl := builder.WithInterceptorFuncs(funcs).Build()

			recorder := events.NewFakeRecorder(10)
			handled, err := HandleDeletion(context.Background(), cl, recorder, tt.obj, finalizerName, clusterGVKs, "Test instance deleted")

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHandled, handled)

			if tt.wantHandled && !controllerutil.ContainsFinalizer(tt.obj, finalizerName) {
				assert.NotContains(t, tt.obj.Finalizers, finalizerName)
			}
		})
	}
}
