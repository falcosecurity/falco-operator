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

	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

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
			name:         "no-op when finalizer already present",
			obj:          builders.NewConfigMap().WithName("test").WithNamespace("default").WithFinalizers([]string{"test-finalizer"}).Build(),
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

func TestHandleDeletion(t *testing.T) {
	scheme := testScheme(t)
	finalizerName := "test-finalizer"

	clusterGVKs := []schema.GroupVersionKind{
		{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"},
		{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"},
	}

	now := metav1.Now()

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
			obj: builders.NewConfigMap().WithName("test").WithNamespace("default").
				WithFinalizers([]string{finalizerName}).Build(),
			wantHandled: false,
		},
		{
			name: "no finalizer returns true",
			obj: builders.NewConfigMap().WithName("test").WithNamespace("default").
				WithDeletionTimestamp(&now).Build(),
			skipObjInClient: true,
			wantHandled:     true,
		},
		{
			name: "removes cluster resources and finalizer",
			obj: builders.NewConfigMap().WithName("test").WithNamespace("default").
				WithFinalizers([]string{finalizerName}).WithDeletionTimestamp(&now).Build(),
			createClusterResources: true,
			wantHandled:            true,
		},
		{
			name: "handles deletion when cluster resources do not exist",
			obj: builders.NewConfigMap().WithName("test").WithNamespace("default").
				WithFinalizers([]string{finalizerName}).WithDeletionTimestamp(&now).Build(),
			createClusterResources: false,
			wantHandled:            true,
		},
		{
			name: "returns error when cluster resource deletion fails",
			obj: builders.NewConfigMap().WithName("test").WithNamespace("default").
				WithFinalizers([]string{finalizerName}).WithDeletionTimestamp(&now).Build(),
			deleteErr: fmt.Errorf("injected delete error"),
			wantErr:   "injected delete error",
		},
		{
			name: "returns error when finalizer patch fails",
			obj: builders.NewConfigMap().WithName("test").WithNamespace("default").
				WithFinalizers([]string{finalizerName}).WithDeletionTimestamp(&now).Build(),
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
				resourceName := resources.GenerateUniqueName("test", "default")
				objs = append(objs,
					builders.NewClusterRole().WithName(resourceName).Build(),
					builders.NewClusterRoleBinding().WithName(resourceName).Build(),
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

			if tt.wantHandled {
				fetched := &corev1.ConfigMap{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.obj), fetched)
				if err == nil {
					assert.NotContains(t, fetched.Finalizers, finalizerName, "finalizer should be removed from persisted object")
				}
				// If NotFound, the object was fully deleted (finalizer removal + deletion completed) — also valid.
			}
		})
	}
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, rbacv1.AddToScheme(s))
	return s
}

// newConfigMap creates a ConfigMap for use as a client.Object in tests.
func newConfigMap() *corev1.ConfigMap {
	return builders.NewConfigMap().WithName("test").WithNamespace("default").Build()
}

// testSAGenerator creates a ServiceAccount runtime.Object from the given ConfigMap.
func testSAGenerator(cm *corev1.ConfigMap) runtime.Object {
	return builders.NewServiceAccount().
		WithName(cm.Name).WithNamespace(cm.Namespace).Build()
}

func TestPrepareResource_InputValidation(t *testing.T) {
	scheme := testScheme(t)
	defaultClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	defaultObj := builders.NewConfigMap().WithName("test").WithNamespace("default").Build()
	dummyResource := builders.NewService().Build()

	tests := []struct {
		name        string
		nilObj      bool
		nilClient   bool
		nilResource bool
		wantErr     string
	}{
		{
			name:    "nil owner",
			nilObj:  true,
			wantErr: "owner cannot be nil",
		},
		{
			name:      "nil client",
			nilClient: true,
			wantErr:   "client cannot be nil",
		},
		{
			name:        "nil resource",
			nilResource: true,
			wantErr:     "resource cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := defaultObj
			if tt.nilObj {
				obj = nil
			}
			cl := defaultClient
			if tt.nilClient {
				cl = nil
			}
			var resource runtime.Object
			if !tt.nilResource {
				resource = dummyResource
			}

			_, err := PrepareResource(cl, obj, resource, GenerateOptions{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestPrepareResource_NamespacedResource(t *testing.T) {
	scheme := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	ownerCM := builders.NewConfigMap().WithName("test-owner").
		WithNamespace("default").
		WithLabels(map[string]string{"app": "test"}).Build()
	ownerCM.UID = "test-uid"

	resource := builders.NewService().
		WithNamespace(ownerCM.Namespace).
		WithLabels(ownerCM.Labels).Build()

	result, err := PrepareResource(cl, ownerCM, resource, GenerateOptions{
		SetControllerRef: true,
		IsClusterScoped:  false,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "Service", result.GetKind())
	assert.Equal(t, "v1", result.GetAPIVersion())
	assert.Equal(t, "test-owner", result.GetName())
	assert.Equal(t, map[string]string{"app": "test"}, result.GetLabels())
}

func TestPrepareResource_ClusterScopedResource(t *testing.T) {
	scheme := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	ownerCM := builders.NewConfigMap().WithName("test-owner").WithNamespace("default").
		WithLabels(map[string]string{"app": "test"}).Build()

	resource := builders.NewClusterRole().
		WithName(resources.GenerateUniqueName(ownerCM.Name, ownerCM.Namespace)).
		WithLabels(ownerCM.Labels).Build()

	result, err := PrepareResource(cl, ownerCM, resource, GenerateOptions{
		SetControllerRef: false,
		IsClusterScoped:  true,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "ClusterRole", result.GetKind())
	assert.Equal(t, "rbac.authorization.k8s.io/v1", result.GetAPIVersion())
	assert.Equal(t, "test-owner--default", result.GetName())
	assert.Equal(t, map[string]string{"app": "test"}, result.GetLabels())
}

func TestPrepareResource_ControllerRefFailure(t *testing.T) {
	scheme := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Owner without UID causes SetControllerReference to fail.
	ownerCM := builders.NewConfigMap().WithName("test-owner").WithNamespace("default").Build()

	resource := builders.NewService().Build()

	_, err := PrepareResource(cl, ownerCM, resource, GenerateOptions{
		SetControllerRef: true,
		IsClusterScoped:  false,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to set controller reference")
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
				builders.NewServiceAccount().
					WithName("test").WithNamespace("default").Build(),
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
			err := EnsureResource(context.Background(), cl, recorder, obj, "test-manager", testSAGenerator(obj), opts)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			// Verify the resource was actually applied/persisted by the fake client.
			sa := &unstructured.Unstructured{}
			sa.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "ServiceAccount"})
			fetchErr := cl.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "default"}, sa)
			assert.NoError(t, fetchErr, "resource should exist after EnsureResource")
		})
	}
}
