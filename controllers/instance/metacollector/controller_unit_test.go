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

package metacollector

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func TestEnsureResourceErrors(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name     string
		getErr   error
		applyErr error
		wantErr  string
	}{
		{
			name:    "returns error when fetching existing resource fails",
			getErr:  fmt.Errorf("injected get error"),
			wantErr: "unable to fetch existing",
		},
		{
			name:     "returns error when apply fails",
			applyErr: fmt.Errorf("injected apply error"),
			wantErr:  "unable to apply",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := newMetacollector(withName("test-mc"))
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mc)
			funcs := interceptor.Funcs{}
			if tt.getErr != nil {
				funcs.Get = func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*unstructured.Unstructured); ok {
						return tt.getErr
					}
					return cl.Get(ctx, key, obj, opts...)
				}
			}
			if tt.applyErr != nil {
				funcs.Apply = func(ctx context.Context, cl client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					return tt.applyErr
				}
			}
			cl := builder.WithInterceptorFuncs(funcs).Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			err := r.ensureServiceAccount(context.Background(), mc)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestEnsureFinalizer(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name        string
		mc          *instancev1alpha1.Metacollector
		patchErr    error
		wantUpdated bool
		wantErr     string
	}{
		{
			name:        "adds finalizer when not present",
			mc:          newMetacollector(),
			wantUpdated: true,
		},
		{
			name:        "no-op when finalizer already present",
			mc:          newMetacollector(withFinalizer()),
			wantUpdated: false,
		},
		{
			name:     "returns error when patch fails",
			mc:       newMetacollector(),
			patchErr: fmt.Errorf("injected patch error"),
			wantErr:  "injected patch error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.mc)
			if tt.patchErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						return tt.patchErr
					},
				})
			}
			cl := builder.Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			updated, err := r.ensureFinalizer(context.Background(), tt.mc)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, updated)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantUpdated, updated)

			fetched := &instancev1alpha1.Metacollector{}
			err = cl.Get(context.Background(), client.ObjectKeyFromObject(tt.mc), fetched)
			require.NoError(t, err)
			assert.Contains(t, fetched.Finalizers, finalizer)
		})
	}
}

func TestEnsureVersion(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name        string
		mc          *instancev1alpha1.Metacollector
		patchErr    error
		wantUpdated bool
		wantVersion string
		wantErr     string
	}{
		{
			name:        "sets default version when not set",
			mc:          newMetacollector(),
			wantUpdated: true,
		},
		{
			name:        "keeps existing version",
			mc:          newMetacollector(withVersion("0.2.0")),
			wantUpdated: false,
			wantVersion: "0.2.0",
		},
		{
			name:        "extracts version from image",
			mc:          newMetacollector(withImage("falcosecurity/k8s-metacollector:0.3.0")),
			wantUpdated: true,
			wantVersion: "0.3.0",
		},
		{
			name:        "image version takes precedence over spec version",
			mc:          newMetacollector(withVersion("0.1.0"), withImage("falcosecurity/k8s-metacollector:0.3.0")),
			wantUpdated: true,
			wantVersion: "0.3.0",
		},
		{
			name:     "returns error when patch fails",
			mc:       newMetacollector(),
			patchErr: fmt.Errorf("injected patch error"),
			wantErr:  "injected patch error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.mc)
			if tt.patchErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						return tt.patchErr
					},
				})
			}
			cl := builder.Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			updated, err := r.ensureVersion(context.Background(), tt.mc)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, updated)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantUpdated, updated)
			if tt.wantVersion != "" {
				assert.Equal(t, tt.wantVersion, tt.mc.Spec.Version)
			} else if tt.wantUpdated {
				assert.NotEmpty(t, tt.mc.Spec.Version)
			}
		})
	}
}

func TestHandleDeletion(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name                   string
		mc                     *instancev1alpha1.Metacollector
		createClusterResources bool
		skipMCInClient         bool
		crbDeleteErr           error
		crDeleteErr            error
		patchErr               error
		wantErr                string
		wantHandled            bool
		wantFinalizerPresent   bool
		wantClusterResExist    bool
	}{
		{
			name:                   "preserves finalizer and resources when not marked for deletion",
			mc:                     newMetacollector(withFinalizer()),
			createClusterResources: true,
			wantHandled:            false,
			wantFinalizerPresent:   true,
			wantClusterResExist:    true,
		},
		{
			name:                   "handles deletion when cluster resources do not exist",
			mc:                     newMetacollector(withFinalizer(), withDeletionTimestamp()),
			createClusterResources: false,
			wantHandled:            true,
			wantFinalizerPresent:   false,
			wantClusterResExist:    false,
		},
		{
			name:                   "removes cluster resources and finalizer during deletion",
			mc:                     newMetacollector(withFinalizer(), withDeletionTimestamp()),
			createClusterResources: true,
			wantHandled:            true,
			wantFinalizerPresent:   false,
			wantClusterResExist:    false,
		},
		{
			name:                 "returns early when deleted without finalizer",
			mc:                   newMetacollector(withDeletionTimestamp()),
			skipMCInClient:       true,
			wantHandled:          true,
			wantFinalizerPresent: false,
			wantClusterResExist:  false,
		},
		{
			name:         "returns error when ClusterRoleBinding deletion fails",
			mc:           newMetacollector(withFinalizer(), withDeletionTimestamp()),
			crbDeleteErr: fmt.Errorf("injected delete error"),
			wantErr:      "injected delete error",
		},
		{
			name:        "returns error when ClusterRole deletion fails",
			mc:          newMetacollector(withFinalizer(), withDeletionTimestamp()),
			crDeleteErr: fmt.Errorf("injected delete error"),
			wantErr:     "injected delete error",
		},
		{
			name:     "returns error when finalizer removal patch fails",
			mc:       newMetacollector(withFinalizer(), withDeletionTimestamp()),
			patchErr: fmt.Errorf("injected patch error"),
			wantErr:  "injected patch error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if !tt.skipMCInClient {
				objs = append(objs, tt.mc)
			}
			if tt.createClusterResources {
				objs = append(objs,
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: instance.GenerateUniqueName(defaultName, testutil.TestNamespace)}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: instance.GenerateUniqueName(defaultName, testutil.TestNamespace)}},
				)
			}

			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...)
			if tt.crbDeleteErr != nil || tt.crDeleteErr != nil || tt.patchErr != nil {
				funcs := interceptor.Funcs{}
				if tt.crbDeleteErr != nil || tt.crDeleteErr != nil {
					funcs.Delete = func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						if u, ok := obj.(*unstructured.Unstructured); ok {
							if u.GetKind() == "ClusterRoleBinding" && tt.crbDeleteErr != nil {
								return tt.crbDeleteErr
							}
							if u.GetKind() == "ClusterRole" && tt.crDeleteErr != nil {
								return tt.crDeleteErr
							}
						}
						return cl.Delete(ctx, obj, opts...)
					}
				}
				if tt.patchErr != nil {
					funcs.Patch = func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						return tt.patchErr
					}
				}
				builder = builder.WithInterceptorFuncs(funcs)
			}
			cl := builder.Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			handled, err := r.handleDeletion(context.Background(), tt.mc)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, handled)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHandled, handled)

			if tt.wantFinalizerPresent {
				assert.Contains(t, tt.mc.Finalizers, finalizer)
			} else {
				assert.NotContains(t, tt.mc.Finalizers, finalizer)
			}

			uniqueName := instance.GenerateUniqueName(defaultName, testutil.TestNamespace)
			crErr := cl.Get(context.Background(), client.ObjectKey{Name: uniqueName}, &rbacv1.ClusterRole{})
			crbErr := cl.Get(context.Background(), client.ObjectKey{Name: uniqueName}, &rbacv1.ClusterRoleBinding{})

			if tt.wantClusterResExist {
				assert.NoError(t, crErr, "ClusterRole should exist")
				assert.NoError(t, crbErr, "ClusterRoleBinding should exist")
			} else if tt.createClusterResources {
				assert.Error(t, crErr, "ClusterRole should be deleted")
				assert.Error(t, crbErr, "ClusterRoleBinding should be deleted")
			}
		})
	}
}

func TestComputeAvailableCondition(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name                string
		mc                  *instancev1alpha1.Metacollector
		workload            client.Object
		getErr              error
		wantErr             string
		wantDesired         int32
		wantAvailable       int32
		wantUnavailable     int32
		wantConditionStatus metav1.ConditionStatus
		wantConditionReason string
	}{
		{
			name: "deployment available",
			mc:   newMetacollector(withReplicas(2)),
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testutil.TestNamespace},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 2, AvailableReplicas: 2, UnavailableReplicas: 0},
			},
			wantDesired: 2, wantAvailable: 2, wantUnavailable: 0,
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonDeploymentAvailable,
		},
		{
			name: "deployment unavailable",
			mc:   newMetacollector(withReplicas(3)),
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testutil.TestNamespace},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1, UnavailableReplicas: 2},
			},
			wantDesired: 3, wantAvailable: 1, wantUnavailable: 2,
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonDeploymentUnavailable,
		},
		{
			name:                "deployment not found sets zero availability",
			mc:                  newMetacollector(withReplicas(1)),
			wantDesired:         1,
			wantAvailable:       0,
			wantUnavailable:     0,
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonDeploymentNotFound,
		},
		{
			name: "defaults to 1 replica when spec.replicas is nil",
			mc:   newMetacollector(),
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testutil.TestNamespace},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1},
			},
			wantDesired: 1, wantAvailable: 1, wantUnavailable: 0,
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonDeploymentAvailable,
		},
		{
			name:                "returns error when deployment fetch fails",
			mc:                  newMetacollector(withReplicas(1)),
			getErr:              fmt.Errorf("injected get error"),
			wantErr:             "unable to fetch deployment",
			wantDesired:         1,
			wantConditionStatus: metav1.ConditionUnknown,
			wantConditionReason: instance.ReasonDeploymentFetchError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{tt.mc}
			if tt.workload != nil {
				objs = append(objs, tt.workload)
			}
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(tt.mc)
			if tt.getErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if _, ok := obj.(*appsv1.Deployment); ok {
							return tt.getErr
						}
						return cl.Get(ctx, key, obj, opts...)
					},
				})
			}
			cl := builder.Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			err := r.computeAvailableCondition(context.Background(), tt.mc)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantDesired, tt.mc.Status.DesiredReplicas)
			assert.Equal(t, tt.wantAvailable, tt.mc.Status.AvailableReplicas)
			assert.Equal(t, tt.wantUnavailable, tt.mc.Status.UnavailableReplicas)

			testutil.RequireCondition(t, tt.mc.Status.Conditions,
				commonv1alpha1.ConditionAvailable.String(),
				tt.wantConditionStatus, tt.wantConditionReason)
		})
	}
}

func TestEnsureDeployment(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name                string
		mc                  *instancev1alpha1.Metacollector
		existingObjs        []client.Object
		wantConditionStatus metav1.ConditionStatus
		wantConditionReason string
		wantImage           string
		wantStrategyType    appsv1.DeploymentStrategyType
	}{
		{
			name:                "creates deployment with default values",
			mc:                  newMetacollector(withName("test-mc")),
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceCreated,
			wantImage:           image.BuildMetacollectorImageStringFromVersion(""),
			wantStrategyType:    appsv1.RollingUpdateDeploymentStrategyType,
		},
		{
			name:                "creates deployment with custom version",
			mc:                  newMetacollector(withName("test-mc"), withVersion("0.2.0")),
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceCreated,
			wantImage:           image.BuildMetacollectorImageStringFromVersion("0.2.0"),
			wantStrategyType:    appsv1.RollingUpdateDeploymentStrategyType,
		},
		{
			name:                "creates deployment with Recreate strategy",
			mc:                  newMetacollector(withName("test-mc"), withStrategy(appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType})),
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceCreated,
			wantImage:           image.BuildMetacollectorImageStringFromVersion(""),
			wantStrategyType:    appsv1.RecreateDeploymentStrategyType,
		},
		{
			name: "updates existing deployment",
			mc:   newMetacollector(withName("test-mc"), withVersion("0.3.0")),
			existingObjs: []client.Object{
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "test-mc", Namespace: testutil.TestNamespace},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app.kubernetes.io/name": "test-mc", "app.kubernetes.io/instance": "test-mc"},
						},
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: containerName, Image: image.BuildMetacollectorImageStringFromVersion("")}},
							},
						},
					},
				},
			},
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceUpdated,
			wantImage:           image.BuildMetacollectorImageStringFromVersion("0.3.0"),
			wantStrategyType:    appsv1.RollingUpdateDeploymentStrategyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tt.mc}, tt.existingObjs...)
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			err := r.ensureDeployment(context.Background(), tt.mc)
			require.NoError(t, err)

			testutil.RequireCondition(t, tt.mc.Status.Conditions,
				commonv1alpha1.ConditionReconciled.String(),
				tt.wantConditionStatus, tt.wantConditionReason)

			dep := &appsv1.Deployment{}
			require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(tt.mc), dep))
			require.NotEmpty(t, dep.Spec.Template.Spec.Containers)
			assert.Equal(t, tt.wantImage, dep.Spec.Template.Spec.Containers[0].Image)
			assert.Equal(t, tt.wantStrategyType, dep.Spec.Strategy.Type)
			require.Len(t, dep.GetOwnerReferences(), 1)
			assert.Equal(t, tt.mc.Name, dep.GetOwnerReferences()[0].Name)
		})
	}
}

// TestEnsureDeploymentWithCustomPodTemplateSpec verifies container merge — structurally
// different assertions (iterating containers) from the table-driven TestEnsureDeployment.
func TestEnsureDeploymentWithCustomPodTemplateSpec(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	mc := newMetacollector(withName("test-mc"), withImage("custom-image:latest"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mc).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

	require.NoError(t, r.ensureDeployment(context.Background(), mc))

	dep := &appsv1.Deployment{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(mc), dep))

	foundCustomContainer := false
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Image == "custom-image:latest" {
			foundCustomContainer = true
			break
		}
	}
	assert.True(t, foundCustomContainer, "Deployment should contain user-specified container image")
}

func TestEnsureDeploymentErrors(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	// Scheme missing the Metacollector type — causes ctrl.SetControllerReference to fail.
	incompleteScheme := runtime.NewScheme()
	_ = corev1.AddToScheme(incompleteScheme)
	_ = appsv1.AddToScheme(incompleteScheme)
	_ = rbacv1.AddToScheme(incompleteScheme)

	tests := []struct {
		name                string
		mc                  *instancev1alpha1.Metacollector
		existingDeployment  bool
		reconcilerScheme    *runtime.Scheme
		getErr              error
		applyErr            error
		wantErr             string
		wantConditionStatus metav1.ConditionStatus
		wantConditionReason string
	}{
		{
			name:                "returns error when fetching existing resource fails",
			mc:                  newMetacollector(withName("test-mc")),
			getErr:              fmt.Errorf("injected get error"),
			wantErr:             "injected get error",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonExistingResourceError,
		},
		{
			name:                "returns error when SetControllerReference fails",
			mc:                  newMetacollector(withName("test-mc")),
			reconcilerScheme:    incompleteScheme,
			wantErr:             "no kind is registered",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonOwnerReferenceError,
		},
		{
			name:                "returns error when Apply fails on create",
			mc:                  newMetacollector(withName("test-mc")),
			applyErr:            fmt.Errorf("injected apply error"),
			wantErr:             "injected apply error",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonApplyPatchErrorOnCreate,
		},
		{
			name:                "returns error when Apply fails on update",
			mc:                  newMetacollector(withName("test-mc")),
			existingDeployment:  true,
			applyErr:            fmt.Errorf("injected apply error"),
			wantErr:             "injected apply error",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonApplyPatchErrorOnUpdate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.mc)
			if tt.existingDeployment {
				builder = builder.WithObjects(&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "test-mc", Namespace: testutil.TestNamespace},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app.kubernetes.io/name": "test-mc", "app.kubernetes.io/instance": "test-mc"},
						},
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: containerName, Image: "old:version"}},
							},
						},
					},
				})
			}
			funcs := interceptor.Funcs{}
			if tt.getErr != nil {
				funcs.Get = func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*unstructured.Unstructured); ok {
						return tt.getErr
					}
					return cl.Get(ctx, key, obj, opts...)
				}
			}
			if tt.applyErr != nil {
				funcs.Apply = func(ctx context.Context, cl client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					return tt.applyErr
				}
			}
			cl := builder.WithInterceptorFuncs(funcs).Build()

			rs := scheme
			if tt.reconcilerScheme != nil {
				rs = tt.reconcilerScheme
			}
			r := NewReconciler(cl, rs, events.NewFakeRecorder(10))

			err := r.ensureDeployment(context.Background(), tt.mc)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)

			testutil.RequireCondition(t, tt.mc.Status.Conditions,
				commonv1alpha1.ConditionReconciled.String(),
				tt.wantConditionStatus, tt.wantConditionReason)
		})
	}
}

func TestPatchStatus(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	mc := newMetacollector(withName("test-mc"))
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(mc).
		WithStatusSubresource(mc).
		Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

	fetched := &instancev1alpha1.Metacollector{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(mc), fetched))

	fetched.Status.Conditions = []metav1.Condition{
		common.NewReconciledCondition(metav1.ConditionTrue,
			instance.ReasonResourceCreated, instance.MessageResourceCreated, fetched.Generation),
	}
	fetched.Status.DesiredReplicas = 1
	fetched.Status.AvailableReplicas = 1

	require.NoError(t, r.patchStatus(context.Background(), fetched))

	obj := &instancev1alpha1.Metacollector{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(mc), obj))
	testutil.RequireCondition(t, obj.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionTrue, instance.ReasonResourceCreated)
	assert.Equal(t, int32(1), obj.Status.DesiredReplicas)
	assert.Equal(t, int32(1), obj.Status.AvailableReplicas)
}
