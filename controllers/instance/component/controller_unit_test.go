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

package component

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
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

const defaultName = "test"

func newMetacollectorComponent(name string) *builders.ComponentBuilder {
	return builders.NewComponent().
		WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
		WithName(name).WithNamespace(testutil.TestNamespace)
}

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
			comp := newMetacollectorComponent("test-mc").Build()
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(comp)
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
			recorder := events.NewFakeRecorder(10)

			err := instance.EnsureResource(context.Background(), cl, recorder, comp, fieldManager,
				resources.GenerateServiceAccount(comp),
				instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestEnsureFinalizer(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name        string
		comp        *instancev1alpha1.Component
		patchErr    error
		wantUpdated bool
		wantErr     string
	}{
		{
			name:        "adds finalizer when not present",
			comp:        newMetacollectorComponent(defaultName).Build(),
			wantUpdated: true,
		},
		{
			name:        "no-op when finalizer already present",
			comp:        newMetacollectorComponent(defaultName).WithFinalizers([]string{finalizer}).Build(),
			wantUpdated: false,
		},
		{
			name:     "returns error when patch fails",
			comp:     newMetacollectorComponent(defaultName).Build(),
			patchErr: fmt.Errorf("injected patch error"),
			wantErr:  "injected patch error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.comp)
			if tt.patchErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						return tt.patchErr
					},
				})
			}
			cl := builder.Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			updated, err := r.ensureFinalizer(context.Background(), tt.comp)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, updated)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantUpdated, updated)

			fetched := &instancev1alpha1.Component{}
			err = cl.Get(context.Background(), client.ObjectKeyFromObject(tt.comp), fetched)
			require.NoError(t, err)
			assert.Contains(t, fetched.Finalizers, finalizer)
		})
	}
}

func TestHandleDeletion(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	now := metav1.Now()

	tests := []struct {
		name                   string
		comp                   *instancev1alpha1.Component
		createClusterResources bool
		skipCompInClient       bool
		crbDeleteErr           error
		crDeleteErr            error
		patchErr               error
		wantErr                string
		wantHandled            bool
		wantFinalizerPresent   bool
		wantClusterResExist    bool
	}{
		{
			name: "preserves finalizer and resources when not marked for deletion",
			comp: newMetacollectorComponent(defaultName).
				WithFinalizers([]string{finalizer}).Build(),
			createClusterResources: true,
			wantHandled:            false,
			wantFinalizerPresent:   true,
			wantClusterResExist:    true,
		},
		{
			name: "handles deletion when cluster resources do not exist",
			comp: newMetacollectorComponent(defaultName).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			createClusterResources: false,
			wantHandled:            true,
			wantFinalizerPresent:   false,
			wantClusterResExist:    false,
		},
		{
			name: "removes cluster resources and finalizer during deletion",
			comp: newMetacollectorComponent(defaultName).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			createClusterResources: true,
			wantHandled:            true,
			wantFinalizerPresent:   false,
			wantClusterResExist:    false,
		},
		{
			name:                 "returns early when deleted without finalizer",
			comp:                 newMetacollectorComponent(defaultName).WithDeletionTimestamp(&now).Build(),
			skipCompInClient:     true,
			wantHandled:          true,
			wantFinalizerPresent: false,
			wantClusterResExist:  false,
		},
		{
			name: "returns error when ClusterRoleBinding deletion fails",
			comp: newMetacollectorComponent(defaultName).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			crbDeleteErr: fmt.Errorf("injected delete error"),
			wantErr:      "injected delete error",
		},
		{
			name: "returns error when ClusterRole deletion fails",
			comp: newMetacollectorComponent(defaultName).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			crDeleteErr: fmt.Errorf("injected delete error"),
			wantErr:     "injected delete error",
		},
		{
			name: "returns error when finalizer removal patch fails",
			comp: newMetacollectorComponent(defaultName).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			patchErr: fmt.Errorf("injected patch error"),
			wantErr:  "injected patch error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if !tt.skipCompInClient {
				objs = append(objs, tt.comp)
			}
			if tt.createClusterResources {
				objs = append(objs,
					builders.NewClusterRole().WithName(resources.GenerateUniqueName(defaultName, testutil.TestNamespace)).Build(),
					builders.NewClusterRoleBinding().WithName(resources.GenerateUniqueName(defaultName, testutil.TestNamespace)).Build(),
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

			handled, err := r.handleDeletion(context.Background(), tt.comp)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, handled)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHandled, handled)

			if tt.wantFinalizerPresent {
				assert.Contains(t, tt.comp.Finalizers, finalizer)
			} else {
				assert.NotContains(t, tt.comp.Finalizers, finalizer)
			}

			uniqueName := resources.GenerateUniqueName(defaultName, testutil.TestNamespace)
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
		comp                *instancev1alpha1.Component
		workload            client.Object
		wantDesired         int32
		wantAvailable       int32
		wantConditionStatus metav1.ConditionStatus
		wantConditionReason string
		wantEventMessage    string
	}{
		{
			name: "deployment available — applies status and emits event",
			comp: newMetacollectorComponent(defaultName).WithReplicas(2).Build(),
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testutil.TestNamespace},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 2, AvailableReplicas: 2},
			},
			wantDesired: 2, wantAvailable: 2,
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonDeploymentAvailable,
			wantEventMessage:    instance.MessageDeploymentAvailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{tt.comp}
			if tt.workload != nil {
				objs = append(objs, tt.workload)
			}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(tt.comp).Build()
			recorder := events.NewFakeRecorder(10)
			r := NewReconciler(cl, scheme, recorder)

			err := r.computeAvailableCondition(context.Background(), tt.comp)
			require.NoError(t, err)

			assert.Equal(t, tt.wantDesired, tt.comp.Status.DesiredReplicas)
			assert.Equal(t, tt.wantAvailable, tt.comp.Status.AvailableReplicas)

			testutil.RequireCondition(t, tt.comp.Status.Conditions,
				commonv1alpha1.ConditionAvailable.String(),
				tt.wantConditionStatus, tt.wantConditionReason)

			select {
			case event := <-recorder.Events:
				assert.Contains(t, event, tt.wantEventMessage)
			default:
				t.Fatal("expected event to be emitted")
			}
		})
	}
}

func TestEnsureDeployment(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	defs := resources.MetacollectorDefaults

	tests := []struct {
		name                string
		comp                *instancev1alpha1.Component
		existingObjs        []client.Object
		wantConditionStatus metav1.ConditionStatus
		wantConditionReason string
		wantImage           string
		wantStrategyType    appsv1.DeploymentStrategyType
	}{
		{
			name:                "creates deployment with default values",
			comp:                newMetacollectorComponent("test-mc").Build(),
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceCreated,
			wantImage:           defs.ImageRepository + ":" + defs.ImageTag,
			wantStrategyType:    appsv1.RollingUpdateDeploymentStrategyType,
		},
		{
			name:                "creates deployment with custom version",
			comp:                newMetacollectorComponent("test-mc").WithVersion("0.2.0").Build(),
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceCreated,
			wantImage:           fmt.Sprintf("%s:%s", defs.ImageRepository, "0.2.0"),
			wantStrategyType:    appsv1.RollingUpdateDeploymentStrategyType,
		},
		{
			name: "creates deployment with Recreate strategy",
			comp: newMetacollectorComponent("test-mc").
				WithStrategy(appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}).Build(),
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceCreated,
			wantImage:           defs.ImageRepository + ":" + defs.ImageTag,
			wantStrategyType:    appsv1.RecreateDeploymentStrategyType,
		},
		{
			name: "updates existing deployment",
			comp: newMetacollectorComponent("test-mc").WithVersion("0.3.0").Build(),
			existingObjs: []client.Object{
				builders.NewDeployment().WithName("test-mc").WithNamespace(testutil.TestNamespace).
					WithSelector(map[string]string{
						"app.kubernetes.io/name":     "test-mc",
						"app.kubernetes.io/instance": "test-mc",
					}).
					AddContainer(&corev1.Container{
						Name:  defs.ContainerName,
						Image: defs.ImageRepository + ":" + defs.ImageTag,
					}).Build(),
			},
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceUpdated,
			wantImage:           fmt.Sprintf("%s:%s", defs.ImageRepository, "0.3.0"),
			wantStrategyType:    appsv1.RollingUpdateDeploymentStrategyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tt.comp}, tt.existingObjs...)
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			err := r.ensureDeployment(context.Background(), tt.comp, defs)
			require.NoError(t, err)

			testutil.RequireCondition(t, tt.comp.Status.Conditions,
				commonv1alpha1.ConditionReconciled.String(),
				tt.wantConditionStatus, tt.wantConditionReason)

			dep := &appsv1.Deployment{}
			require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(tt.comp), dep))
			require.NotEmpty(t, dep.Spec.Template.Spec.Containers)
			assert.Equal(t, tt.wantImage, dep.Spec.Template.Spec.Containers[0].Image)
			assert.Equal(t, tt.wantStrategyType, dep.Spec.Strategy.Type)
			require.Len(t, dep.GetOwnerReferences(), 1)
			assert.Equal(t, tt.comp.Name, dep.GetOwnerReferences()[0].Name)
		})
	}
}

// TestEnsureDeploymentWithCustomPodTemplateSpec verifies container merge -- structurally
// different assertions (iterating containers) from the table-driven TestEnsureDeployment.
func TestEnsureDeploymentWithCustomPodTemplateSpec(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	defs := resources.MetacollectorDefaults
	comp := newMetacollectorComponent("test-mc").WithImage(defs.ContainerName, "custom-image:latest").Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(comp).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

	require.NoError(t, r.ensureDeployment(context.Background(), comp, defs))

	dep := &appsv1.Deployment{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(comp), dep))

	foundCustomContainer := false
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Image == "custom-image:latest" {
			foundCustomContainer = true
			break
		}
	}
	assert.True(t, foundCustomContainer, "Deployment should contain user-specified container image")
}

func TestEnsureDeploymentApplyConfigError(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	invalidDefs := &resources.InstanceDefaults{ResourceType: "InvalidType"}
	comp := newMetacollectorComponent("test-mc").Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(comp).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

	err := r.ensureDeployment(context.Background(), comp, invalidDefs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported resource type")
	testutil.RequireCondition(t, comp.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionFalse, instance.ReasonApplyConfigurationError)
}

func TestEnsureDeploymentErrors(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	defs := resources.MetacollectorDefaults

	tests := []struct {
		name                string
		comp                *instancev1alpha1.Component
		existingDeployment  bool
		getErr              error
		applyErr            error
		wantErr             string
		wantConditionStatus metav1.ConditionStatus
		wantConditionReason string
	}{
		{
			name:                "returns error when fetching existing resource fails",
			comp:                newMetacollectorComponent("test-mc").Build(),
			getErr:              fmt.Errorf("injected get error"),
			wantErr:             "injected get error",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonExistingResourceError,
		},
		{
			name:                "returns error when Apply fails on create",
			comp:                newMetacollectorComponent("test-mc").Build(),
			applyErr:            fmt.Errorf("injected apply error"),
			wantErr:             "injected apply error",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonApplyPatchErrorOnCreate,
		},
		{
			name:                "returns error when Apply fails on update",
			comp:                newMetacollectorComponent("test-mc").Build(),
			existingDeployment:  true,
			applyErr:            fmt.Errorf("injected apply error"),
			wantErr:             "injected apply error",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonApplyPatchErrorOnUpdate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.comp)
			if tt.existingDeployment {
				builder = builder.WithObjects(
					builders.NewDeployment().WithName("test-mc").WithNamespace(testutil.TestNamespace).
						WithSelector(map[string]string{
							"app.kubernetes.io/name":     "test-mc",
							"app.kubernetes.io/instance": "test-mc",
						}).
						AddContainer(&corev1.Container{
							Name: defs.ContainerName, Image: "old:version",
						}).Build(),
				)
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

			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			err := r.ensureDeployment(context.Background(), tt.comp, defs)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)

			testutil.RequireCondition(t, tt.comp.Status.Conditions,
				commonv1alpha1.ConditionReconciled.String(),
				tt.wantConditionStatus, tt.wantConditionReason)
		})
	}
}

func TestPatchStatus(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	comp := newMetacollectorComponent("test-mc").Build()
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(comp).
		WithStatusSubresource(comp).
		Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

	fetched := &instancev1alpha1.Component{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(comp), fetched))

	fetched.Status.Conditions = []metav1.Condition{
		common.NewReconciledCondition(metav1.ConditionTrue,
			instance.ReasonResourceCreated, instance.MessageResourceCreated, fetched.Generation),
	}
	fetched.Status.DesiredReplicas = 1
	fetched.Status.AvailableReplicas = 1

	require.NoError(t, r.patchStatus(context.Background(), fetched))

	obj := &instancev1alpha1.Component{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(comp), obj))
	testutil.RequireCondition(t, obj.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionTrue, instance.ReasonResourceCreated)
	assert.Equal(t, int32(1), obj.Status.DesiredReplicas)
	assert.Equal(t, int32(1), obj.Status.AvailableReplicas)
}
