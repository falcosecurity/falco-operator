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

package falco

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
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

const defaultName = "test"

// testContainerName is the container name from the registered Falco defaults.
var testContainerName = resources.FalcoDefaults.ContainerName

func TestEnsureFinalizer(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name        string
		falco       *instancev1alpha1.Falco
		patchErr    error
		wantUpdated bool
		wantErr     string
	}{
		{
			name:        "adds finalizer when not present",
			falco:       builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).Build(),
			wantUpdated: true,
		},
		{
			name:        "no-op when finalizer already present",
			falco:       builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithFinalizers([]string{finalizer}).Build(),
			wantUpdated: false,
		},
		{
			name:     "returns error when patch fails",
			falco:    builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).Build(),
			patchErr: fmt.Errorf("injected patch error"),
			wantErr:  "injected patch error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.falco)
			if tt.patchErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						return tt.patchErr
					},
				})
			}
			cl := builder.Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			updated, err := r.ensureFinalizer(context.Background(), tt.falco)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, updated)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantUpdated, updated)

			fetched := &instancev1alpha1.Falco{}
			err = cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), fetched)
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
		falco                  *instancev1alpha1.Falco
		createClusterResources bool
		skipFalcoInClient      bool
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
			falco:                  builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithFinalizers([]string{finalizer}).Build(),
			createClusterResources: true,
			wantHandled:            false,
			wantFinalizerPresent:   true,
			wantClusterResExist:    true,
		},
		{
			name: "handles deletion when cluster resources do not exist",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			createClusterResources: false,
			wantHandled:            true,
			wantFinalizerPresent:   false,
			wantClusterResExist:    false,
		},
		{
			name: "removes cluster resources and finalizer during deletion",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			createClusterResources: true,
			wantHandled:            true,
			wantFinalizerPresent:   false,
			wantClusterResExist:    false,
		},
		{
			name: "returns early when deleted without finalizer",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithDeletionTimestamp(&now).Build(),
			skipFalcoInClient:    true,
			wantHandled:          true,
			wantFinalizerPresent: false,
			wantClusterResExist:  false,
		},
		{
			name: "returns error when ClusterRoleBinding deletion fails",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			crbDeleteErr: fmt.Errorf("injected delete error"),
			wantErr:      "injected delete error",
		},
		{
			name: "returns error when ClusterRole deletion fails",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			crDeleteErr: fmt.Errorf("injected delete error"),
			wantErr:     "injected delete error",
		},
		{
			name: "returns error when finalizer removal patch fails",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithFinalizers([]string{finalizer}).WithDeletionTimestamp(&now).Build(),
			patchErr: fmt.Errorf("injected patch error"),
			wantErr:  "injected patch error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if !tt.skipFalcoInClient {
				objs = append(objs, tt.falco)
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
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			handled, err := r.handleDeletion(context.Background(), tt.falco)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, handled)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHandled, handled)

			if tt.wantFinalizerPresent {
				assert.Contains(t, tt.falco.Finalizers, finalizer)
			} else {
				assert.NotContains(t, tt.falco.Finalizers, finalizer)
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
		falco               *instancev1alpha1.Falco
		workload            client.Object
		wantDesired         int32
		wantAvailable       int32
		wantConditionStatus metav1.ConditionStatus
		wantConditionReason string
		wantEventMessage    string
	}{
		{
			name: "deployment available — applies status and emits event",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).WithReplicas(2).Build(),
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testutil.TestNamespace},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 2, AvailableReplicas: 2},
			},
			wantDesired: 2, wantAvailable: 2,
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonDeploymentAvailable,
			wantEventMessage:    instance.MessageDeploymentAvailable,
		},
		{
			name:  "daemonset available — applies status and emits event",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDaemonSet).Build(),
			workload: &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testutil.TestNamespace},
				Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberAvailable: 3},
			},
			wantDesired: 3, wantAvailable: 3,
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonDaemonSetAvailable,
			wantEventMessage:    instance.MessageDaemonSetAvailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{tt.falco}
			if tt.workload != nil {
				objs = append(objs, tt.workload)
			}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(tt.falco).Build()
			recorder := events.NewFakeRecorder(10)
			r := NewReconciler(cl, scheme, recorder, false)

			err := r.computeAvailableCondition(context.Background(), tt.falco)
			require.NoError(t, err)

			assert.Equal(t, tt.wantDesired, tt.falco.Status.DesiredReplicas)
			assert.Equal(t, tt.wantAvailable, tt.falco.Status.AvailableReplicas)

			testutil.RequireCondition(t, tt.falco.Status.Conditions,
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

func TestCleanupDualDeployments(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name         string
		falco        *instancev1alpha1.Falco
		existingObjs []client.Object
		getErr       error
		deleteErr    error
		wantDeleted  string // "Deployment" or "DaemonSet" that should be deleted
		wantErr      string
	}{
		{
			name:  "preserves Deployment when no DaemonSet exists",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDeployment).Build(),
			existingObjs: []client.Object{
				builders.NewDeployment().WithName("test").WithNamespace(testutil.TestNamespace).Build(),
			},
		},
		{
			name:  "deletes DaemonSet when type is Deployment",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDeployment).Build(),
			existingObjs: []client.Object{
				builders.NewDaemonSet().WithName("test").WithNamespace(testutil.TestNamespace).Build(),
			},
			wantDeleted: resources.ResourceTypeDaemonSet,
		},
		{
			name:  "deletes Deployment when type is DaemonSet",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDaemonSet).Build(),
			existingObjs: []client.Object{
				builders.NewDeployment().WithName("test").WithNamespace(testutil.TestNamespace).Build(),
			},
			wantDeleted: resources.ResourceTypeDeployment,
		},
		{
			name:    "returns error when Get fails with non-NotFound",
			falco:   builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDeployment).Build(),
			getErr:  fmt.Errorf("injected get error"),
			wantErr: "injected get error",
		},
		{
			name:  "returns error when Delete fails",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDeployment).Build(),
			existingObjs: []client.Object{
				builders.NewDaemonSet().WithName("test").WithNamespace(testutil.TestNamespace).Build(),
			},
			deleteErr: fmt.Errorf("injected delete error"),
			wantErr:   "injected delete error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tt.falco}, tt.existingObjs...)
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...)
			if tt.getErr != nil || tt.deleteErr != nil {
				funcs := interceptor.Funcs{}
				if tt.getErr != nil {
					funcs.Get = func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if _, ok := obj.(*unstructured.Unstructured); ok {
							return tt.getErr
						}
						return cl.Get(ctx, key, obj, opts...)
					}
				}
				if tt.deleteErr != nil {
					funcs.Delete = func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						return tt.deleteErr
					}
				}
				builder = builder.WithInterceptorFuncs(funcs)
			}
			cl := builder.Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			err := r.cleanupDualDeployments(context.Background(), tt.falco)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)

			switch tt.wantDeleted {
			case resources.ResourceTypeDaemonSet:
				ds := &appsv1.DaemonSet{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), ds)
				assert.Error(t, err, "DaemonSet should be deleted")
			case resources.ResourceTypeDeployment:
				dep := &appsv1.Deployment{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), dep)
				assert.Error(t, err, "Deployment should be deleted")
			default:
				if *tt.falco.Spec.Type == resources.ResourceTypeDeployment {
					dep := &appsv1.Deployment{}
					err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), dep)
					assert.NoError(t, err, "Deployment should still exist")
				}
				if *tt.falco.Spec.Type == resources.ResourceTypeDaemonSet {
					ds := &appsv1.DaemonSet{}
					err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), ds)
					assert.NoError(t, err, "DaemonSet should still exist")
				}
			}
		})
	}
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
			falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).Build()
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco)
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

			err := instance.EnsureResource(context.Background(), cl, events.NewFakeRecorder(10), falco, fieldManager,
				resources.GenerateServiceAccount(falco),
				instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestPatchStatus(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDeployment).Build()
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(falco).
		WithStatusSubresource(falco).
		Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	fetched := &instancev1alpha1.Falco{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(falco), fetched))

	fetched.Status.Conditions = []metav1.Condition{
		common.NewReconciledCondition(metav1.ConditionTrue,
			instance.ReasonResourceCreated, instance.MessageResourceCreated, fetched.Generation),
	}
	fetched.Status.DesiredReplicas = 1
	fetched.Status.AvailableReplicas = 1

	require.NoError(t, r.patchStatus(context.Background(), fetched))

	obj := &instancev1alpha1.Falco{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(falco), obj))
	testutil.RequireCondition(t, obj.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionTrue, instance.ReasonResourceCreated)
	assert.Equal(t, int32(1), obj.Status.DesiredReplicas)
	assert.Equal(t, int32(1), obj.Status.AvailableReplicas)
}

func TestEnsureDeployment(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name                string
		falco               *instancev1alpha1.Falco
		existingObjs        []client.Object
		wantConditionStatus metav1.ConditionStatus
		wantConditionReason string
		wantKind            string
	}{
		{
			name: "creates Deployment with default values and default Falco version",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).Build(),
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceCreated,
			wantKind:            resources.ResourceTypeDeployment,
		},
		{
			name: "creates Deployment with custom version",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).WithVersion("0.38.0").Build(),
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceCreated,
			wantKind:            resources.ResourceTypeDeployment,
		},
		{
			name: "creates DaemonSet",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDaemonSet).Build(),
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceCreated,
			wantKind:            resources.ResourceTypeDaemonSet,
		},
		{
			name: "updates existing Deployment",
			falco: builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
				WithType(resources.ResourceTypeDeployment).WithVersion("0.39.0").Build(),
			existingObjs: []client.Object{
				builders.NewDeployment().WithName("test").WithNamespace(testutil.TestNamespace).
					WithSelector(map[string]string{
						"app.kubernetes.io/name": "test", "app.kubernetes.io/instance": "test",
					}).
					AddContainer(&corev1.Container{
						Name:  testContainerName,
						Image: image.BuildFalcoImageStringFromVersion("0.38.0"),
					}).Build(),
			},
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: instance.ReasonResourceUpdated,
			wantKind:            resources.ResourceTypeDeployment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tt.falco}, tt.existingObjs...)
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			err := r.ensureDeployment(context.Background(), tt.falco)
			require.NoError(t, err)

			testutil.RequireCondition(t, tt.falco.Status.Conditions,
				commonv1alpha1.ConditionReconciled.String(),
				tt.wantConditionStatus, tt.wantConditionReason)

			switch tt.wantKind {
			case resources.ResourceTypeDaemonSet:
				ds := &appsv1.DaemonSet{}
				require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), ds))
				require.NotEmpty(t, ds.Spec.Template.Spec.Containers)
				assert.Contains(t, ds.Spec.Template.Spec.Containers[0].Image, "falco")
				require.Len(t, ds.GetOwnerReferences(), 1)
				assert.Equal(t, tt.falco.Name, ds.GetOwnerReferences()[0].Name)
			case resources.ResourceTypeDeployment:
				dep := &appsv1.Deployment{}
				require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), dep))
				require.NotEmpty(t, dep.Spec.Template.Spec.Containers)
				actualImage := dep.Spec.Template.Spec.Containers[0].Image
				if tt.falco.Spec.Version != nil {
					wantImage := image.BuildFalcoImageStringFromVersion(*tt.falco.Spec.Version)
					assert.Equal(t, wantImage, actualImage)
				} else {
					// When no version is specified, the controller must use the default from FalcoDefaults.
					wantImage := image.BuildImageString(image.Registry, image.Repository, image.FalcoImage, resources.FalcoDefaults.ImageTag)
					assert.Equal(t, wantImage, actualImage,
						"default Falco image must use FalcoDefaults.ImageTag when spec.version is nil")
				}
				require.Len(t, dep.GetOwnerReferences(), 1)
				assert.Equal(t, tt.falco.Name, dep.GetOwnerReferences()[0].Name)
			default:
				assert.Fail(t, "unknown resource type")
			}
		})
	}
}

// TestEnsureDeploymentWithCustomPodTemplateSpec verifies container merge — structurally
// different assertions (iterating containers) from the table-driven TestEnsureDeployment.
func TestEnsureDeploymentWithCustomPodTemplateSpec(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
		WithType(resources.ResourceTypeDeployment).
		WithImage(testContainerName, "custom-image:latest").Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	require.NoError(t, r.ensureDeployment(context.Background(), falco))

	dep := &appsv1.Deployment{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(falco), dep))

	foundCustomContainer := false
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Image == "custom-image:latest" {
			foundCustomContainer = true
			break
		}
	}
	assert.True(t, foundCustomContainer, "Deployment should contain user-specified container image")
}

func TestEnsureConfigMapError(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
		WithType("InvalidType").Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	err := r.ensureConfigMap(context.Background(), falco)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported falco type")
}

func TestEnsureDeploymentApplyConfigError(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
		WithType("InvalidType").Build()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

	err := r.ensureDeployment(context.Background(), falco)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported resource type")
	testutil.RequireCondition(t, falco.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionFalse, instance.ReasonApplyConfigurationError)
}

func TestEnsureDeploymentOwnerReferenceError(t *testing.T) {
	// An empty scheme has no GVK registered for Falco, so SetControllerReference fails.
	emptyScheme := runtime.NewScheme()
	falco := builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).
		WithType(resources.ResourceTypeDeployment).Build()
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, instancev1alpha1.AddToScheme)).WithObjects(falco).Build()
	r := NewReconciler(cl, emptyScheme, events.NewFakeRecorder(10), false)

	err := r.ensureDeployment(context.Background(), falco)
	require.Error(t, err)
	testutil.RequireCondition(t, falco.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionFalse, instance.ReasonOwnerReferenceError)
}

func TestEnsureDeploymentErrors(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name                string
		falco               *instancev1alpha1.Falco
		existingDeployment  bool
		getErr              error
		applyErr            error
		wantErr             string
		wantConditionStatus metav1.ConditionStatus
		wantConditionReason string
	}{
		{
			name:                "returns error when fetching existing resource fails",
			falco:               builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDeployment).Build(),
			getErr:              fmt.Errorf("injected get error"),
			wantErr:             "injected get error",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonExistingResourceError,
		},
		{
			name:                "returns error when Apply fails on create",
			falco:               builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDeployment).Build(),
			applyErr:            fmt.Errorf("injected apply error"),
			wantErr:             "injected apply error",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonApplyPatchErrorOnCreate,
		},
		{
			name:                "returns error when Apply fails on update",
			falco:               builders.NewFalco().WithName("test").WithNamespace(testutil.TestNamespace).WithType(resources.ResourceTypeDeployment).Build(),
			existingDeployment:  true,
			applyErr:            fmt.Errorf("injected apply error"),
			wantErr:             "injected apply error",
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: instance.ReasonApplyPatchErrorOnUpdate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.falco)
			if tt.existingDeployment {
				builder = builder.WithObjects(&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testutil.TestNamespace},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app.kubernetes.io/name": "test", "app.kubernetes.io/instance": "test"},
						},
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: testContainerName, Image: "old:version"}},
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

			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			err := r.ensureDeployment(context.Background(), tt.falco)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)

			testutil.RequireCondition(t, tt.falco.Status.Conditions,
				commonv1alpha1.ConditionReconciled.String(),
				tt.wantConditionStatus, tt.wantConditionReason)
		})
	}
}
