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
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
)

func TestMain(m *testing.M) {
	ctrllog.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.UseDevMode(true)))

	if err := instancev1alpha1.AddToScheme(scheme.Scheme); err != nil {
		ctrllog.Log.Error(err, "Failed to add scheme")
		os.Exit(1)
	}

	testEnv = &envtest.Environment{
		// testdata/crds holds a minimal cert-manager Certificate CRD fixture used by
		// ensureArtifactClientCertificate's tests to create and read Certificate objects
		// against envtest's apiserver.
		CRDDirectoryPaths:     []string{testutil.CRDDirPath(), "testdata/crds"},
		ErrorIfCRDPathMissing: true,
	}

	if dir := testutil.GetFirstFoundEnvTestBinaryDir(); dir != "" {
		testEnv.BinaryAssetsDirectory = dir
	}

	cfg, err := testEnv.Start()
	if err != nil {
		ctrllog.Log.Error(err, "Failed to start envtest")
		os.Exit(1)
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		ctrllog.Log.Error(err, "Failed to create client")
		os.Exit(1)
	}

	code := m.Run()

	if err := testEnv.Stop(); err != nil {
		ctrllog.Log.Error(err, "Failed to stop envtest")
	}

	os.Exit(code)
}

// newTestReconciler creates a new reconciler for integration tests.
func newTestReconciler() *Reconciler {
	return NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100))
}

// createFalco creates a Falco resource and registers cleanup to run after the test.
func createFalco(t *testing.T, ctx context.Context, falco *instancev1alpha1.Falco) *instancev1alpha1.Falco {
	t.Helper()

	err := k8sClient.Create(ctx, falco)
	require.NoError(t, err)

	t.Cleanup(func() {
		fetched := &instancev1alpha1.Falco{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, fetched); err == nil {
			fetched.Finalizers = nil
			_ = k8sClient.Update(ctx, fetched)
			_ = k8sClient.Delete(ctx, fetched)
		}
	})

	return falco
}

// reconcileN runs reconciliation N times.
func reconcileN(t *testing.T, ctx context.Context, reconciler *Reconciler, name string, n int) {
	t.Helper()
	for range n {
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: testutil.TestNamespace},
		})
		require.NoError(t, err)
	}
}

// TestReconcile_NonExistent verifies that reconciling a non-existent resource returns no error.
func TestReconcile_NonExistent(t *testing.T) {
	ctx := context.Background()
	reconciler := newTestReconciler()

	result, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "non-existent", Namespace: testutil.TestNamespace},
	})
	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter, "should not requeue for non-existent resource")
}

// TestReconcile_FinalizerAdded verifies that a finalizer is added on the first reconciliation.
func TestReconcile_FinalizerAdded(t *testing.T) {
	ctx := context.Background()
	falco := createFalco(t, ctx, &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-finalizer",
			Namespace: testutil.TestNamespace,
		},
	})

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, falco.Name, 1)

	fetched := &instancev1alpha1.Falco{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)
	assert.Contains(t, fetched.Finalizers, finalizer)
}

// TestReconcile_StatusInfo verifies that status.version and status.resourceType are set after reconciliation.
func TestReconcile_StatusInfo(t *testing.T) {
	ctx := context.Background()
	falco := createFalco(t, ctx, &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-status-info",
			Namespace: testutil.TestNamespace,
		},
	})

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, falco.Name, 3)

	fetched := &instancev1alpha1.Falco{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)
	assert.Nil(t, fetched.Spec.Version, "spec.version should remain nil (not patched)")
	assert.Equal(t, resources.FalcoDefaults.ImageTag, fetched.Status.Version)
	assert.Equal(t, resources.ResourceTypeDaemonSet, fetched.Status.ResourceType)
}

// TestReconcile_ServiceAccountCreated verifies that a ServiceAccount is created after reconciliation.
func TestReconcile_ServiceAccountCreated(t *testing.T) {
	ctx := context.Background()
	falco := createFalco(t, ctx, &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-basic",
			Namespace: testutil.TestNamespace,
		},
	})

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, falco.Name, 3)

	sa := &corev1.ServiceAccount{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, sa)
	require.NoError(t, err)
	assert.Equal(t, falco.Name, sa.Name)
}

// TestReconcile_EmptyCRD tests that an empty CRD has nil spec fields.
func TestReconcile_EmptyCRD(t *testing.T) {
	ctx := context.Background()
	falco := createFalco(t, ctx, &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-empty-crd",
			Namespace: testutil.TestNamespace,
		},
	})

	fetched := &instancev1alpha1.Falco{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)

	assert.Nil(t, fetched.Spec.Type, "type should be nil, defaults are resolved at runtime")
	assert.Nil(t, fetched.Spec.Replicas, "replicas should be nil, defaults are resolved at runtime")
	assert.Nil(t, fetched.Spec.Version, "version should be nil initially")
	assert.Nil(t, fetched.Spec.PodTemplateSpec, "podTemplateSpec should be nil")
}

// TestReconcile_Deletion tests the deletion handling and finalizer removal.
func TestReconcile_Deletion(t *testing.T) {
	ctx := context.Background()
	falco := createFalco(t, ctx, &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deletion",
			Namespace: testutil.TestNamespace,
		},
	})

	reconciler := newTestReconciler()

	// Reconcile to add finalizer
	reconcileN(t, ctx, reconciler, falco.Name, 1)

	// Verify finalizer was added before deletion
	fetched := &instancev1alpha1.Falco{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)
	assert.Contains(t, fetched.Finalizers, finalizer, "finalizer should be present before deletion")

	// Delete the resource
	err = k8sClient.Delete(ctx, fetched)
	require.NoError(t, err)

	// Reconcile deletion - should remove finalizer and allow deletion
	reconcileN(t, ctx, reconciler, falco.Name, 1)

	// Verify resource is deleted (finalizer was removed, allowing deletion to complete)
	err = k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, fetched)
	assert.True(t, errors.IsNotFound(err), "resource should be deleted after finalizer removal")
}

// TestReconcile_DeploymentFullCycle verifies that a Deployment is created with owner reference.
func TestReconcile_DeploymentFullCycle(t *testing.T) {
	ctx := context.Background()
	falco := createFalco(t, ctx, &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-full-deploy",
			Namespace: testutil.TestNamespace,
		},
		Spec: instancev1alpha1.FalcoSpec{
			Type:     new(resources.ResourceTypeDeployment),
			Replicas: new(int32(2)),
		},
	})

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, falco.Name, 5)

	deployment := &appsv1.Deployment{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, deployment)
	require.NoError(t, err)
	assert.Equal(t, falco.Name, deployment.Name)
	assert.Len(t, deployment.OwnerReferences, 1, "should have owner reference")
	assert.Equal(t, "Falco", deployment.OwnerReferences[0].Kind)
}

// TestReconcile_DaemonSetFullCycle verifies that a DaemonSet is created with owner reference.
func TestReconcile_DaemonSetFullCycle(t *testing.T) {
	ctx := context.Background()
	falco := createFalco(t, ctx, &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-full-ds",
			Namespace: testutil.TestNamespace,
		},
		Spec: instancev1alpha1.FalcoSpec{
			Type: new(resources.ResourceTypeDaemonSet),
		},
	})

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, falco.Name, 5)

	daemonset := &appsv1.DaemonSet{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, daemonset)
	require.NoError(t, err)
	assert.Equal(t, falco.Name, daemonset.Name)
	assert.Len(t, daemonset.OwnerReferences, 1, "should have owner reference")
	assert.Equal(t, "Falco", daemonset.OwnerReferences[0].Kind)
}

// TestReconcile_UpdateDeployment tests updating an existing Deployment.
func TestReconcile_UpdateDeployment(t *testing.T) {
	ctx := context.Background()
	falco := createFalco(t, ctx, &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-update-deploy",
			Namespace: testutil.TestNamespace,
		},
		Spec: instancev1alpha1.FalcoSpec{
			Type:     new(resources.ResourceTypeDeployment),
			Replicas: new(int32(1)),
		},
	})

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, falco.Name, 5)

	// Update replicas
	fetched := &instancev1alpha1.Falco{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)

	newReplicas := int32(3)
	fetched.Spec.Replicas = &newReplicas
	err = k8sClient.Update(ctx, fetched)
	require.NoError(t, err)

	// Reconcile after update
	reconcileN(t, ctx, reconciler, falco.Name, 1)

	// Verify Deployment was updated
	deployment := &appsv1.Deployment{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, deployment)
	require.NoError(t, err)
	assert.Equal(t, int32(3), *deployment.Spec.Replicas)
}

// TestReconcile_SwitchFromDeploymentToDaemonSet tests switching resource type.
func TestReconcile_SwitchFromDeploymentToDaemonSet(t *testing.T) {
	ctx := context.Background()
	falco := createFalco(t, ctx, &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-switch-type",
			Namespace: testutil.TestNamespace,
		},
		Spec: instancev1alpha1.FalcoSpec{
			Type:     new(resources.ResourceTypeDeployment),
			Replicas: new(int32(1)),
		},
	})

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, falco.Name, 5)

	// Verify Deployment exists
	deployment := &appsv1.Deployment{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, deployment)
	require.NoError(t, err)

	// Switch to DaemonSet
	fetched := &instancev1alpha1.Falco{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)

	newType := resources.ResourceTypeDaemonSet
	fetched.Spec.Type = &newType
	err = k8sClient.Update(ctx, fetched)
	require.NoError(t, err)

	// Reconcile after type switch
	reconcileN(t, ctx, reconciler, falco.Name, 3)

	// Verify DaemonSet was created
	daemonset := &appsv1.DaemonSet{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, daemonset)
	require.NoError(t, err)

	// Verify Deployment was deleted
	err = k8sClient.Get(ctx, types.NamespacedName{Name: falco.Name, Namespace: testutil.TestNamespace}, deployment)
	assert.True(t, errors.IsNotFound(err), "Deployment should be deleted after type switch")
}

func applyConfigMap(t *testing.T, ctx context.Context, name string, data map[string]string) string {
	t.Helper()
	cm := builders.NewConfigMap().WithName(name).WithNamespace(testutil.TestNamespace).WithData(data).Build()

	u, err := controllerhelper.ToUnstructured(cm)
	require.NoError(t, err)

	applyOpts := []client.ApplyOption{client.ForceOwnership, client.FieldOwner("test-controller")}
	err = k8sClient.Apply(ctx, client.ApplyConfigurationFromUnstructured(u), applyOpts...)
	require.NoError(t, err)
	return u.GetResourceVersion()
}

func TestReconcile_UnchangedStatus(t *testing.T) {
	for _, cachedState := range []string{"current", "condition order", "transition time"} {
		t.Run(cachedState, func(t *testing.T) {
			ctx := context.Background()
			falco := createFalco(t, ctx, &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "test-status-noop-", Namespace: testutil.TestNamespace},
			})
			key := client.ObjectKeyFromObject(falco)
			r := newTestReconciler()
			reconcileN(t, ctx, r, falco.Name, 4)
			current := &instancev1alpha1.Falco{}
			require.NoError(t, k8sClient.Get(ctx, key, current))
			require.Len(t, current.Status.Conditions, 2)
			cached := current.DeepCopy()
			switch cachedState {
			case "condition order":
				slices.Reverse(cached.Status.Conditions)
			case "transition time":
				cached.Status.Conditions[0].LastTransitionTime = metav1.NewTime(cached.Status.Conditions[0].LastTransitionTime.Add(-time.Minute))
			}
			// Seed two real API versions; only the parent read lags behind the latest one.
			require.NoError(t, r.patchStatus(ctx, cached))
			require.NoError(t, k8sClient.Get(ctx, key, cached))
			require.NoError(t, r.patchStatus(ctx, current))
			require.NoError(t, k8sClient.Get(ctx, key, current))
			workload := &appsv1.DaemonSet{}
			require.NoError(t, k8sClient.Get(ctx, key, workload))
			workloadRV := workload.ResourceVersion
			cl, err := client.NewWithWatch(testEnv.Config, client.Options{Scheme: k8sClient.Scheme()})
			require.NoError(t, err)
			writes := 0
			r.Client = interceptor.NewClient(cl, interceptor.Funcs{
				Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if parent, ok := obj.(*instancev1alpha1.Falco); ok {
						cached.DeepCopyInto(parent)
						return nil
					}
					return cl.Get(ctx, key, obj, opts...)
				},
				SubResourceApply: func(
					ctx context.Context, cl client.Client, subresource string,
					obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption,
				) error {
					writes++
					return cl.SubResource(subresource).Apply(ctx, obj, opts...)
				},
			})
			reconcileN(t, ctx, r, falco.Name, 3)
			assert.Zero(t, writes, "unchanged cached status must not be republished")
			got := &instancev1alpha1.Falco{}
			require.NoError(t, k8sClient.Get(ctx, key, got))
			assert.Equal(t, current.Status, got.Status)
			assert.Equal(t, current.ResourceVersion, got.ResourceVersion)
			require.NoError(t, k8sClient.Get(ctx, key, workload))
			assert.Equal(t, workloadRV, workload.ResourceVersion)
		})
	}
}

func TestReconcile_StatusRecoveryAndRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status metav1.ConditionStatus
	}{
		{name: "stale true", status: metav1.ConditionTrue},
		{name: "stale unknown", status: metav1.ConditionUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			falco := createFalco(t, ctx, &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "test-status-retry-", Namespace: testutil.TestNamespace},
			})
			key := client.ObjectKeyFromObject(falco)
			r := newTestReconciler()
			reconcileN(t, ctx, r, falco.Name, 4)
			current := &instancev1alpha1.Falco{}
			require.NoError(t, k8sClient.Get(ctx, key, current))
			condition := apimeta.FindStatusCondition(current.Status.Conditions, "Available")
			require.NotNil(t, condition)
			condition.Status = tc.status
			require.NoError(t, r.patchStatus(ctx, current))
			cl, err := client.NewWithWatch(testEnv.Config, client.Options{Scheme: k8sClient.Scheme()})
			require.NoError(t, err)
			applyFailure, fetchFailure := fmt.Errorf("injected status failure"), fmt.Errorf("injected availability failure")
			failApply, failFetch, writes := true, false, 0
			r.Client = interceptor.NewClient(cl, interceptor.Funcs{
				Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*appsv1.DaemonSet); ok && failFetch {
						return fetchFailure
					}
					return cl.Get(ctx, key, obj, opts...)
				},
				SubResourceApply: func(
					ctx context.Context, cl client.Client, subresource string,
					obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption,
				) error {
					writes++
					if failApply {
						return applyFailure
					}
					return cl.SubResource(subresource).Apply(ctx, obj, opts...)
				},
			})
			_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
			require.ErrorIs(t, err, applyFailure)
			require.NoError(t, k8sClient.Get(ctx, key, current))
			condition = apimeta.FindStatusCondition(current.Status.Conditions, "Available")
			require.NotNil(t, condition)
			require.Equal(t, tc.status, condition.Status)
			failApply = false
			reconcileN(t, ctx, r, falco.Name, 2)
			assert.Equal(t, 2, writes, "retry must publish the correction, then stop writing")
			require.NoError(t, k8sClient.Get(ctx, key, current))
			testutil.RequireCondition(t, current.Status.Conditions, "Available", metav1.ConditionFalse, instance.ReasonDaemonSetUnavailable)
			failFetch = true
			for range 2 {
				_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
				require.ErrorIs(t, err, fetchFailure, "an unchanged error status must not suppress the retry")
			}
			assert.Equal(t, 3, writes, "the repeated availability error needs only one status update")
			failFetch = false
			reconcileN(t, ctx, r, falco.Name, 2)
			assert.Equal(t, 4, writes)
			require.NoError(t, k8sClient.Get(ctx, key, current))
			testutil.RequireCondition(t, current.Status.Conditions, "Available", metav1.ConditionFalse, instance.ReasonDaemonSetUnavailable)

			expected := current.Status.DeepCopy()
			current.Status = instancev1alpha1.FalcoStatus{}
			require.NoError(t, k8sClient.Status().Update(ctx, current))
			reconcileN(t, ctx, r, falco.Name, 2)
			assert.Equal(t, 5, writes, "missing status must be rebuilt, then stop writing")
			require.NoError(t, k8sClient.Get(ctx, key, current))
			assert.Equal(t, expected.Version, current.Status.Version)
			assert.Equal(t, expected.ResourceType, current.Status.ResourceType)
			testutil.RequireCondition(t, current.Status.Conditions, "Reconciled", metav1.ConditionTrue, instance.ReasonResourceUpToDate)
			testutil.RequireCondition(t, current.Status.Conditions, "Available", metav1.ConditionFalse, instance.ReasonDaemonSetUnavailable)
		})
	}
}

// TestApplyResourceVersionBehavior verifies SSA ResourceVersion behavior for change detection.
func TestApplyResourceVersionBehavior(t *testing.T) {
	ctx := context.Background()
	cmName := "test-rv-behavior"

	t.Cleanup(func() {
		cm := builders.NewConfigMap().WithName(cmName).WithNamespace(testutil.TestNamespace).Build()
		_ = k8sClient.Delete(ctx, cm)
	})

	tests := []struct {
		name           string
		data           map[string]string
		expectRVChange bool
	}{
		{"create sets ResourceVersion", map[string]string{"key": "value"}, true},
		{"no changes keeps same ResourceVersion", map[string]string{"key": "value"}, false},
		{"changes increments ResourceVersion", map[string]string{"key": "new-value"}, true},
	}

	var previousRV string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv := applyConfigMap(t, ctx, cmName, tt.data)
			t.Logf("ResourceVersion: %s (previous: %s)", rv, previousRV)

			switch {
			case previousRV == "":
				assert.NotEmpty(t, rv)
			case tt.expectRVChange:
				assert.NotEqual(t, previousRV, rv)
			default:
				assert.Equal(t, previousRV, rv)
			}
			previousRV = rv
		})
	}
}
