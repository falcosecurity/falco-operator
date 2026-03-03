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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
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
		CRDDirectoryPaths:     []string{testutil.CRDDirPath()},
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
	return NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100), false)
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
	falco := createFalco(t, ctx, builders.NewFalco().WithName("test-finalizer").WithNamespace(testutil.TestNamespace).Build())

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
	falco := createFalco(t, ctx, builders.NewFalco().WithName("test-status-info").WithNamespace(testutil.TestNamespace).Build())

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
	falco := createFalco(t, ctx, builders.NewFalco().WithName("test-basic").WithNamespace(testutil.TestNamespace).Build())

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
	falco := createFalco(t, ctx, builders.NewFalco().WithName("test-empty-crd").WithNamespace(testutil.TestNamespace).Build())

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
	falco := createFalco(t, ctx, builders.NewFalco().WithName("test-deletion").WithNamespace(testutil.TestNamespace).Build())

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
	falco := createFalco(t, ctx, builders.NewFalco().WithName("test-full-deploy").
		WithNamespace(testutil.TestNamespace).
		WithType(resources.ResourceTypeDeployment).WithReplicas(2).Build())

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
	falco := createFalco(t, ctx, builders.NewFalco().WithName("test-full-ds").
		WithNamespace(testutil.TestNamespace).
		WithType(resources.ResourceTypeDaemonSet).Build())

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
	falco := createFalco(t, ctx, builders.NewFalco().WithName("test-update-deploy").
		WithNamespace(testutil.TestNamespace).
		WithType(resources.ResourceTypeDeployment).WithReplicas(1).Build())

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
	falco := createFalco(t, ctx, builders.NewFalco().WithName("test-switch-type").
		WithNamespace(testutil.TestNamespace).
		WithType(resources.ResourceTypeDeployment).WithReplicas(1).Build())

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
