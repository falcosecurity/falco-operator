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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/metacollector/testutil"
)

const testNamespaceIntegration = "default"

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
)

func TestMain(m *testing.M) {
	logf.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.UseDevMode(true)))

	if err := instancev1alpha1.AddToScheme(scheme.Scheme); err != nil {
		logf.Log.Error(err, "Failed to add scheme")
		os.Exit(1)
	}

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	if dir := getFirstFoundEnvTestBinaryDir(); dir != "" {
		testEnv.BinaryAssetsDirectory = dir
	}

	cfg, err := testEnv.Start()
	if err != nil {
		logf.Log.Error(err, "Failed to start envtest")
		os.Exit(1)
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		logf.Log.Error(err, "Failed to create client")
		os.Exit(1)
	}

	code := m.Run()

	if err := testEnv.Stop(); err != nil {
		logf.Log.Error(err, "Failed to stop envtest")
	}

	os.Exit(code)
}

func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}

// newTestReconciler creates a new reconciler for integration tests.
func newTestReconciler() *Reconciler {
	return NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100))
}

// createMetacollector creates a Metacollector resource and registers cleanup to run after the test.
func createMetacollector(t *testing.T, ctx context.Context, name string, opts ...func(*instancev1alpha1.Metacollector)) {
	t.Helper()

	mc := newMetacollector(name, opts...)

	err := k8sClient.Create(ctx, mc)
	require.NoError(t, err)

	t.Cleanup(func() {
		fetched := &instancev1alpha1.Metacollector{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: testNamespaceIntegration}, fetched); err == nil {
			fetched.Finalizers = nil
			_ = k8sClient.Update(ctx, fetched)
			_ = k8sClient.Delete(ctx, fetched)
		}
	})
}

// reconcileN runs reconciliation N times.
func reconcileN(t *testing.T, ctx context.Context, reconciler *Reconciler, name string, n int) {
	t.Helper()
	for range n {
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: testNamespaceIntegration},
		})
		require.NoError(t, err)
	}
}

// TestReconcile_NonExistent verifies that reconciling a non-existent resource returns no error.
func TestReconcile_NonExistent(t *testing.T) {
	ctx := context.Background()
	reconciler := newTestReconciler()

	result, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "non-existent", Namespace: testNamespaceIntegration},
	})
	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter, "should not requeue for non-existent resource")
}

// TestReconcile_FullReconciliation verifies that all sub-resources are created after a full reconciliation.
func TestReconcile_FullReconciliation(t *testing.T) {
	ctx := context.Background()
	resourceName := "test-full"

	createMetacollector(t, ctx, resourceName)

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, resourceName, 5)

	// Verify ServiceAccount.
	sa := &corev1.ServiceAccount{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, sa)
	require.NoError(t, err)
	assert.Equal(t, resourceName, sa.Name)
	require.Len(t, sa.OwnerReferences, 1)
	assert.Equal(t, "Metacollector", sa.OwnerReferences[0].Kind)

	// Verify ClusterRole.
	uniqueName := GenerateUniqueName(resourceName, testNamespaceIntegration)
	cr := &rbacv1.ClusterRole{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, cr)
	require.NoError(t, err)
	assert.NotEmpty(t, cr.Rules)

	// Verify ClusterRoleBinding.
	crb := &rbacv1.ClusterRoleBinding{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, crb)
	require.NoError(t, err)
	require.Len(t, crb.Subjects, 1)
	assert.Equal(t, resourceName, crb.Subjects[0].Name)

	// Verify Service with 3 ports (metrics, health-probe, broker-grpc).
	svc := &corev1.Service{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, svc)
	require.NoError(t, err)
	require.Len(t, svc.Spec.Ports, 3)
	portNames := make(map[string]int32)
	for _, p := range svc.Spec.Ports {
		portNames[p.Name] = p.Port
	}
	assert.Equal(t, int32(8080), portNames["metrics"])
	assert.Equal(t, int32(8081), portNames["health-probe"])
	assert.Equal(t, int32(45000), portNames["broker-grpc"])

	// Verify Deployment.
	dep := &appsv1.Deployment{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, dep)
	require.NoError(t, err)
	require.NotEmpty(t, dep.Spec.Template.Spec.Containers)
	assert.Contains(t, dep.Spec.Template.Spec.Containers[0].Image, DefaultImage)
	require.Len(t, dep.OwnerReferences, 1)
	assert.Equal(t, "Metacollector", dep.OwnerReferences[0].Kind)

	// Verify finalizer is present.
	fetched := &instancev1alpha1.Metacollector{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, fetched)
	require.NoError(t, err)
	assert.Contains(t, fetched.Finalizers, finalizer)

	// Verify status is persisted.
	testutil.RequireCondition(t, fetched.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionTrue, ReasonResourceUpToDate)
	assert.Equal(t, int32(1), fetched.Status.DesiredReplicas)
}

// TestReconcile_Deletion verifies that deletion removes cluster-scoped resources and the finalizer.
func TestReconcile_Deletion(t *testing.T) {
	ctx := context.Background()
	resourceName := "test-delete"

	createMetacollector(t, ctx, resourceName)

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, resourceName, 3)

	// Verify finalizer and ClusterRole/CRB exist.
	fetched := &instancev1alpha1.Metacollector{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, fetched)
	require.NoError(t, err)
	assert.Contains(t, fetched.Finalizers, finalizer)

	uniqueName := GenerateUniqueName(resourceName, testNamespaceIntegration)
	cr := &rbacv1.ClusterRole{}
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, cr))
	crb := &rbacv1.ClusterRoleBinding{}
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, crb))

	// Delete MC.
	err = k8sClient.Delete(ctx, fetched)
	require.NoError(t, err)

	// Reconcile deletion.
	reconcileN(t, ctx, reconciler, resourceName, 1)

	// Verify MC deleted.
	err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, fetched)
	assert.True(t, errors.IsNotFound(err), "Metacollector should be deleted after finalizer removal")

	// Verify ClusterRole deleted.
	err = k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, cr)
	assert.True(t, errors.IsNotFound(err), "ClusterRole should be deleted")

	// Verify ClusterRoleBinding deleted.
	err = k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, crb)
	assert.True(t, errors.IsNotFound(err), "ClusterRoleBinding should be deleted")
}

// TestReconcile_UpdateDeployment verifies that updating the spec propagates changes to the Deployment.
func TestReconcile_UpdateDeployment(t *testing.T) {
	ctx := context.Background()
	resourceName := "test-update"

	createMetacollector(t, ctx, resourceName, withReplicas(1))

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, resourceName, 5)

	// Verify initial replicas.
	dep := &appsv1.Deployment{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, dep)
	require.NoError(t, err)
	require.NotNil(t, dep.Spec.Replicas)
	assert.Equal(t, int32(1), *dep.Spec.Replicas)

	// Update MC replicas to 3.
	fetched := &instancev1alpha1.Metacollector{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, fetched)
	require.NoError(t, err)

	newReplicas := int32(3)
	fetched.Spec.Replicas = &newReplicas
	err = k8sClient.Update(ctx, fetched)
	require.NoError(t, err)

	// Reconcile after update.
	reconcileN(t, ctx, reconciler, resourceName, 1)

	// Verify Deployment was updated.
	err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, dep)
	require.NoError(t, err)
	require.NotNil(t, dep.Spec.Replicas)
	assert.Equal(t, int32(3), *dep.Spec.Replicas)
}

// TestReconcile_StatusPersisted verifies that status conditions are actually persisted to the API server.
func TestReconcile_StatusPersisted(t *testing.T) {
	ctx := context.Background()
	resourceName := "test-status"

	createMetacollector(t, ctx, resourceName)

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, resourceName, 5)

	// Re-fetch from API — do NOT use the in-memory object.
	fetched := &instancev1alpha1.Metacollector{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespaceIntegration}, fetched)
	require.NoError(t, err)

	// Verify Reconciled condition is persisted with status True.
	testutil.RequireCondition(t, fetched.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionTrue, ReasonResourceUpToDate)

	// Verify Available condition is present (False/DeploymentUnavailable in envtest since pods don't actually become ready).
	testutil.RequireCondition(t, fetched.Status.Conditions,
		commonv1alpha1.ConditionAvailable.String(),
		metav1.ConditionFalse, ReasonDeploymentUnavailable)

	// Verify DesiredReplicas is set.
	assert.Equal(t, int32(1), fetched.Status.DesiredReplicas)
}
