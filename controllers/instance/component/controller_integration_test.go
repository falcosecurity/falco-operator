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
	"os"
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
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
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
	return NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100))
}

// createComponent creates a Component resource and registers cleanup to run after the test.
func createComponent(t *testing.T, ctx context.Context, comp *instancev1alpha1.Component) *instancev1alpha1.Component {
	t.Helper()

	err := k8sClient.Create(ctx, comp)
	require.NoError(t, err)

	t.Cleanup(func() {
		fetched := &instancev1alpha1.Component{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, fetched); err == nil {
			fetched.Finalizers = nil
			_ = k8sClient.Update(ctx, fetched)
			_ = k8sClient.Delete(ctx, fetched)
		}
	})

	return comp
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

// TestReconcile_FullReconciliation verifies that all sub-resources are created after a full reconciliation.
func TestReconcile_FullReconciliation(t *testing.T) {
	ctx := context.Background()
	defs := resources.MetacollectorDefaults
	comp := createComponent(t, ctx, builders.NewComponent().
		WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
		WithName("test-full").WithNamespace(testutil.TestNamespace).Build())

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, comp.Name, 5)

	// Verify ServiceAccount.
	sa := &corev1.ServiceAccount{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, sa)
	require.NoError(t, err)
	assert.Equal(t, comp.Name, sa.Name)
	require.Len(t, sa.OwnerReferences, 1)
	assert.Equal(t, "Component", sa.OwnerReferences[0].Kind)

	// Verify ClusterRole.
	uniqueName := resources.GenerateUniqueName(comp.Name, testutil.TestNamespace)
	cr := &rbacv1.ClusterRole{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, cr)
	require.NoError(t, err)
	assert.NotEmpty(t, cr.Rules)

	// Verify ClusterRoleBinding.
	crb := &rbacv1.ClusterRoleBinding{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, crb)
	require.NoError(t, err)
	require.Len(t, crb.Subjects, 1)
	assert.Equal(t, comp.Name, crb.Subjects[0].Name)

	// Verify Service with 3 ports (metrics, health-probe, broker-grpc).
	svc := &corev1.Service{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, svc)
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
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, dep)
	require.NoError(t, err)
	require.NotEmpty(t, dep.Spec.Template.Spec.Containers)
	assert.Contains(t, dep.Spec.Template.Spec.Containers[0].Image, image.MetacollectorImage)
	require.Len(t, dep.OwnerReferences, 1)
	assert.Equal(t, "Component", dep.OwnerReferences[0].Kind)

	// Verify finalizer is present.
	fetched := &instancev1alpha1.Component{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)
	assert.Contains(t, fetched.Finalizers, finalizer)

	// Verify status is persisted.
	testutil.RequireCondition(t, fetched.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionTrue, instance.ReasonResourceUpToDate)
	assert.Equal(t, int32(1), fetched.Status.DesiredReplicas)

	// Verify defaults were used (sanity check).
	assert.Equal(t, defs.ContainerName, dep.Spec.Template.Spec.Containers[0].Name)
}

// TestReconcile_Deletion verifies that deletion removes cluster-scoped resources and the finalizer.
func TestReconcile_Deletion(t *testing.T) {
	ctx := context.Background()
	comp := createComponent(t, ctx, builders.NewComponent().
		WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
		WithName("test-delete").WithNamespace(testutil.TestNamespace).Build())

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, comp.Name, 3)

	// Verify finalizer and ClusterRole/CRB exist.
	fetched := &instancev1alpha1.Component{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)
	assert.Contains(t, fetched.Finalizers, finalizer)

	uniqueName := resources.GenerateUniqueName(comp.Name, testutil.TestNamespace)
	cr := &rbacv1.ClusterRole{}
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, cr))
	crb := &rbacv1.ClusterRoleBinding{}
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, crb))

	// Delete Component.
	err = k8sClient.Delete(ctx, fetched)
	require.NoError(t, err)

	// Reconcile deletion.
	reconcileN(t, ctx, reconciler, comp.Name, 1)

	// Verify Component deleted.
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, fetched)
	assert.True(t, errors.IsNotFound(err), "Component should be deleted after finalizer removal")

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
	comp := createComponent(t, ctx, builders.NewComponent().
		WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
		WithName("test-update").WithNamespace(testutil.TestNamespace).
		WithReplicas(1).Build())

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, comp.Name, 5)

	// Verify initial replicas.
	dep := &appsv1.Deployment{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, dep)
	require.NoError(t, err)
	require.NotNil(t, dep.Spec.Replicas)
	assert.Equal(t, int32(1), *dep.Spec.Replicas)

	// Update Component replicas to 3.
	fetched := &instancev1alpha1.Component{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)

	newReplicas := int32(3)
	fetched.Spec.Replicas = &newReplicas
	err = k8sClient.Update(ctx, fetched)
	require.NoError(t, err)

	// Reconcile after update.
	reconcileN(t, ctx, reconciler, comp.Name, 1)

	// Verify Deployment was updated.
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, dep)
	require.NoError(t, err)
	require.NotNil(t, dep.Spec.Replicas)
	assert.Equal(t, int32(3), *dep.Spec.Replicas)
}

// TestReconcile_StatusPersisted verifies that status conditions are actually persisted to the API server.
func TestReconcile_StatusPersisted(t *testing.T) {
	ctx := context.Background()
	comp := createComponent(t, ctx, builders.NewComponent().
		WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
		WithName("test-status").WithNamespace(testutil.TestNamespace).Build())

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, comp.Name, 5)

	// Re-fetch from API -- do NOT use the in-memory object.
	fetched := &instancev1alpha1.Component{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)

	// Verify Reconciled condition is persisted with status True.
	testutil.RequireCondition(t, fetched.Status.Conditions,
		commonv1alpha1.ConditionReconciled.String(),
		metav1.ConditionTrue, instance.ReasonResourceUpToDate)

	// Verify Available condition is present (False/DeploymentUnavailable in envtest since pods don't actually become ready).
	testutil.RequireCondition(t, fetched.Status.Conditions,
		commonv1alpha1.ConditionAvailable.String(),
		metav1.ConditionFalse, instance.ReasonDeploymentUnavailable)

	// Verify DesiredReplicas is set.
	assert.Equal(t, int32(1), fetched.Status.DesiredReplicas)
}

// TestReconcile_StatusInfo verifies that status.version and status.resourceType are set after reconciliation.
func TestReconcile_StatusInfo(t *testing.T) {
	ctx := context.Background()
	comp := createComponent(t, ctx, builders.NewComponent().
		WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
		WithName("test-status-info").WithNamespace(testutil.TestNamespace).Build())

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, comp.Name, 3)

	fetched := &instancev1alpha1.Component{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, fetched)
	require.NoError(t, err)
	assert.Nil(t, fetched.Spec.Component.Version, "spec.component.version should remain nil")
	assert.Equal(t, resources.MetacollectorDefaults.ImageTag, fetched.Status.Version)
	assert.Equal(t, resources.MetacollectorDefaults.ResourceType, fetched.Status.ResourceType)
}

// TestReconcile_FalcosidekickRoleCreation verifies that components with RoleRules
// get a namespace-scoped Role and RoleBinding, and components without ClusterRoleRules
// do NOT get an empty ClusterRole.
func TestReconcile_FalcosidekickRoleCreation(t *testing.T) {
	ctx := context.Background()
	comp := createComponent(t, ctx, builders.NewComponent().
		WithComponentType(instancev1alpha1.ComponentTypeFalcosidekick).
		WithName("test-sidekick-rbac").WithNamespace(testutil.TestNamespace).Build())

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, comp.Name, 5)

	// Verify Role exists with endpoint get permission.
	role := &rbacv1.Role{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, role)
	require.NoError(t, err, "Role should exist for falcosidekick")
	require.NotEmpty(t, role.Rules, "Role should have rules")
	assert.Contains(t, role.Rules[0].Resources, "endpoints", "Role should grant access to endpoints")
	assert.Contains(t, role.Rules[0].Verbs, "get", "Role should grant get verb")

	// Verify RoleBinding exists.
	rb := &rbacv1.RoleBinding{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, rb)
	require.NoError(t, err, "RoleBinding should exist for falcosidekick")
	require.Len(t, rb.Subjects, 1)
	assert.Equal(t, comp.Name, rb.Subjects[0].Name)

	// Verify ClusterRole does NOT exist (falcosidekick has no ClusterRoleRules).
	uniqueName := resources.GenerateUniqueName(comp.Name, testutil.TestNamespace)
	cr := &rbacv1.ClusterRole{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: uniqueName}, cr)
	assert.True(t, errors.IsNotFound(err), "ClusterRole should NOT exist for falcosidekick (no ClusterRoleRules)")

	// Verify Service exists with port 2801.
	svc := &corev1.Service{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, svc)
	require.NoError(t, err)
	require.Len(t, svc.Spec.Ports, 1)
	assert.Equal(t, int32(2801), svc.Spec.Ports[0].Port)

	// Verify Deployment.
	dep := &appsv1.Deployment{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, dep)
	require.NoError(t, err)
	assert.Contains(t, dep.Spec.Template.Spec.Containers[0].Image, image.FalcosidekickImage)
}

// TestReconcile_RecoveryAfterSubResourceDeletion verifies that the controller
// recreates a sub-resource (ServiceAccount) that was deleted externally.
func TestReconcile_RecoveryAfterSubResourceDeletion(t *testing.T) {
	ctx := context.Background()
	comp := createComponent(t, ctx, builders.NewComponent().
		WithComponentType(instancev1alpha1.ComponentTypeMetacollector).
		WithName("test-recovery").WithNamespace(testutil.TestNamespace).Build())

	reconciler := newTestReconciler()
	reconcileN(t, ctx, reconciler, comp.Name, 5)

	// Verify the ServiceAccount exists.
	sa := &corev1.ServiceAccount{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, sa)
	require.NoError(t, err, "ServiceAccount should exist after initial reconciliation")

	// Delete the ServiceAccount externally to simulate partial failure.
	err = k8sClient.Delete(ctx, sa)
	require.NoError(t, err, "should be able to delete ServiceAccount")

	// Confirm it is actually gone.
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, sa)
	require.True(t, errors.IsNotFound(err), "ServiceAccount should be deleted")

	// Reconcile again -- the controller should recreate the missing resource.
	reconcileN(t, ctx, reconciler, comp.Name, 1)

	// Verify the ServiceAccount was recreated.
	recreated := &corev1.ServiceAccount{}
	err = k8sClient.Get(ctx, types.NamespacedName{Name: comp.Name, Namespace: testutil.TestNamespace}, recreated)
	require.NoError(t, err, "ServiceAccount should be recreated after reconciliation")
	assert.Equal(t, comp.Name, recreated.Name)
	require.Len(t, recreated.OwnerReferences, 1)
	assert.Equal(t, "Component", recreated.OwnerReferences[0].Kind)
}
