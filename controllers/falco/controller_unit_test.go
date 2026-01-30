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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// testScheme returns a scheme with all required types registered.
func testScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = instancev1alpha1.AddToScheme(scheme)
	return scheme
}

const testNamespaceUnit = "default"

// newFalco creates a basic Falco instance for testing.
func newFalco(name string, opts ...func(*instancev1alpha1.Falco)) *instancev1alpha1.Falco {
	f := &instancev1alpha1.Falco{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespaceUnit,
		},
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// withFinalizer adds the finalizer to the Falco instance.
func withFinalizer() func(*instancev1alpha1.Falco) {
	return func(f *instancev1alpha1.Falco) {
		f.Finalizers = []string{finalizer}
	}
}

// withDeletionTimestamp sets the deletion timestamp.
func withDeletionTimestamp() func(*instancev1alpha1.Falco) {
	return func(f *instancev1alpha1.Falco) {
		now := metav1.Now()
		f.DeletionTimestamp = &now
	}
}

// withType sets the Falco type (Deployment or DaemonSet).
func withType(t string) func(*instancev1alpha1.Falco) {
	return func(f *instancev1alpha1.Falco) {
		f.Spec.Type = t
	}
}

// withReplicas sets the number of replicas.
func withReplicas(r int32) func(*instancev1alpha1.Falco) {
	return func(f *instancev1alpha1.Falco) {
		f.Spec.Replicas = &r
	}
}

// withVersion sets the Falco version.
func withVersion(v string) func(*instancev1alpha1.Falco) {
	return func(f *instancev1alpha1.Falco) {
		f.Spec.Version = v
	}
}

// withImage sets the Falco container image.
func withImage(image string) func(*instancev1alpha1.Falco) {
	return func(f *instancev1alpha1.Falco) {
		f.Spec.PodTemplateSpec = &corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "falco", Image: image}},
			},
		}
	}
}

func TestEnsureResource(t *testing.T) {
	scheme := testScheme()

	// Generator that creates a ServiceAccount
	saGenerator := func(labels map[string]string) func(context.Context, client.Client, *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
		return func(_ context.Context, _ client.Client, f *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
			sa := &corev1.ServiceAccount{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
				ObjectMeta: metav1.ObjectMeta{Name: f.Name, Namespace: f.Namespace, Labels: labels},
			}
			return toUnstructured(sa)
		}
	}

	tests := []struct {
		name           string
		existingObjs   []client.Object
		generator      func(context.Context, client.Client, *instancev1alpha1.Falco) (*unstructured.Unstructured, error)
		wantErr        bool
		errContains    string
		validateResult func(*testing.T, client.Client)
	}{
		{
			name:      "creates new resource",
			generator: saGenerator(nil),
			validateResult: func(t *testing.T, cl client.Client) {
				sa := &corev1.ServiceAccount{}
				err := cl.Get(context.Background(), client.ObjectKey{Name: "test-falco", Namespace: testNamespaceUnit}, sa)
				require.NoError(t, err)
				assert.Equal(t, "test-falco", sa.Name)
			},
		},
		{
			name: "updates existing resource",
			existingObjs: []client.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-falco", Namespace: testNamespaceUnit, Labels: map[string]string{"old": "label"},
					},
				},
			},
			generator: saGenerator(map[string]string{"new": "label"}),
			validateResult: func(t *testing.T, cl client.Client) {
				sa := &corev1.ServiceAccount{}
				err := cl.Get(context.Background(), client.ObjectKey{Name: "test-falco", Namespace: testNamespaceUnit}, sa)
				require.NoError(t, err)
				assert.Equal(t, "label", sa.Labels["new"])
			},
		},
		{
			name: "handles no-change scenario",
			existingObjs: []client.Object{
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "test-falco", Namespace: testNamespaceUnit}},
			},
			generator: saGenerator(nil),
		},
		{
			name: "returns error when generator fails",
			generator: func(_ context.Context, _ client.Client, _ *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
				return nil, assert.AnError
			},
			wantErr:     true,
			errContains: "unable to generate desired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			falco := newFalco("test-falco")
			objs := append([]client.Object{falco}, tt.existingObjs...)
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := &Reconciler{Client: cl, Scheme: scheme, ReconciledConditions: map[string]metav1.Condition{}}

			err := r.ensureResource(context.Background(), falco, "ServiceAccount", tt.generator)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, cl)
			}
		})
	}
}

func TestEnsureFinalizer(t *testing.T) {
	scheme := testScheme()

	tests := []struct {
		name        string
		falco       *instancev1alpha1.Falco
		wantUpdated bool
	}{
		{
			name:        "adds finalizer when not present",
			falco:       newFalco("test"),
			wantUpdated: true,
		},
		{
			name:        "no-op when finalizer already present",
			falco:       newFalco("test", withFinalizer()),
			wantUpdated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.falco).Build()
			r := &Reconciler{Client: cl, Scheme: scheme, ReconciledConditions: map[string]metav1.Condition{}}

			updated, err := r.ensureFinalizer(context.Background(), tt.falco)

			require.NoError(t, err)
			assert.Equal(t, tt.wantUpdated, updated)

			if tt.wantUpdated {
				fetched := &instancev1alpha1.Falco{}
				_ = cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), fetched)
				assert.Contains(t, fetched.Finalizers, finalizer)
			}
		})
	}
}

func TestEnsureVersion(t *testing.T) {
	scheme := testScheme()

	tests := []struct {
		name        string
		falco       *instancev1alpha1.Falco
		wantUpdated bool
		wantVersion string
	}{
		{
			name:        "sets default version when not set",
			falco:       newFalco("test"),
			wantUpdated: true,
		},
		{
			name:        "keeps existing version",
			falco:       newFalco("test", withVersion("0.40.0")),
			wantUpdated: false,
			wantVersion: "0.40.0",
		},
		{
			name:        "extracts version from image",
			falco:       newFalco("test", withImage("falcosecurity/falco:0.38.0")),
			wantUpdated: true,
			wantVersion: "0.38.0",
		},
		{
			name:        "image version takes precedence over spec version",
			falco:       newFalco("test", withVersion("0.35.0"), withImage("falcosecurity/falco:0.39.0")),
			wantUpdated: true,
			wantVersion: "0.39.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.falco).Build()
			r := &Reconciler{Client: cl, Scheme: scheme, ReconciledConditions: map[string]metav1.Condition{}}

			updated, err := r.ensureVersion(context.Background(), tt.falco)

			require.NoError(t, err)
			assert.Equal(t, tt.wantUpdated, updated)
			if tt.wantVersion != "" {
				assert.Equal(t, tt.wantVersion, tt.falco.Spec.Version)
			} else if tt.wantUpdated {
				assert.NotEmpty(t, tt.falco.Spec.Version)
			}
		})
	}
}

func TestHandleDeletion(t *testing.T) {
	scheme := testScheme()

	t.Run("no-op when not marked for deletion", func(t *testing.T) {
		falco := newFalco("test")
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
		r := &Reconciler{Client: cl, Scheme: scheme, ReconciledConditions: map[string]metav1.Condition{}}

		handled, err := r.handleDeletion(context.Background(), falco)

		require.NoError(t, err)
		assert.False(t, handled)
	})

	t.Run("handles deletion without finalizer", func(t *testing.T) {
		// Create without deletion timestamp, then set it in-memory
		// (fake client doesn't allow creating with deletionTimestamp but no finalizers)
		falco := newFalco("test")
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco).Build()
		r := &Reconciler{Client: cl, Scheme: scheme, ReconciledConditions: map[string]metav1.Condition{}}

		// Set deletion timestamp in-memory to simulate the scenario
		now := metav1.Now()
		falco.DeletionTimestamp = &now

		handled, err := r.handleDeletion(context.Background(), falco)

		require.NoError(t, err)
		assert.True(t, handled)
	})

	t.Run("removes cluster resources and finalizer during deletion", func(t *testing.T) {
		falco := newFalco("test", withFinalizer(), withDeletionTimestamp())
		cr := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: GenerateUniqueName("test", testNamespaceUnit)}}
		crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: GenerateUniqueName("test", testNamespaceUnit)}}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(falco, cr, crb).Build()
		r := &Reconciler{Client: cl, Scheme: scheme, ReconciledConditions: map[string]metav1.Condition{}}

		// Verify finalizer is present before deletion
		assert.Contains(t, falco.Finalizers, finalizer, "finalizer should be present before handleDeletion")

		handled, err := r.handleDeletion(context.Background(), falco)

		require.NoError(t, err)
		assert.True(t, handled)

		// Verify finalizer was removed
		assert.NotContains(t, falco.Finalizers, finalizer, "finalizer should be removed after handleDeletion")

		// Verify ClusterRole was deleted
		fetchedCR := &rbacv1.ClusterRole{}
		err = cl.Get(context.Background(), client.ObjectKey{Name: GenerateUniqueName("test", testNamespaceUnit)}, fetchedCR)
		assert.Error(t, err, "ClusterRole should be deleted")

		// Verify ClusterRoleBinding was deleted
		fetchedCRB := &rbacv1.ClusterRoleBinding{}
		err = cl.Get(context.Background(), client.ObjectKey{Name: GenerateUniqueName("test", testNamespaceUnit)}, fetchedCRB)
		assert.Error(t, err, "ClusterRoleBinding should be deleted")
	})
}

func TestUpdateStatus(t *testing.T) {
	scheme := testScheme()

	tests := []struct {
		name                 string
		falco                *instancev1alpha1.Falco
		workload             client.Object // Deployment or DaemonSet
		wantDesired          int32
		wantAvailable        int32
		wantUnavailable      int32
		withReconciledCond   bool
		wantConditionsNotNil bool
	}{
		{
			name:  "deployment available",
			falco: newFalco("test", withType("Deployment"), withReplicas(2)),
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testNamespaceUnit},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 2, AvailableReplicas: 2, UnavailableReplicas: 0},
			},
			wantDesired: 2, wantAvailable: 2, wantUnavailable: 0,
		},
		{
			name:  "deployment unavailable",
			falco: newFalco("test", withType("Deployment"), withReplicas(3)),
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testNamespaceUnit},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1, UnavailableReplicas: 2},
			},
			wantDesired: 3, wantAvailable: 1, wantUnavailable: 2,
		},
		{
			name:        "deployment not found",
			falco:       newFalco("test", withType("Deployment"), withReplicas(1)),
			wantDesired: 1,
		},
		{
			name:  "daemonset available",
			falco: newFalco("test", withType("DaemonSet")),
			workload: &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testNamespaceUnit},
				Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberAvailable: 3, NumberUnavailable: 0},
			},
			wantDesired: 3, wantAvailable: 3, wantUnavailable: 0,
		},
		{
			name:  "daemonset unavailable",
			falco: newFalco("test", withType("DaemonSet")),
			workload: &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testNamespaceUnit},
				Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 5, NumberAvailable: 3, NumberUnavailable: 2},
			},
			wantDesired: 5, wantAvailable: 3, wantUnavailable: 2,
		},
		{
			name:  "daemonset not found",
			falco: newFalco("test", withType("DaemonSet")),
		},
		{
			name:  "with reconciled condition",
			falco: newFalco("test", withType("Deployment"), withReplicas(1)),
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testNamespaceUnit},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 1},
			},
			withReconciledCond:   true,
			wantConditionsNotNil: true,
			wantDesired:          1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{tt.falco}
			if tt.workload != nil {
				objs = append(objs, tt.workload)
			}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(tt.falco).Build()
			r := &Reconciler{Client: cl, Scheme: scheme, ReconciledConditions: map[string]metav1.Condition{}}

			if tt.withReconciledCond {
				r.ReconciledConditions["default/test"] = metav1.Condition{
					Type: "Reconciled", Status: metav1.ConditionTrue, Reason: "Success",
				}
			}

			err := r.updateStatus(context.Background(), tt.falco)

			require.NoError(t, err)
			assert.Equal(t, tt.wantDesired, tt.falco.Status.DesiredReplicas)
			assert.Equal(t, tt.wantAvailable, tt.falco.Status.AvailableReplicas)
			assert.Equal(t, tt.wantUnavailable, tt.falco.Status.UnavailableReplicas)

			if tt.wantConditionsNotNil {
				assert.NotEmpty(t, tt.falco.Status.Conditions)
			}
		})
	}
}

func TestCleanupDualDeployments(t *testing.T) {
	scheme := testScheme()

	tests := []struct {
		name         string
		falco        *instancev1alpha1.Falco
		existingObjs []client.Object
		wantDeleted  string // "Deployment" or "DaemonSet" that should be deleted
	}{
		{
			name:  "no-op when no opposite type exists",
			falco: newFalco("test", withType("Deployment")),
		},
		{
			name:  "deletes DaemonSet when type is Deployment",
			falco: newFalco("test", withType("Deployment")),
			existingObjs: []client.Object{
				&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testNamespaceUnit}},
			},
			wantDeleted: "DaemonSet",
		},
		{
			name:  "deletes Deployment when type is DaemonSet",
			falco: newFalco("test", withType("DaemonSet")),
			existingObjs: []client.Object{
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testNamespaceUnit}},
			},
			wantDeleted: "Deployment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tt.falco}, tt.existingObjs...)
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := &Reconciler{Client: cl, Scheme: scheme, ReconciledConditions: map[string]metav1.Condition{}}

			err := r.cleanupDualDeployments(context.Background(), tt.falco)

			require.NoError(t, err)

			if tt.wantDeleted == "DaemonSet" {
				ds := &appsv1.DaemonSet{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), ds)
				assert.Error(t, err, "DaemonSet should be deleted")
			}
			if tt.wantDeleted == "Deployment" {
				dep := &appsv1.Deployment{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), dep)
				assert.Error(t, err, "Deployment should be deleted")
			}
		})
	}
}

func TestReconcilerConditionsMap(t *testing.T) {
	r := &Reconciler{ReconciledConditions: map[string]metav1.Condition{}}

	assert.Empty(t, r.ReconciledConditions)

	condition := metav1.Condition{
		Type:               "Reconciled",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: time.Now()},
		Reason:             "TestReason",
		Message:            "Test message",
	}
	r.ReconciledConditions["default/test"] = condition

	stored, ok := r.ReconciledConditions["default/test"]
	assert.True(t, ok)
	assert.Equal(t, "TestReason", stored.Reason)
}
