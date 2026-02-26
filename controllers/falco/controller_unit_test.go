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

const (
	testNamespaceUnit  = "default"
	resourceConfigMaps = "configmaps"
)

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

// withLabels sets the Falco labels.
func withLabels(labels map[string]string) func(*instancev1alpha1.Falco) {
	return func(f *instancev1alpha1.Falco) {
		f.Labels = labels
	}
}

func TestEnsureResource(t *testing.T) {
	scheme := testScheme()

	tests := []struct {
		name           string
		falco          *instancev1alpha1.Falco
		existingObjs   []client.Object
		generator      func(client.Client, *instancev1alpha1.Falco) (*unstructured.Unstructured, error)
		validateResult func(*testing.T, client.Client, *instancev1alpha1.Falco)
		wantErr        string
	}{
		{
			name:      "creates ServiceAccount",
			falco:     newFalco("test-falco"),
			generator: generateServiceAccount,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				sa := &corev1.ServiceAccount{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(falco), sa)
				require.NoError(t, err)
				assert.Equal(t, falco.Name, sa.Name)
				assert.Equal(t, falco.Namespace, sa.Namespace)
			},
		},
		{
			name:      "creates Role with correct rules",
			falco:     newFalco("test-falco"),
			generator: generateRole,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				role := &rbacv1.Role{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(falco), role)
				require.NoError(t, err)
				assert.Equal(t, falco.Name, role.Name)
				require.NotEmpty(t, role.Rules)
				// Verify configmaps rule exists
				foundConfigMapRule := false
				for _, rule := range role.Rules {
					for _, resource := range rule.Resources {
						if resource == resourceConfigMaps {
							foundConfigMapRule = true
							assert.Contains(t, rule.Verbs, "get")
							assert.Contains(t, rule.Verbs, "list")
						}
					}
				}
				assert.True(t, foundConfigMapRule, "Role should have configmaps rule")
			},
		},
		{
			name:      "creates RoleBinding",
			falco:     newFalco("test-falco"),
			generator: generateRoleBinding,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				rb := &rbacv1.RoleBinding{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(falco), rb)
				require.NoError(t, err)
				assert.Equal(t, falco.Name, rb.Name)
				assert.Equal(t, falco.Name, rb.RoleRef.Name)
				require.Len(t, rb.Subjects, 1)
				assert.Equal(t, falco.Name, rb.Subjects[0].Name)
			},
		},
		{
			name:      "creates ClusterRole",
			falco:     newFalco("test-falco"),
			generator: generateClusterRole,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				cr := &rbacv1.ClusterRole{}
				expectedName := GenerateUniqueName(falco.Name, falco.Namespace)
				err := cl.Get(context.Background(), client.ObjectKey{Name: expectedName}, cr)
				require.NoError(t, err)
				assert.Equal(t, expectedName, cr.Name)
				require.NotEmpty(t, cr.Rules)
			},
		},
		{
			name:      "creates ClusterRoleBinding",
			falco:     newFalco("test-falco"),
			generator: generateClusterRoleBinding,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				crb := &rbacv1.ClusterRoleBinding{}
				expectedName := GenerateUniqueName(falco.Name, falco.Namespace)
				err := cl.Get(context.Background(), client.ObjectKey{Name: expectedName}, crb)
				require.NoError(t, err)
				assert.Equal(t, expectedName, crb.Name)
				assert.Equal(t, expectedName, crb.RoleRef.Name)
				require.Len(t, crb.Subjects, 1)
				assert.Equal(t, falco.Name, crb.Subjects[0].Name)
				assert.Equal(t, falco.Namespace, crb.Subjects[0].Namespace)
			},
		},
		{
			name:      "creates Service",
			falco:     newFalco("test-falco"),
			generator: generateService,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				svc := &corev1.Service{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(falco), svc)
				require.NoError(t, err)
				assert.Equal(t, falco.Name, svc.Name)
				require.NotEmpty(t, svc.Spec.Ports)
			},
		},
		{
			name:      "creates ConfigMap with DaemonSet config",
			falco:     newFalco("test-falco", withType(resourceTypeDaemonSet)),
			generator: generateConfigmap,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				cm := &corev1.ConfigMap{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(falco), cm)
				require.NoError(t, err)
				assert.Equal(t, falco.Name, cm.Name)
				assert.Contains(t, cm.Data, "falco.yaml")
				// Verify it contains DaemonSet-specific config
				assert.Contains(t, cm.Data["falco.yaml"], daemonsetFalcoConfig)
			},
		},
		{
			name:      "creates ConfigMap with Deployment config",
			falco:     newFalco("test-falco", withType(resourceTypeDeployment)),
			generator: generateConfigmap,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				cm := &corev1.ConfigMap{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(falco), cm)
				require.NoError(t, err)
				assert.Equal(t, falco.Name, cm.Name)
				assert.Contains(t, cm.Data, "falco.yaml")
				// Verify it contains Deployment-specific config
				assert.Contains(t, cm.Data["falco.yaml"], deploymentFalcoConfig)
			},
		},
		{
			name:  "updates existing ServiceAccount labels",
			falco: newFalco("test-falco", withLabels(map[string]string{"new": "label"})),
			existingObjs: []client.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-falco", Namespace: testNamespaceUnit,
						Labels: map[string]string{"old": "label"},
					},
				},
			},
			generator: generateServiceAccount,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				sa := &corev1.ServiceAccount{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(falco), sa)
				require.NoError(t, err)
				assert.Equal(t, "label", sa.Labels["new"])
			},
		},
		{
			name:  "preserves existing ServiceAccount annotations during update",
			falco: newFalco("test-falco"),
			existingObjs: []client.Object{
				&corev1.ServiceAccount{
					TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-falco", Namespace: testNamespaceUnit,
						Annotations: map[string]string{"existing": "annotation"},
					},
				},
			},
			generator: generateServiceAccount,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				sa := &corev1.ServiceAccount{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(falco), sa)
				require.NoError(t, err)
				// SSA should preserve existing annotations not managed by controller
				assert.Equal(t, "annotation", sa.Annotations["existing"])
			},
		},
		{
			name:  "updates Role when rules change",
			falco: newFalco("test-falco"),
			existingObjs: []client.Object{
				&rbacv1.Role{
					TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-falco", Namespace: testNamespaceUnit,
					},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"secrets"}, // Wrong resource, should be updated
							Verbs:     []string{"get"},
						},
					},
				},
			},
			generator: generateRole,
			validateResult: func(t *testing.T, cl client.Client, falco *instancev1alpha1.Falco) {
				role := &rbacv1.Role{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(falco), role)
				require.NoError(t, err)
				// Verify rules were updated to include configmaps
				foundConfigMapRule := false
				for _, rule := range role.Rules {
					for _, resource := range rule.Resources {
						if resource == resourceConfigMaps {
							foundConfigMapRule = true
						}
					}
				}
				assert.True(t, foundConfigMapRule, "Role should have configmaps rule after update")
			},
		},
		{
			name:      "returns error when generator fails with invalid Falco type",
			falco:     newFalco("test-falco", withType("InvalidType")),
			generator: generateConfigmap,
			wantErr:   "unsupported falco type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tt.falco}, tt.existingObjs...)
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			err := r.ensureResource(context.Background(), tt.falco, tt.generator)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, cl, tt.falco)
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
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			updated, err := r.ensureFinalizer(context.Background(), tt.falco)

			require.NoError(t, err)
			assert.Equal(t, tt.wantUpdated, updated)

			// Always verify finalizer is present after the call
			fetched := &instancev1alpha1.Falco{}
			err = cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), fetched)
			require.NoError(t, err)
			assert.Contains(t, fetched.Finalizers, finalizer)
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
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

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

	tests := []struct {
		name                   string
		falco                  *instancev1alpha1.Falco
		createClusterResources bool
		wantHandled            bool
		wantFinalizerPresent   bool
		wantClusterResExist    bool
	}{
		{
			name:                   "preserves finalizer and resources when not marked for deletion",
			falco:                  newFalco("test", withFinalizer()),
			createClusterResources: true,
			wantHandled:            false,
			wantFinalizerPresent:   true,
			wantClusterResExist:    true,
		},
		{
			name:                   "handles deletion when cluster resources do not exist",
			falco:                  newFalco("test", withFinalizer(), withDeletionTimestamp()),
			createClusterResources: false,
			wantHandled:            true,
			wantFinalizerPresent:   false,
			wantClusterResExist:    false,
		},
		{
			name:                   "removes cluster resources and finalizer during deletion",
			falco:                  newFalco("test", withFinalizer(), withDeletionTimestamp()),
			createClusterResources: true,
			wantHandled:            true,
			wantFinalizerPresent:   false,
			wantClusterResExist:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{tt.falco}
			if tt.createClusterResources {
				objs = append(objs,
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: GenerateUniqueName("test", testNamespaceUnit)}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: GenerateUniqueName("test", testNamespaceUnit)}},
				)
			}

			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			handled, err := r.handleDeletion(context.Background(), tt.falco)

			require.NoError(t, err)
			assert.Equal(t, tt.wantHandled, handled)

			// Verify finalizer state
			if tt.wantFinalizerPresent {
				assert.Contains(t, tt.falco.Finalizers, finalizer)
			} else {
				assert.NotContains(t, tt.falco.Finalizers, finalizer)
			}

			// Verify cluster resources state
			crErr := cl.Get(context.Background(), client.ObjectKey{Name: GenerateUniqueName("test", testNamespaceUnit)}, &rbacv1.ClusterRole{})
			crbErr := cl.Get(context.Background(), client.ObjectKey{Name: GenerateUniqueName("test", testNamespaceUnit)}, &rbacv1.ClusterRoleBinding{})

			if tt.wantClusterResExist {
				assert.NoError(t, crErr, "ClusterRole should exist")
				assert.NoError(t, crbErr, "ClusterRoleBinding should exist")
			} else if tt.createClusterResources {
				// Only check deletion if resources were created
				assert.Error(t, crErr, "ClusterRole should be deleted")
				assert.Error(t, crbErr, "ClusterRoleBinding should be deleted")
			}
		})
	}
}

func TestComputeAvailableCondition(t *testing.T) {
	scheme := testScheme()

	tests := []struct {
		name            string
		falco           *instancev1alpha1.Falco
		workload        client.Object // Deployment or DaemonSet
		wantDesired     int32
		wantAvailable   int32
		wantUnavailable int32
		wantErr         bool
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
			name:            "deployment not found sets zero availability",
			falco:           newFalco("test", withType("Deployment"), withReplicas(1)),
			wantDesired:     1,
			wantAvailable:   0,
			wantUnavailable: 0,
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
			name:            "daemonset not found sets zero availability",
			falco:           newFalco("test", withType("DaemonSet")),
			wantDesired:     0, // DaemonSet desired comes from status, not spec
			wantAvailable:   0,
			wantUnavailable: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{tt.falco}
			if tt.workload != nil {
				objs = append(objs, tt.workload)
			}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(tt.falco).Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			err := r.computeAvailableCondition(context.Background(), tt.falco)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantDesired, tt.falco.Status.DesiredReplicas)
			assert.Equal(t, tt.wantAvailable, tt.falco.Status.AvailableReplicas)
			assert.Equal(t, tt.wantUnavailable, tt.falco.Status.UnavailableReplicas)

			// computeAvailableCondition always sets the Available condition.
			assert.NotEmpty(t, tt.falco.Status.Conditions)
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
			name:  "preserves Deployment when no DaemonSet exists",
			falco: newFalco("test", withType("Deployment")),
			existingObjs: []client.Object{
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: testNamespaceUnit}},
			},
			// wantDeleted is empty, meaning nothing should be deleted
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
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10), false)

			err := r.cleanupDualDeployments(context.Background(), tt.falco)

			require.NoError(t, err)

			switch tt.wantDeleted {
			case resourceTypeDaemonSet:
				ds := &appsv1.DaemonSet{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), ds)
				assert.Error(t, err, "DaemonSet should be deleted")
			case resourceTypeDeployment:
				dep := &appsv1.Deployment{}
				err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), dep)
				assert.Error(t, err, "Deployment should be deleted")
			default:
				// When wantDeleted is empty, verify existing resources are preserved
				if tt.falco.Spec.Type == resourceTypeDeployment {
					dep := &appsv1.Deployment{}
					err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), dep)
					assert.NoError(t, err, "Deployment should still exist")
				}
				if tt.falco.Spec.Type == resourceTypeDaemonSet {
					ds := &appsv1.DaemonSet{}
					err := cl.Get(context.Background(), client.ObjectKeyFromObject(tt.falco), ds)
					assert.NoError(t, err, "DaemonSet should still exist")
				}
			}
		})
	}
}
