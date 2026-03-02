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

package config

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
)

const testConfigName = "test-config"

const testConfigYAML = `engine:
  ebpf:
    buf_size_preset: 4
    drop_failed_exit: false
    probe: ${HOME}/.falco/falco-bpf.o
  kind: modern_ebpf
  kmod:
    buf_size_preset: 4
    drop_failed_exit: false
  modern_ebpf:
    buf_size_preset: 4
    cpus_for_each_buffer: 2
    drop_failed_exit: false
falco_libs:
  thread_table_size: 262144
file_output:
  enabled: false
  filename: ./events.txt
  keep_alive: false
grpc:
  bind_address: "unix:///run/falco/falco.sock"
  enabled: false
  threadiness: 1
`

func testFinalizerName() string {
	return common.FormatFinalizerName(configFinalizerPrefix, testutil.NodeName)
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*ConfigReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		Build()

	mockFS := filesystem.NewMockFileSystem()
	am := artifact.NewManagerWithOptions(cl, testutil.Namespace,
		artifact.WithFS(mockFS),
	)

	return &ConfigReconciler{
		Client:          cl,
		Scheme:          s,
		recorder:        events.NewFakeRecorder(100),
		finalizer:       testFinalizerName(),
		artifactManager: am,
		nodeName:        testutil.NodeName,
	}, cl
}

func TestNewConfigReconciler(t *testing.T) {
	s := testutil.Scheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	r := NewConfigReconciler(cl, s, events.NewFakeRecorder(10), "my-node", "my-namespace")

	require.NotNil(t, r)
	assert.Equal(t, "my-node", r.nodeName)
	assert.Equal(t, common.FormatFinalizerName(configFinalizerPrefix, "my-node"), r.finalizer)
	assert.NotNil(t, r.artifactManager)
	assert.NotNil(t, r.recorder)
}

func TestReconcile(t *testing.T) {
	tests := []struct {
		name            string
		objects         []client.Object
		req             ctrl.Request
		triggerDeletion bool
		writeErr        error
		wantErr         bool
		wantFinalizer   *bool
		wantConditions  []testutil.ConditionExpect
	}{
		{
			name: "resource not found returns no error",
			req:  testutil.Request("nonexistent"),
		},
		{
			name: "selector mismatch without finalizer",
			objects: []client.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   testutil.NodeName,
						Labels: map[string]string{"role": "worker"},
					},
				},
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testConfigName,
						Namespace: testutil.Namespace,
					},
					Spec: artifactv1alpha1.ConfigSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "gpu"},
						},
					},
				},
			},
			req:           testutil.Request(testConfigName),
			wantFinalizer: testutil.BoolPtr(false),
		},
		{
			name: "selector mismatch with finalizer removes finalizer",
			objects: []client.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   testutil.NodeName,
						Labels: map[string]string{"role": "worker"},
					},
				},
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testConfigName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.ConfigSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "gpu"},
						},
					},
				},
			},
			req:           testutil.Request(testConfigName),
			wantFinalizer: testutil.BoolPtr(false),
		},
		{
			name: "deletion with finalizer removes artifacts and finalizer",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testConfigName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.ConfigSpec{
						Config: "engine:\n  kind: modern_ebpf\n",
					},
				},
			},
			req:             testutil.Request(testConfigName),
			triggerDeletion: true,
			wantFinalizer:   testutil.BoolPtr(false),
		},
		{
			name: "sets finalizer on first reconcile and returns early",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testConfigName,
						Namespace: testutil.Namespace,
					},
					Spec: artifactv1alpha1.ConfigSpec{
						Config: "engine:\n  kind: modern_ebpf\n",
					},
				},
			},
			req:           testutil.Request(testConfigName),
			wantFinalizer: testutil.BoolPtr(true),
		},
		{
			name: "happy path with inline config stores config and sets conditions",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testConfigName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.ConfigSpec{
						Config:   testConfigYAML,
						Priority: 50,
					},
				},
			},
			req: testutil.Request(testConfigName),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "deletion without our finalizer is no-op",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testConfigName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{"some-other-finalizer"},
					},
				},
			},
			req:             testutil.Request(testConfigName),
			triggerDeletion: true,
		},
		{
			name: "node not found with selector returns error",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testConfigName,
						Namespace: testutil.Namespace,
					},
					Spec: artifactv1alpha1.ConfigSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "worker"},
						},
					},
				},
			},
			req:     testutil.Request(testConfigName),
			wantErr: true,
		},
		{
			name: "ensureConfig failure sets error conditions on status",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testConfigName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.ConfigSpec{
						Config:   testConfigYAML,
						Priority: 50,
					},
				},
			},
			req:      testutil.Request(testConfigName),
			writeErr: fmt.Errorf("disk full"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonInlineConfigStoreFailed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			if tt.writeErr != nil {
				mockFS := filesystem.NewMockFileSystem()
				mockFS.WriteErr = tt.writeErr
				r.artifactManager = artifact.NewManagerWithOptions(cl, testutil.Namespace,
					artifact.WithFS(mockFS),
				)
			}

			if tt.triggerDeletion {
				obj := &artifactv1alpha1.Config{}
				require.NoError(t, cl.Get(context.Background(), tt.req.NamespacedName, obj))
				require.NoError(t, cl.Delete(context.Background(), obj))
			}

			result, err := r.Reconcile(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, ctrl.Result{}, result)
			}

			if tt.wantFinalizer != nil {
				obj := &artifactv1alpha1.Config{}
				if err := cl.Get(context.Background(), tt.req.NamespacedName, obj); err == nil {
					assert.Equal(t, *tt.wantFinalizer, controllerutil.ContainsFinalizer(obj, testFinalizerName()))
				}
			}

			if len(tt.wantConditions) > 0 {
				obj := &artifactv1alpha1.Config{}
				require.NoError(t, cl.Get(context.Background(), tt.req.NamespacedName, obj))
				testutil.RequireConditions(t, obj.Status.Conditions, tt.wantConditions)
			}
		})
	}
}

func TestReconcile_GetErrorPropagates(t *testing.T) {
	s := testutil.Scheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return fmt.Errorf("internal server error")
			},
		}).
		Build()

	mockFS := filesystem.NewMockFileSystem()
	am := artifact.NewManagerWithOptions(cl, testutil.Namespace, artifact.WithFS(mockFS))
	r := &ConfigReconciler{
		Client:          cl,
		Scheme:          s,
		recorder:        events.NewFakeRecorder(100),
		finalizer:       testFinalizerName(),
		artifactManager: am,
		nodeName:        testutil.NodeName,
	}

	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
}

func TestEnsureFinalizer(t *testing.T) {
	tests := []struct {
		name       string
		finalizers []string
		wantOK     bool
	}{
		{
			name:   "adds finalizer when not present",
			wantOK: true,
		},
		{
			name:       "no-op when finalizer already present",
			finalizers: []string{testFinalizerName()},
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.Namespace,
					Finalizers: tt.finalizers,
				},
			}
			r, cl := newTestReconciler(t, config)

			fetched := &artifactv1alpha1.Config{}
			require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testConfigName, Namespace: testutil.Namespace}, fetched))

			ok, err := r.ensureFinalizer(context.Background(), fetched)

			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)

			if tt.wantOK {
				updated := &artifactv1alpha1.Config{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testConfigName, Namespace: testutil.Namespace}, updated))
				assert.True(t, controllerutil.ContainsFinalizer(updated, testFinalizerName()))
			}
		})
	}
}

func TestEnsureConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         *artifactv1alpha1.Config
		writeErr       error
		wantErr        bool
		wantConditions []testutil.ConditionExpect
	}{
		{
			name: "success stores inline config and sets conditions",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.Namespace,
					Generation: 1,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					Config:   testConfigYAML,
					Priority: 50,
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "failure sets error condition on inline content",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.Namespace,
					Generation: 2,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					Config:   testConfigYAML,
					Priority: 50,
				},
			},
			writeErr: fmt.Errorf("disk full"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonInlineConfigStoreFailed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t)

			if tt.writeErr != nil {
				mockFS := filesystem.NewMockFileSystem()
				mockFS.WriteErr = tt.writeErr
				r.artifactManager = artifact.NewManagerWithOptions(cl, testutil.Namespace,
					artifact.WithFS(mockFS),
				)
			}

			err := r.ensureConfig(context.Background(), tt.config)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			testutil.RequireConditions(t, tt.config.Status.Conditions, tt.wantConditions)
		})
	}
}

func TestPatchStatus(t *testing.T) {
	config := &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testConfigName,
			Namespace: testutil.Namespace,
		},
	}
	r, cl := newTestReconciler(t, config)

	fetched := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testConfigName, Namespace: testutil.Namespace}, fetched))

	fetched.Status.Conditions = []metav1.Condition{
		common.NewReconciledCondition(metav1.ConditionTrue, artifact.ReasonReconciled, artifact.MessageConfigReconciled, 1),
	}

	require.NoError(t, r.patchStatus(context.Background(), fetched))

	obj := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testConfigName, Namespace: testutil.Namespace}, obj))
	testutil.RequireConditions(t, obj.Status.Conditions, []testutil.ConditionExpect{
		{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReconciled},
	})
}
