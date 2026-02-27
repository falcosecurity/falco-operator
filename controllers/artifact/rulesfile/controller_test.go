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

package rulesfile

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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

const testRulesfileName = "test-rulesfile"

var testInlineRules = "- rule: test_rule\n  desc: test\n  condition: always_true\n  output: test\n  priority: WARNING\n"

func testFinalizerName() string {
	return common.FormatFinalizerName(rulesfileFinalizerPrefix, testutil.NodeName)
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*RulesfileReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Rulesfile{}).
		Build()

	mockFS := filesystem.NewMockFileSystem()
	am := artifact.NewManagerWithOptions(cl, testutil.Namespace,
		artifact.WithFS(mockFS),
		artifact.WithOCIPuller(&puller.MockOCIPuller{}),
	)

	return &RulesfileReconciler{
		Client:          cl,
		Scheme:          s,
		recorder:        events.NewFakeRecorder(100),
		finalizer:       testFinalizerName(),
		artifactManager: am,
		nodeName:        testutil.NodeName,
		namespace:       testutil.Namespace,
	}, cl
}

func TestNewRulesfileReconciler(t *testing.T) {
	s := testutil.Scheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	r := NewRulesfileReconciler(cl, s, events.NewFakeRecorder(10), "my-node", "my-namespace")

	require.NotNil(t, r)
	assert.Equal(t, "my-node", r.nodeName)
	assert.Equal(t, "my-namespace", r.namespace)
	assert.Equal(t, common.FormatFinalizerName(rulesfileFinalizerPrefix, "my-node"), r.finalizer)
	assert.NotNil(t, r.artifactManager)
}

func TestReconcile(t *testing.T) {
	tests := []struct {
		name            string
		objects         []client.Object
		req             ctrl.Request
		triggerDeletion bool
		pullErr         error
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
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testRulesfileName,
						Namespace: testutil.Namespace,
					},
					Spec: artifactv1alpha1.RulesfileSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "gpu"},
						},
					},
				},
			},
			req:           testutil.Request(testRulesfileName),
			wantFinalizer: testutil.BoolPtr(false),
		},
		{
			name: "selector mismatch with finalizer removes artifacts and finalizer",
			objects: []client.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   testutil.NodeName,
						Labels: map[string]string{"role": "worker"},
					},
				},
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testRulesfileName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.RulesfileSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "gpu"},
						},
					},
				},
			},
			req:           testutil.Request(testRulesfileName),
			wantFinalizer: testutil.BoolPtr(false),
		},
		{
			name: "deletion with finalizer removes artifacts and finalizer",
			objects: []client.Object{
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testRulesfileName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
				},
			},
			req:             testutil.Request(testRulesfileName),
			triggerDeletion: true,
			wantFinalizer:   testutil.BoolPtr(false),
		},
		{
			name: "sets finalizer on first reconcile",
			objects: []client.Object{
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testRulesfileName,
						Namespace: testutil.Namespace,
					},
				},
			},
			req:           testutil.Request(testRulesfileName),
			wantFinalizer: testutil.BoolPtr(true),
		},
		{
			name: "happy path with inline rules",
			objects: []client.Object{
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testRulesfileName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.RulesfileSpec{
						InlineRules: &testInlineRules,
					},
				},
			},
			req: testutil.Request(testRulesfileName),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineContent.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineRulesStored},
				{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReconciled},
			},
		},
		{
			name: "OCI artifact pull error sets failure conditions",
			objects: []client.Object{
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testRulesfileName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.RulesfileSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Reference: "ghcr.io/falcosecurity/rules/falco-rules:latest",
						},
					},
				},
			},
			req:     testutil.Request(testRulesfileName),
			pullErr: fmt.Errorf("mock pull error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionOCIArtifact.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactStoreFailed},
				{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReconcileFailed},
			},
		},
		{
			name: "node not found with selector returns error",
			objects: []client.Object{
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testRulesfileName,
						Namespace: testutil.Namespace,
					},
					Spec: artifactv1alpha1.RulesfileSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "worker"},
						},
					},
				},
			},
			req:     testutil.Request(testRulesfileName),
			wantErr: true,
		},
		{
			name: "happy path with configmap ref",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-rules-cm",
						Namespace: testutil.Namespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testInlineRules,
					},
				},
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testRulesfileName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.RulesfileSpec{
						ConfigMapRef: &commonv1alpha1.ConfigMapRef{
							Name: "my-rules-cm",
						},
					},
				},
			},
			req: testutil.Request(testRulesfileName),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRef.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReconciled},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			if tt.pullErr != nil {
				mockFS := filesystem.NewMockFileSystem()
				r.artifactManager = artifact.NewManagerWithOptions(cl, testutil.Namespace,
					artifact.WithFS(mockFS),
					artifact.WithOCIPuller(&puller.MockOCIPuller{PullErr: tt.pullErr}),
				)
			}

			if tt.triggerDeletion {
				obj := &artifactv1alpha1.Rulesfile{}
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
				obj := &artifactv1alpha1.Rulesfile{}
				if err := cl.Get(context.Background(), tt.req.NamespacedName, obj); err == nil {
					assert.Equal(t, *tt.wantFinalizer, controllerutil.ContainsFinalizer(obj, testFinalizerName()))
				}
			}

			if len(tt.wantConditions) > 0 {
				obj := &artifactv1alpha1.Rulesfile{}
				require.NoError(t, cl.Get(context.Background(), tt.req.NamespacedName, obj))
				testutil.RequireConditions(t, obj.Status.Conditions, tt.wantConditions)
			}
		})
	}
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
			rf := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testRulesfileName,
					Namespace:  testutil.Namespace,
					Finalizers: tt.finalizers,
				},
			}
			r, cl := newTestReconciler(t, rf)

			fetched := &artifactv1alpha1.Rulesfile{}
			require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testRulesfileName, Namespace: testutil.Namespace}, fetched))

			ok, err := r.ensureFinalizer(context.Background(), fetched)

			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)

			if tt.wantOK {
				updated := &artifactv1alpha1.Rulesfile{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testRulesfileName, Namespace: testutil.Namespace}, updated))
				assert.True(t, controllerutil.ContainsFinalizer(updated, testFinalizerName()))
			}
		})
	}
}

func TestEnsureRulesfile(t *testing.T) {
	tests := []struct {
		name                   string
		objects                []client.Object
		rf                     *artifactv1alpha1.Rulesfile
		writeErr               error
		pullErr                error
		wantErr                bool
		wantConditions         []testutil.ConditionExpect
		wantNoSourceConditions bool
	}{
		{
			name: "OCI pull error sets failure condition",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Reference: "ghcr.io/falcosecurity/rules/falco-rules:latest",
					},
				},
			},
			pullErr: fmt.Errorf("mock pull error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionOCIArtifact.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactStoreFailed},
				{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReconcileFailed},
			},
		},
		{
			name: "stores inline rules successfully",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &testInlineRules,
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineContent.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineRulesStored},
				{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReconciled},
			},
		},
		{
			name: "stores configmap ref successfully",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-rules-cm",
						Namespace: testutil.Namespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testInlineRules,
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{
						Name: "my-rules-cm",
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRef.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReconciled},
			},
		},
		{
			name: "inline rules store failure sets condition",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &testInlineRules,
				},
			},
			writeErr: fmt.Errorf("mock write error"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineContent.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonInlineRulesStoreFailed},
				{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReconcileFailed},
			},
		},
		{
			name: "configmap ref store fails on filesystem write error",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-rules-cm",
						Namespace: testutil.Namespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testInlineRules,
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{
						Name: "my-rules-cm",
					},
				},
			},
			writeErr: fmt.Errorf("mock write error"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRef.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
				{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReconcileFailed},
			},
		},
		{
			name: "removes conditions for absent source types",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
				Status: artifactv1alpha1.RulesfileStatus{
					Conditions: []metav1.Condition{
						{Type: commonv1alpha1.ConditionOCIArtifact.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactStored},
						{Type: commonv1alpha1.ConditionInlineContent.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineRulesStored},
						{Type: commonv1alpha1.ConditionResolvedRef.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
					},
				},
			},
			wantNoSourceConditions: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReconciled},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			if tt.writeErr != nil || tt.pullErr != nil {
				mockFS := filesystem.NewMockFileSystem()
				if tt.writeErr != nil {
					mockFS.WriteErr = tt.writeErr
				}
				r.artifactManager = artifact.NewManagerWithOptions(cl, testutil.Namespace,
					artifact.WithFS(mockFS),
					artifact.WithOCIPuller(&puller.MockOCIPuller{PullErr: tt.pullErr}),
				)
			}

			err := r.ensureRulesfile(context.Background(), tt.rf)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if len(tt.wantConditions) > 0 {
				testutil.RequireConditions(t, tt.rf.Status.Conditions, tt.wantConditions)
			}

			if tt.wantNoSourceConditions {
				for _, c := range tt.rf.Status.Conditions {
					assert.NotEqual(t, commonv1alpha1.ConditionOCIArtifact.String(), c.Type)
					assert.NotEqual(t, commonv1alpha1.ConditionInlineContent.String(), c.Type)
					assert.NotEqual(t, commonv1alpha1.ConditionResolvedRef.String(), c.Type)
				}
			}
		})
	}
}

func TestPatchStatus(t *testing.T) {
	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRulesfileName,
			Namespace: testutil.Namespace,
		},
	}
	r, cl := newTestReconciler(t, rf)

	fetched := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testRulesfileName, Namespace: testutil.Namespace}, fetched))

	fetched.Status.Conditions = []metav1.Condition{
		common.NewReconciledCondition(metav1.ConditionTrue, artifact.ReasonReconciled, artifact.MessageRulesfileReconciled, 1),
	}

	require.NoError(t, r.patchStatus(context.Background(), fetched))

	obj := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testRulesfileName, Namespace: testutil.Namespace}, obj))
	testutil.RequireConditions(t, obj.Status.Conditions, []testutil.ConditionExpect{
		{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReconciled},
	})
}

func TestIndexRulesfileByConfigMapRef(t *testing.T) {
	tests := []struct {
		name     string
		rf       *artifactv1alpha1.Rulesfile
		expected []string
	}{
		{
			name: "returns nil when no configmap ref",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			expected: nil,
		},
		{
			name: "returns index key when configmap ref present",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{
						Name: "my-rules-cm",
					},
				},
			},
			expected: []string{testutil.Namespace + "/my-rules-cm"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := indexRulesfileByConfigMapRef(tt.rf)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindRulesfilesForConfigMap(t *testing.T) {
	s := testutil.Scheme(t)
	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRulesfileName,
			Namespace: testutil.Namespace,
		},
		Spec: artifactv1alpha1.RulesfileSpec{
			ConfigMapRef: &commonv1alpha1.ConfigMapRef{
				Name: "my-rules-cm",
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rf).
		WithIndex(&artifactv1alpha1.Rulesfile{}, configMapRefIndexField, indexRulesfileByConfigMapRef).
		Build()

	mockFS := filesystem.NewMockFileSystem()
	am := artifact.NewManagerWithOptions(cl, testutil.Namespace,
		artifact.WithFS(mockFS),
		artifact.WithOCIPuller(&puller.MockOCIPuller{}),
	)

	r := &RulesfileReconciler{
		Client:          cl,
		Scheme:          s,
		recorder:        events.NewFakeRecorder(100),
		finalizer:       testFinalizerName(),
		artifactManager: am,
		nodeName:        testutil.NodeName,
		namespace:       testutil.Namespace,
	}

	tests := []struct {
		name          string
		configMapName string
		wantCount     int
	}{
		{
			name:          "matching configmap returns rulesfile requests",
			configMapName: "my-rules-cm",
			wantCount:     1,
		},
		{
			name:          "non-matching configmap returns empty",
			configMapName: "other-cm",
			wantCount:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tt.configMapName,
					Namespace: testutil.Namespace,
				},
			}
			requests := r.findRulesfilesForConfigMap(context.Background(), cm)
			require.Len(t, requests, tt.wantCount)
			if tt.wantCount > 0 {
				assert.Equal(t, testRulesfileName, requests[0].Name)
				assert.Equal(t, testutil.Namespace, requests[0].Namespace)
			}
		})
	}
}
