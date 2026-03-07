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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

const testRulesfileName = "test-rulesfile"

// testInlineRulesJSON is sample Falco rules in JSON format (used for *apiextensionsv1.JSON fields).
const testInlineRulesJSON = `[{"rule":"test_rule","desc":"test","condition":"always_true","output":"test","priority":"WARNING"}]`

// testInlineRulesYAML is the expected YAML representation of testInlineRulesJSON after conversion.
const testInlineRulesYAML = "- condition: always_true\n  desc: test\n  output: test\n  priority: WARNING\n  rule: test_rule\n"

// testRulesData is used as a ConfigMap data value for rules.yaml.
const testRulesData = "- rule: test_rule\n  desc: test\n  condition: always_true\n  output: test\n  priority: WARNING\n"

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
			wantFinalizer: new(false),
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
			wantFinalizer: new(false),
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
			wantFinalizer:   new(false),
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
			wantFinalizer: new(true),
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
						InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
					},
				},
			},
			req: testutil.Request(testRulesfileName),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
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
							Image: commonv1alpha1.ImageSpec{
								Repository: "falcosecurity/rules/falco-rules",
								Tag:        "latest",
							},
						},
					},
				},
			},
			req:     testutil.Request(testRulesfileName),
			pullErr: fmt.Errorf("mock pull error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactStoreFailed},
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
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
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
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "references resolved but OCI pull fails sets ResolvedRefs true and Programmed false",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-pull-secret",
						Namespace: testutil.Namespace,
					},
				},
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testRulesfileName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.RulesfileSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{
								Repository: "falcosecurity/rules/falco-rules",
								Tag:        "latest",
							},
							Registry: &commonv1alpha1.RegistryConfig{
								Auth: &commonv1alpha1.RegistryAuth{
									SecretRef: &commonv1alpha1.SecretRef{Name: "my-pull-secret"},
								},
							},
						},
					},
				},
			},
			req:     testutil.Request(testRulesfileName),
			pullErr: fmt.Errorf("mock pull error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactStoreFailed},
			},
		},
		{
			name: "references resolved but configmap store fails sets ResolvedRefs true and Programmed false",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-rules-cm",
						Namespace: testutil.Namespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
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
			req:      testutil.Request(testRulesfileName),
			writeErr: fmt.Errorf("disk full"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonConfigMapRulesStoreFailed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			if tt.pullErr != nil || tt.writeErr != nil {
				mockFS := filesystem.NewMockFileSystem()
				if tt.writeErr != nil {
					mockFS.WriteErr = tt.writeErr
				}
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
		name     string
		objects  []client.Object
		preRf    *artifactv1alpha1.Rulesfile // reconciled first to set up prior state
		rf       *artifactv1alpha1.Rulesfile
		writeErr error
		pullErr  error
		// useRealFS uses a real OS filesystem backed by a temp dir instead of the mock FS.
		// Required for test cases that exercise the full OCI pull path (ExtractTarGz uses os.* directly).
		useRealFS      bool
		wantErr        bool
		wantConditions []testutil.ConditionExpect
		// wantFiles is nil to skip the check; an empty slice asserts no files remain (mock FS only).
		wantFiles []string
		// wantDirEmpty asserts the rulesfile temp dir is empty after the test (real FS only).
		wantDirEmpty bool
		// wantEvents is nil to skip the check; otherwise asserts the exact set of events recorded during the main call.
		wantEvents []string
	}{
		{
			name: "OCI pull error sets failure condition",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{
							Repository: "falcosecurity/rules/falco-rules",
							Tag:        "latest",
						},
					},
				},
			},
			pullErr: fmt.Errorf("mock pull error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactStoreFailed},
			},
			wantEvents: []string{"Warning OCIArtifactStoreFailed Failed to store OCI artifact: mock pull error"},
		},
		{
			name: "stores inline rules successfully",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
			wantFiles:  []string{testInlineRulesYAML},
			wantEvents: []string{"Normal InlineArtifactStored Inline artifact stored successfully"},
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
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
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
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
			wantFiles:  []string{testRulesData},
			wantEvents: []string{"Normal ConfigMapArtifactStored ConfigMap artifact stored successfully"},
		},
		{
			name: "both inline and configmap sources write two files",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-rules-cm",
						Namespace: testutil.Namespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules:  &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-rules-cm"},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
			wantFiles: []string{testInlineRulesYAML, testRulesData},
			wantEvents: []string{
				"Normal InlineArtifactStored Inline artifact stored successfully",
				"Normal ConfigMapArtifactStored ConfigMap artifact stored successfully",
			},
		},
		{
			name: "malformed YAML in inline rules returns error",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte("\t")},
				},
			},
			wantErr:    true,
			wantEvents: []string{},
		},
		{
			name: "inline rules store failure sets condition",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
				},
			},
			writeErr: fmt.Errorf("mock write error"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonInlineRulesStoreFailed},
			},
			wantEvents: []string{"Warning InlineRulesStoreFailed Failed to store inline rules: mock write error"},
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
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
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
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonConfigMapRulesStoreFailed},
			},
			wantEvents: []string{"Warning ConfigMapRulesStoreFailed Failed to store ConfigMap rules: mock write error"},
		},
		{
			name: "no sources sets programmed without touching resolved refs",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
			wantEvents: []string{},
		},
		{
			name: "non-nil InlineRules with empty Raw is treated as no inline rules",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace, Generation: 1},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{},
					Priority:    50,
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
			wantEvents: []string{},
		},
		{
			name: "removing inline rules deletes previously written file",
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
			wantFiles:  []string{},
			wantEvents: []string{"Normal InlineArtifactRemoved Inline artifact removed from filesystem"},
		},
		{
			name: "removing configmap ref deletes previously written file",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-rules-cm",
						Namespace: testutil.Namespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
					},
				},
			},
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-rules-cm"},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
			wantFiles:  []string{},
			wantEvents: []string{"Normal ConfigMapArtifactRemoved ConfigMap artifact removed from filesystem"},
		},
		{
			name: "removing OCI artifact deletes previously stored file",
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "ghcr.io/falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			// ExtractTarGz uses os.* directly, so the full OCI path needs a real FS with an injectable dir.
			useRealFS: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
			wantDirEmpty: true,
			wantEvents:   []string{"Normal OCIArtifactRemoved OCI artifact removed from filesystem"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			var managerOpts []artifact.ManagerOption
			var mockFS *filesystem.MockFileSystem
			var tmpDir string

			if tt.useRealFS {
				// ExtractTarGz calls os.* directly, so tests that exercise the full
				// OCI pull-and-extract path need a real FS backed by a temp directory.
				realFS := filesystem.NewOSFileSystem()
				tmpDir = t.TempDir()
				managerOpts = append(managerOpts,
					artifact.WithFS(realFS),
					artifact.WithRulesfileDir(tmpDir),
					artifact.WithOCIPuller(&puller.MockOCIPuller{
						Result: &puller.RegistryResult{Filename: "falco-rules.tar.gz"},
						FS:     realFS,
					}),
				)
			} else {
				mockFS = filesystem.NewMockFileSystem()
				if tt.writeErr != nil {
					mockFS.WriteErr = tt.writeErr
				}
				managerOpts = append(managerOpts,
					artifact.WithFS(mockFS),
					artifact.WithOCIPuller(&puller.MockOCIPuller{PullErr: tt.pullErr}),
				)
			}

			r.artifactManager = artifact.NewManagerWithOptions(cl, testutil.Namespace, managerOpts...)

			if tt.preRf != nil {
				require.NoError(t, r.ensureRulesfile(context.Background(), tt.preRf), "preRf setup failed")
				testutil.DrainEvents(r.recorder.(*events.FakeRecorder).Events)
			}

			err := r.ensureRulesfile(context.Background(), tt.rf)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			testutil.RequireConditions(t, tt.rf.Status.Conditions, tt.wantConditions)
			testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events, tt.wantEvents)

			if tt.wantFiles != nil {
				require.Len(t, mockFS.Files, len(tt.wantFiles), "unexpected number of files written")
				gotContents := make([]string, 0, len(mockFS.Files))
				for _, content := range mockFS.Files {
					gotContents = append(gotContents, string(content))
				}
				assert.ElementsMatch(t, tt.wantFiles, gotContents)
			}

			if tt.wantDirEmpty {
				entries, err := os.ReadDir(tmpDir)
				require.NoError(t, err)
				assert.Empty(t, entries, "expected rulesfile dir to be empty after cleanup")
			}
		})
	}
}

func TestEnforceReferenceResolution(t *testing.T) {
	tests := []struct {
		name             string
		objects          []client.Object
		rf               *artifactv1alpha1.Rulesfile
		wantErr          bool
		wantConditions   []testutil.ConditionExpect
		wantNoConditions bool
		wantStaleRemoved bool
		presetConditions []metav1.Condition
	}{
		{
			name: "inline only has no references and removes stale ResolvedRefs",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
				},
			},
			presetConditions: []metav1.Condition{
				common.NewResolvedRefsCondition(metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, 0),
			},
			wantNoConditions: true,
		},
		{
			name: "OCI without registry has no references",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{
							Repository: "falcosecurity/rules/falco-rules",
							Tag:        "latest",
						},
					},
				},
			},
			wantNoConditions: true,
		},
		{
			name: "ConfigMap ref exists sets ResolvedRefs true",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.Namespace},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-rules-cm"},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
			},
		},
		{
			name: "ConfigMap ref not found sets ResolvedRefs false and Programmed false",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "missing-cm"},
				},
			},
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
			},
		},
		{
			name: "OCI auth secret exists sets ResolvedRefs true",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: testutil.Namespace},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{
							Repository: "falcosecurity/rules/falco-rules",
							Tag:        "latest",
						},
						Registry: &commonv1alpha1.RegistryConfig{
							Auth: &commonv1alpha1.RegistryAuth{
								SecretRef: &commonv1alpha1.SecretRef{Name: "my-pull-secret"},
							},
						},
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
			},
		},
		{
			name: "OCI auth secret not found sets ResolvedRefs false and Programmed false",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{
							Repository: "falcosecurity/rules/falco-rules",
							Tag:        "latest",
						},
						Registry: &commonv1alpha1.RegistryConfig{
							Auth: &commonv1alpha1.RegistryAuth{
								SecretRef: &commonv1alpha1.SecretRef{Name: "missing-secret"},
							},
						},
					},
				},
			},
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
			},
		},
		{
			name: "ConfigMap and auth secret both exist sets ResolvedRefs true",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.Namespace},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: testutil.Namespace},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-rules-cm"},
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{
							Repository: "falcosecurity/rules/falco-rules",
							Tag:        "latest",
						},
						Registry: &commonv1alpha1.RegistryConfig{
							Auth: &commonv1alpha1.RegistryAuth{
								SecretRef: &commonv1alpha1.SecretRef{Name: "my-pull-secret"},
							},
						},
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
			},
		},
		{
			name: "ConfigMap exists but auth secret missing fails on auth secret",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.Namespace},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-rules-cm"},
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{
							Repository: "falcosecurity/rules/falco-rules",
							Tag:        "latest",
						},
						Registry: &commonv1alpha1.RegistryConfig{
							Auth: &commonv1alpha1.RegistryAuth{
								SecretRef: &commonv1alpha1.SecretRef{Name: "missing-secret"},
							},
						},
					},
				},
			},
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t, tt.objects...)

			if len(tt.presetConditions) > 0 {
				tt.rf.Status.Conditions = tt.presetConditions
			}

			err := r.enforceReferenceResolution(context.Background(), tt.rf)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantNoConditions {
				assert.Empty(t, tt.rf.Status.Conditions)
			}

			if len(tt.wantConditions) > 0 {
				testutil.RequireConditions(t, tt.rf.Status.Conditions, tt.wantConditions)
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
		WithIndex(&artifactv1alpha1.Rulesfile{}, index.ConfigMapOnRulesfile, index.RulesfileByConfigMapRef).
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
