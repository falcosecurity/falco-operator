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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
	"github.com/falcosecurity/falco-operator/internal/testutil"
	"github.com/falcosecurity/falco-operator/internal/testutil/nodetest"
)

const testConfigName = "test-config"

// testConfigJSON is a sample Falco config in JSON format (used for *apiextensionsv1.JSON fields).
const testConfigJSON = `{"engine":{"kind":"modern_ebpf"},"falco_libs":{"thread_table_size":262144}}`

// testConfigYAML is the expected YAML representation of testConfigJSON after conversion.
const testConfigYAML = "engine:\n  kind: modern_ebpf\nfalco_libs:\n  thread_table_size: 262144\n"

// testConfigData is used as a ConfigMap data value for config.yaml.
const testConfigData = `engine:
  kind: modern_ebpf
falco_libs:
  thread_table_size: 262144
`

// testReconciler is a ConfigReconciler with the recorder its node emits Events to.
type testReconciler struct {
	*ConfigReconciler
	recorder events.EventRecorder
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*testReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(testutil.EnsureArtifactNode(objs)...).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		Build()

	mockFS := fsfake.NewMockFileSystem()
	recorder := events.NewFakeRecorder(100)
	store := nodetest.NewTestNodeOn(t, cl, mockFS, recorder, nodetest.WithFetcher(testutil.NewFakeFetcher(cl)))
	r := &testReconciler{ConfigReconciler: &ConfigReconciler{Client: cl, node: store}, recorder: recorder}
	useNode(t, r, store, objs)
	return r, cl
}

// useNode makes r use n, as after a restart: what the ArtifactNodes among objs say is installed is
// recovered into it, and it publishes through the client n was built over.
func useNode(t *testing.T, r *testReconciler, n *node.Node, objs []client.Object) {
	t.Helper()
	r.node = n
	nodetest.Prime(n, objs)
}

func TestNewConfigReconciler(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), events.NewFakeRecorder(10))
	r := NewConfigReconciler(cl, n)

	require.NotNil(t, r)
	assert.Same(t, n, r.node, "the reconciler works through the node it was given")
	assert.Equal(t, testutil.TestNodeName, r.node.Name())
	assert.Equal(t, testutil.TestNamespace, r.node.Namespace())
}

func TestReconcile(t *testing.T) {
	inlineConfig := func(mods ...func(*artifactv1alpha1.Config)) *artifactv1alpha1.Config {
		c := &artifactv1alpha1.Config{
			ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
			Spec: artifactv1alpha1.ConfigSpec{
				Config:   &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
				Priority: 50,
			},
		}
		for _, m := range mods {
			m(c)
		}
		return c
	}
	configMapConfig := func(name string) *artifactv1alpha1.Config {
		return &artifactv1alpha1.Config{
			ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
			Spec:       artifactv1alpha1.ConfigSpec{ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: name}},
		}
	}
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "my-config-cm", Namespace: testutil.TestNamespace},
		Data:       map[string]string{commonv1alpha1.ConfigMapConfigKey: testConfigData},
	}

	tests := []struct {
		name           string
		objects        []client.Object
		req            ctrl.Request
		writeErr       error
		wantErr        bool
		wantConditions []testutil.ConditionExpect
	}{
		{
			name: "resource not found returns no error",
			req:  testutil.Request("nonexistent"),
		},
		{
			name:    "happy path with inline config stores config and sets conditions",
			objects: []client.Object{inlineConfig(), testutil.NewAssigningArtifactNode("Config", testConfigName, "")},
			req:     testutil.Request(testConfigName),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name:    "happy path with configmap ref stores config and sets conditions",
			objects: []client.Object{configMap, configMapConfig("my-config-cm"), testutil.NewAssigningArtifactNode("Config", testConfigName, "")},
			req:     testutil.Request(testConfigName),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigMapArtifactProgrammed,
				},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name:    "configmap ref not found fails reference resolution",
			objects: []client.Object{configMapConfig("missing-cm"), testutil.NewAssigningArtifactNode("Config", testConfigName, "")},
			req:     testutil.Request(testConfigName),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			name:     "ensureConfig failure sets error conditions on status",
			objects:  []client.Object{inlineConfig(), testutil.NewAssigningArtifactNode("Config", testConfigName, "")},
			req:      testutil.Request(testConfigName),
			writeErr: fmt.Errorf("disk full"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionInlineArtifactProgrammed.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonInlineArtifactProgramFailed,
				},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			name:     "references resolved but configmap store fails sets ResolvedRefs true and Programmed false",
			objects:  []client.Object{configMap, configMapConfig("my-config-cm"), testutil.NewAssigningArtifactNode("Config", testConfigName, "")},
			req:      testutil.Request(testConfigName),
			writeErr: fmt.Errorf("disk full"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonConfigMapArtifactProgramFailed,
				},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			if tt.writeErr != nil {
				mockFS := fsfake.NewMockFileSystem()
				mockFS.WriteErr = tt.writeErr
				useNode(t, r, nodetest.NewTestNodeOn(t, cl, mockFS, r.recorder, nodetest.WithFetcher(testutil.NewFakeFetcher(cl))), tt.objects)
			}

			result, err := r.Reconcile(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, ctrl.Result{}, result)
			}

			if len(tt.wantConditions) > 0 {
				entry, ok := r.node.StatusEntry(artifact.KindConfig, testConfigName)
				require.True(t, ok, "the flow's status must reach the publisher")
				testutil.RequireConditions(t, entry.Conditions, tt.wantConditions)
			}
		})
	}
}

func TestReconcile_GetErrorPropagates(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return fmt.Errorf("internal server error")
			},
		}).
		Build()

	recorder := events.NewFakeRecorder(100)
	r := &ConfigReconciler{
		Client: cl,
		node:   nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), recorder, nodetest.WithFetcher(testutil.NewFakeFetcher(cl))),
	}

	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
}

func TestEnforceReferenceResolution(t *testing.T) {
	tests := []struct {
		name           string
		objects        []client.Object
		config         *artifactv1alpha1.Config
		wantErr        bool
		wantConditions []testutil.ConditionExpect
	}{
		{
			name: "no refs removes ResolvedRefs condition",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigName,
					Namespace: testutil.TestNamespace,
				},
			},
			wantConditions: []testutil.ConditionExpect{},
		},
		{
			name: "configmap exists sets ResolvedRefs true",
			objects: []client.Object{
				// The data key is present because resolving references is part of applying
				// the artifact: the source is read straight afterwards, in the same call.
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-config-cm",
						Namespace: testutil.TestNamespace,
					},
					Data: map[string]string{commonv1alpha1.ConfigMapConfigKey: testConfigData},
				},
			},
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.ConfigSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-config-cm"},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				// Resolution is the first half of applying the artifact; the source it resolved
				// is written in the same call.
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigMapArtifactProgrammed,
				},
			},
		},
		{
			name: "configmap missing sets ResolvedRefs false and Programmed false",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.ConfigSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "missing-cm"},
				},
			},
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t, tt.objects...)
			status := &artifactv1alpha1.NodeArtifactStatus{}

			// Pre-seed a stale ResolvedRefs condition to verify it's removed when no refs.
			if tt.config.Spec.ConfigMapRef == nil {
				status.Conditions = []metav1.Condition{
					common.NewResolvedRefsCondition(metav1.ConditionTrue, artifact.ReasonReferenceResolved, "", 1),
				}
			}

			// The generation gate lives inside the apply, after reference resolution, so a
			// fixture has to look like one the instance operator has already processed.
			tt.config.Status.ObservedGeneration = tt.config.Generation
			err := r.node.ApplyArtifact(context.Background(), tt.config, status)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			testutil.RequireConditions(t, status.Conditions, tt.wantConditions)
		})
	}
}

func TestEnsureConfig(t *testing.T) {
	tests := []struct {
		name           string
		objects        []client.Object
		config         *artifactv1alpha1.Config
		writeErr       error
		wantErr        bool
		wantConditions []testutil.ConditionExpect
		wantFiles      []string
		wantNoFiles    bool
		wantEvents     []string
	}{
		{
			name: "success stores inline config and sets conditions",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.TestNamespace,
					Generation: 1,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					Config:   &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
					Priority: 50,
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
			},
			wantFiles:  []string{testConfigYAML},
			wantEvents: []string{"Normal ArtifactStored inline artifact stored successfully"},
		},
		{
			name: "no sources sets Programmed true",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.TestNamespace,
					Generation: 1,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					Priority: 50,
				},
			},
			wantConditions: nil,
			wantEvents:     []string{},
		},
		{
			name: "non-nil config with empty Raw is treated as no inline config",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.TestNamespace,
					Generation: 1,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					Config:   &apiextensionsv1.JSON{},
					Priority: 50,
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
			},
			wantEvents: []string{},
		},
		{
			name: "success stores configmap config and sets conditions",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-config-cm",
						Namespace: testutil.TestNamespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapConfigKey: testConfigData,
					},
				},
			},
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.TestNamespace,
					Generation: 1,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-config-cm"},
					Priority:     50,
				},
			},
			wantConditions: []testutil.ConditionExpect{
				// Reference resolution is part of applying the artifact, so its condition
				// is set on the same pass.
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigMapArtifactProgrammed,
				},
			},
			wantFiles: []string{testConfigData},
			wantEvents: []string{
				"Normal ReferenceResolved All references were resolved successfully", "Normal ArtifactStored configmap artifact stored successfully"},
		},
		{
			name: "both inline and configmap sources write two files",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-config-cm",
						Namespace: testutil.TestNamespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapConfigKey: testConfigData,
					},
				},
			},
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.TestNamespace,
					Generation: 1,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					Config:       &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-config-cm"},
					Priority:     50,
				},
			},
			wantConditions: []testutil.ConditionExpect{
				// Reference resolution is part of applying the artifact, so its condition
				// is set on the same pass.
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigMapArtifactProgrammed,
				},
			},
			wantFiles: []string{testConfigYAML, testConfigData},
			wantEvents: []string{
				"Normal ReferenceResolved All references were resolved successfully",
				"Normal ArtifactStored inline artifact stored successfully",
				"Normal ArtifactStored configmap artifact stored successfully",
			},
		},
		{
			name: "malformed YAML in inline config returns error",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.TestNamespace,
					Generation: 1,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					Config:   &apiextensionsv1.JSON{Raw: []byte("\t")},
					Priority: 50,
				},
			},
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionInlineArtifactProgrammed.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonInlineArtifactProgramFailed,
				},
			},
		},
		{
			name: "failure sets error condition on inline content",
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.TestNamespace,
					Generation: 2,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					Config:   &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
					Priority: 50,
				},
			},
			writeErr: fmt.Errorf("disk full"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionInlineArtifactProgrammed.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonInlineArtifactProgramFailed,
				},
			},
			wantEvents: []string{"Warning InlineConfigStoreFailed Failed to store config: disk full"},
		},
		{
			name: "failure on configmap store sets error condition",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-config-cm",
						Namespace: testutil.TestNamespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapConfigKey: testConfigData,
					},
				},
			},
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.TestNamespace,
					Generation: 2,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-config-cm"},
					Priority:     50,
				},
			},
			writeErr: fmt.Errorf("disk full"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				// Reference resolution is part of applying the artifact, so its condition
				// is set on the same pass.
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonConfigMapArtifactProgramFailed,
				},
			},
			wantEvents: []string{
				"Normal ReferenceResolved All references were resolved successfully",
				"Warning ConfigMapConfigStoreFailed Failed to store ConfigMap config: disk full",
			},
		},
		{
			// The ConfigMap is read before anything is written, so a read that fails holds back the
			// inline source too: nothing lands until both can.
			name: "configmap without the config key fails before anything is written",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-config-cm",
						Namespace: testutil.TestNamespace,
					},
					Data: map[string]string{"other": testConfigData},
				},
			},
			config: &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testConfigName,
					Namespace:  testutil.TestNamespace,
					Generation: 1,
				},
				Spec: artifactv1alpha1.ConfigSpec{
					Config:       &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-config-cm"},
					Priority:     50,
				},
			},
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonConfigMapArtifactProgramFailed,
				},
			},
			wantNoFiles: true,
			wantEvents: []string{
				"Normal ReferenceResolved All references were resolved successfully",
				`Warning ConfigMapConfigStoreFailed Failed to store ConfigMap config: ConfigMap ` + testutil.TestNamespace +
					`/my-config-cm missing expected key "` + commonv1alpha1.ConfigMapConfigKey + `"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)
			status := &artifactv1alpha1.NodeArtifactStatus{}

			mockFS := fsfake.NewMockFileSystem()
			if tt.writeErr != nil {
				mockFS.WriteErr = tt.writeErr
			}
			r.node = nodetest.NewTestNodeOn(t, cl, mockFS, r.recorder, nodetest.WithFetcher(testutil.NewFakeFetcher(cl)))

			// The generation gate lives inside the apply, after reference resolution, so a
			// fixture has to look like one the instance operator has already processed.
			tt.config.Status.ObservedGeneration = tt.config.Generation
			err := r.node.ApplyArtifact(context.Background(), tt.config, status)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			testutil.RequireConditions(t, status.Conditions, tt.wantConditions)
			testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events, tt.wantEvents)

			if tt.wantNoFiles {
				assert.Empty(t, mockFS.Files, "no file may be written")
			}
			if len(tt.wantFiles) > 0 {
				require.Len(t, mockFS.Files, len(tt.wantFiles), "unexpected number of files written")
				gotContents := make([]string, 0, len(mockFS.Files))
				for _, content := range mockFS.Files {
					gotContents = append(gotContents, string(content))
				}
				assert.ElementsMatch(t, tt.wantFiles, gotContents)
			}
		})
	}
}

// TestEnsureConfig_PublishesFromTheNodesRecordEvenWhenStatusStartsEmpty covers the case where the
// node's record (seeded from disk by the warm sync, or surviving a status patch dropped by an SSA
// conflict) already considers the inline config installed and unchanged, but this specific
// status's InstalledArtifacts starts empty. The apply must still populate status from the
// node's record, not only when Store returns a fresh Added/Updated action.
func TestEnsureConfig_PublishesFromTheNodesRecordEvenWhenStatusStartsEmpty(t *testing.T) {
	r, cl := newTestReconciler(t)
	mockFS := fsfake.NewMockFileSystem()
	r.node = nodetest.NewTestNodeOn(t, cl, mockFS, r.recorder, nodetest.WithFetcher(testutil.NewFakeFetcher(cl)))

	path := testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), testConfigName, 50, artifact.MediumInline, artifact.KindConfig)
	content := []byte(testConfigYAML)
	hash := testutil.SHA256Hex(content)
	mockFS.Files[path] = content

	key := artifact.Ref{Kind: artifact.KindConfig, Name: testConfigName}
	r.node.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{
		{Path: path, Medium: string(artifact.MediumInline), Priority: 50, ContentHash: hash},
	})

	config := &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace, Generation: 1},
		Spec: artifactv1alpha1.ConfigSpec{
			Config:   &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
			Priority: 50,
		},
	}
	status := &artifactv1alpha1.NodeArtifactStatus{} // InstalledArtifacts starts nil, unlike the node's record.

	config.Status.ObservedGeneration = config.Generation
	require.NoError(t, r.node.ApplyArtifact(context.Background(), config, status))
	// What a reconcile publishes on its way out, which is where the installed files are derived.
	r.node.PublishStatus(artifact.KindConfig, config, status)

	entry := artifact.FindInstalled(status.InstalledArtifacts, artifact.MediumInline)
	require.NotNil(t, entry, "status must be derived from the node's record even when Store returns Unchanged")
	assert.Equal(t, path, entry.Path)
	assert.Equal(t, hash, entry.ContentHash)
}

// TestEnsureConfig_ProgrammedLastTransitionTime verifies LastTransitionTime stays put on a
// steady-state reconcile and only moves on a real status transition.
func TestEnsureConfig_ProgrammedLastTransitionTime(t *testing.T) {
	pinned := metav1.NewTime(time.Now().Add(-time.Hour))
	tests := []struct {
		name          string
		initialStatus metav1.ConditionStatus
		wantPreserved bool
	}{
		{name: "steady state preserves timestamp", initialStatus: metav1.ConditionTrue, wantPreserved: true},
		{name: "real transition restamps timestamp", initialStatus: metav1.ConditionFalse, wantPreserved: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			config := &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace, Generation: 1},
				Spec: artifactv1alpha1.ConfigSpec{
					Config:   &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
					Priority: 50,
				},
			}
			status := &artifactv1alpha1.NodeArtifactStatus{}
			status.Conditions = []metav1.Condition{{
				Type:               commonv1alpha1.ConditionInlineArtifactProgrammed.String(),
				Status:             tt.initialStatus,
				Reason:             artifact.ReasonInlineArtifactProgrammed,
				Message:            artifact.MessageInlineArtifactProgrammed,
				LastTransitionTime: pinned,
			}}

			config.Status.ObservedGeneration = config.Generation
			require.NoError(t, r.node.ApplyArtifact(context.Background(), config, status))

			cond := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionInlineArtifactProgrammed.String())
			require.NotNil(t, cond)
			require.Equal(t, metav1.ConditionTrue, cond.Status)
			require.Equal(t, tt.wantPreserved, cond.LastTransitionTime.Equal(&pinned))
		})
	}
}

const assignedUID = "config-uid"

func assignedConfig(uid string) *artifactv1alpha1.Config {
	return &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace, UID: types.UID(uid), Generation: 1},
		Spec: artifactv1alpha1.ConfigSpec{
			Config:   &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
			Priority: 50,
		},
		Status: artifactv1alpha1.ConfigStatus{ObservedGeneration: 1},
	}
}

func configKey() artifact.Ref {
	return artifact.Ref{Kind: artifact.KindConfig, Name: testConfigName}
}

func TestReconcile_InstallsAndPublishesWhenAssigned(t *testing.T) {
	r, cl := newTestReconciler(t, assignedConfig(assignedUID), testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID))

	result, err := r.Reconcile(t.Context(), testutil.Request(testConfigName))

	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter)
	assert.NotEmpty(t, r.node.GetInstalled(configKey()), "the config is on disk")
	got := testutil.RequirePublishedWhere(t, cl, "Config", testConfigName, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.IsStatusConditionTrue(e.Conditions, commonv1alpha1.ConditionProgrammed.String())
	})
	assert.Equal(t, assignedUID, got.UID)
}

func TestReconcile_DoesNothingWhenNotAssigned(t *testing.T) {
	for name, objs := range map[string][]client.Object{
		"the ArtifactNode lists nothing": {assignedConfig(assignedUID), testutil.NewTestArtifactNode()},
		"there is no ArtifactNode":       {assignedConfig(assignedUID)},
		"the ArtifactNode is being deleted": {
			assignedConfig(assignedUID), terminating(testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := newTestReconciler(t, objs...)

			result, err := r.Reconcile(t.Context(), testutil.Request(testConfigName))

			require.NoError(t, err)
			assert.Equal(t, time.Duration(0), result.RequeueAfter)
			assert.Empty(t, r.node.GetInstalled(configKey()))
			_, held := r.node.StatusEntry(artifact.KindConfig, testConfigName)
			assert.False(t, held)
		})
	}
}

func terminating(artifactNode *artifactv1alpha1.ArtifactNode) *artifactv1alpha1.ArtifactNode {
	now := metav1.Now()
	artifactNode.DeletionTimestamp = &now
	artifactNode.Finalizers = []string{controllerhelper.ArtifactNodeSidecarFinalizer}
	return artifactNode
}

func TestReconcile_WaitsWhenTheSpecListsAnotherIncarnation(t *testing.T) {
	r, _ := newTestReconciler(t, assignedConfig("new-uid"), testutil.NewAssigningArtifactNode("Config", testConfigName, "old-uid"))

	result, err := r.Reconcile(t.Context(), testutil.Request(testConfigName))

	require.NoError(t, err)
	assert.Equal(t, shared.AssignmentRetryDelay, result.RequeueAfter)
	assert.Empty(t, r.node.GetInstalled(configKey()), "never install for an incarnation the operator did not assign")
}

func TestReconcile_IgnoresAMissingOrDeletingConfig(t *testing.T) {
	r, _ := newTestReconciler(t, testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID))

	_, err := r.Reconcile(t.Context(), testutil.Request("nonexistent"))
	require.NoError(t, err)

	now := metav1.Now()
	deleting := assignedConfig(assignedUID)
	deleting.DeletionTimestamp = &now
	deleting.Finalizers = []string{"test/finalizer"}
	r, _ = newTestReconciler(t, deleting, testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID))
	_, err = r.Reconcile(t.Context(), testutil.Request(testConfigName))
	require.NoError(t, err)
	assert.Empty(t, r.node.GetInstalled(configKey()), "a deleting artifact is removed when the operator drops its assignment")
}

func TestReconcile_DoesNotInstallWhenTheStatusEntryCannotBePersisted(t *testing.T) {
	cl := fake.NewClientBuilder().
		WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(assignedConfig(assignedUID), testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID)).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		Build()
	failing := interceptor.NewClient(cl, interceptor.Funcs{
		SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
			return fmt.Errorf("apiserver unavailable")
		},
	})
	// The only node publishes through a client whose status patches fail, so no entry can be persisted. A second
	// node over a working client would publish the entry its ArtifactNode reserves, and the install would then
	// rightly proceed.
	n := nodetest.NewTestNodeOn(t, failing, fsfake.NewMockFileSystem(), events.NewFakeRecorder(100),
		nodetest.WithFetcher(testutil.NewFakeFetcher(failing)))
	r := &testReconciler{ConfigReconciler: &ConfigReconciler{Client: cl, node: n}}

	_, err := r.Reconcile(t.Context(), testutil.Request(testConfigName))

	require.Error(t, err)
	assert.Empty(t, r.node.GetInstalled(configKey()),
		"a file must never exist without a persisted status entry naming it")
}

func TestReconcile_ReplacesTheFilesOfAPreviousIncarnation(t *testing.T) {
	r, cl := newTestReconciler(t, assignedConfig("uid-1"), testutil.NewAssigningArtifactNode("Config", testConfigName, "uid-1"))
	_, err := r.Reconcile(t.Context(), testutil.Request(testConfigName))
	require.NoError(t, err)
	require.NotEmpty(t, r.node.GetInstalled(configKey()))

	// The Config is deleted and recreated with the same name, and the operator re-lists it.
	require.NoError(t, cl.Delete(t.Context(), assignedConfig("uid-1")))
	require.NoError(t, cl.Create(t.Context(), func() *artifactv1alpha1.Config {
		c := assignedConfig("uid-2")
		c.ResourceVersion = ""
		return c
	}()))
	artifactNodeKey := client.ObjectKeyFromObject(testutil.NewAssigningArtifactNode("Config", testConfigName, ""))
	require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		artifactNode := &artifactv1alpha1.ArtifactNode{}
		if err := cl.Get(t.Context(), artifactNodeKey, artifactNode); err != nil {
			return err
		}
		artifactNode.Spec.Artifacts[0].UID = "uid-2"
		return cl.Update(t.Context(), artifactNode)
	}))

	_, err = r.Reconcile(t.Context(), testutil.Request(testConfigName))

	require.NoError(t, err)
	assert.Len(t, r.node.GetInstalled(configKey()), 1, "the old incarnation's file was replaced, not duplicated")
	entry, ok := r.node.StatusEntry(artifact.KindConfig, testConfigName)
	require.True(t, ok)
	assert.Equal(t, "uid-2", entry.UID)
}

func TestCleanup_RemovesFilesAndTheStatusEntry(t *testing.T) {
	r, cl := newTestReconciler(t, assignedConfig(assignedUID), testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID))
	_, err := r.Reconcile(t.Context(), testutil.Request(testConfigName))
	require.NoError(t, err)
	testutil.RequirePublished(t, cl, "Config", testConfigName)
	testutil.DropAssignments(t, cl) // an artifact the ArtifactNode still lists keeps an entry to be filled in

	require.NoError(t, r.Cleanup(t.Context(), testConfigName))

	assert.Empty(t, r.node.GetInstalled(configKey()))
	artifactNodeKey := client.ObjectKeyFromObject(testutil.NewAssigningArtifactNode("Config", testConfigName, ""))
	require.Eventually(t, func() bool {
		artifactNode := &artifactv1alpha1.ArtifactNode{}
		return cl.Get(t.Context(), artifactNodeKey, artifactNode) == nil && len(artifactNode.Status.Artifacts) == 0
	}, 2*time.Second, 5*time.Millisecond, "the entry is withdrawn once the last file is gone")
}

func TestCleanup_IsIdempotent(t *testing.T) {
	r, _ := newTestReconciler(t)

	require.NoError(t, r.Cleanup(t.Context(), "never-installed"))
	require.NoError(t, r.Cleanup(t.Context(), "never-installed"))
}

// withFinalizer keeps the object around when it is deleted, terminating.
func withFinalizer(t *testing.T, cl client.Client, obj client.Object) {
	t.Helper()
	// The ArtifactNode is patched concurrently by the node's status publisher: retry on a conflict.
	require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := cl.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
			return err
		}
		obj.SetFinalizers([]string{"test/finalizer"})
		return cl.Update(t.Context(), obj)
	}))
}

func installedConfig(t *testing.T) (*testReconciler, client.Client) {
	t.Helper()
	r, cl := newTestReconciler(t, assignedConfig(assignedUID), testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID))
	_, err := r.Reconcile(t.Context(), testutil.Request(testConfigName))
	require.NoError(t, err)
	require.NotEmpty(t, r.node.GetInstalled(configKey()), "the config is on disk")
	return r, cl
}

// The node controller asks for the removal of an artifact by having its reconciler reconcile it, which is then
// the only one working on it. Each way the artifact can stop being assigned must remove what the node holds.
func TestReconcile_RemovesWhatItHoldsWhenTheConfigIsNoLongerAssigned(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, client.Client){
		"the ArtifactNode stops listing it": testutil.DropAssignments,
		"the Config is gone and the ArtifactNode stopped listing it": func(t *testing.T, cl client.Client) {
			testutil.DropAssignments(t, cl)
			require.NoError(t, cl.Delete(t.Context(), assignedConfig(assignedUID)))
		},
		"the Config is being deleted and the ArtifactNode stopped listing it": func(t *testing.T, cl client.Client) {
			testutil.DropAssignments(t, cl)
			withFinalizer(t, cl, assignedConfig(assignedUID))
			require.NoError(t, cl.Delete(t.Context(), assignedConfig(assignedUID)))
		},
		"the ArtifactNode is being deleted": func(t *testing.T, cl client.Client) {
			withFinalizer(t, cl, testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID))
			require.NoError(t, cl.Delete(t.Context(), testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID)))
		},
		"there is no ArtifactNode": func(t *testing.T, cl client.Client) {
			require.NoError(t, cl.Delete(t.Context(), testutil.NewAssigningArtifactNode("Config", testConfigName, assignedUID)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, cl := installedConfig(t)
			prepare(t, cl)

			result, err := r.Reconcile(t.Context(), testutil.Request(testConfigName))

			require.NoError(t, err)
			assert.Equal(t, time.Duration(0), result.RequeueAfter)
			assert.Empty(t, r.node.GetInstalled(configKey()))
			_, held := r.node.StatusEntry(artifact.KindConfig, testConfigName)
			assert.False(t, held, "an entry left behind would keep the parent's finalizer")
		})
	}
}

// While the ArtifactNode still lists a Config that is gone or being deleted, the operator has yet to drop it: nothing is
// removed until it does, which reconciles the Config again.
func TestReconcile_KeepsWhatItHoldsWhileTheArtifactNodeStillListsAGoneConfig(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, client.Client){
		"the Config is gone": func(t *testing.T, cl client.Client) {
			require.NoError(t, cl.Delete(t.Context(), assignedConfig(assignedUID)))
		},
		"the Config is being deleted": func(t *testing.T, cl client.Client) {
			withFinalizer(t, cl, assignedConfig(assignedUID))
			require.NoError(t, cl.Delete(t.Context(), assignedConfig(assignedUID)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, cl := installedConfig(t)
			prepare(t, cl)

			_, err := r.Reconcile(t.Context(), testutil.Request(testConfigName))

			require.NoError(t, err)
			assert.NotEmpty(t, r.node.GetInstalled(configKey()))
		})
	}
}

func TestCleanup_ReportsWhatCannotBeRemoved(t *testing.T) {
	mockFS := fsfake.NewMockFileSystem()
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	n := nodetest.NewTestNodeOn(t, cl, mockFS, events.NewFakeRecorder(100))
	r := &ConfigReconciler{node: n}
	require.NoError(t, n.ApplyArtifact(t.Context(), &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: testConfigName, UID: "uid"},
		Spec:       artifactv1alpha1.ConfigSpec{Config: &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)}, Priority: 50},
	}, &artifactv1alpha1.NodeArtifactStatus{}))
	mockFS.RemoveErr = errors.New("disk on fire")

	err := r.Cleanup(t.Context(), testConfigName)

	require.ErrorIs(t, err, mockFS.RemoveErr)
	assert.NotEmpty(t, n.GetInstalled(configKey()), "what could not be removed is still recorded")
}

// A ConfigMap event reconciles the Configs that reference it, and only those.
func TestFindConfigsForConfigMap(t *testing.T) {
	config := func(name, configMap string) *artifactv1alpha1.Config {
		c := &artifactv1alpha1.Config{}
		c.Namespace, c.Name = testutil.TestNamespace, name
		if configMap != "" {
			c.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: configMap}
		}
		return c
	}
	tests := []struct {
		name    string
		listErr error
		want    []reconcile.Request
	}{
		{name: "the Configs that reference it", want: []reconcile.Request{testutil.Request("a"), testutil.Request("b")}},
		{name: "the Configs cannot be listed", listErr: errors.New("boom")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
				WithObjects(config("a", "cm"), config("b", "cm"), config("c", "other"), config("d", ""))
			for _, idx := range index.All {
				builder = builder.WithIndex(idx.Object, idx.Field, idx.ExtractValueFn)
			}
			if tt.listErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
						return tt.listErr
					},
				})
			}
			r := &ConfigReconciler{Client: builder.Build()}
			cm := &corev1.ConfigMap{}
			cm.Namespace, cm.Name = testutil.TestNamespace, "cm"

			got := r.findConfigsForConfigMap(t.Context(), cm)

			assert.ElementsMatch(t, tt.want, got)
		})
	}
}
