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
	"crypto/sha256"
	"encoding/hex"
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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

// testFetcher implements artifact.ArtifactFetcher for controller unit tests.
// ConfigMap and Inline use the real artifact.Fetcher backed by the fake k8s client.
// FetchOCI returns in-memory bytes to avoid HTTP calls to a real artifact server.
type testFetcher struct {
	delegate *artifact.Fetcher
	ociErr   error
	ociBytes []byte
}

func newTestFetcher(cl client.Client) *testFetcher {
	return &testFetcher{delegate: &artifact.Fetcher{K8sClient: cl}}
}

func (f *testFetcher) FetchOCI(_ context.Context, _, _ string, _ artifact.Type) (artifact.FetchResult, error) {
	if f.ociErr != nil {
		return artifact.FetchResult{}, f.ociErr
	}
	content := f.ociBytes
	if content == nil {
		content = []byte("mock-oci-content")
	}
	h := sha256.Sum256(content)
	return artifact.FetchResult{
		Content:     content,
		ContentHash: hex.EncodeToString(h[:]),
		Perm:        0o755,
	}, nil
}

func (f *testFetcher) FetchInline(ctx context.Context, content []byte) (artifact.FetchResult, error) {
	return f.delegate.FetchInline(ctx, content)
}

func (f *testFetcher) FetchConfigMap(
	ctx context.Context, namespace string, cmRef *commonv1alpha1.ConfigMapRef, artifactType artifact.Type,
) (artifact.FetchResult, error) {
	return f.delegate.FetchConfigMap(ctx, namespace, cmRef, artifactType)
}

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

func testConfigNodeName() string {
	return controllerhelper.NodeObjectName(controllerhelper.ArtifactKindConfig, testConfigName, testutil.TestNodeName)
}

func newTestConfigNodeObj(opts ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	n := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testConfigNodeName(),
			Namespace: testutil.TestNamespace,
			Labels:    controllerhelper.NodeObjectLabels(controllerhelper.ArtifactKindConfig, testConfigName, testutil.TestNodeName),
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
	}
	for _, o := range opts {
		o(n)
	}
	return n
}

func withConfigOwnerRef() func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) {
		n.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: artifactv1alpha1.GroupVersion.String(),
			Kind:       "Config",
			Name:       testConfigName,
		}}
	}
}

func withConfigFinalizer() func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{configNodeFinalizer}
	}
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*ConfigReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		Build()

	mockFS := filesystem.NewMockFileSystem()

	return &ConfigReconciler{
		Client:    cl,
		Scheme:    s,
		recorder:  events.NewFakeRecorder(100),
		fetcher:   newTestFetcher(cl),
		store:     nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compat.NewMockVersionsFetcher(nil)),
		nodeName:  testutil.TestNodeName,
		namespace: testutil.TestNamespace,
	}, cl
}

func TestNewConfigReconciler(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	store := nodeartifacts.NewManager(&artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
		compat.NewMockVersionsFetcher(nil))
	r := NewConfigReconciler(cl, s, events.NewFakeRecorder(10), "my-node", "my-namespace", store)

	require.NotNil(t, r)
	assert.Equal(t, "my-node", r.nodeName)
	assert.Equal(t, "my-namespace", r.namespace)
	assert.NotNil(t, r.fetcher)
	assert.NotNil(t, r.store)
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
			name: "deletion with finalizer removes artifacts and finalizer",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.ConfigSpec{
						Config: &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
					},
				},
				newTestConfigNodeObj(withConfigFinalizer(), withConfigOwnerRef()),
			},
			req:             testutil.Request(testConfigNodeName()),
			triggerDeletion: true,
			wantFinalizer:   new(false),
		},
		{
			name: "sets finalizer on first reconcile and returns early",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.ConfigSpec{
						Config: &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
					},
				},
				newTestConfigNodeObj(withConfigOwnerRef()),
			},
			req:           testutil.Request(testConfigNodeName()),
			wantFinalizer: new(true),
		},
		{
			name: "happy path with inline config stores config and sets conditions",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.ConfigSpec{
						Config:   &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
						Priority: 50,
					},
				},
				newTestConfigNodeObj(withConfigFinalizer(), withConfigOwnerRef()),
			},
			req: testutil.Request(testConfigNodeName()),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "happy path with configmap ref stores config and sets conditions",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-config-cm", Namespace: testutil.TestNamespace},
					Data: map[string]string{
						commonv1alpha1.ConfigMapConfigKey: testConfigData,
					},
				},
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.ConfigSpec{
						ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-config-cm"},
					},
				},
				newTestConfigNodeObj(withConfigFinalizer(), withConfigOwnerRef()),
			},
			req: testutil.Request(testConfigNodeName()),
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
			name: "configmap ref not found fails reference resolution",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.ConfigSpec{
						ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "missing-cm"},
					},
				},
				newTestConfigNodeObj(withConfigFinalizer(), withConfigOwnerRef()),
			},
			req:     testutil.Request(testConfigNodeName()),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			name: "deletion without our finalizer is no-op",
			objects: []client.Object{
				newTestConfigNodeObj(func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{"some-other-finalizer"}
				}),
			},
			req:             testutil.Request(testConfigNodeName()),
			triggerDeletion: true,
		},
		{
			name: "ensureConfig failure sets error conditions on status",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.ConfigSpec{
						Config:   &apiextensionsv1.JSON{Raw: []byte(testConfigJSON)},
						Priority: 50,
					},
				},
				newTestConfigNodeObj(withConfigFinalizer(), withConfigOwnerRef()),
			},
			req:      testutil.Request(testConfigNodeName()),
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
			name: "references resolved but configmap store fails sets ResolvedRefs true and Programmed false",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-config-cm", Namespace: testutil.TestNamespace},
					Data: map[string]string{
						commonv1alpha1.ConfigMapConfigKey: testConfigData,
					},
				},
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.ConfigSpec{
						ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-config-cm"},
					},
				},
				newTestConfigNodeObj(withConfigFinalizer(), withConfigOwnerRef()),
			},
			req:      testutil.Request(testConfigNodeName()),
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
				mockFS := filesystem.NewMockFileSystem()
				mockFS.WriteErr = tt.writeErr
				r.store = nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compat.NewMockVersionsFetcher(nil))
			}

			if tt.triggerDeletion {
				nodeObj := &artifactv1alpha1.ArtifactNode{}
				require.NoError(t, cl.Get(context.Background(), tt.req.NamespacedName, nodeObj))
				require.NoError(t, cl.Delete(context.Background(), nodeObj))
			}

			result, err := r.Reconcile(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, ctrl.Result{}, result)
			}

			if tt.wantFinalizer != nil {
				nodeObj := &artifactv1alpha1.ArtifactNode{}
				if err := cl.Get(context.Background(), tt.req.NamespacedName, nodeObj); err == nil {
					assert.Equal(t, *tt.wantFinalizer, controllerutil.ContainsFinalizer(nodeObj, configNodeFinalizer))
				}
			}

			if len(tt.wantConditions) > 0 {
				nodeObj := &artifactv1alpha1.ArtifactNode{}
				require.NoError(t, cl.Get(context.Background(), tt.req.NamespacedName, nodeObj))
				testutil.RequireConditions(t, nodeObj.Status.Conditions, tt.wantConditions)
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

	r := &ConfigReconciler{
		Client:   cl,
		Scheme:   s,
		recorder: events.NewFakeRecorder(100),
		fetcher:  newTestFetcher(cl),
		store: nodeartifacts.NewManager(&artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
			compat.NewMockVersionsFetcher(nil)),
		nodeName:  testutil.TestNodeName,
		namespace: testutil.TestNamespace,
	}

	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigNodeName()))
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
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-config-cm",
						Namespace: testutil.TestNamespace,
					},
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
			nodeObj := newTestConfigNodeObj()

			// Pre-seed a stale ResolvedRefs condition to verify it's removed when no refs.
			if tt.config.Spec.ConfigMapRef == nil {
				nodeObj.Status.Conditions = []metav1.Condition{
					common.NewResolvedRefsCondition(metav1.ConditionTrue, artifact.ReasonReferenceResolved, "", 1),
				}
			}

			err := r.enforceReferenceResolution(context.Background(), tt.config, nodeObj)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			testutil.RequireConditions(t, nodeObj.Status.Conditions, tt.wantConditions)
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
			wantEvents: []string{"Normal InlineArtifactStored Inline artifact stored successfully"},
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
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigMapArtifactProgrammed,
				},
			},
			wantFiles:  []string{testConfigData},
			wantEvents: []string{"Normal ConfigMapArtifactStored ConfigMap artifact stored successfully"},
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
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigMapArtifactProgrammed,
				},
			},
			wantFiles: []string{testConfigYAML, testConfigData},
			wantEvents: []string{
				"Normal InlineArtifactStored Inline artifact stored successfully",
				"Normal ConfigMapArtifactStored ConfigMap artifact stored successfully",
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
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonConfigMapArtifactProgramFailed,
				},
			},
			wantEvents: []string{"Warning ConfigMapConfigStoreFailed Failed to store ConfigMap config: disk full"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t, tt.objects...)
			nodeObj := newTestConfigNodeObj()

			mockFS := filesystem.NewMockFileSystem()
			if tt.writeErr != nil {
				mockFS.WriteErr = tt.writeErr
			}
			r.store = nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compat.NewMockVersionsFetcher(nil))

			err := r.ensureConfig(context.Background(), tt.config, nodeObj)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			testutil.RequireConditions(t, nodeObj.Status.Conditions, tt.wantConditions)
			testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events, tt.wantEvents)

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
			nodeObj := newTestConfigNodeObj()
			nodeObj.Status.Conditions = []metav1.Condition{{
				Type:               commonv1alpha1.ConditionInlineArtifactProgrammed.String(),
				Status:             tt.initialStatus,
				Reason:             artifact.ReasonInlineArtifactProgrammed,
				Message:            artifact.MessageInlineArtifactProgrammed,
				LastTransitionTime: pinned,
			}}

			require.NoError(t, r.ensureConfig(context.Background(), config, nodeObj))

			cond := apimeta.FindStatusCondition(nodeObj.Status.Conditions, commonv1alpha1.ConditionInlineArtifactProgrammed.String())
			require.NotNil(t, cond)
			require.Equal(t, metav1.ConditionTrue, cond.Status)
			require.Equal(t, tt.wantPreserved, cond.LastTransitionTime.Equal(&pinned))
		})
	}
}

func TestFindNodeObjectsForConfigMap(t *testing.T) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-config-cm",
			Namespace: testutil.TestNamespace,
		},
	}
	config := &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testConfigName,
			Namespace: testutil.TestNamespace,
		},
		Spec: artifactv1alpha1.ConfigSpec{
			ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-config-cm"},
		},
	}

	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(configMap, config).
		WithIndex(&artifactv1alpha1.Config{}, index.ConfigMapOnConfig, index.ConfigByConfigMapRef).
		Build()

	r := &ConfigReconciler{
		Client:    cl,
		namespace: testutil.TestNamespace,
		nodeName:  testutil.TestNodeName,
	}

	requests := r.findNodeObjectsForConfigMap(context.Background(), configMap)
	require.Len(t, requests, 1)
	assert.Equal(t, testConfigNodeName(), requests[0].Name)
	assert.Equal(t, testutil.TestNamespace, requests[0].Namespace)
}

func TestFindNodeObjectForConfig(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	r := &ConfigReconciler{
		Client:   cl,
		nodeName: testutil.TestNodeName,
	}

	cfg := &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testConfigName,
			Namespace: testutil.TestNamespace,
		},
	}

	requests := r.findNodeObjectForConfig(context.Background(), cfg)
	require.Len(t, requests, 1)
	assert.Equal(t, testConfigNodeName(), requests[0].Name)
	assert.Equal(t, testutil.TestNamespace, requests[0].Namespace)
}

func TestHandleDeletion(t *testing.T) {
	tests := []struct {
		name    string
		objects []client.Object
		trigger bool
		wantOK  bool
	}{
		{
			name: "not marked for deletion returns false",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
				},
				newTestConfigNodeObj(withConfigFinalizer(), withConfigOwnerRef()),
			},
			wantOK: false,
		},
		{
			name: "marked for deletion with finalizer cleans up",
			objects: []client.Object{
				&artifactv1alpha1.Config{
					ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
				},
				newTestConfigNodeObj(withConfigFinalizer(), withConfigOwnerRef()),
			},
			trigger: true,
			wantOK:  true,
		},
		{
			name: "marked for deletion without our finalizer skips cleanup",
			objects: []client.Object{
				newTestConfigNodeObj(func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{"some-other-finalizer"}
				}),
			},
			trigger: true,
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			nodeObj := &artifactv1alpha1.ArtifactNode{}
			require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testConfigNodeName(), Namespace: testutil.TestNamespace}, nodeObj))

			if tt.trigger {
				require.NoError(t, cl.Delete(context.Background(), nodeObj))
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testConfigNodeName(), Namespace: testutil.TestNamespace}, nodeObj))
			}

			ok, err := r.handleDeletion(context.Background(), nodeObj)
			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}
