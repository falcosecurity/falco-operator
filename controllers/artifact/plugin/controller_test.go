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

package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
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
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactserver"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

const testPluginName = "test-plugin"

func pluginNodeName(pluginName string) string {
	return controllerhelper.NodeObjectName(controllerhelper.ArtifactKindPlugin, pluginName, testutil.TestNodeName)
}

func testPluginNodeName() string {
	return pluginNodeName(testPluginName)
}

// testFetcher implements artifact.ArtifactFetcher for controller unit tests.
// ConfigMap and Inline delegate to a real artifact.Fetcher backed by the fake k8s client.
// FetchOCI returns in-memory bytes to avoid HTTP calls to a real artifact server.
type testFetcher struct {
	delegate     *artifact.Fetcher
	ociErr       error
	ociBytes     []byte
	ociCallCount int // incremented on every FetchOCI call
}

func newTestFetcher(cl client.Client) *testFetcher {
	return &testFetcher{delegate: &artifact.Fetcher{K8sClient: cl}}
}

func (f *testFetcher) FetchOCI(_ context.Context, _, _ string, _ artifact.Type, _ string) (artifact.FetchResult, error) {
	f.ociCallCount++
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

func newTestPluginNodeObj(opts ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	n := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPluginNodeName(),
			Namespace: testutil.TestNamespace,
			Labels:    controllerhelper.NodeObjectLabels(controllerhelper.ArtifactKindPlugin, testPluginName, testutil.TestNodeName),
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
	}
	for _, o := range opts {
		o(n)
	}
	return n
}

func withPluginOwnerRef() func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) {
		n.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: artifactv1alpha1.GroupVersion.String(),
			Kind:       "Plugin",
			Name:       testPluginName,
		}}
	}
}

// withPreviousInstallStatus seeds the ArtifactNode with the status that would result from a
// prior successful reconcile: an OCI binary in InstalledArtifacts plus all installation
// conditions set to True. Used to test the update-rejected flow.
func withPreviousInstallStatus() func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) {
		n.Status.InstalledArtifacts = []artifactv1alpha1.InstalledArtifact{
			{Path: "/usr/share/falco/plugins/test-plugin.so", Medium: string(artifact.MediumOCI)},
		}
		n.Status.Conditions = []metav1.Condition{
			common.NewOCIArtifactProgrammedCondition(metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed, artifact.MessageOCIArtifactProgrammed, 0),
			common.NewConfigProgrammedCondition(metav1.ConditionTrue, artifact.ReasonConfigProgrammed, artifact.MessageConfigProgrammed, 0),
			common.NewDependenciesSatisfiedCondition(metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, 0),
		}
	}
}

func withPluginFinalizer() func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{pluginNodeFinalizer}
	}
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*PluginReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		Build()

	mockFS := fsfake.NewMockFileSystem()
	store := nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	seedInstalledCacheFromObjs(store, objs)

	return &PluginReconciler{
		Client:   cl,
		Scheme:   s,
		recorder: events.NewFakeRecorder(100),
		fetcher:  newTestFetcher(cl),
		store:    store,
		nodeName: testutil.TestNodeName,
	}, cl
}

// seedInstalledCacheFromObjs mirrors what WarmSync does at startup: any pre-set
// ArtifactNode.Status.InstalledArtifacts among objs is seeded into store's installed-artifact
// cache, keyed by the owning Rulesfile/Plugin/Config's Kind+Name. Filesystem decisions are made
// from that cache, never from status, so a test simulating "this was already installed" must
// seed the cache the same way a real restart would, not just set status on the object.
func seedInstalledCacheFromObjs(store *nodeartifacts.Manager, objs []client.Object) {
	for _, obj := range objs {
		node, ok := obj.(*artifactv1alpha1.ArtifactNode)
		if !ok || len(node.Status.InstalledArtifacts) == 0 {
			continue
		}
		for _, ref := range node.OwnerReferences {
			var kind nodeartifacts.Kind
			switch ref.Kind {
			case controllerhelper.KindRulesfile:
				kind = nodeartifacts.KindRulesfile
			case controllerhelper.KindPlugin:
				kind = nodeartifacts.KindPlugin
			case controllerhelper.KindConfig:
				kind = nodeartifacts.KindConfig
			default:
				continue
			}
			store.SeedInstalled(nodeartifacts.Key{Kind: kind, Namespace: node.Namespace, Name: ref.Name}, node.Status.InstalledArtifacts)
			break
		}
	}
}

func TestNewPluginReconciler(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	store := nodeartifacts.NewManager(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
		compatfake.NewMockVersionsFetcher(nil))
	r := NewPluginReconciler(cl, s, events.NewFakeRecorder(10), "my-node", "my-namespace", false, &artifact.Fetcher{}, store)

	require.NotNil(t, r)
	assert.Equal(t, "my-node", r.nodeName)
	assert.NotNil(t, r.fetcher)
	assert.NotNil(t, r.store)
}

func TestReconcile(t *testing.T) {
	containerNodeName := pluginNodeName("container")

	tests := []struct {
		name                string
		objects             []client.Object
		req                 ctrl.Request
		triggerDeletion     bool
		pullErr             error
		preInstallPlugin    *artifactv1alpha1.Plugin // if set, seeds the shared node artifact manager via AddPluginConfig before Reconcile
		enforceRequirements bool
		wantErr             bool
		wantResult          *ctrl.Result // nil means the zero-value ctrl.Result{} is expected
		// wantRequeueAfterGE, when non-zero, replaces exact equality on wantResult.RequeueAfter
		// with a >= assertion. Use for cases where RequeueDelay applies jitter.
		wantRequeueAfterGE time.Duration
		wantFinalizer      *bool
		wantConditions     []testutil.ConditionExpect
	}{
		{
			name: "node object not found returns no error",
			req:  testutil.Request("nonexistent"),
		},
		{
			name: "first reconcile sets finalizer and returns early",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				},
				newTestPluginNodeObj(withPluginOwnerRef()),
			},
			req:           testutil.Request(testPluginNodeName()),
			wantFinalizer: new(true),
		},
		{
			name: "happy path with finalizer already set writes config",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/test-plugin", Tag: "latest"},
						},
					},
				},
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			req: testutil.Request(testPluginNodeName()),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
				{Type: commonv1alpha1.ConditionConfigProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigProgrammed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "happy path with plugin config",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/container", Tag: "latest"},
						},
						Config: &artifactv1alpha1.PluginConfig{
							InitConfig: &apiextensionsv1.JSON{
								Raw: []byte(`{"engines":{"containerd":{"enabled":true}}}`),
							},
						},
					},
				},
				&artifactv1alpha1.ArtifactNode{
					ObjectMeta: metav1.ObjectMeta{
						Name:       containerNodeName,
						Namespace:  testutil.TestNamespace,
						Labels:     controllerhelper.NodeObjectLabels(controllerhelper.ArtifactKindPlugin, "container", testutil.TestNodeName),
						Finalizers: []string{pluginNodeFinalizer},
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: artifactv1alpha1.GroupVersion.String(),
							Kind:       "Plugin",
							Name:       "container",
						}},
					},
					Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
				},
			},
			req: testutil.Request(containerNodeName),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
				{Type: commonv1alpha1.ConditionConfigProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigProgrammed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "deletion with finalizer cleans up",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				},
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			triggerDeletion: true,
			preInstallPlugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
			},
			req: testutil.Request(testPluginNodeName()),
		},
		{
			name: "deletion without our finalizer is no-op",
			objects: []client.Object{
				newTestPluginNodeObj(func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{"some-other-finalizer"}
				}),
			},
			req:             testutil.Request(testPluginNodeName()),
			triggerDeletion: true,
		},
		{
			name: "OCI store failure sets error conditions on status",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{
								Repository: "falcosecurity/plugins/test",
								Tag:        "latest",
							},
						},
					},
				},
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			req:     testutil.Request(testPluginNodeName()),
			pullErr: fmt.Errorf("network error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactProgramFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			// A retryable OCI-fetch failure requeues via RequeueAfter instead of returning a reconcile error.
			// RequeueDelay applies wait.Jitter (up to +30%) so the exact duration is non-deterministic;
			// assert >= the base delay rather than exact equality.
			name: "OCI pull retryable error requeues without a reconcile error",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{
								Repository: "falcosecurity/plugins/test",
								Tag:        "latest",
							},
						},
					},
				},
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			req:                testutil.Request(testPluginNodeName()),
			pullErr:            &artifact.RetryableError{Err: errors.New("mock pull error"), RetryAfter: 7 * time.Second},
			wantRequeueAfterGE: 7 * time.Second,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactProgramFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			name: "references resolved but OCI pull fails sets ResolvedRefs true and Programmed false",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-pull-secret",
						Namespace: testutil.TestNamespace,
					},
					Data: map[string][]byte{
						commonv1alpha1.SecretUsernameKey: []byte("user"),
						commonv1alpha1.SecretPasswordKey: []byte("pass"),
					},
				},
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{
								Repository: "falcosecurity/plugins/test",
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
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			req:     testutil.Request(testPluginNodeName()),
			pullErr: fmt.Errorf("network error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactProgramFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			// When enforce-requirements=true, requirements are not met, and the plugin was never
			// installed on this node, the controller must explicitly set ConfigProgrammed=False and
			// OCIArtifactProgrammed=False. Without this, those condition types are absent from the
			// ArtifactNode, which lets another node's True status win unopposed in AggregateConditions
			// and makes the Plugin-level status show ConfigProgrammed=True while DependenciesSatisfied=False.
			name: "enforce mode: requirements not satisfied and never installed sets ConfigProgrammed and OCIArtifactProgrammed to False",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/test-plugin", Tag: "latest"},
						},
					},
					Status: artifactv1alpha1.PluginStatus{
						ArtifactMeta: &commonv1alpha1.ArtifactMeta{
							Requirements: []commonv1alpha1.ArtifactMetaRequirement{
								{Name: "plugin_api_version", Version: "3.0.0"},
							},
						},
					},
				},
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			req:                 testutil.Request(testPluginNodeName()),
			enforceRequirements: true,
			// store has no Falco capabilities (default from newTestReconciler) → DependenciesNotSatisfied.
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
				{Type: commonv1alpha1.ConditionConfigProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			// When enforce-requirements=true, requirements are not met, but the plugin WAS previously
			// installed (alreadyInstalled=true), the controller must NOT clear ConfigProgrammed or
			// OCIArtifactProgrammed: the old version is still on disk and its aggregate conditions
			// correctly reflect that (DependenciesNotSatisfiedUpdateRejected reason).
			name: "enforce mode: requirements fail on previously installed plugin keeps ConfigProgrammed and OCIArtifactProgrammed True",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/test-plugin", Tag: "latest"},
						},
					},
					Status: artifactv1alpha1.PluginStatus{
						ArtifactMeta: &commonv1alpha1.ArtifactMeta{
							Requirements: []commonv1alpha1.ArtifactMetaRequirement{
								{Name: "plugin_api_version", Version: "3.0.0"},
							},
						},
					},
				},
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef(), withPreviousInstallStatus()),
			},
			req:                 testutil.Request(testPluginNodeName()),
			enforceRequirements: true,
			wantConditions: []testutil.ConditionExpect{
				{
					Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse,
					Reason: artifact.ReasonDependenciesNotSatisfiedUpdateRejected,
				},
				{Type: commonv1alpha1.ConditionConfigProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigProgrammed},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			name: "advise mode installs despite unsatisfied requirement and stays Programmed",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/test-plugin", Tag: "latest"},
						},
					},
					Status: artifactv1alpha1.PluginStatus{
						ArtifactMeta: &commonv1alpha1.ArtifactMeta{
							Requirements: []commonv1alpha1.ArtifactMetaRequirement{
								{Name: "plugin_api_version", Version: "99.0.0"},
							},
						},
					},
				},
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			req:                 testutil.Request(testPluginNodeName()),
			enforceRequirements: false,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfiedInstalledAnyway,
				},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
				{Type: commonv1alpha1.ConditionConfigProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigProgrammed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)
			r.enforceRequirements = tt.enforceRequirements

			if tt.pullErr != nil {
				r.fetcher = &testFetcher{
					delegate: &artifact.Fetcher{K8sClient: cl},
					ociErr:   tt.pullErr,
				}
			}

			if tt.preInstallPlugin != nil {
				_, _, err := r.store.AddPluginConfig(context.Background(), tt.preInstallPlugin, r.fetcher)
				require.NoError(t, err)
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
				switch {
				case tt.wantRequeueAfterGE > 0:
					assert.GreaterOrEqual(t, result.RequeueAfter, tt.wantRequeueAfterGE,
						"RequeueAfter should be >= base delay (jitter adds up to 30%%)")
				case tt.wantResult != nil:
					assert.Equal(t, *tt.wantResult, result)
				default:
					assert.Equal(t, ctrl.Result{}, result)
				}
			}

			if tt.wantFinalizer != nil {
				nodeObj := &artifactv1alpha1.ArtifactNode{}
				if err := cl.Get(context.Background(), tt.req.NamespacedName, nodeObj); err == nil {
					assert.Equal(t, *tt.wantFinalizer, controllerutil.ContainsFinalizer(nodeObj, pluginNodeFinalizer))
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

// TestReconcile_SecondReconcileDoesNotDropConfigSubEntry covers repeated back-to-back reconciles
// for the same PluginNode with nothing in the spec changed (e.g. a watch event bounce): the
// second Reconcile call must not lose the Config sub-entry a prior reconcile already established
// in installedArtifacts[0].config.
func TestReconcile_SecondReconcileDoesNotDropConfigSubEntry(t *testing.T) {
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/container", Tag: "latest"},
			},
		},
	}
	nodeObj := newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef())
	r, cl := newTestReconciler(t, plugin, nodeObj)
	req := testutil.Request(testPluginNodeName())

	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)

	got := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), req.NamespacedName, got))
	require.Len(t, got.Status.InstalledArtifacts, 1, "after the first reconcile")
	require.NotNil(t, got.Status.InstalledArtifacts[0].Config, "Config must be set after the first reconcile")

	// Second reconcile: nothing changed in the spec, simulating a watch event bounce (e.g. a
	// Secret or unrelated ArtifactNode update re-enqueuing this object).
	_, err = r.Reconcile(context.Background(), req)
	require.NoError(t, err)

	require.NoError(t, cl.Get(context.Background(), req.NamespacedName, got))
	require.Len(t, got.Status.InstalledArtifacts, 1, "after the second reconcile")
	assert.NotNil(t, got.Status.InstalledArtifacts[0].Config, "second reconcile must not drop the Config sub-entry")
}

func TestHandleDeletion(t *testing.T) {
	tests := []struct {
		name             string
		objects          []client.Object
		triggerDeletion  bool
		preInstallPlugin *artifactv1alpha1.Plugin // if set, seeds the shared node artifact manager via AddPluginConfig before handleDeletion
		wantOK           bool
	}{
		{
			name: "not marked for deletion returns false",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				},
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			wantOK: false,
		},
		{
			name: "marked for deletion with finalizer cleans up",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				},
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			triggerDeletion: true,
			preInstallPlugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
			},
			wantOK: true,
		},
		{
			name: "marked for deletion without our finalizer skips cleanup",
			objects: []client.Object{
				newTestPluginNodeObj(func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{"some-other-finalizer"}
				}),
			},
			triggerDeletion: true,
			wantOK:          true,
		},
		{
			// Parent Plugin already deleted; config removal falls back to the ownerRef name instead of being skipped.
			name: "marked for deletion with finalizer but parent Plugin already deleted cleans up config",
			objects: []client.Object{
				// No Plugin object: it has already been garbage-collected.
				newTestPluginNodeObj(withPluginFinalizer(), withPluginOwnerRef()),
			},
			triggerDeletion: true,
			preInstallPlugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
			},
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			if tt.preInstallPlugin != nil {
				_, _, err := r.store.AddPluginConfig(context.Background(), tt.preInstallPlugin, r.fetcher)
				require.NoError(t, err)
			}

			nodeObj := &artifactv1alpha1.ArtifactNode{}
			require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginNodeName(), Namespace: testutil.TestNamespace}, nodeObj))

			if tt.triggerDeletion {
				require.NoError(t, cl.Delete(context.Background(), nodeObj))
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginNodeName(), Namespace: testutil.TestNamespace}, nodeObj))
			}

			ok, err := r.handleDeletion(context.Background(), nodeObj)

			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

func TestEnsurePlugin(t *testing.T) {
	tests := []struct {
		name    string
		plugin  *artifactv1alpha1.Plugin
		wantErr bool
		// prePlugin, if set, is installed first to populate InstalledArtifacts.
		prePlugin *artifactv1alpha1.Plugin
		// preSpecHash is set on prePlugin.Status.ArtifactMeta before the pre-install.
		preSpecHash string
		// parentSpecHash is set on plugin.Status.ArtifactMeta before the main reconcile.
		parentSpecHash string
		// wantOCIFetchCount, when non-nil, asserts the exact FetchOCI call count in the main reconcile.
		wantOCIFetchCount *int
		// wantInstalledOCISpecHash, when non-empty, asserts OCI InstalledArtifact.SpecHash after main reconcile.
		wantInstalledOCISpecHash string
		// wantOCIConditionRemoved, when true, asserts OCIArtifactProgrammed is absent after the main reconcile.
		wantOCIConditionRemoved bool
	}{
		{
			name: "nil OCI artifact succeeds",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
			},
		},
		{
			name: "removing OCIArtifact cleans up stale binary and removes OCIArtifactProgrammed",
			prePlugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/plugin", Tag: "latest"},
					},
				},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
			},
			wantOCIConditionRemoved: true,
		},
		{
			name: "nil OCI artifact spec is also fine",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.PluginSpec{},
			},
		},
		{
			name:           "OCI: specHash written to InstalledArtifacts after install",
			parentSpecHash: "plugin-spec-hash-v1",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/plugin", Tag: "latest"},
					},
				},
			},
			wantOCIFetchCount:        new(1),
			wantInstalledOCISpecHash: "plugin-spec-hash-v1",
		},
		{
			name:        "OCI: skips fetch when specHash matches and disk is intact",
			preSpecHash: "stable-hash",
			prePlugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/plugin", Tag: "latest"},
					},
				},
			},
			parentSpecHash: "stable-hash",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/plugin", Tag: "latest"},
					},
				},
			},
			wantOCIFetchCount:        new(0),
			wantInstalledOCISpecHash: "stable-hash",
		},
		{
			name:        "OCI: re-fetches when specHash changes",
			preSpecHash: "old-hash",
			prePlugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/plugin", Tag: "latest"},
					},
				},
			},
			parentSpecHash: "new-hash",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/plugin", Tag: "latest"},
					},
				},
			},
			wantOCIFetchCount:        new(1),
			wantInstalledOCISpecHash: "new-hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			nodeObj := newTestPluginNodeObj()

			if tt.prePlugin != nil {
				if tt.preSpecHash != "" {
					tt.prePlugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{SpecHash: tt.preSpecHash}
				}
				preNode := newTestPluginNodeObj()
				require.NoError(t, r.ensurePlugin(context.Background(), tt.prePlugin, preNode), "prePlugin setup failed")
				nodeObj.Status = preNode.Status
			}

			if tt.parentSpecHash != "" {
				tt.plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{SpecHash: tt.parentSpecHash}
			}
			tf := r.fetcher.(*testFetcher)
			tf.ociCallCount = 0

			err := r.ensurePlugin(context.Background(), tt.plugin, nodeObj)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantOCIFetchCount != nil {
				assert.Equal(t, *tt.wantOCIFetchCount, tf.ociCallCount, "unexpected FetchOCI call count")
			}
			if tt.wantInstalledOCISpecHash != "" {
				ociEntry := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI)
				require.NotNil(t, ociEntry, "expected OCI entry in InstalledArtifacts")
				assert.Equal(t, tt.wantInstalledOCISpecHash, ociEntry.SpecHash, "OCI InstalledArtifact.SpecHash mismatch")
			}
			if tt.wantOCIConditionRemoved {
				assert.Nil(t, artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI),
					"expected OCI entry removed from InstalledArtifacts")
				assert.Nil(t, apimeta.FindStatusCondition(nodeObj.Status.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String()),
					"expected OCIArtifactProgrammed condition to be removed, not set True, after stale cleanup")
			}
		})
	}
}

// TestEnsurePlugin_ProgrammedLastTransitionTime verifies LastTransitionTime stays put on a
// steady-state reconcile and only moves on a real status transition.
func TestEnsurePlugin_ProgrammedLastTransitionTime(t *testing.T) {
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
			// OCIArtifact must be set: the nil-spec branch removes this condition instead of setting it.
			plugin := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/plugin", Tag: "latest"},
					},
				},
			}
			nodeObj := newTestPluginNodeObj()
			nodeObj.Status.Conditions = []metav1.Condition{{
				Type:               commonv1alpha1.ConditionOCIArtifactProgrammed.String(),
				Status:             tt.initialStatus,
				Reason:             artifact.ReasonOCIArtifactProgrammed,
				Message:            artifact.MessageOCIArtifactProgrammed,
				LastTransitionTime: pinned,
			}}

			require.NoError(t, r.ensurePlugin(context.Background(), plugin, nodeObj))

			cond := apimeta.FindStatusCondition(nodeObj.Status.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String())
			require.NotNil(t, cond)
			require.Equal(t, metav1.ConditionTrue, cond.Status)
			require.Equal(t, tt.wantPreserved, cond.LastTransitionTime.Equal(&pinned))
		})
	}
}

// TestEnsurePluginConfig covers this reconciler's own responsibilities around
// nodeartifacts.Manager.AddPluginConfig: translating its result into conditions/events, and
// propagating a blocked rename as an error. The aggregate-file behavior itself (rename handling,
// content, store failures) is covered directly against the Manager in the nodeartifacts package.
func TestEnsurePluginConfig(t *testing.T) {
	tests := []struct {
		name string

		plugin   *artifactv1alpha1.Plugin
		writeErr error
		wantErr  bool

		// preConditions, if set, seed nodeObj.Status.Conditions before the call.
		preConditions []metav1.Condition
		// wantConfigConditionRemoved, when true, asserts ConfigProgrammed is absent afterward.
		wantConfigConditionRemoved bool

		wantConditions []testutil.ConditionExpect
		wantEvents     []string
	}{
		{
			name: "nil OCIArtifact removes stale ConfigProgrammed condition",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
			},
			preConditions: []metav1.Condition{{
				Type:    commonv1alpha1.ConditionConfigProgrammed.String(),
				Status:  metav1.ConditionTrue,
				Reason:  artifact.ReasonConfigProgrammed,
				Message: artifact.MessageConfigProgrammed,
			}},
			wantConfigConditionRemoved: true,
		},
		{
			name: "writes config for basic plugin",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json", Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/json", Tag: "latest"},
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionConfigProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigProgrammed},
			},
			wantEvents: []string{"Normal InlineArtifactStored Inline artifact stored successfully"},
		},
		{
			name: "store inline yaml fails sets error conditions",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/test-plugin", Tag: "latest"},
					},
				},
			},
			writeErr: fmt.Errorf("disk full"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionConfigProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonConfigProgramFailed},
			},
			wantEvents: []string{"Warning InlinePluginConfigStoreFailed Failed to store inline plugin config: disk full"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			nodeObj := newTestPluginNodeObj()
			if tt.preConditions != nil {
				nodeObj.Status.Conditions = tt.preConditions
			}

			if tt.writeErr != nil {
				mockFS := fsfake.NewMockFileSystem()
				mockFS.WriteErr = tt.writeErr
				r.store = nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
			}

			err := r.ensurePluginConfig(context.Background(), tt.plugin, nodeObj)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if len(tt.wantConditions) > 0 {
				testutil.RequireConditions(t, nodeObj.Status.Conditions, tt.wantConditions)
			}
			if tt.wantConfigConditionRemoved {
				assert.Nil(t, apimeta.FindStatusCondition(nodeObj.Status.Conditions, commonv1alpha1.ConditionConfigProgrammed.String()),
					"expected ConfigProgrammed condition to be removed, not left True, when OCIArtifact is nil")
			}
			testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events, tt.wantEvents)
		})
	}
}

// TestEnsurePluginConfig_PopulatesConfigSubEntryEvenWhenUnchanged covers the shared
// plugins-config aggregate, tracked in the manager's own cache (keyed by PluginConfigKey) rather
// than per-Plugin-CR status: a re-add that the cache already knows is unchanged must still
// mirror the file's path into this Plugin's own status entry, not only on the reconcile that
// first wrote it.
func TestEnsurePluginConfig_PopulatesConfigSubEntryEvenWhenUnchanged(t *testing.T) {
	r, _ := newTestReconciler(t)
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "json", Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/json", Tag: "latest"},
			},
		},
	}
	// Establishes the shared config file in the manager's cache (StoreActionAdded).
	require.NoError(t, r.ensurePluginConfig(context.Background(), plugin, newTestPluginNodeObj()))

	// A separate nodeObj whose status never recorded the Config sub-entry (e.g. an earlier status
	// patch dropped by an SSA conflict), even though the OCI binary entry already exists and the
	// shared file, per the cache, is unchanged (configAction will be StoreActionUnchanged).
	nodeObj := newTestPluginNodeObj()
	nodeObj.Status.InstalledArtifacts = []artifactv1alpha1.InstalledArtifact{
		{Path: "/usr/share/falco/plugins/json.so", Medium: string(artifact.MediumOCI)},
	}

	require.NoError(t, r.ensurePluginConfig(context.Background(), plugin, nodeObj))

	var configEntry *artifactv1alpha1.InstalledArtifactConfig
	for _, a := range nodeObj.Status.InstalledArtifacts {
		if a.Medium == string(artifact.MediumOCI) {
			configEntry = a.Config
			break
		}
	}
	require.NotNil(t, configEntry, "Config sub-entry must be populated from the cache even when configAction is Unchanged")
	assert.NotEmpty(t, configEntry.Path)
}

func TestEnforceReferenceResolution(t *testing.T) {
	tests := []struct {
		name             string
		objects          []client.Object
		plugin           *artifactv1alpha1.Plugin
		wantErr          bool
		wantConditions   []testutil.ConditionExpect
		wantNoConditions bool
		presetConditions []metav1.Condition
	}{
		{
			name: "no registry has no references and removes stale ResolvedRefs",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{
							Repository: "falcosecurity/plugins/test",
							Tag:        "latest",
						},
					},
				},
			},
			presetConditions: []metav1.Condition{
				common.NewResolvedRefsCondition(metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, 0),
			},
			wantNoConditions: true,
		},
		{
			name: "nil OCIArtifact has no references",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
			},
			wantNoConditions: true,
		},
		{
			name: "auth secret exists sets ResolvedRefs true",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: testutil.TestNamespace},
				},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{
							Repository: "falcosecurity/plugins/test",
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
			name: "auth secret not found sets ResolvedRefs false and Programmed false",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{
							Repository: "falcosecurity/plugins/test",
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
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t, tt.objects...)
			nodeObj := newTestPluginNodeObj()

			if len(tt.presetConditions) > 0 {
				nodeObj.Status.Conditions = tt.presetConditions
			}

			err := r.enforceReferenceResolution(context.Background(), tt.plugin, nodeObj)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantNoConditions {
				assert.Empty(t, nodeObj.Status.Conditions)
			}

			if len(tt.wantConditions) > 0 {
				testutil.RequireConditions(t, nodeObj.Status.Conditions, tt.wantConditions)
			}
		})
	}
}

func TestFindNodeObjectsForSecret(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPluginName,
			Namespace: testutil.TestNamespace,
		},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "ghcr.io/repo", Tag: "latest"},
				Registry: &commonv1alpha1.RegistryConfig{
					Auth: &commonv1alpha1.RegistryAuth{
						SecretRef: &commonv1alpha1.SecretRef{Name: "my-pull-secret"},
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(pl).
		WithIndex(&artifactv1alpha1.Plugin{}, index.SecretOnPlugin, index.PluginBySecretRef).
		Build()

	mockFS := fsfake.NewMockFileSystem()

	r := &PluginReconciler{
		Client:   cl,
		Scheme:   s,
		recorder: events.NewFakeRecorder(100),
		fetcher:  newTestFetcher(cl),
		store:    nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil)),
		nodeName: testutil.TestNodeName,
	}

	tests := []struct {
		name       string
		secretName string
		wantCount  int
	}{
		{
			name:       "matching secret returns node object requests",
			secretName: "my-pull-secret",
			wantCount:  1,
		},
		{
			name:       "non-matching secret returns empty",
			secretName: "other-secret",
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tt.secretName,
					Namespace: testutil.TestNamespace,
				},
			}
			requests := r.findNodeObjectsForSecret(context.Background(), secret)
			require.Len(t, requests, tt.wantCount)
			if tt.wantCount > 0 {
				assert.Equal(t, testPluginNodeName(), requests[0].Name)
				assert.Equal(t, testutil.TestNamespace, requests[0].Namespace)
			}
		})
	}
}

func TestEnforcePluginCompatibility(t *testing.T) {
	ociPlugin := func(meta *commonv1alpha1.ArtifactMeta) *artifactv1alpha1.Plugin {
		return &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
			Spec: artifactv1alpha1.PluginSpec{
				OCIArtifact: &commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/test", Tag: "latest"},
				},
			},
			Status: artifactv1alpha1.PluginStatus{ArtifactMeta: meta},
		}
	}

	tests := []struct {
		name                string
		plugin              *artifactv1alpha1.Plugin
		falcoCaps           map[string]string
		falcoErr            error
		enforceRequirements bool
		preInstalled        bool
		wantSkip            bool
		wantErr             bool
		wantConditions      []testutil.ConditionExpect
		wantMsgContain      string
		wantNoConditions    bool
	}{
		{
			name:             "nil OCI artifact removes DependenciesSatisfied condition",
			plugin:           &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace}},
			wantSkip:         false,
			wantNoConditions: true,
		},
		{
			name:     "nil ArtifactMeta non-strict sets DependenciesSatisfied=True",
			plugin:   ociPlugin(nil),
			wantSkip: false,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name:                "nil ArtifactMeta strict blocks with Unknown",
			plugin:              ociPlugin(nil),
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionUnknown, Reason: artifact.ReasonDependenciesUnknown},
			},
		},
		{
			name: "empty requirements sets DependenciesSatisfied=True",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{},
			}),
			wantSkip: false,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "requirement satisfied sets DependenciesSatisfied=True",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "3.0.0"},
				},
			}),
			falcoCaps: map[string]string{"plugin_api_version": "3.12.0"},
			wantSkip:  false,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "plugin_api_version major mismatch blocks with False",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "2.0.0"},
				},
			}),
			falcoCaps:           map[string]string{"plugin_api_version": "3.12.0"},
			enforceRequirements: true,
			wantSkip:            true,
			wantMsgContain:      "major versions are incompatible",
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "plugin_api_version downgrade blocks with False",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "3.0.0"},
				},
			}),
			falcoCaps:           map[string]string{"plugin_api_version": "2.12.0"},
			enforceRequirements: true,
			wantSkip:            true,
			wantMsgContain:      "major versions are incompatible",
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "generic requirement too low blocks with False",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "engine_version_semver", Version: "0.62.0"},
				},
			}),
			falcoCaps:           map[string]string{"engine_version_semver": "0.57.0"},
			enforceRequirements: true,
			wantSkip:            true,
			wantMsgContain:      "engine_version_semver",
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "capability not advertised by Falco blocks with False",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "3.0.0"},
				},
			}),
			falcoCaps:           map[string]string{},
			enforceRequirements: true,
			wantSkip:            true,
			wantMsgContain:      "does not advertise",
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "advise mode installs anyway on unsatisfied requirement",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "2.0.0"},
				},
			}),
			falcoCaps:           map[string]string{"plugin_api_version": "3.12.0"},
			enforceRequirements: false,
			wantSkip:            false,
			wantMsgContain:      "installed anyway",
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfiedInstalledAnyway,
				},
			},
		},
		{
			name: "enforce mode rejects an update but keeps the previous install",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "2.0.0"},
				},
			}),
			falcoCaps:           map[string]string{"plugin_api_version": "3.12.0"},
			enforceRequirements: true,
			preInstalled:        true,
			wantSkip:            true,
			wantMsgContain:      "keeping the previously installed version",
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfiedUpdateRejected,
				},
			},
		},
		{
			name: "Falco versions not yet observed non-strict installs anyway",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "3.0.0"},
				},
			}),
			falcoErr: fmt.Errorf("connection refused"),
			wantSkip: false,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse,
					Reason: artifact.ReasonDependenciesNotSatisfiedInstalledAnyway,
				},
			},
		},
		{
			name: "Falco versions not yet observed strict blocks without returning an error",
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "3.0.0"},
				},
			}),
			falcoErr:            fmt.Errorf("connection refused"),
			enforceRequirements: true,
			wantSkip:            true,
			wantErr:             false,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			r.enforceRequirements = tt.enforceRequirements
			if tt.falcoErr == nil && tt.falcoCaps != nil {
				r.store.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.falcoCaps).Result)
			}
			nodeObj := newTestPluginNodeObj()
			if tt.preInstalled {
				installed := []artifactv1alpha1.InstalledArtifact{
					{Path: "/var/lib/falco/plugins/test.so", Medium: string(artifact.MediumOCI)},
				}
				nodeObj.Status.InstalledArtifacts = installed
				// alreadyInstalled is read from the manager's cache, not status; seed it the way
				// WarmSync would from a real restart.
				r.store.SeedInstalled(nodeartifacts.Key{Kind: nodeartifacts.KindPlugin, Namespace: testutil.TestNamespace, Name: testPluginName}, installed)
			}

			skip, err := r.enforcePluginCompatibility(context.Background(), tt.plugin, nodeObj)

			assert.Equal(t, tt.wantSkip, skip)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.wantNoConditions {
				assert.Empty(t, nodeObj.Status.Conditions)
			}
			if tt.wantMsgContain != "" {
				cond := apimeta.FindStatusCondition(nodeObj.Status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
				require.NotNil(t, cond)
				assert.Contains(t, cond.Message, tt.wantMsgContain)
			}
			if len(tt.wantConditions) > 0 {
				testutil.RequireConditions(t, nodeObj.Status.Conditions, tt.wantConditions)
			}
		})
	}
}

func TestEnsurePluginConfig_RegistersProvidesWithNodeArtifactManager(t *testing.T) {
	r, _ := newTestReconciler(t)
	nodeObj := newTestPluginNodeObj()
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "r", Tag: "t"}},
		},
	}

	require.NoError(t, r.ensurePluginConfig(context.Background(), pl, nodeObj))

	err := r.store.RemovePluginConfigByName(context.Background(), r.fetcher, testPluginName, testPluginName)
	require.NoError(t, err, "nothing requires it yet, so this proves the name was registered as provided")

	require.NoError(t, r.ensurePluginConfig(context.Background(), pl, nodeObj))

	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "some-rulesfile"}
	r.store.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: testPluginName, Version: "1.0.0"}}})

	err = r.store.RemovePluginConfigByName(context.Background(), r.fetcher, testPluginName, testPluginName)
	require.Error(t, err)
	blocked, ok := errors.AsType[*nodeartifacts.BlockedError](err)
	require.True(t, ok)
	assert.Contains(t, blocked.BlockedBy, rfKey)
}

func TestHandleDeletion_BlockedByRequiringRulesfileDoesNotRemoveFinalizer(t *testing.T) {
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
	}
	nodeObj := newTestPluginNodeObj(withPluginOwnerRef(), withPluginFinalizer())

	r, cl := newTestReconciler(t, pl, nodeObj)
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: nodeObj.Name, Namespace: nodeObj.Namespace}, nodeObj))

	// Simulate config already installed for this plugin (as if a prior reconcile ran).
	_, _, err := r.store.AddPluginConfig(context.Background(), pl, r.fetcher)
	require.NoError(t, err)
	rfKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "some-rulesfile"}
	r.store.Sync(rfKey, []nodeartifacts.RequirementGroup{{{Name: testPluginName, Version: "1.0.0"}}})

	require.NoError(t, cl.Delete(context.Background(), nodeObj))
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: nodeObj.Name, Namespace: nodeObj.Namespace}, nodeObj))

	handled, err := r.handleDeletion(context.Background(), nodeObj)

	require.NoError(t, err, "a blocked removal must not surface as a reconcile error")
	assert.True(t, handled, "blocked cleanup must stop normal reconciliation")
	assert.True(t, controllerutil.ContainsFinalizer(nodeObj, pluginNodeFinalizer), "finalizer must remain while blocked")

	cond := apimeta.FindStatusCondition(nodeObj.Status.Conditions, commonv1alpha1.ConditionDeletionBlocked.String())
	require.NotNil(t, cond, "DeletionBlocked condition must be set while blocked")
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, artifact.ReasonPluginConfigStillRequired, cond.Reason)
	assert.Contains(t, cond.Message, rfKey.Name)

	persisted := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: nodeObj.Name, Namespace: nodeObj.Namespace}, persisted))
	persistedCond := apimeta.FindStatusCondition(persisted.Status.Conditions, commonv1alpha1.ConditionDeletionBlocked.String())
	require.NotNil(t, persistedCond, "DeletionBlocked condition must be patched to the ArtifactNode status")
	assert.Equal(t, metav1.ConditionTrue, persistedCond.Status)

	// Now clear the requirement and confirm cleanup proceeds.
	r.store.Sync(rfKey, nil)
	handled, err = r.handleDeletion(context.Background(), nodeObj)
	require.NoError(t, err)
	assert.True(t, handled)
}

func TestReconcile_BlockedDeletionDoesNotInstall(t *testing.T) {
	patchFailure := errors.New("status unavailable")
	for _, failPatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("status patch fails=%t", failPatch), func(t *testing.T) {
			ctx := t.Context()
			parent := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "example/plugin", Tag: "new"}},
				},
				Status: artifactv1alpha1.PluginStatus{ArtifactMeta: &commonv1alpha1.ArtifactMeta{SpecHash: "new-spec"}},
			}
			node := newTestPluginNodeObj(withPluginOwnerRef(), withPluginFinalizer())
			r, cl := newTestReconciler(t, parent, node)
			_, configFile, err := r.store.AddPluginConfig(ctx, parent, r.fetcher)
			require.NoError(t, err)
			result, err := r.fetcher.FetchInline(ctx, []byte("installed binary"))
			require.NoError(t, err)
			action, binaryFile, err := r.store.Store(ctx, parent.Namespace, parent.Name, 0, artifact.TypePlugin, artifact.MediumOCI, result)
			require.NoError(t, err)
			artifact.UpdateInstalledStatus(&node.Status.InstalledArtifacts, action, artifact.MediumOCI, binaryFile)
			artifact.UpdateInstalledSpecHash(&node.Status.InstalledArtifacts, artifact.MediumOCI, "old-spec")
			require.NoError(t, cl.Status().Update(ctx, node))
			installed := node.Status.InstalledArtifacts
			key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: "installed-rules"}
			r.store.Sync(key, []nodeartifacts.RequirementGroup{{{Name: testPluginName, Version: "1.0.0"}}})
			require.NoError(t, cl.Delete(ctx, node))
			if failPatch {
				watchClient, ok := cl.(client.WithWatch)
				require.True(t, ok)
				r.Client = interceptor.NewClient(watchClient, interceptor.Funcs{
					SubResourceApply: func(context.Context, client.Client, string, k8sruntime.ApplyConfiguration, ...client.SubResourceApplyOption) error {
						return patchFailure
					},
				})
			}
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(node)}
			_, err = r.Reconcile(ctx, request)
			if failPatch {
				require.ErrorIs(t, err, patchFailure)
			} else {
				require.NoError(t, err)
			}
			assert.Zero(t, r.fetcher.(*testFetcher).ociCallCount, "deletion must not fall through to an OCI update")
			for _, file := range []*artifact.File{binaryFile, configFile} {
				intact, verifyErr := r.store.Verify(ctx, file)
				require.NoError(t, verifyErr)
				assert.True(t, intact, "blocked deletion must preserve installed files")
			}
			require.NoError(t, cl.Get(ctx, request.NamespacedName, node))
			assert.Contains(t, node.Finalizers, pluginNodeFinalizer)
			assert.Equal(t, installed, node.Status.InstalledArtifacts)
			if !failPatch {
				condition := apimeta.FindStatusCondition(node.Status.Conditions, commonv1alpha1.ConditionDeletionBlocked.String())
				require.NotNil(t, condition)
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
			}

			// Once the dependent rules are removed, normal cleanup can finish without installing.
			r.Client = cl
			r.store.Sync(key, nil)
			_, err = r.Reconcile(ctx, request)
			require.NoError(t, err)
			err = cl.Get(ctx, request.NamespacedName, node)
			require.True(t, k8serrors.IsNotFound(err), "cleanup should release the finalizer and delete the ArtifactNode: %v", err)
			present, err := r.store.Verify(ctx, binaryFile)
			require.NoError(t, err)
			assert.False(t, present)
			assert.Zero(t, r.fetcher.(*testFetcher).ociCallCount)
		})
	}
}

func TestEnsurePlugin_WaitsForExpectedOCIDigest(t *testing.T) {
	for _, alreadyInstalled := range []bool{false, true} {
		name := "first installation"
		if alreadyInstalled {
			name = "update preserves installed revision"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cache := artifactcache.NewCache(t.TempDir())
			require.NoError(t, cache.Load())
			goos, goarch, platform := runtime.GOOS, runtime.GOARCH, runtime.GOOS+"-"+runtime.GOARCH
			oldDigest := digest.FromString("old OCI manifest").String()
			newDigest := digest.FromString("new OCI manifest").String()
			oldPath := artifactcache.BlobPath(cache.Dir(), "plugin", "artifact:old", oldDigest, goos, goarch)
			newPath := artifactcache.BlobPath(cache.Dir(), "plugin", "artifact:new", newDigest, goos, goarch)
			require.NoError(t, cache.Store(oldPath, []byte("old artifact bytes"), 0o755))
			require.NoError(t, cache.Set("plugin", "default", "artifact", platform, oldPath))

			srv := httptest.NewServer(artifactserver.New(cache).Handler())
			defer srv.Close()
			fs := fsfake.NewMockFileSystem()
			reconciler := &PluginReconciler{
				recorder: events.NewFakeRecorder(20),
				fetcher:  &artifact.Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client()},
				store:    nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil)),
			}
			parent := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "artifact", Namespace: "default", Generation: 1},
				Spec: artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{Repository: "artifact", Tag: "old"},
				}},
				Status: artifactv1alpha1.PluginStatus{
					ObservedGeneration: 1,
					ArtifactMeta:       &commonv1alpha1.ArtifactMeta{SpecHash: "spec-old", Digest: oldDigest},
				},
			}
			node := &artifactv1alpha1.ArtifactNode{}
			if alreadyInstalled {
				require.NoError(t, reconciler.ensurePlugin(ctx, parent, node))
			}
			previous := node.DeepCopy().Status.InstalledArtifacts

			// The parent metadata is published before the aggregator replaces the cache entry.
			parent.Generation = 2
			parent.Spec.OCIArtifact.Image.Tag = "new"
			parent.Status.ObservedGeneration = 2
			parent.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{SpecHash: "spec-new", Digest: newDigest}

			err := reconciler.ensurePlugin(ctx, parent, node)
			var retryErr *artifact.RetryableError
			require.ErrorAs(t, err, &retryErr, "an old cached revision must not be accepted as the new spec")
			require.Equal(t, previous, node.Status.InstalledArtifacts)
			if alreadyInstalled {
				require.Equal(t, []byte("old artifact bytes"), fs.Files[previous[0].Path])
			} else {
				require.Empty(t, fs.Files)
			}
			condition := apimeta.FindStatusCondition(node.Status.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String())
			require.NotNil(t, condition)
			require.Equal(t, metav1.ConditionFalse, condition.Status)

			// Once the expected digest is available, the retry installs it and records its spec.
			require.NoError(t, cache.Store(newPath, []byte("new artifact bytes"), 0o755))
			require.NoError(t, cache.Set("plugin", "default", "artifact", platform, newPath))
			require.NoError(t, reconciler.ensurePlugin(ctx, parent, node))
			require.Len(t, node.Status.InstalledArtifacts, 1)
			installed := node.Status.InstalledArtifacts[0]
			require.Equal(t, "spec-new", installed.SpecHash)
			require.Equal(t, []byte("new artifact bytes"), fs.Files[installed.Path])
			condition = apimeta.FindStatusCondition(node.Status.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String())
			require.Equal(t, metav1.ConditionTrue, condition.Status)
			require.Equal(t, int64(2), condition.ObservedGeneration)

			// A verified, installed revision remains usable without another download.
			srv.Close()
			require.NoError(t, reconciler.ensurePlugin(ctx, parent, node))
		})
	}
}
