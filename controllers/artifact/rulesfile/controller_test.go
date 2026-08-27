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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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

const testRulesfileName = "test-rulesfile"

// testFetcher implements artifact.ArtifactFetcher for controller unit tests.
// ConfigMap and Inline use the real artifact.Fetcher backed by the fake k8s client.
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

func (f *testFetcher) FetchOCI(_ context.Context, _, _ string, _ artifact.Type) (artifact.FetchResult, error) {
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

// testInlineRulesJSON is sample Falco rules in JSON format (used for *apiextensionsv1.JSON fields).
const testInlineRulesJSON = `[{"rule":"test_rule","desc":"test","condition":"always_true","output":"test","priority":"WARNING"}]`

// testInlineRulesYAML is the expected YAML representation of testInlineRulesJSON after conversion.
const testInlineRulesYAML = "- condition: always_true\n  desc: test\n  output: test\n  priority: WARNING\n  rule: test_rule\n"

// testRulesData is used as a ConfigMap data value for rules.yaml.
const testRulesData = "- rule: test_rule\n  desc: test\n  condition: always_true\n  output: test\n  priority: WARNING\n"

// testNodeObjectName returns the expected RulesfileNode name for the test rulesfile and node.
func testNodeObjectName() string {
	return controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, testRulesfileName, testutil.TestNodeName)
}

// newTestNodeObj creates a fresh RulesfileNode for unit tests. It has no finalizer by default.
func newTestNodeObj(opts ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	n := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testNodeObjectName(),
			Namespace: testutil.TestNamespace,
			Labels:    controllerhelper.NodeObjectLabels(controllerhelper.ArtifactKindRulesfile, testRulesfileName, testutil.TestNodeName),
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
	}
	for _, o := range opts {
		o(n)
	}
	return n
}

// withOwnerRef sets an owner reference to testRulesfileName on a RulesfileNode.
func withOwnerRef() func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) {
		n.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: artifactv1alpha1.GroupVersion.String(),
				Kind:       "Rulesfile",
				Name:       testRulesfileName,
			},
		}
	}
}

// withPreviousOCIInstallStatus simulates an ArtifactNode where the OCI rulesfile was already
// installed on a prior reconcile. Used to verify that the update-rejected code path keeps
// OCIArtifactProgrammed=True even when requirements are no longer satisfied.
func withPreviousOCIInstallStatus() func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) {
		n.Status.InstalledArtifacts = []artifactv1alpha1.InstalledArtifact{
			{Path: "/etc/falco/rules.d/test-rulesfile-oci.yaml", Medium: string(artifact.MediumOCI)},
		}
		n.Status.Conditions = []metav1.Condition{
			common.NewOCIArtifactProgrammedCondition(metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed, artifact.MessageOCIArtifactProgrammed, 0),
			common.NewDependenciesSatisfiedCondition(metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, 0),
		}
	}
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*RulesfileReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).
		Build()

	mockFS := filesystem.NewMockFileSystem()

	return &RulesfileReconciler{
		Client:    cl,
		Scheme:    s,
		recorder:  events.NewFakeRecorder(100),
		fetcher:   newTestFetcher(cl),
		store:     nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compat.NewMockVersionsFetcher(nil)),
		nodeName:  testutil.TestNodeName,
		namespace: testutil.TestNamespace,
	}, cl
}

func TestNewRulesfileReconciler(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	store := nodeartifacts.NewManager(&artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
		compat.NewMockVersionsFetcher(nil))
	r := NewRulesfileReconciler(cl, s, events.NewFakeRecorder(10), "my-node", "my-namespace", false, &artifact.Fetcher{}, store)

	require.NotNil(t, r)
	assert.Equal(t, "my-node", r.nodeName)
	assert.Equal(t, "my-namespace", r.namespace)
	assert.NotNil(t, r.fetcher)
	assert.NotNil(t, r.store)
}

func TestReconcile(t *testing.T) {
	parentRulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRulesfileName,
			Namespace: testutil.TestNamespace,
		},
	}
	parentWithInline := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRulesfileName,
			Namespace: testutil.TestNamespace,
		},
		Spec: artifactv1alpha1.RulesfileSpec{
			InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
		},
	}
	parentWithOCI := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRulesfileName,
			Namespace: testutil.TestNamespace,
		},
		Spec: artifactv1alpha1.RulesfileSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
					Tag:        "latest",
				},
			},
		},
	}
	nodeObjWithFinalizer := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{rulesfileNodeFinalizer}
	})
	tests := []struct {
		name                string
		objects             []client.Object
		req                 ctrl.Request
		triggerDeletion     bool
		pullErr             error
		enforceRequirements bool
		wantErr             bool
		wantResult          *ctrl.Result // nil means the zero-value ctrl.Result{} is expected
		wantRequeueAfterGE  time.Duration
		wantFinalizer       *bool
		wantConditions      []testutil.ConditionExpect
	}{
		{
			name: "RulesfileNode not found returns no error",
			req:  testutil.Request("nonexistent"),
		},
		{
			name:    "parent Rulesfile not found returns no error (waiting for GC)",
			objects: []client.Object{newTestNodeObj(withOwnerRef())},
			req:     testutil.Request(testNodeObjectName()),
		},
		{
			name:            "deletion with finalizer removes artifacts and finalizer",
			objects:         []client.Object{nodeObjWithFinalizer, parentRulesfile},
			req:             testutil.Request(testNodeObjectName()),
			triggerDeletion: true,
			wantFinalizer:   func() *bool { b := false; return &b }(),
		},
		{
			name: "sets finalizer on first reconcile",
			objects: []client.Object{
				parentRulesfile,
				newTestNodeObj(withOwnerRef()),
			},
			req:           testutil.Request(testNodeObjectName()),
			wantFinalizer: func() *bool { b := true; return &b }(),
		},
		{
			name: "happy path with inline rules writes conditions to node object",
			objects: []client.Object{
				parentWithInline,
				newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{rulesfileNodeFinalizer}
				}),
			},
			req: testutil.Request(testNodeObjectName()),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "OCI artifact pull error sets failure conditions on node object",
			objects: []client.Object{
				parentWithOCI,
				newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{rulesfileNodeFinalizer}
				}),
			},
			req:     testutil.Request(testNodeObjectName()),
			pullErr: fmt.Errorf("mock pull error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactProgramFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			// A retryable OCI-fetch failure (uncached image, transient network error) requeues via
			// RequeueAfter instead of returning a reconcile error. RequeueDelay applies
			// wait.Jitter(retryAfter, 0.3) so the result is always >= the base delay.
			name: "OCI artifact pull retryable error requeues without a reconcile error",
			objects: []client.Object{
				parentWithOCI,
				newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{rulesfileNodeFinalizer}
				}),
			},
			req:                testutil.Request(testNodeObjectName()),
			pullErr:            &artifact.RetryableError{Err: errors.New("mock pull error"), RetryAfter: 7 * time.Second},
			wantRequeueAfterGE: 7 * time.Second,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactProgramFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			name: "enforce mode: requirements not satisfied and never installed sets OCIArtifactProgrammed to False",
			objects: []client.Object{
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.RulesfileSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"},
						},
					},
					Status: artifactv1alpha1.RulesfileStatus{
						ArtifactMeta: &commonv1alpha1.ArtifactMeta{
							Requirements: []commonv1alpha1.ArtifactMetaRequirement{
								{Name: "engine_version_semver", Version: "999.0.0"},
							},
						},
					},
				},
				newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{rulesfileNodeFinalizer}
				}),
			},
			req:                 testutil.Request(testNodeObjectName()),
			enforceRequirements: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			name: "enforce mode: requirements fail on previously installed rulesfile keeps OCIArtifactProgrammed True",
			objects: []client.Object{
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.RulesfileSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"},
						},
					},
					Status: artifactv1alpha1.RulesfileStatus{
						ArtifactMeta: &commonv1alpha1.ArtifactMeta{
							Requirements: []commonv1alpha1.ArtifactMetaRequirement{
								{Name: "engine_version_semver", Version: "999.0.0"},
							},
						},
					},
				},
				newTestNodeObj(withOwnerRef(), withPreviousOCIInstallStatus(), func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{rulesfileNodeFinalizer}
				}),
			},
			req:                 testutil.Request(testNodeObjectName()),
			enforceRequirements: true,
			wantConditions: []testutil.ConditionExpect{
				{
					Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse,
					Reason: artifact.ReasonDependenciesNotSatisfiedUpdateRejected,
				},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			name: "advise mode installs inline rulesfile despite unsatisfied engine requirement and stays Programmed",
			objects: []client.Object{
				&artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.RulesfileSpec{
						InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
					},
					Status: artifactv1alpha1.RulesfileStatus{
						ArtifactMeta: &commonv1alpha1.ArtifactMeta{
							Requirements: []commonv1alpha1.ArtifactMetaRequirement{
								{Name: "engine_version_semver", Version: "0.57.0"},
							},
						},
					},
				},
				newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{rulesfileNodeFinalizer}
				}),
			},
			req:                 testutil.Request(testNodeObjectName()),
			enforceRequirements: false,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfiedInstalledAnyway,
				},
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
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

			if tt.triggerDeletion {
				obj := &artifactv1alpha1.ArtifactNode{}
				require.NoError(t, cl.Get(context.Background(), tt.req.NamespacedName, obj))
				require.NoError(t, cl.Delete(context.Background(), obj))
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
				obj := &artifactv1alpha1.ArtifactNode{}
				if err := cl.Get(context.Background(), tt.req.NamespacedName, obj); err == nil {
					assert.Equal(t, *tt.wantFinalizer, controllerutil.ContainsFinalizer(obj, rulesfileNodeFinalizer))
				}
			}

			if len(tt.wantConditions) > 0 {
				obj := &artifactv1alpha1.ArtifactNode{}
				require.NoError(t, cl.Get(context.Background(), tt.req.NamespacedName, obj))
				testutil.RequireConditions(t, obj.Status.Conditions, tt.wantConditions)
			}
		})
	}
}

func TestEnsureRulesfile(t *testing.T) {
	tests := []struct {
		name    string
		objects []client.Object
		preRf   *artifactv1alpha1.Rulesfile
		// preSpecHash is set as the pre-Rulesfile's ArtifactMeta.SpecHash before the pre-reconcile.
		preSpecHash string
		rf          *artifactv1alpha1.Rulesfile
		// parentSpecHash is set as the parent Rulesfile's ArtifactMeta.SpecHash before the main reconcile.
		parentSpecHash string
		writeErr       error
		pullErr        error
		// useRealFS uses a real OS filesystem backed by a temp dir instead of the mock FS.
		useRealFS      bool
		wantErr        bool
		wantConditions []testutil.ConditionExpect
		// wantFiles is nil to skip the check; an empty slice asserts no files remain (mock FS only).
		wantFiles []string
		// wantDirEmpty asserts the rulesfile temp dir is empty after the test (real FS only).
		wantDirEmpty bool
		// wantEvents is nil to skip the check; otherwise asserts the exact set of events recorded.
		wantEvents []string
		// wantOCIFetchCount is nil to skip; non-nil asserts exact FetchOCI call count in the main reconcile.
		wantOCIFetchCount *int
		// wantInstalledOCISpecHash, when non-empty, asserts InstalledArtifacts OCI entry has this SpecHash.
		wantInstalledOCISpecHash string
	}{
		{
			name: "OCI pull error sets failure condition",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
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
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactProgramFailed},
			},
			wantEvents: []string{"Warning OCIArtifactStoreFailed Failed to store OCI artifact: mock pull error"},
		},
		{
			name: "stores inline rules successfully",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
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
						Namespace: testutil.TestNamespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{
						Name: "my-rules-cm",
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigMapArtifactProgrammed,
				},
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
						Namespace: testutil.TestNamespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules:  &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-rules-cm"},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigMapArtifactProgrammed,
				},
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
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte("\t")},
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
			name: "inline rules store failure sets condition",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
				},
			},
			writeErr: fmt.Errorf("mock write error"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionInlineArtifactProgrammed.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonInlineArtifactProgramFailed,
				},
			},
			wantEvents: []string{"Warning InlineRulesStoreFailed Failed to store inline rules: mock write error"},
		},
		{
			name: "configmap ref store fails on filesystem write error",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-rules-cm",
						Namespace: testutil.TestNamespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{
						Name: "my-rules-cm",
					},
				},
			},
			writeErr: fmt.Errorf("mock write error"),
			wantErr:  true,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonConfigMapArtifactProgramFailed,
				},
			},
			wantEvents: []string{"Warning ConfigMapRulesStoreFailed Failed to store ConfigMap rules: mock write error"},
		},
		{
			name: "no sources sets programmed without touching resolved refs",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			wantConditions: nil,
			wantEvents:     []string{},
		},
		{
			name: "non-nil InlineRules with empty Raw is treated as no inline rules",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 1},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{},
					Priority:    50,
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionInlineArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonInlineArtifactProgrammed},
			},
			wantEvents: []string{},
		},
		{
			name: "removing inline rules deletes previously written file",
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			wantConditions: nil,
			wantFiles:      []string{},
			wantEvents:     []string{"Normal InlineArtifactRemoved Inline artifact removed from filesystem"},
		},
		{
			name: "removing configmap ref deletes previously written file",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-rules-cm",
						Namespace: testutil.TestNamespace,
					},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: testRulesData,
					},
				},
			},
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "my-rules-cm"},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			wantConditions: nil,
			wantFiles:      []string{},
			wantEvents:     []string{"Normal ConfigMapArtifactRemoved ConfigMap artifact removed from filesystem"},
		},
		{
			name: "removing OCI artifact deletes previously stored file",
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "ghcr.io/falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			useRealFS:      true,
			wantConditions: nil,
			wantDirEmpty:   true,
			wantEvents:     []string{"Normal OCIArtifactRemoved OCI artifact removed from filesystem"},
		},
		// SpecHash tests
		{
			name:           "OCI: specHash written to InstalledArtifacts after install",
			parentSpecHash: "abc123specHash",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
			},
			wantInstalledOCISpecHash: "abc123specHash",
			wantOCIFetchCount:        new(1),
			wantEvents:               []string{"Normal OCIArtifactStored OCI artifact stored successfully"},
		},
		{
			name:        "OCI: skips fetch when specHash matches and disk is intact",
			preSpecHash: "stable-hash",
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			parentSpecHash: "stable-hash", // same as pre; no change
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
			},
			wantOCIFetchCount:        new(0), // must not hit the artifact server
			wantInstalledOCISpecHash: "stable-hash",
			wantEvents:               []string{},
		},
		{
			name:        "OCI: re-fetches when specHash changes",
			preSpecHash: "old-hash",
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			parentSpecHash: "new-hash", // changed; aggregator fetched a new blob
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
			},
			wantOCIFetchCount:        new(1),
			wantInstalledOCISpecHash: "new-hash",
			// StoreActionUnchanged because mock content is the same bytes; no store event
			wantEvents: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			var mockFS *filesystem.MockFileSystem
			var tmpDir string

			if tt.useRealFS {
				tmpDir = t.TempDir()
				r.fetcher = &testFetcher{
					delegate: &artifact.Fetcher{K8sClient: cl},
					ociBytes: []byte("fake-rules-content"),
				}
				r.store = nodeartifacts.NewManager(&artifact.LocalStore{
					FS:   filesystem.NewOSFileSystem(),
					Dirs: artifact.ArtifactDirs{Rulesfile: tmpDir, Plugin: tmpDir, Config: tmpDir},
				}, compat.NewMockVersionsFetcher(nil))
			} else {
				mockFS = filesystem.NewMockFileSystem()
				if tt.writeErr != nil {
					mockFS.WriteErr = tt.writeErr
				}
				r.fetcher = &testFetcher{
					delegate: &artifact.Fetcher{K8sClient: cl},
					ociErr:   tt.pullErr,
				}
				r.store = nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compat.NewMockVersionsFetcher(nil))
			}

			nodeObj := newTestNodeObj()
			if tt.preRf != nil {
				if tt.preSpecHash != "" {
					tt.preRf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{SpecHash: tt.preSpecHash}
				}
				preNode := newTestNodeObj()
				require.NoError(t, r.ensureRulesfile(context.Background(), tt.preRf, preNode), "preRf setup failed")
				testutil.DrainEvents(r.recorder.(*events.FakeRecorder).Events)
				nodeObj.Status = preNode.Status
			}

			if tt.parentSpecHash != "" {
				tt.rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{SpecHash: tt.parentSpecHash}
			}
			tf := r.fetcher.(*testFetcher)
			tf.ociCallCount = 0 // reset counter before the main reconcile

			err := r.ensureRulesfile(context.Background(), tt.rf, nodeObj)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			testutil.RequireConditions(t, nodeObj.Status.Conditions, tt.wantConditions)
			testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events, tt.wantEvents)

			if tt.wantOCIFetchCount != nil {
				assert.Equal(t, *tt.wantOCIFetchCount, tf.ociCallCount, "unexpected FetchOCI call count")
			}
			if tt.wantInstalledOCISpecHash != "" {
				ociEntry := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI)
				require.NotNil(t, ociEntry, "expected OCI entry in InstalledArtifacts")
				assert.Equal(t, tt.wantInstalledOCISpecHash, ociEntry.SpecHash, "OCI InstalledArtifact.SpecHash mismatch")
			}

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

// TestEnsureRulesfile_ProgrammedLastTransitionTime verifies LastTransitionTime stays put on a
// steady-state reconcile and only moves on a real status transition.
func TestEnsureRulesfile_ProgrammedLastTransitionTime(t *testing.T) {
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
			rf := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
				},
			}
			nodeObj := newTestNodeObj()
			nodeObj.Status.Conditions = []metav1.Condition{{
				Type:               commonv1alpha1.ConditionInlineArtifactProgrammed.String(),
				Status:             tt.initialStatus,
				Reason:             artifact.ReasonInlineArtifactProgrammed,
				Message:            artifact.MessageInlineArtifactProgrammed,
				LastTransitionTime: pinned,
			}}

			require.NoError(t, r.ensureRulesfile(context.Background(), rf, nodeObj))

			cond := apimeta.FindStatusCondition(nodeObj.Status.Conditions, commonv1alpha1.ConditionInlineArtifactProgrammed.String())
			require.NotNil(t, cond)
			require.Equal(t, metav1.ConditionTrue, cond.Status)
			require.Equal(t, tt.wantPreserved, cond.LastTransitionTime.Equal(&pinned))
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
		presetConditions []metav1.Condition
	}{
		{
			name: "inline only has no references and removes stale ResolvedRefs",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
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
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
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
					ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.TestNamespace},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
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
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "missing-cm"},
				},
			},
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
			},
		},
		{
			name: "OCI auth secret exists sets ResolvedRefs true",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: testutil.TestNamespace},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
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
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
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
			},
		},
		{
			name: "ConfigMap and auth secret both exist sets ResolvedRefs true",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.TestNamespace},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: testutil.TestNamespace},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
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
					ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.TestNamespace},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
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
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t, tt.objects...)

			nodeObj := newTestNodeObj()
			if len(tt.presetConditions) > 0 {
				nodeObj.Status.Conditions = tt.presetConditions
			}

			err := r.enforceReferenceResolution(context.Background(), tt.rf, nodeObj)

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
	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRulesfileName,
			Namespace: testutil.TestNamespace,
		},
		Spec: artifactv1alpha1.RulesfileSpec{
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
		WithObjects(rf).
		WithIndex(&artifactv1alpha1.Rulesfile{}, index.SecretOnRulesfile, index.RulesfileBySecretRef).
		Build()

	r := &RulesfileReconciler{
		Client:   cl,
		Scheme:   s,
		recorder: events.NewFakeRecorder(100),
		fetcher:  &artifact.Fetcher{K8sClient: cl},
		store: nodeartifacts.NewManager(&artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
			compat.NewMockVersionsFetcher(nil)),
		nodeName:  testutil.TestNodeName,
		namespace: testutil.TestNamespace,
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
				assert.Equal(t, testNodeObjectName(), requests[0].Name)
				assert.Equal(t, testutil.TestNamespace, requests[0].Namespace)
			}
		})
	}
}

func TestFindNodeObjectsForConfigMap(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRulesfileName,
			Namespace: testutil.TestNamespace,
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

	r := &RulesfileReconciler{
		Client:   cl,
		Scheme:   s,
		recorder: events.NewFakeRecorder(100),
		fetcher:  &artifact.Fetcher{K8sClient: cl},
		store: nodeartifacts.NewManager(&artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
			compat.NewMockVersionsFetcher(nil)),
		nodeName:  testutil.TestNodeName,
		namespace: testutil.TestNamespace,
	}

	tests := []struct {
		name          string
		configMapName string
		wantCount     int
	}{
		{
			name:          "matching configmap returns node object requests",
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
					Namespace: testutil.TestNamespace,
				},
			}
			requests := r.findNodeObjectsForConfigMap(context.Background(), cm)
			require.Len(t, requests, tt.wantCount)
			if tt.wantCount > 0 {
				assert.Equal(t, testNodeObjectName(), requests[0].Name)
				assert.Equal(t, testutil.TestNamespace, requests[0].Namespace)
			}
		})
	}
}

func TestCheckEngineRequirement(t *testing.T) {
	tests := []struct {
		name                string
		capability          string
		falcoCaps           map[string]string
		requiredVersion     string
		enforceRequirements bool
		preInstalled        bool
		wantSkip            bool
		wantSatisfied       bool
		wantErr             bool
	}{
		{
			name:            "capability found and version satisfied",
			capability:      "engine_version_semver",
			falcoCaps:       map[string]string{"engine_version_semver": "0.57.0"},
			requiredVersion: "0.57.0",
			wantSkip:        false,
			wantSatisfied:   true,
		},
		{
			name:                "capability found but version too low",
			capability:          "engine_version_semver",
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			requiredVersion:     "0.57.0",
			enforceRequirements: true,
			wantSkip:            true,
			wantSatisfied:       false,
		},
		{
			name:                "capability not found in Falco versions",
			capability:          "engine_version_semver",
			falcoCaps:           map[string]string{},
			requiredVersion:     "0.57.0",
			enforceRequirements: true,
			wantSkip:            true,
			wantSatisfied:       false,
		},
		{
			name:            "invalid provided version string returns error",
			capability:      "engine_version_semver",
			falcoCaps:       map[string]string{"engine_version_semver": "invalid"},
			requiredVersion: "0.57.0",
			wantSkip:        false,
			wantSatisfied:   false,
			wantErr:         true,
		},
		{
			name:                "advise mode installs anyway when capability too low",
			capability:          "engine_version_semver",
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			requiredVersion:     "0.57.0",
			enforceRequirements: false,
			wantSkip:            false,
			wantSatisfied:       false,
		},
		{
			name:                "enforce mode rejects update but keeps previous install",
			capability:          "engine_version_semver",
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			requiredVersion:     "0.57.0",
			enforceRequirements: true,
			preInstalled:        true,
			wantSkip:            true,
			wantSatisfied:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			r.enforceRequirements = tt.enforceRequirements
			rf := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
			}
			nodeObj := newTestNodeObj()
			if tt.preInstalled {
				nodeObj.Status.InstalledArtifacts = []artifactv1alpha1.InstalledArtifact{
					{Path: "/etc/falco/rules.d/test.yaml", Medium: string(artifact.MediumOCI)},
				}
			}
			if tt.falcoCaps != nil {
				r.store.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(tt.falcoCaps).Result)
			}

			skip, satisfied, err := r.checkEngineRequirement(context.Background(), rf, nodeObj, tt.capability, tt.requiredVersion, 0)

			assert.Equal(t, tt.wantSkip, skip)
			assert.Equal(t, tt.wantSatisfied, satisfied)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckDependency(t *testing.T) {
	tests := []struct {
		name          string
		falcaCaps     map[string]string
		dep           commonv1alpha1.ArtifactMetaDependency
		wantSatisfied bool
		wantFailMsg   bool
		wantErr       bool
	}{
		{
			name:          "primary dependency found and satisfied",
			falcaCaps:     map[string]string{"container": "0.4.0"},
			dep:           commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.4.0"},
			wantSatisfied: true,
		},
		{
			name:      "primary found but version too low alternative satisfied",
			falcaCaps: map[string]string{"container": "0.3.0", "k8smeta": "0.1.0"},
			dep: commonv1alpha1.ArtifactMetaDependency{
				Name: "container", Version: "0.4.0",
				Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "k8smeta", Version: "0.1.0"}},
			},
			wantSatisfied: true,
		},
		{
			name:      "primary not found alternative satisfied",
			falcaCaps: map[string]string{"k8smeta": "0.2.0"},
			dep: commonv1alpha1.ArtifactMetaDependency{
				Name: "container", Version: "0.4.0",
				Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "k8smeta", Version: "0.1.0"}},
			},
			wantSatisfied: true,
		},
		{
			name:        "primary not found no alternatives",
			falcaCaps:   map[string]string{},
			dep:         commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.4.0"},
			wantFailMsg: true,
		},
		{
			name:      "primary and all alternatives not found",
			falcaCaps: map[string]string{},
			dep: commonv1alpha1.ArtifactMetaDependency{
				Name: "container", Version: "0.4.0",
				Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "k8smeta", Version: "0.1.0"}},
			},
			wantFailMsg: true,
		},
		{
			name:      "invalid provided version string returns error",
			falcaCaps: map[string]string{"container": "invalid"},
			dep:       commonv1alpha1.ArtifactMetaDependency{Name: "container", Version: "0.4.0"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			if tt.falcaCaps != nil {
				r.store.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(tt.falcaCaps).Result)
			}

			satisfied, failMsg, err := r.checkDependency(context.Background(), tt.dep)

			assert.Equal(t, tt.wantSatisfied, satisfied)
			assert.Equal(t, tt.wantFailMsg, failMsg != "")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEnforceRulesfileCompatibility(t *testing.T) {
	engineReq := func(name, version string) commonv1alpha1.ArtifactMetaRequirement {
		return commonv1alpha1.ArtifactMetaRequirement{Name: name, Version: version}
	}
	pluginDep := func(name, version string, alts ...commonv1alpha1.ArtifactMetaDependencyVariant) commonv1alpha1.ArtifactMetaDependency {
		return commonv1alpha1.ArtifactMetaDependency{Name: name, Version: version, Alternatives: alts}
	}
	altDep := func(name, version string) commonv1alpha1.ArtifactMetaDependencyVariant {
		return commonv1alpha1.ArtifactMetaDependencyVariant{Name: name, Version: version}
	}

	tests := []struct {
		name                string
		rf                  *artifactv1alpha1.Rulesfile
		artifactMeta        *commonv1alpha1.ArtifactMeta
		falcoCaps           map[string]string
		falcoErr            error
		enforceRequirements bool
		preInstalled        bool
		presetConditions    []metav1.Condition
		wantSkip            bool
		wantErr             bool
		wantConditions      []testutil.ConditionExpect
		wantMessageContains []string
	}{
		{
			name: "no source configured removes DependenciesSatisfied condition",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			presetConditions: []metav1.Condition{
				common.NewDependenciesSatisfiedCondition(metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, 0),
			},
			wantConditions: nil,
		},
		{
			name: "source configured with nil ArtifactMeta in non-strict mode proceeds",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "source configured with nil ArtifactMeta in strict mode blocks",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionUnknown, Reason: artifact.ReasonDependenciesUnknown},
			},
		},
		{
			name: "ArtifactMeta with no requirements sets DependenciesSatisfied True",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "engine requirement not found in Falco versions",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoCaps:           map[string]string{},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "engine requirement version too low",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "engine requirement satisfied sets DependenciesSatisfied True",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")}},
			falcoCaps:    map[string]string{"engine_version_semver": "0.57.0"},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "integer engine version requirement satisfied via engine_version capability",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version", "15")}},
			falcoCaps:    map[string]string{"engine_version": "62", "engine_version_semver": "0.62.0"},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "integer engine version requirement not satisfied",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta:        &commonv1alpha1.ArtifactMeta{Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version", "100")}},
			falcoCaps:           map[string]string{"engine_version": "62", "engine_version_semver": "0.62.0"},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "plugin dependency not satisfied no alternatives",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta:        &commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{pluginDep("container", "0.4.0")}},
			falcoCaps:           map[string]string{},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "plugin dependency satisfied sets DependenciesSatisfied True",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{pluginDep("container", "0.4.0")}},
			falcoCaps:    map[string]string{"container": "0.4.0"},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "plugin alternative satisfied sets DependenciesSatisfied True",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{pluginDep("container", "0.4.0", altDep("k8smeta", "0.1.0"))},
			},
			falcoCaps: map[string]string{"k8smeta": "0.1.0"},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "plugin alternatives all unsatisfied sets DependenciesSatisfied False",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{pluginDep("container", "0.4.0", altDep("k8smeta", "0.1.0"))},
			},
			falcoCaps:           map[string]string{},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "Falco versions not yet observed non-strict installs anyway",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")}},
			falcoErr:     fmt.Errorf("connection refused"),
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
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoErr:            fmt.Errorf("connection refused"),
			enforceRequirements: true,
			wantSkip:            true,
			wantErr:             false,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "multiple plugin deps all unsatisfied reports all in condition message",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{
					pluginDep("container", "0.4.0"),
					pluginDep("k8saudit", "0.7.0"),
				},
			},
			falcoCaps:           map[string]string{},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
			wantMessageContains: []string{"container >= 0.4.0", "k8saudit >= 0.7.0"},
		},
		{
			name: "multiple plugin deps partially satisfied reports only unsatisfied",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{
					pluginDep("container", "0.4.0"),
					pluginDep("k8saudit", "0.7.0"),
				},
			},
			falcoCaps:           map[string]string{"container": "0.5.0"},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
			wantMessageContains: []string{"k8saudit >= 0.7.0"},
		},
		{
			name: "advise mode installs despite unsatisfied engine requirement",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			enforceRequirements: false,
			wantSkip:            false,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfiedInstalledAnyway,
				},
			},
			wantMessageContains: []string{"installed anyway"},
		},
		{
			name: "enforce mode rejects update but keeps previously installed rulesfile",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			enforceRequirements: true,
			preInstalled:        true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfiedUpdateRejected,
				},
			},
			wantMessageContains: []string{"keeping the previously installed version"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			r.enforceRequirements = tt.enforceRequirements

			if tt.falcoErr == nil && tt.falcoCaps != nil {
				r.store.OnFalcoVersionsObserved(compat.NewMockVersionsFetcher(tt.falcoCaps).Result)
			}

			tt.rf.Status.ArtifactMeta = tt.artifactMeta
			nodeObj := newTestNodeObj()
			if len(tt.presetConditions) > 0 {
				nodeObj.Status.Conditions = tt.presetConditions
			}
			if tt.preInstalled {
				nodeObj.Status.InstalledArtifacts = []artifactv1alpha1.InstalledArtifact{
					{Path: "/etc/falco/rules.d/test.yaml", Medium: string(artifact.MediumOCI)},
				}
			}

			skip, err := r.enforceRulesfileCompatibility(context.Background(), tt.rf, nodeObj)

			assert.Equal(t, tt.wantSkip, skip)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			testutil.RequireConditions(t, nodeObj.Status.Conditions, tt.wantConditions)
			if len(tt.wantMessageContains) > 0 {
				for _, cond := range nodeObj.Status.Conditions {
					if cond.Type == commonv1alpha1.ConditionDependenciesSatisfied.String() {
						for _, substr := range tt.wantMessageContains {
							assert.Contains(t, cond.Message, substr)
						}
					}
				}
			}
		})
	}
}

func TestFindAllNodeObjectsOnVersionChange(t *testing.T) {
	isController := true
	node1 := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, "rf-one", testutil.TestNodeName),
			Namespace: testutil.TestNamespace,
			Labels:    controllerhelper.NodeObjectLabels(controllerhelper.ArtifactKindRulesfile, "rf-one", testutil.TestNodeName),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: artifactv1alpha1.GroupVersion.String(),
				Kind:       "Rulesfile",
				Name:       "rf-one",
				Controller: &isController,
			}},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
	}
	node2 := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, "rf-two", testutil.TestNodeName),
			Namespace: testutil.TestNamespace,
			Labels:    controllerhelper.NodeObjectLabels(controllerhelper.ArtifactKindRulesfile, "rf-two", testutil.TestNodeName),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: artifactv1alpha1.GroupVersion.String(),
				Kind:       "Rulesfile",
				Name:       "rf-two",
				Controller: &isController,
			}},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
	}

	r, _ := newTestReconciler(t, node1, node2)

	requests := r.findAllNodeObjectsOnVersionChange(context.Background(), nil)

	require.Len(t, requests, 2)
	names := make(map[string]struct{}, 2)
	for _, req := range requests {
		assert.Equal(t, testutil.TestNamespace, req.Namespace)
		names[req.Name] = struct{}{}
	}
	assert.Contains(t, names, controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, "rf-one", testutil.TestNodeName))
	assert.Contains(t, names, controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, "rf-two", testutil.TestNodeName))
}

func TestFindAllNodeObjectsOnVersionChange_Empty(t *testing.T) {
	r, _ := newTestReconciler(t)
	requests := r.findAllNodeObjectsOnVersionChange(context.Background(), nil)
	assert.Empty(t, requests)
}

func TestReconcile_RegistersDependenciesWithNodeArtifactManager(t *testing.T) {
	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testRulesfileName,
			Namespace:  testutil.TestNamespace,
			Generation: 1,
		},
		Spec: artifactv1alpha1.RulesfileSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
					Tag:        "latest",
				},
			},
		},
		Status: artifactv1alpha1.RulesfileStatus{
			ObservedGeneration: 1,
			ArtifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
			},
		},
	}
	nodeObj := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{rulesfileNodeFinalizer}
	})

	r, _ := newTestReconciler(t, rf, nodeObj)

	sharedManager := r.store
	blockedBefore := sharedManager.RemovePluginConfigByName(context.Background(), &artifact.Fetcher{}, "container", "container")
	require.NoError(t, blockedBefore, "nothing provides \"container\" yet, so removal (a no-op here) must not be blocked")

	sharedManager.SyncProvides(nodeartifacts.PluginConfigKey, "container")

	_, err := r.Reconcile(context.Background(), testutil.Request(testNodeObjectName()))
	require.NoError(t, err)

	err = sharedManager.RemovePluginConfigByName(context.Background(), &artifact.Fetcher{}, "container", "container")
	require.Error(t, err, "Reconcile must have registered this rulesfile's dependency on \"container\"")
	blocked, ok := errors.AsType[*nodeartifacts.BlockedError](err)
	require.True(t, ok)
	assert.Equal(t, nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: testRulesfileName}, blocked.BlockedBy[0])
}
