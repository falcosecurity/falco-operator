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
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactserver"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
	"github.com/falcosecurity/falco-operator/internal/testutil"
	"github.com/falcosecurity/falco-operator/internal/testutil/nodetest"
)

const testPluginName = "test-plugin"

// pluginsConfigFile is the shared plugins-config file on the node's disk, or nil when there is none.
func pluginsConfigFile(t *testing.T, n *node.Node) *artifact.File {
	t.Helper()
	path, err := artifact.ArtifactPath(artifact.DefaultArtifactDirs(), "plugins-config", priority.MaxPriority,
		artifact.MediumInline, artifact.KindConfig)
	require.NoError(t, err)
	found, err := n.ScanAll(t.Context(), artifact.KindConfig)
	require.NoError(t, err)
	for _, file := range found["plugins-config"] {
		if file.Path == path {
			return artifact.FindInstalled([]artifactv1alpha1.InstalledArtifact{file}, artifact.MediumInline)
		}
	}
	return nil
}

// testReconciler is the PluginReconciler a test drives, plus a handle on the stub the node fetches
// through. The reconciler holds no fetcher: the node does the fetching, so a test that
// wants to fail, replace or count a fetch reaches the stub here.
type testReconciler struct {
	*PluginReconciler
	fetcher *testutil.FakeFetcher
	// recorder receives the Events of the reconciler's node.
	recorder events.EventRecorder
}

func installRequiringRulesfile(t *testing.T, r *testReconciler, key artifact.Ref) {
	t.Helper()
	content, err := r.fetcher.FetchInline(t.Context(), []byte("test rules"))
	require.NoError(t, err)
	_, _, err = r.node.StoreRulesfile(t.Context(), key.Name, 50, artifact.MediumOCI, content,
		&commonv1alpha1.ArtifactMeta{
			Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: testPluginName, Version: "1.0.0"}},
		}, false)
	require.NoError(t, err)
}

// withPreviousInstallStatus seeds the status entry with the status that would result from a prior successful
// reconcile: an OCI binary in InstalledArtifacts plus all installation conditions set to True. Used to test
// the update-rejected flow.
func withPreviousInstallStatus() func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) {
		n.Status.Artifacts[0].InstalledArtifacts = []artifactv1alpha1.InstalledArtifact{
			{Path: "/usr/share/falco/plugins/test-plugin.so", Medium: string(artifact.MediumOCI)},
		}
		n.Status.Artifacts[0].Conditions = []metav1.Condition{
			common.NewOCIArtifactProgrammedCondition(metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed, artifact.MessageOCIArtifactProgrammed, 0),
			common.NewConfigProgrammedCondition(metav1.ConditionTrue, artifact.ReasonConfigProgrammed, artifact.MessageConfigProgrammed, 0),
			common.NewDependenciesSatisfiedCondition(metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, 0),
		}
	}
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*testReconciler, client.Client) {
	t.Helper()
	return newReconcilerEnforcing(t, false, objs...)
}

// newReconcilerEnforcing is newTestReconciler over a node whose requirements policy is enforce. The policy is the
// node's, set when it is built, so a test that wants one gets it here rather than by changing the node.
func newReconcilerEnforcing(t *testing.T, enforce bool, objs ...client.Object) (*testReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(testutil.EnsureArtifactNode(objs)...).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		Build()

	mockFS := fsfake.NewMockFileSystem()
	fetcher := testutil.NewFakeFetcher(cl)
	recorder := events.NewFakeRecorder(100)
	store := nodetest.NewTestNodeOn(t, cl, mockFS, recorder, nodetest.WithFetcher(fetcher), nodetest.WithEnforceRequirements(enforce))
	r := &PluginReconciler{
		Client:   cl,
		recorder: recorder,
		node:     store,
	}
	useNode(t, r, store, objs)
	return &testReconciler{PluginReconciler: r, fetcher: fetcher, recorder: recorder}, cl
}

// useNode makes r use n, as after a restart: what the ArtifactNodes among objs say is installed is
// recovered into it, and it publishes through the client n was built over.
func useNode(t *testing.T, r *PluginReconciler, n *node.Node, objs []client.Object) {
	t.Helper()
	r.node = n
	nodetest.Prime(n, objs)
}

func TestNewPluginReconciler(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), events.NewFakeRecorder(10),
		nodetest.WithFetcher(&artifact.Fetcher{K8sClient: cl}), nodetest.WithEnforceRequirements(true))
	r := NewPluginReconciler(cl, events.NewFakeRecorder(10), n)

	require.NotNil(t, r)
	assert.True(t, n.EnforceRequirements(), "the policy is the node's, set when it is built, and no reconciler changes it")
	assert.Same(t, n, r.node, "the reconciler works through the node it was given")
	assert.Equal(t, testutil.TestNodeName, r.node.Name())
}

func TestReconcile(t *testing.T) {
	tests := []struct {
		name                string
		objects             []client.Object
		req                 ctrl.Request
		pullErr             error
		preInstallPlugin    *artifactv1alpha1.Plugin // if set, seeds the shared node artifact manager via AddPluginConfig before Reconcile
		enforceRequirements bool
		wantErr             bool
		wantResult          *ctrl.Result // nil means the zero-value ctrl.Result{} is expected
		// wantRequeueAfterGE, when non-zero, replaces exact equality on wantResult.RequeueAfter
		// with a >= assertion. Use for cases where RequeueDelay applies jitter.
		wantRequeueAfterGE time.Duration
		wantConditions     []testutil.ConditionExpect
	}{
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
				testutil.NewReportingArtifactNode("Plugin", testPluginName),
			},
			req: testutil.Request(testPluginName),
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
				testutil.NewReportingArtifactNode("Plugin", "container"),
			},
			req: testutil.Request("container"),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
				{Type: commonv1alpha1.ConditionConfigProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigProgrammed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
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
				testutil.NewReportingArtifactNode("Plugin", testPluginName),
			},
			req:     testutil.Request(testPluginName),
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
				testutil.NewReportingArtifactNode("Plugin", testPluginName),
			},
			req:                testutil.Request(testPluginName),
			pullErr:            &artifact.RetryableError{Err: errors.New("mock pull error"), RetryAfter: 7 * time.Second},
			wantRequeueAfterGE: 7 * time.Second,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactProgramFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			name: "an OCI pull failure sets Programmed false, and the auth secret is not the node's to resolve",
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
				testutil.NewReportingArtifactNode("Plugin", testPluginName),
			},
			req:     testutil.Request(testPluginName),
			pullErr: fmt.Errorf("network error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactProgramFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
			},
		},
		{
			// When enforce-requirements=true, requirements are not met, and the plugin was never
			// installed on this node, the controller must explicitly set ConfigProgrammed=False and
			// OCIArtifactProgrammed=False. Without this, those condition types are absent from the
			// node's status entry, which lets another node's True status win unopposed in AggregateConditions
			// and makes the Plugin-level status show ConfigProgrammed=True while DependenciesSatisfied=False.
			name:                "enforce mode: requirements not satisfied and never installed sets ConfigProgrammed and OCIArtifactProgrammed to False",
			enforceRequirements: true,
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
				testutil.NewReportingArtifactNode("Plugin", testPluginName),
			},
			req: testutil.Request(testPluginName),
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
			name:                "enforce mode: requirements fail on previously installed plugin keeps ConfigProgrammed and OCIArtifactProgrammed True",
			enforceRequirements: true,
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
				testutil.NewReportingArtifactNode("Plugin", testPluginName, withPreviousInstallStatus()),
			},
			req: testutil.Request(testPluginName),
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
			name:                "advise mode installs despite unsatisfied requirement and stays Programmed",
			enforceRequirements: false,
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
				testutil.NewReportingArtifactNode("Plugin", testPluginName),
			},
			req: testutil.Request(testPluginName),
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
			r, _ := newReconcilerEnforcing(t, tt.enforceRequirements, tt.objects...)

			if tt.pullErr != nil {
				// The node does the fetching, and it shares this reconciler's fetcher; failing
				// the shared one is what makes the node's pull fail.
				r.fetcher.OCIErr = tt.pullErr
			}

			if tt.preInstallPlugin != nil {
				_, _, err := r.node.AddPluginConfig(context.Background(), tt.preInstallPlugin)
				require.NoError(t, err)
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

			if len(tt.wantConditions) > 0 {
				entry, ok := r.node.StatusEntry(artifact.KindPlugin, tt.req.Name)
				require.True(t, ok, "the flow's status must reach the publisher")
				testutil.RequireConditions(t, entry.Conditions, tt.wantConditions)
			}
		})
	}
}

// TestReconcile_SecondReconcileKeepsTheInstalledArtifacts covers repeated back-to-back reconciles
// for the same Plugin with nothing in the spec changed (e.g. a watch event bounce): the second
// Reconcile must publish the installed binary again rather than dropping it, since what it
// publishes is derived from the node's record and not from what the previous status held.
func TestReconcile_SecondReconcileKeepsTheInstalledArtifacts(t *testing.T) {
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/container", Tag: "latest"},
			},
		},
	}
	r, _ := newTestReconciler(t, plugin, testutil.NewReportingArtifactNode("Plugin", testPluginName))
	req := testutil.Request(testPluginName)

	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)

	got, ok := r.node.StatusEntry(artifact.KindPlugin, testPluginName)
	require.True(t, ok)
	require.Len(t, got.InstalledArtifacts, 1, "after the first reconcile")

	// Second reconcile: nothing changed in the spec, simulating a watch event bounce (e.g. a
	// Secret or unrelated ArtifactNode update re-enqueuing this object).
	_, err = r.Reconcile(context.Background(), req)
	require.NoError(t, err)

	got, ok = r.node.StatusEntry(artifact.KindPlugin, testPluginName)
	require.True(t, ok)
	require.Len(t, got.InstalledArtifacts, 1, "after the second reconcile")
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
			name: "OCI: empty spec hashes do not prove the installed revision is current",
			prePlugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/plugin", Tag: "latest"},
				}},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/plugins/plugin", Tag: "latest"},
				}},
			},
			wantOCIFetchCount: new(1),
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
			status := &artifactv1alpha1.NodeArtifactStatus{}

			if tt.prePlugin != nil {
				if tt.preSpecHash != "" {
					tt.prePlugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{SpecHash: tt.preSpecHash}
				}
				preNode := &artifactv1alpha1.NodeArtifactStatus{}
				require.NoError(t, r.node.ApplyArtifact(context.Background(), tt.prePlugin, preNode), "prePlugin setup failed")
				*status = *preNode
			}

			if tt.parentSpecHash != "" {
				tt.plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{SpecHash: tt.parentSpecHash}
			}
			tf := r.fetcher
			tf.OCICalls = 0

			err := r.node.ApplyArtifact(context.Background(), tt.plugin, status)
			// The installed files are derived when the reconcile publishes on its way out.
			r.node.PublishStatus(artifact.KindPlugin, tt.plugin, status)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantOCIFetchCount != nil {
				assert.Equal(t, *tt.wantOCIFetchCount, tf.OCICalls, "unexpected FetchOCI call count")
			}
			if tt.wantInstalledOCISpecHash != "" {
				ociEntry := artifact.FindInstalled(status.InstalledArtifacts, artifact.MediumOCI)
				require.NotNil(t, ociEntry, "expected OCI entry in InstalledArtifacts")
				assert.Equal(t, tt.wantInstalledOCISpecHash, ociEntry.SpecHash, "OCI InstalledArtifact.SpecHash mismatch")
			}
			if tt.wantOCIConditionRemoved {
				assert.Nil(t, artifact.FindInstalled(status.InstalledArtifacts, artifact.MediumOCI),
					"expected OCI entry removed from InstalledArtifacts")
				assert.Nil(t, apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String()),
					"expected OCIArtifactProgrammed condition to be removed, not set True, after stale cleanup")
			}
		})
	}
}

func TestEnsurePlugin_RemovedOCIWithoutBinaryCleansRecoveredConfig(t *testing.T) {
	ctx := t.Context()
	r, cl := newTestReconciler(t)
	fs := fsfake.NewMockFileSystem()
	r.node = nodetest.NewTestNodeOn(t, cl, fs, r.recorder, nodetest.WithFetcher(r.fetcher))
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace, UID: "installed-uid"},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "example/plugin", Tag: "old"}},
			Config:      &artifactv1alpha1.PluginConfig{Name: "installed-name"},
		},
	}
	artifactNode := &artifactv1alpha1.NodeArtifactStatus{}
	require.NoError(t, r.node.ApplyArtifact(ctx, plugin, artifactNode))
	r.node.PublishStatus(artifact.KindPlugin, plugin, artifactNode)
	key := artifact.RefOf(artifact.KindPlugin, plugin)
	binary := r.node.FindInstalled(key, artifact.MediumOCI)
	sharedFile := pluginsConfigFile(t, r.node)
	require.NotNil(t, binary)
	require.NotNil(t, sharedFile)
	require.NoError(t, fs.Remove(binary.Path))
	assignment := testutil.NewReportingArtifactNode("Plugin", plugin.Name)
	assignment.Spec.Artifacts[0].UID = string(plugin.UID)
	cl = fake.NewClientBuilder().WithScheme(r.Client.Scheme()).
		WithObjects(testutil.EnsureArtifactNode([]client.Object{plugin, assignment})...).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	r.node = nodetest.NewTestNodeOn(t, cl, fs, r.recorder, nodetest.WithFetcher(r.fetcher))
	require.NoError(t, node.NewWarmSyncRunnable(r.node).Warmup(ctx))
	require.Nil(t, r.node.FindInstalled(key, artifact.MediumOCI))
	assert.Contains(t, string(fs.Files[sharedFile.Path]), "installed-name")
	ociFetches := r.fetcher.OCICalls
	plugin.Spec.OCIArtifact = nil
	plugin.Spec.Config.Name = "never-installed"

	require.NoError(t, r.node.ApplyArtifact(ctx, plugin, artifactNode))
	r.node.PublishStatus(artifact.KindPlugin, plugin, artifactNode)

	assert.Contains(t, string(fs.Files[sharedFile.Path]), "plugins: []")
	assert.NotContains(t, string(fs.Files[sharedFile.Path]), "installed-name")
	assert.NotContains(t, string(fs.Files[sharedFile.Path]), "never-installed")
	assert.NotContains(t, fs.Files, binary.Path)
	assert.Nil(t, apimeta.FindStatusCondition(artifactNode.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String()))
	assert.Nil(t, apimeta.FindStatusCondition(artifactNode.Conditions, commonv1alpha1.ConditionConfigProgrammed.String()))
	assert.Equal(t, ociFetches, r.fetcher.OCICalls)
	writes := len(fs.WriteCalls)
	require.NoError(t, r.node.ApplyArtifact(ctx, plugin, artifactNode))
	assert.Len(t, fs.WriteCalls, writes, "repeated cleanup must not rewrite the empty aggregate")
}

func TestEnsurePlugin_RecreatedOwnerCannotReplaceInstalledBinary(t *testing.T) {
	ctx := t.Context()
	r, _ := newTestReconciler(t)
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace, UID: "original-uid"},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "example/plugin", Tag: "old"}},
			Config:      &artifactv1alpha1.PluginConfig{Name: "installed-name"},
		},
		Status: artifactv1alpha1.PluginStatus{ArtifactMeta: &commonv1alpha1.ArtifactMeta{SpecHash: "old-spec"}},
	}
	artifactNode := &artifactv1alpha1.NodeArtifactStatus{}
	require.NoError(t, r.node.ApplyArtifact(ctx, plugin, artifactNode))
	r.node.PublishStatus(artifact.KindPlugin, plugin, artifactNode)
	key := artifact.RefOf(artifact.KindPlugin, plugin)
	binary := r.node.FindInstalled(key, artifact.MediumOCI)
	config := pluginsConfigFile(t, r.node)
	require.NotNil(t, binary)
	require.NotNil(t, config)
	previous := artifactNode.DeepCopy().InstalledArtifacts

	// The CR name is reused while the previous incarnation's config is still installed.
	candidate := plugin.DeepCopy()
	candidate.UID = "replacement-uid"
	candidate.Spec.Config.Name = "replacement-name"
	candidate.Spec.OCIArtifact.Image.Tag = "replacement-tag"
	candidate.Status.ArtifactMeta.SpecHash = "new-spec"
	r.fetcher.OCIBytes = []byte("replacement binary")

	err := r.node.ApplyArtifact(ctx, candidate, artifactNode)

	require.Error(t, err, "ownership must be checked before writing the downloaded binary")
	assert.Equal(t, previous, artifactNode.InstalledArtifacts)
	for _, file := range []*artifact.File{binary, config} {
		intact, verifyErr := r.node.Verify(ctx, file)
		require.NoError(t, verifyErr)
		assert.True(t, intact)
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
			status := &artifactv1alpha1.NodeArtifactStatus{}
			status.Conditions = []metav1.Condition{{
				Type:               commonv1alpha1.ConditionOCIArtifactProgrammed.String(),
				Status:             tt.initialStatus,
				Reason:             artifact.ReasonOCIArtifactProgrammed,
				Message:            artifact.MessageOCIArtifactProgrammed,
				LastTransitionTime: pinned,
			}}

			require.NoError(t, r.node.ApplyArtifact(context.Background(), plugin, status))

			cond := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String())
			require.NotNil(t, cond)
			require.Equal(t, metav1.ConditionTrue, cond.Status)
			require.Equal(t, tt.wantPreserved, cond.LastTransitionTime.Equal(&pinned))
		})
	}
}

// TestEnsurePluginConfig covers the conditions and events a Plugin gets for its entry in the shared
// plugin configuration. The file itself (rename handling, content, store failures) is covered in the
// node package.
func TestEnsurePluginConfig(t *testing.T) {
	tests := []struct {
		name string

		plugin   *artifactv1alpha1.Plugin
		writeErr error
		wantErr  bool

		// preConditions, if set, seed status.Conditions before the call.
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
			wantEvents: []string{
				"Normal ArtifactStored oci artifact stored successfully",
				"Normal ArtifactStored inline artifact stored successfully",
			},
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
			wantEvents: []string{
				"Normal ArtifactStored oci artifact stored successfully",
				"Warning InlinePluginConfigStoreFailed Failed to store inline plugin config: disk full",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t)
			status := &artifactv1alpha1.NodeArtifactStatus{}
			if tt.preConditions != nil {
				status.Conditions = tt.preConditions
			}

			if tt.writeErr != nil {
				mockFS := fsfake.NewMockFileSystem()
				path := testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), "plugins-config",
					priority.MaxPriority, artifact.MediumInline, artifact.KindConfig)
				mockFS.WriteErrFor = map[string]error{artifact.StagingPath(path): tt.writeErr}
				r.node = nodetest.NewTestNodeOn(t, cl, mockFS, r.recorder, nodetest.WithFetcher(r.fetcher))
			}

			err := r.node.ApplyArtifact(context.Background(), tt.plugin, status)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			// The shared file is written inside the apply, so the whole pipeline runs and
			// sets the conditions that go with it. This test speaks only for ConfigProgrammed.
			for _, exp := range tt.wantConditions {
				testutil.RequireCondition(t, status.Conditions, exp.Type, exp.Status, exp.Reason)
			}
			if tt.wantConfigConditionRemoved {
				assert.Nil(t, apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionConfigProgrammed.String()),
					"expected ConfigProgrammed condition to be removed, not left True, when OCIArtifact is nil")
			}
			testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events, tt.wantEvents)
		})
	}
}

// TestEnsurePluginConfig_PopulatesConfigSubEntryEvenWhenUnchanged covers the shared
// plugins-config aggregate, tracked in the node's own record of it rather than per-Plugin-CR
// status: a re-add that the cache already knows is unchanged must still
// mirror the file's path into this Plugin's own status entry, not only on the reconcile that
// first wrote it.

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
			name: "a registry auth secret is the instance operator's to resolve: none reported, even when missing",
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
			wantNoConditions: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t, tt.objects...)
			status := &artifactv1alpha1.NodeArtifactStatus{}

			if len(tt.presetConditions) > 0 {
				status.Conditions = tt.presetConditions
			}

			// Reference resolution is a step inside the apply, so the whole pipeline runs and
			// sets the conditions that go with it. This test speaks only for ResolvedRefs, so it
			// asserts on that condition rather than on the whole list.
			err := r.node.ApplyArtifact(context.Background(), tt.plugin, status)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantNoConditions {
				assert.Nil(t, apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionResolvedRefs.String()),
					"nothing to resolve must leave no ResolvedRefs condition behind")
			}

			for _, exp := range tt.wantConditions {
				testutil.RequireCondition(t, status.Conditions, exp.Type, exp.Status, exp.Reason)
			}
		})
	}
}

func TestApply_PluginCompatibility(t *testing.T) {
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
			enforceRequirements: true,
			plugin:              ociPlugin(nil),
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
			name:                "plugin_api_version major mismatch blocks with False",
			enforceRequirements: true,
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "2.0.0"},
				},
			}),
			falcoCaps:      map[string]string{"plugin_api_version": "3.12.0"},
			wantSkip:       true,
			wantMsgContain: "major versions are incompatible",
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name:                "plugin_api_version downgrade blocks with False",
			enforceRequirements: true,
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "3.0.0"},
				},
			}),
			falcoCaps:      map[string]string{"plugin_api_version": "2.12.0"},
			wantSkip:       true,
			wantMsgContain: "major versions are incompatible",
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name:                "generic requirement too low blocks with False",
			enforceRequirements: true,
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "engine_version_semver", Version: "0.62.0"},
				},
			}),
			falcoCaps:      map[string]string{"engine_version_semver": "0.57.0"},
			wantSkip:       true,
			wantMsgContain: "engine_version_semver",
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name:                "capability not advertised by Falco blocks with False",
			enforceRequirements: true,
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "3.0.0"},
				},
			}),
			falcoCaps:      map[string]string{},
			wantSkip:       true,
			wantMsgContain: "does not advertise",
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name:                "advise mode installs anyway on unsatisfied requirement",
			enforceRequirements: false,
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "2.0.0"},
				},
			}),
			falcoCaps:      map[string]string{"plugin_api_version": "3.12.0"},
			wantSkip:       false,
			wantMsgContain: "installed anyway",
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfiedInstalledAnyway,
				},
			},
		},
		{
			name:                "enforce mode rejects an update but keeps the previous install",
			enforceRequirements: true,
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "2.0.0"},
				},
			}),
			falcoCaps:      map[string]string{"plugin_api_version": "3.12.0"},
			preInstalled:   true,
			wantSkip:       true,
			wantMsgContain: "keeping the previously installed version",
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
			name:                "Falco versions not yet observed strict blocks without returning an error",
			enforceRequirements: true,
			plugin: ociPlugin(&commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{
					{Name: "plugin_api_version", Version: "3.0.0"},
				},
			}),
			falcoErr: fmt.Errorf("connection refused"),
			wantSkip: true,
			wantErr:  false,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newReconcilerEnforcing(t, tt.enforceRequirements)
			if tt.falcoErr == nil && tt.falcoCaps != nil {
				r.node.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.falcoCaps).Result)
			}
			status := &artifactv1alpha1.NodeArtifactStatus{}
			if tt.preInstalled {
				installed := []artifactv1alpha1.InstalledArtifact{
					{Path: "/var/lib/falco/plugins/test.so", Medium: string(artifact.MediumOCI)},
				}
				status.InstalledArtifacts = installed
				// Whether the plugin is already installed is read from the node's record, not from status: seed
				// it the way the warm sync does after a restart.
				r.node.SeedInstalled(artifact.Ref{Kind: artifact.KindPlugin, Name: testPluginName}, installed)
			}

			r.fetcher.OCICalls = 0
			err := r.node.ApplyArtifact(context.Background(), tt.plugin, status)

			// The compatibility check is a step inside the apply, and it runs before the
			// download: what "skipped" means from the outside is that nothing was fetched. A
			// plugin with no OCI artifact has nothing to fetch either way, so it says nothing here.
			if tt.plugin.Spec.OCIArtifact != nil {
				assert.Equal(t, tt.wantSkip, r.fetcher.OCICalls == 0,
					"a plugin blocked by its requirements must never be downloaded")
			}
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.wantNoConditions {
				assert.Nil(t, apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String()),
					"nothing to check must leave no DependenciesSatisfied condition behind")
			}
			if tt.wantMsgContain != "" {
				cond := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
				require.NotNil(t, cond)
				assert.Contains(t, cond.Message, tt.wantMsgContain)
			}
			for _, exp := range tt.wantConditions {
				testutil.RequireCondition(t, status.Conditions, exp.Type, exp.Status, exp.Reason)
			}
		})
	}
}

func TestEnsurePluginConfig_RegistersProvidesWithNodeArtifactManager(t *testing.T) {
	r, _ := newTestReconciler(t)
	status := &artifactv1alpha1.NodeArtifactStatus{}
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "r", Tag: "t"}},
		},
	}

	require.NoError(t, r.node.ApplyArtifact(context.Background(), pl, status))

	err := r.node.RemovePluginConfig(context.Background(), pl)
	require.NoError(t, err, "nothing requires it yet, so this proves the name was registered as provided")

	require.NoError(t, r.node.ApplyArtifact(context.Background(), pl, status))

	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "some-rulesfile"}
	installRequiringRulesfile(t, r, rfKey)

	err = r.node.RemovePluginConfig(context.Background(), pl)
	require.Error(t, err)
	blocked, ok := errors.AsType[*node.BlockedError](err)
	require.True(t, ok)
	assert.Contains(t, blocked.BlockedBy, rfKey)
}

// A plugin whose config name a Rulesfile on the node still requires cannot be renamed yet. That is not a failed
// store: the Plugin says why in its ConfigProgrammed condition, and the reconcile is tried again shortly, as a
// blocked removal is, instead of failing into the controller's growing backoff.
func TestApplyAndPublish_ABlockedRenameIsReportedAndRetriedShortly(t *testing.T) {
	r, _ := newTestReconciler(t)
	status := &artifactv1alpha1.NodeArtifactStatus{}
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "r", Tag: "t"}},
		},
	}
	require.NoError(t, r.node.ApplyArtifact(t.Context(), pl, status))
	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "some-rulesfile"}
	installRequiringRulesfile(t, r, rfKey)
	renamed := pl.DeepCopy()
	renamed.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "renamed"}

	result, err := shared.ApplyAndPublish(t.Context(), r.node, renamed, status)

	require.NoError(t, err, "a blocked rename is waited out, not failed")
	assert.Equal(t, shared.BlockedRetryDelay, result.RequeueAfter)
	testutil.RequireCondition(t, status.Conditions, commonv1alpha1.ConditionConfigProgrammed.String(),
		metav1.ConditionFalse, artifact.ReasonPluginConfigStillRequired)
	cond := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionConfigProgrammed.String())
	assert.Contains(t, cond.Message, rfKey.Name)
	testutil.RequireCondition(t, status.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String(),
		metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed)

	// Once the Rulesfile is gone the rename goes through.
	require.NoError(t, r.node.Remove(t.Context(), rfKey))
	result, err = shared.ApplyAndPublish(t.Context(), r.node, renamed, status)
	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)
	testutil.RequireCondition(t, status.Conditions, commonv1alpha1.ConditionConfigProgrammed.String(),
		metav1.ConditionTrue, artifact.ReasonConfigProgrammed)
}

func TestCleanup_BlockedByARequiringRulesfileKeepsTheFilesAndPublishesWhy(t *testing.T) {
	pl := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace, UID: "plugin-uid"},
	}
	reporting := testutil.NewReportingArtifactNode("Plugin", testPluginName)
	reporting.Spec.Artifacts[0].UID, reporting.Status.Artifacts[0].UID = string(pl.UID), string(pl.UID)
	r, _ := newTestReconciler(t, pl, reporting)

	// Simulate config already installed for this plugin (as if a prior reconcile ran).
	_, _, err := r.node.AddPluginConfig(context.Background(), pl)
	require.NoError(t, err)
	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "some-rulesfile"}
	installRequiringRulesfile(t, r, rfKey)

	err = r.Cleanup(context.Background(), testPluginName)

	blocked, ok := errors.AsType[*node.BlockedError](err)
	require.True(t, ok, "a blocked removal must be reported so that the node controller retries it: %v", err)
	assert.Contains(t, blocked.BlockedBy, rfKey)
	entry, held := r.node.StatusEntry(artifact.KindPlugin, testPluginName)
	require.True(t, held)
	cond := apimeta.FindStatusCondition(entry.Conditions, commonv1alpha1.ConditionDeletionBlocked.String())
	require.NotNil(t, cond, "DeletionBlocked condition must be published while blocked")
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, artifact.ReasonPluginConfigStillRequired, cond.Reason)
	assert.Contains(t, cond.Message, rfKey.Name)

	// Remove the dependent file and confirm cleanup proceeds.
	rmErr := r.node.Remove(t.Context(), rfKey)
	require.NoError(t, rmErr)
	require.NoError(t, r.Cleanup(context.Background(), testPluginName))
}

// A plugin that is gone, and that the node knows of from its files alone, has no uid to report a blocked
// removal under. Nothing is published: an entry without a uid would get every later write of the node's
// status rejected. The removal is still reported as blocked, so that it is retried.
func TestCleanup_BlockedRemovalOfAGonePluginWithoutAnEntryPublishesNothing(t *testing.T) {
	gone := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
	}
	r, _ := newTestReconciler(t, testutil.NewTestArtifactNode())
	_, _, err := r.node.AddPluginConfig(t.Context(), gone)
	require.NoError(t, err)
	r.node.WithdrawStatus(artifact.RefOf(artifact.KindPlugin, gone))
	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "some-rulesfile"}
	installRequiringRulesfile(t, r, rfKey)

	err = r.Cleanup(t.Context(), testPluginName)

	_, blocked := errors.AsType[*node.BlockedError](err)
	require.True(t, blocked, "the removal must stay blocked so it is retried: %v", err)
	_, held := r.node.StatusEntry(artifact.KindPlugin, testPluginName)
	assert.False(t, held, "no entry without a uid may be published")
}

func TestReconcile_ARemovedPluginIsNeverInstalledAgain(t *testing.T) {
	ctx := t.Context()
	parent := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "example/plugin", Tag: "new"}},
		},
		Status: artifactv1alpha1.PluginStatus{ArtifactMeta: &commonv1alpha1.ArtifactMeta{SpecHash: "new-spec"}},
	}
	// The node's spec no longer lists the plugin, while the plugin still has files installed and reported.
	artifactNode := testutil.NewReportingArtifactNode("Plugin", testPluginName)
	artifactNode.Spec.Artifacts = nil
	r, _ := newTestReconciler(t, parent, artifactNode)
	require.NoError(t, r.node.ApplyArtifact(ctx, parent, &artifactv1alpha1.NodeArtifactStatus{}))
	configFile := pluginsConfigFile(t, r.node)
	binaryFile := r.node.FindInstalled(artifact.RefOf(artifact.KindPlugin, parent), artifact.MediumOCI)
	require.NotNil(t, configFile)
	require.NotNil(t, binaryFile)
	r.fetcher.OCICalls = 0
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "installed-rules"}
	installRequiringRulesfile(t, r, key)

	_, err := r.Reconcile(ctx, testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Zero(t, r.fetcher.OCICalls, "an unassigned plugin must not fall through to an OCI update")

	// Removing it is the node controller's job, and is refused while a rulesfile still needs the plugin.
	blockedErr := r.Cleanup(ctx, testPluginName)
	_, isBlocked := errors.AsType[*node.BlockedError](blockedErr)
	require.True(t, isBlocked)
	for _, file := range []*artifact.File{binaryFile, configFile} {
		intact, verifyErr := r.node.Verify(ctx, file)
		require.NoError(t, verifyErr)
		assert.True(t, intact, "a blocked removal must preserve installed files")
	}

	// Once the dependent rules are removed, cleanup finishes without installing anything.
	rmErr := r.node.Remove(ctx, key)
	require.NoError(t, rmErr)
	require.NoError(t, r.Cleanup(ctx, testPluginName))
	present, err := r.node.Verify(ctx, binaryFile)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Zero(t, r.fetcher.OCICalls)
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
			oldPath := artifactcache.BlobPath(cache.Dir(), string(artifact.KindPlugin), "artifact:old", oldDigest, goos, goarch)
			newPath := artifactcache.BlobPath(cache.Dir(), string(artifact.KindPlugin), "artifact:new", newDigest, goos, goarch)
			require.NoError(t, cache.Store(oldPath, []byte("old artifact bytes"), 0o755))
			require.NoError(t, cache.Set(string(artifact.KindPlugin), "default", "artifact", platform, oldPath))

			srv := httptest.NewServer(artifactserver.New(cache).Handler())
			defer srv.Close()
			fs := fsfake.NewMockFileSystem()
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
				WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
			fetcher := &artifact.Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client()}
			recorder := events.NewFakeRecorder(20)
			// Only the node is exercised here.
			testNode := nodetest.NewTestNodeOn(t, cl, fs, recorder, nodetest.WithFetcher(fetcher))
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
			artifactNode := &artifactv1alpha1.NodeArtifactStatus{}
			if alreadyInstalled {
				require.NoError(t, testNode.ApplyArtifact(ctx, parent, artifactNode))
				testNode.PublishStatus(artifact.KindPlugin, parent, artifactNode)
			}
			previous := artifactNode.DeepCopy().InstalledArtifacts

			// The parent metadata is published before the aggregator replaces the cache entry.
			parent.Generation = 2
			parent.Spec.OCIArtifact.Image.Tag = "new"
			parent.Status.ObservedGeneration = 2
			parent.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{SpecHash: "spec-new", Digest: newDigest}

			err := testNode.ApplyArtifact(ctx, parent, artifactNode)
			testNode.PublishStatus(artifact.KindPlugin, parent, artifactNode)
			var retryErr *artifact.RetryableError
			require.ErrorAs(t, err, &retryErr, "an old cached revision must not be accepted as the new spec")
			require.Equal(t, previous, artifactNode.InstalledArtifacts)
			if alreadyInstalled {
				require.Equal(t, []byte("old artifact bytes"), fs.Files[previous[0].Path])
			} else {
				require.Empty(t, fs.Files)
			}
			condition := apimeta.FindStatusCondition(artifactNode.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String())
			require.NotNil(t, condition)
			require.Equal(t, metav1.ConditionFalse, condition.Status)

			// Once the expected digest is available, the retry installs it and records its spec.
			require.NoError(t, cache.Store(newPath, []byte("new artifact bytes"), 0o755))
			require.NoError(t, cache.Set(string(artifact.KindPlugin), "default", "artifact", platform, newPath))
			require.NoError(t, testNode.ApplyArtifact(ctx, parent, artifactNode))
			testNode.PublishStatus(artifact.KindPlugin, parent, artifactNode)
			require.Len(t, artifactNode.InstalledArtifacts, 1)
			installed := artifactNode.InstalledArtifacts[0]
			require.Equal(t, "spec-new", installed.SpecHash)
			require.Equal(t, []byte("new artifact bytes"), fs.Files[installed.Path])
			condition = apimeta.FindStatusCondition(artifactNode.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String())
			require.Equal(t, metav1.ConditionTrue, condition.Status)
			require.Equal(t, int64(2), condition.ObservedGeneration)

			// A verified, installed revision remains usable without another download.
			srv.Close()
			require.NoError(t, testNode.ApplyArtifact(ctx, parent, artifactNode))
		})
	}
}

const assignedPluginUID = "plugin-uid"

// newAssignedReconciler is newTestReconciler for the spec-driven path, which looks the node's
// ArtifactNode up in the node's own namespace.
func newAssignedReconciler(t *testing.T, objs ...client.Object) (*testReconciler, client.Client) {
	t.Helper()
	r, cl := newTestReconciler(t, objs...)
	return r, cl
}

func assignedPlugin(uid string) *artifactv1alpha1.Plugin {
	return &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace, UID: types.UID(uid), Generation: 2},
	}
}

func TestReconcile_RunsTheFlowAndPublishesWhenAssigned(t *testing.T) {
	// Enforcing: the flow waits for the instance operator to observe generation 2.
	r, cl := newReconcilerEnforcing(t, true, assignedPlugin(assignedPluginUID),
		testutil.NewAssigningArtifactNode("Plugin", testPluginName, assignedPluginUID))

	result, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))

	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter)
	got := testutil.RequirePublishedWhere(t, cl, "Plugin", testPluginName, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.FindStatusCondition(e.Conditions, commonv1alpha1.ConditionProgrammed.String()) != nil
	})
	assert.Equal(t, assignedPluginUID, got.UID)
}

func TestReconcile_LeavesAPluginAloneUnlessAssigned(t *testing.T) {
	r, _ := newAssignedReconciler(t, assignedPlugin(assignedPluginUID), testutil.NewTestArtifactNode())

	result, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))

	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter)
	_, held := r.node.StatusEntry(artifact.KindPlugin, testPluginName)
	assert.False(t, held)
}

func TestReconcile_WaitsWhenTheSpecListsAnotherIncarnation(t *testing.T) {
	r, _ := newAssignedReconciler(t, assignedPlugin("new-uid"), testutil.NewAssigningArtifactNode("Plugin", testPluginName, "old-uid"))

	result, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))

	require.NoError(t, err)
	assert.Equal(t, shared.AssignmentRetryDelay, result.RequeueAfter)
	nodetest.AssertNothingDone(t, r.node, artifact.KindPlugin, testPluginName, "never act for an incarnation the operator did not assign")
}

func TestReconcile_IgnoresAMissingOrDeletingPlugin(t *testing.T) {
	r, _ := newAssignedReconciler(t, testutil.NewAssigningArtifactNode("Plugin", testPluginName, assignedPluginUID))
	_, err := r.Reconcile(t.Context(), testutil.Request("nonexistent"))
	require.NoError(t, err)

	now := metav1.Now()
	deleting := assignedPlugin(assignedPluginUID)
	deleting.DeletionTimestamp = &now
	deleting.Finalizers = []string{"test/finalizer"}
	r, _ = newAssignedReconciler(t, deleting, testutil.NewAssigningArtifactNode("Plugin", testPluginName, assignedPluginUID))
	_, err = r.Reconcile(t.Context(), testutil.Request(testPluginName))
	require.NoError(t, err)
	nodetest.AssertNothingDone(t, r.node, artifact.KindPlugin, testPluginName, "a deleting artifact is left alone")
}

func TestCleanup_IsIdempotentWhenNothingIsInstalled(t *testing.T) {
	r, _ := newAssignedReconciler(t, assignedPlugin(assignedPluginUID))

	require.NoError(t, r.Cleanup(t.Context(), testPluginName))
	require.NoError(t, r.Cleanup(t.Context(), testPluginName))
}

func TestCleanup_WorksWithoutTheParent(t *testing.T) {
	r, _ := newAssignedReconciler(t)

	require.NoError(t, r.Cleanup(t.Context(), "already-deleted"), "removal needs only what installation recorded")
}

func TestCleanup_RemovesThePluginConfig(t *testing.T) {
	pl := assignedPlugin(assignedPluginUID)
	r, _ := newAssignedReconciler(t, pl)
	_, _, err := r.node.AddPluginConfig(t.Context(), pl)
	require.NoError(t, err)

	// While the entry is there it is the plugin's, and no other Plugin can take its name.
	other := assignedPlugin("other-uid")
	other.Name = "other-plugin"
	other.Spec.Config = &artifactv1alpha1.PluginConfig{Name: testPluginName}
	_, _, err = r.node.AddPluginConfig(t.Context(), other)
	require.Error(t, err)

	require.NoError(t, r.Cleanup(t.Context(), testPluginName))

	_, _, err = r.node.AddPluginConfig(t.Context(), other)
	require.NoError(t, err, "the entry is gone, so its name is free")
}

func TestCleanup_BlockedByARequiringRulesfilePublishesWhy(t *testing.T) {
	pl := assignedPlugin(assignedPluginUID)
	r, cl := newAssignedReconciler(t, pl, testutil.NewAssigningArtifactNode("Plugin", testPluginName, assignedPluginUID))
	_, _, err := r.node.AddPluginConfig(t.Context(), pl)
	require.NoError(t, err)
	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "some-rulesfile"}
	installRequiringRulesfile(t, r, rfKey)

	err = r.Cleanup(t.Context(), testPluginName)

	blocked, ok := errors.AsType[*node.BlockedError](err)
	require.True(t, ok, "the node controller must be able to tell a blocked removal from a failure")
	assert.Contains(t, blocked.BlockedBy, rfKey)
	got := testutil.RequirePublishedWhere(t, cl, "Plugin", testPluginName, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.FindStatusCondition(e.Conditions, commonv1alpha1.ConditionDeletionBlocked.String()) != nil
	})
	cond := apimeta.FindStatusCondition(got.Conditions, commonv1alpha1.ConditionDeletionBlocked.String())
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, artifact.ReasonPluginConfigStillRequired, cond.Reason)
	assert.Equal(t, assignedPluginUID, got.UID)

	rmErr := r.node.Remove(t.Context(), rfKey)
	require.NoError(t, rmErr)
	require.NoError(t, r.Cleanup(t.Context(), testPluginName), "once nothing requires the plugin it can be removed")
}

// heldPlugin returns a reconciler that has reconciled an assigned Plugin, so that the node holds an entry for it.
func heldPlugin(t *testing.T) (*testReconciler, client.Client) {
	t.Helper()
	// Enforcing: the flow waits for the instance operator to observe generation 2.
	r, cl := newReconcilerEnforcing(t, true, assignedPlugin(assignedPluginUID),
		testutil.NewAssigningArtifactNode("Plugin", testPluginName, assignedPluginUID))
	_, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))
	require.NoError(t, err)
	_, held := r.node.StatusEntry(artifact.KindPlugin, testPluginName)
	require.True(t, held)
	return r, cl
}

func TestReconcile_RemovesWhatItHoldsWhenThePluginIsNoLongerAssigned(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, client.Client){
		"the ArtifactNode stops listing it": testutil.DropAssignments,
		"the Plugin is gone and the ArtifactNode stopped listing it": func(t *testing.T, cl client.Client) {
			testutil.DropAssignments(t, cl)
			require.NoError(t, cl.Delete(t.Context(), assignedPlugin(assignedPluginUID)))
		},
		"there is no ArtifactNode": func(t *testing.T, cl client.Client) {
			require.NoError(t, cl.Delete(t.Context(), testutil.NewAssigningArtifactNode("Plugin", testPluginName, "")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, cl := heldPlugin(t)
			prepare(t, cl)

			result, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))

			require.NoError(t, err)
			assert.Equal(t, time.Duration(0), result.RequeueAfter)
			_, held := r.node.StatusEntry(artifact.KindPlugin, testPluginName)
			assert.False(t, held, "an entry left behind would keep the parent's finalizer")
		})
	}
}

func TestReconcile_KeepsWhatItHoldsWhileTheArtifactNodeStillListsAGonePlugin(t *testing.T) {
	r, cl := heldPlugin(t)
	require.NoError(t, cl.Delete(t.Context(), assignedPlugin(assignedPluginUID)))

	_, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))

	require.NoError(t, err)
	_, held := r.node.StatusEntry(artifact.KindPlugin, testPluginName)
	assert.True(t, held, "the operator has yet to drop it from the ArtifactNode, which reconciles the Plugin again")
}

// A plugin a Rulesfile on the node still requires cannot be removed yet: the reconcile says why, and tries again.
func TestReconcile_ARemovalABlockedByARequiringRulesfileIsRetried(t *testing.T) {
	r, cl := heldPlugin(t)
	pl := assignedPlugin(assignedPluginUID)
	_, _, err := r.node.AddPluginConfig(t.Context(), pl)
	require.NoError(t, err)
	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "some-rulesfile"}
	installRequiringRulesfile(t, r, rfKey)
	testutil.DropAssignments(t, cl)

	result, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))

	require.NoError(t, err, "a removal that has to wait is not a failure")
	assert.Equal(t, shared.BlockedRetryDelay, result.RequeueAfter)
	testutil.RequirePublishedWhere(t, cl, "Plugin", testPluginName, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.FindStatusCondition(e.Conditions, commonv1alpha1.ConditionDeletionBlocked.String()) != nil
	})

	rmErr := r.node.Remove(t.Context(), rfKey)
	require.NoError(t, rmErr)
	result, err = r.Reconcile(t.Context(), testutil.Request(testPluginName))

	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter)
	_, held := r.node.StatusEntry(artifact.KindPlugin, testPluginName)
	assert.False(t, held)
}

// A Plugin recreated under the same name while a Rulesfile still requires what its previous incarnation
// installed takes that over: waiting for a removal that cannot happen would keep it from ever being installed.
func TestReconcile_ARecreatedPluginTakesOverWhatARulesfileStillRequires(t *testing.T) {
	const recreatedUID = "recreated-uid"
	previous := assignedPlugin(assignedPluginUID)
	previous.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{}
	r, cl := newTestReconciler(t, previous, testutil.NewAssigningArtifactNode("Plugin", testPluginName, assignedPluginUID))
	_, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))
	require.NoError(t, err)
	key := artifact.Ref{Kind: kind, Name: testPluginName}
	binary := r.node.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, binary)
	installRequiringRulesfile(t, r, artifact.Ref{Kind: artifact.KindRulesfile, Name: "some-rulesfile"})

	require.NoError(t, cl.Delete(t.Context(), previous))
	recreated := assignedPlugin(recreatedUID)
	recreated.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{}
	require.NoError(t, cl.Create(t.Context(), recreated))
	artifactNode := testutil.NewAssigningArtifactNode("Plugin", testPluginName, recreatedUID)
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(artifactNode), artifactNode))
	artifactNode.Spec.Artifacts[0].UID = recreatedUID
	require.NoError(t, cl.Update(t.Context(), artifactNode))

	result, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))

	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter, "nothing is left to wait for")
	got := testutil.RequirePublishedWhere(t, cl, "Plugin", testPluginName, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return e.UID == recreatedUID && apimeta.IsStatusConditionTrue(e.Conditions, commonv1alpha1.ConditionProgrammed.String())
	})
	assert.Nil(t, apimeta.FindStatusCondition(got.Conditions, commonv1alpha1.ConditionDeletionBlocked.String()))
	present, err := r.node.Verify(t.Context(), binary)
	require.NoError(t, err)
	assert.True(t, present, "the rules still need the plugin")
}

var errBoom = errors.New("boom")

func TestCleanup_ReportsWhatCannotBeDone(t *testing.T) {
	tests := []struct {
		name     string
		getErr   error
		removeFS error
		// blocked keeps a Rulesfile requiring the plugin on the node, so that the removal is refused and
		// Cleanup reads the Plugin to publish why. Removal itself never reads the Plugin.
		blocked bool
	}{
		{name: "the Plugin cannot be read while the removal is blocked", getErr: errBoom, blocked: true},
		{name: "the binary cannot be removed", removeFS: errBoom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS := fsfake.NewMockFileSystem()
			// Reads fail only once the plugin is installed: installing it reads the node's ArtifactNode.
			failGets := false
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
				WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if failGets && tt.getErr != nil {
							return tt.getErr
						}
						return cl.Get(ctx, key, obj, opts...)
					},
				}).Build()
			fetcher := testutil.NewFakeFetcher(cl)
			store := nodetest.NewTestNodeOn(t, cl, mockFS, events.NewFakeRecorder(20), nodetest.WithFetcher(fetcher))
			r := &PluginReconciler{Client: cl, node: store}
			require.NoError(t, store.ApplyArtifact(t.Context(), &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: testPluginName, UID: "uid"},
				Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}},
			}, &artifactv1alpha1.NodeArtifactStatus{}))
			if tt.blocked {
				installRequiringRulesfile(t, &testReconciler{PluginReconciler: r, fetcher: fetcher},
					artifact.Ref{Kind: artifact.KindRulesfile, Name: "requiring-rules"})
			}
			failGets = true
			mockFS.RemoveErr = tt.removeFS

			err := r.Cleanup(t.Context(), testPluginName)

			require.ErrorIs(t, err, errBoom)
		})
	}
}

func TestCleanup_ReleasesTheEntryOfARecreatedPluginAfterARestart(t *testing.T) {
	ctx := t.Context()
	// The plugin was deleted and recreated while the sidecar was down. The new incarnation is the one the
	// ArtifactNode assigns, so the restarted sidecar's warm sync restored the shared-config entry under its
	// UID, while the status entry the previous process published still names the old one.
	parent := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace, UID: "new-uid"},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "example/plugin", Tag: "v1"}},
		},
		Status: artifactv1alpha1.PluginStatus{ArtifactMeta: &commonv1alpha1.ArtifactMeta{SpecHash: "spec"}},
	}
	r, _ := newTestReconciler(t, parent, testutil.NewAssigningArtifactNode("Plugin", testPluginName, "new-uid"))
	require.NoError(t, r.node.ApplyArtifact(ctx, parent, &artifactv1alpha1.NodeArtifactStatus{}))
	binary := r.node.FindInstalled(artifact.RefOf(artifact.KindPlugin, parent), artifact.MediumOCI)
	require.NotNil(t, binary)
	previous := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: testPluginName, UID: "old-uid"}}
	r.node.PublishStatus(artifact.KindPlugin, previous, &artifactv1alpha1.NodeArtifactStatus{})

	// StatusFor reports the entry stale, and the reconcile cleans up before installing the new incarnation.
	require.NoError(t, r.Cleanup(ctx, testPluginName))

	present, err := r.node.Verify(ctx, binary)
	require.NoError(t, err)
	assert.False(t, present, "the old incarnation's binary must go, whichever UID the entry was filed under")
	_, held := r.node.StatusEntry(artifact.KindPlugin, testPluginName)
	assert.False(t, held, "the stale entry goes with the last file")
}
