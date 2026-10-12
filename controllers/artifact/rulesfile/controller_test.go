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
	"errors"
	"fmt"
	"net/http/httptest"
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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/shared"
	instancerulesfile "github.com/falcosecurity/falco-operator/controllers/instance/artifact/rulesfile"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactserver"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
	"github.com/falcosecurity/falco-operator/internal/testutil"
	"github.com/falcosecurity/falco-operator/internal/testutil/nodetest"
)

// testReconciler is the RulesfileReconciler a test drives, plus a handle on the stub the node
// fetches through. The reconciler holds no fetcher: the node does the fetching, so a test
// that wants to fail, replace or count a fetch reaches the stub here.
type testReconciler struct {
	*RulesfileReconciler
	fetcher *testutil.FakeFetcher
	// recorder receives the Events of the reconciler's node.
	recorder events.EventRecorder
}

const testRulesfileName = "test-rulesfile"

// setCurrentRulesfileMetadata explicitly models a completed instance-operator metadata update.
// Tests that exercise stale metadata must call this before changing the sources, not during reconciliation.
func setCurrentRulesfileMetadata(t *testing.T, rf *artifactv1alpha1.Rulesfile, cl client.Client) {
	t.Helper()
	sources, err := artifact.ResolveRulesfileSources(t.Context(), &artifact.Fetcher{K8sClient: cl}, rf)
	require.NoError(t, err)
	if rf.Status.ArtifactMeta == nil {
		rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{}
	}
	rf.Status.ArtifactMetaSourcesHash, err = sources.Hash()
	require.NoError(t, err)
	rf.Status.ArtifactMeta.SpecHash, err = sources.OCISpecHash()
	require.NoError(t, err)
	if sources.OCIArtifact != nil && rf.Status.ArtifactMeta.Digest == "" {
		rf.Status.ArtifactMeta.Digest = digest.FromString("mock OCI manifest").String()
	}
	rf.Status.ObservedGeneration = rf.Generation
}

// testInlineRulesJSON is sample Falco rules in JSON format (used for *apiextensionsv1.JSON fields).
const testInlineRulesJSON = `[{"rule":"test_rule","desc":"test","condition":"always_true","output":"test","priority":"WARNING"}]`

// testInlineRulesYAML is the expected YAML representation of testInlineRulesJSON after conversion.
const testInlineRulesYAML = "- condition: always_true\n  desc: test\n  output: test\n  priority: WARNING\n  rule: test_rule\n"

// testRulesData is used as a ConfigMap data value for rules.yaml.
const testRulesData = "- rule: test_rule\n  desc: test\n  condition: always_true\n  output: test\n  priority: WARNING\n"

// withPreviousOCIInstallStatus simulates a node where the OCI rulesfile was already installed on a prior
// reconcile. Used to verify that the update-rejected code path keeps OCIArtifactProgrammed=True even when
// requirements are no longer satisfied.
func withPreviousOCIInstallStatus() func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) {
		n.Status.Artifacts[0].InstalledArtifacts = []artifactv1alpha1.InstalledArtifact{
			{Path: "/etc/falco/rules.d/test-rulesfile-oci.yaml", Medium: string(artifact.MediumOCI)},
		}
		n.Status.Artifacts[0].Conditions = []metav1.Condition{
			common.NewOCIArtifactProgrammedCondition(metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed, artifact.MessageOCIArtifactProgrammed, 0),
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
	r := &RulesfileReconciler{
		Client: cl,
		node:   store,
	}
	useNode(t, r, store, objs)
	return &testReconciler{RulesfileReconciler: r, fetcher: fetcher, recorder: recorder}, cl
}

// useNode makes r use n, as after a restart: what the ArtifactNodes among objs say is installed is
// recovered into it, and it publishes through the client n was built over.
func useNode(t *testing.T, r *RulesfileReconciler, n *node.Node, objs []client.Object) {
	t.Helper()
	r.node = n
	nodetest.Prime(n, objs)
}

// entryOf is the status the reconciler holds for the test Rulesfile: what it has published, or found on the
// node's ArtifactNode.
func entryOf(t *testing.T, n *node.Node) artifactv1alpha1.NodeArtifactStatus {
	t.Helper()
	entry, ok := n.StatusEntry(artifact.KindRulesfile, testRulesfileName)
	require.True(t, ok, "the flow's status must reach the publisher")
	return entry
}

func TestNewRulesfileReconciler(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), events.NewFakeRecorder(10),
		nodetest.WithFetcher(testutil.NewFakeFetcher(cl)), nodetest.WithEnforceRequirements(true))
	r := NewRulesfileReconciler(cl, n)

	require.NotNil(t, r)
	assert.True(t, n.EnforceRequirements(), "the policy is the node's, set when it is built, and no reconciler changes it")
	assert.Same(t, n, r.node, "the reconciler works through the node it was given")
	assert.Equal(t, testutil.TestNodeName, r.node.Name())
	assert.Equal(t, testutil.TestNamespace, r.node.Namespace())
}

func TestReconcile_ConfigMapUpdateWaitsForMatchingMetadata(t *testing.T) {
	for _, instanceFirst := range []bool{false, true} {
		for _, installed := range []bool{false, true} {
			for _, compatible := range []bool{false, true} {
				t.Run(fmt.Sprintf("instanceFirst=%t/installed=%t/compatible=%t", instanceFirst, installed, compatible), func(t *testing.T) {
					testConfigMapUpdate(t, instanceFirst, installed, compatible)
				})
			}
		}
	}
}

func testConfigMapUpdate(t *testing.T, instanceFirst, installed, compatible bool) {
	var status artifactv1alpha1.NodeArtifactStatus
	t.Helper()
	ctx := t.Context()
	parent := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 1},
		Spec:       artifactv1alpha1.RulesfileSpec{ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "rules"}},
	}
	oldContent := "- required_engine_version: 0.57.0\n" + testRulesData
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: parent.Namespace},
		Data:       map[string]string{commonv1alpha1.ConfigMapRulesKey: oldContent},
	}
	scheme := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	kubeNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName}}
	falco := &instancev1alpha1.Falco{ObjectMeta: metav1.ObjectMeta{Name: "falco", Namespace: parent.Namespace}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "falco", Namespace: parent.Namespace, Labels: map[string]string{"app.kubernetes.io/instance": falco.Name}},
		Spec:       corev1.PodSpec{NodeName: kubeNode.Name},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	artifactNode := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent, cm, kubeNode, falco, pod, artifactNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}, &artifactv1alpha1.Rulesfile{}).Build()
	fs := fsfake.NewMockFileSystem()
	versions := compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.57.0"})
	fetcher := testutil.NewFakeFetcher(cl)
	recorder := events.NewFakeRecorder(100)
	store := nodetest.NewTestNode(t, cl,
		nodetest.WithStore(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}),
		nodetest.WithFetcher(fetcher),
		nodetest.WithRecorder(recorder),
		nodetest.WithFalcoFetcher(versions),
		nodetest.WithEnforceRequirements(true))
	store.OnFalcoVersionsObserved(versions.Result)
	r := NewRulesfileReconciler(cl, store)
	useNode(t, r, store, []client.Object{artifactNode})
	aggregator := instancerulesfile.NewRulesfileAggregatorReconciler(cl, scheme, events.NewFakeRecorder(100), nil)
	_, err := aggregator.Reconcile(ctx, testutil.Request(parent.Name))
	require.NoError(t, err)
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(parent), parent))
	require.NotEmpty(t, parent.Status.ArtifactMetaSourcesHash)
	require.Equal(t, parent.Generation, parent.Status.ObservedGeneration)

	path := testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), parent.Name, parent.Spec.Priority,
		artifact.MediumConfigMap, artifact.KindRulesfile)
	var previousContent []byte
	if installed {
		_, err = r.Reconcile(ctx, testutil.Request(testRulesfileName))
		require.NoError(t, err)
		previousContent = []byte(oldContent)
		require.Equal(t, previousContent, fs.Files[path])
	}
	status, _ = r.node.StatusEntry(artifact.KindRulesfile, testRulesfileName)
	previousInstalled := status.DeepCopy().InstalledArtifacts

	// ConfigMap and Rulesfile informer events can arrive in either order. Change only the
	// ConfigMap, leaving the parent generation and the instance operator's metadata untouched.
	oldConfigMap := cm.DeepCopy()
	newContent := "- required_engine_version: 999.0.0\n" + testRulesData
	if compatible {
		newContent = "- required_engine_version: 0.56.0\n" + testRulesData
	}
	cm.Data[commonv1alpha1.ConfigMapRulesKey] = newContent
	require.NoError(t, cl.Update(ctx, cm))
	if instanceFirst {
		_, err = aggregator.Reconcile(ctx, testutil.Request(parent.Name))
		require.NoError(t, err)
		// Model the sidecar's independent informer cache still holding the old ConfigMap.
		fetcher.Delegate.K8sClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(oldConfigMap).Build()
	}
	_, err = r.Reconcile(ctx, testutil.Request(testRulesfileName))
	require.NoError(t, err)
	require.Equal(t, previousContent, fs.Files[path], "mismatching metadata must not authorize any write")
	status = entryOf(t, r.node)
	require.Equal(t, previousInstalled, status.InstalledArtifacts)
	wantConditions := []testutil.ConditionExpect{
		{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
		{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionUnknown, Reason: artifact.ReasonArtifactMetaNotReady},
		{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonProgramFailed},
	}
	if installed {
		wantConditions = append(wantConditions, testutil.ConditionExpect{
			Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
			Status: metav1.ConditionTrue, Reason: artifact.ReasonConfigMapArtifactProgrammed,
		})
	} else {
		wantConditions = append(wantConditions, testutil.ConditionExpect{
			Type:   commonv1alpha1.ConditionConfigMapArtifactProgrammed.String(),
			Status: metav1.ConditionFalse, Reason: artifact.ReasonArtifactMetaNotReady,
		})
	}
	testutil.RequireConditions(t, status.Conditions, wantConditions)

	// Once both controllers see matching inputs, resume without any spec/generation change.
	fetcher.Delegate.K8sClient = cl
	_, err = aggregator.Reconcile(ctx, testutil.Request(parent.Name))
	require.NoError(t, err)
	_, err = r.Reconcile(ctx, testutil.Request(testRulesfileName))
	require.NoError(t, err)
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(parent), parent))
	require.EqualValues(t, 1, parent.Generation)
	status = entryOf(t, r.node)
	if compatible {
		require.Equal(t, []byte(newContent), fs.Files[path])
		require.True(t, apimeta.IsStatusConditionTrue(status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
	} else {
		require.Equal(t, previousContent, fs.Files[path], "incompatible update must leave the installed rules untouched")
		require.Equal(t, previousInstalled, status.InstalledArtifacts)
		require.True(t, apimeta.IsStatusConditionFalse(status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String()))
		require.True(t, apimeta.IsStatusConditionFalse(status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
	}
}

func TestReconcile_ConfigMapSnapshot(t *testing.T) {
	var status artifactv1alpha1.NodeArtifactStatus
	for _, tt := range []struct {
		name       string
		enforce    bool
		metadata   string
		missingKey bool
		wantWrite  bool
	}{
		{name: "enforce stores the checked snapshot even if ConfigMap changes during OCI fetch", enforce: true, metadata: "current", wantWrite: true},
		{name: "enforce waits for matching metadata before installing any source", enforce: true, metadata: "stale"},
		{name: "enforce waits for the source hash", enforce: true, metadata: "no hash"},
		{name: "enforce waits for metadata even if the hash matches", enforce: true, metadata: "nil"},
		{name: "missing ConfigMap key prevents writes of every source", enforce: true, metadata: "current", missingKey: true},
		{name: "advise still installs without matching metadata", metadata: "stale", wantWrite: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			content := "- required_engine_version: 0.57.0\n" + testRulesData
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: testutil.TestNamespace},
				Data:       map[string]string{commonv1alpha1.ConfigMapRulesKey: content},
			}
			parent := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 1},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: cm.Name},
					InlineRules:  &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
					OCIArtifact:  &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "test/rules", Tag: "latest"}},
				},
			}
			sourceClient := fake.NewClientBuilder().WithScheme(testutil.Scheme(t)).WithObjects(cm).Build()
			sources, err := artifact.ResolveRulesfileSources(ctx, &artifact.Fetcher{K8sClient: sourceClient}, parent)
			require.NoError(t, err)
			parent.Status.ObservedGeneration = parent.Generation
			ociSpecHash, err := sources.OCISpecHash()
			require.NoError(t, err)
			parent.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{
				SpecHash:     ociSpecHash,
				Digest:       digest.FromString("pinned OCI manifest").String(),
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{{Name: "engine_version_semver", Version: "0.57.0"}},
			}
			if tt.metadata == "stale" {
				sources.ConfigMap.Content = []byte("old rules")
			}
			parent.Status.ArtifactMetaSourcesHash, err = sources.Hash()
			require.NoError(t, err)
			if tt.metadata == "no hash" {
				parent.Status.ArtifactMetaSourcesHash = ""
			}
			if tt.metadata == "nil" {
				parent.Status.ArtifactMeta = nil
			}
			if tt.missingKey {
				delete(cm.Data, commonv1alpha1.ConfigMapRulesKey)
			}
			artifactNode := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName)
			r, cl := newTestReconciler(t, parent, cm, artifactNode)
			fs := fsfake.NewMockFileSystem()
			versions := compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.57.0"})
			useNode(t, r.RulesfileReconciler, nodetest.NewTestNode(t, cl,
				nodetest.WithStore(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}),
				nodetest.WithFetcher(r.fetcher),
				nodetest.WithRecorder(r.recorder),
				nodetest.WithFalcoFetcher(versions),
				// Enforcement is the node's setting, so it goes on the node this test ends up with, not
				// on the one newTestReconciler built and useNode just replaced.
				nodetest.WithEnforceRequirements(tt.enforce)), []client.Object{artifactNode})
			r.node.OnFalcoVersionsObserved(versions.Result)
			fetcher := r.fetcher
			fetcher.OnFetchOCI = func() {
				// Fetching OCI can take time: a concurrent ConfigMap edit must not replace the
				// content whose requirements were checked earlier in this reconcile.
				cm.Data[commonv1alpha1.ConfigMapRulesKey] = "- required_engine_version: 999.0.0\n" + testRulesData
				require.NoError(t, cl.Update(ctx, cm))
			}
			_, err = r.Reconcile(ctx, testutil.Request(testRulesfileName))
			if tt.missingKey {
				require.ErrorContains(t, err, commonv1alpha1.ConfigMapRulesKey)
			} else {
				require.NoError(t, err)
			}
			status = entryOf(t, r.node)
			if tt.wantWrite {
				require.Equal(t, 1, fetcher.ConfigMapCalls, "install must consume the checked content without refetching")
				installed, err := r.node.ScanAll(ctx, artifact.KindRulesfile)
				require.NoError(t, err)
				require.Len(t, installed[parent.Name], 3)
				path := testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), parent.Name, parent.Spec.Priority,
					artifact.MediumConfigMap, artifact.KindRulesfile)
				require.Equal(t, []byte(content), fs.Files[path])
				require.Equal(t, 1, fetcher.OCICalls)
				require.Equal(t, parent.Status.ArtifactMeta.Digest, fetcher.OCIDigest, "floating tags must retain the resolved digest")
				require.True(t, apimeta.IsStatusConditionTrue(status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
			} else {
				require.Empty(t, fs.Files)
				require.Empty(t, status.InstalledArtifacts)
				require.Zero(t, fetcher.OCICalls)
				require.True(t, apimeta.IsStatusConditionFalse(status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
				if !tt.missingKey {
					for _, conditionType := range []commonv1alpha1.ConditionType{
						commonv1alpha1.ConditionOCIArtifactProgrammed,
						commonv1alpha1.ConditionInlineArtifactProgrammed,
						commonv1alpha1.ConditionConfigMapArtifactProgrammed,
					} {
						condition := apimeta.FindStatusCondition(status.Conditions, conditionType.String())
						require.NotNil(t, condition)
						require.Equal(t, metav1.ConditionFalse, condition.Status)
						require.Equal(t, artifact.ReasonArtifactMetaNotReady, condition.Reason)
					}
				}
			}
		})
	}
}

func TestReconcile_DeferredGenerationCannotReportProgrammed(t *testing.T) {
	var status artifactv1alpha1.NodeArtifactStatus
	for _, installed := range []bool{false, true} {
		t.Run(fmt.Sprintf("installed=%t", installed), func(t *testing.T) {
			parent := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 2},
				Status:     artifactv1alpha1.RulesfileStatus{ObservedGeneration: 1},
			}
			artifactNode := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName, func(n *artifactv1alpha1.ArtifactNode) {
				if installed {
					n.Status.Artifacts[0].Conditions = []metav1.Condition{
						common.NewOCIArtifactProgrammedCondition(metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed, "old rules installed", 1),
					}
				}
			})
			r, _ := newReconcilerEnforcing(t, true, parent, artifactNode)
			_, err := r.Reconcile(t.Context(), testutil.Request(testRulesfileName))
			require.NoError(t, err)
			status = entryOf(t, r.node)
			programmed := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionProgrammed.String())
			require.NotNil(t, programmed)
			require.Equal(t, metav1.ConditionUnknown, programmed.Status)
			require.Equal(t, "GenerationPending", programmed.Reason)
			require.Zero(t, r.fetcher.OCICalls)
		})
	}
}

func TestReconcile(t *testing.T) {
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
	tests := []struct {
		name                string
		objects             []client.Object
		req                 ctrl.Request
		pullErr             error
		enforceRequirements bool
		wantErr             bool
		wantResult          *ctrl.Result // nil means the zero-value ctrl.Result{} is expected
		wantRequeueAfterGE  time.Duration
		wantConditions      []testutil.ConditionExpect
	}{
		{
			name: "happy path with inline rules writes conditions to node object",
			objects: []client.Object{
				parentWithInline,
				testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName),
			},
			req: testutil.Request(testRulesfileName),
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
				testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName),
			},
			req:     testutil.Request(testRulesfileName),
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
				testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName),
			},
			req:                testutil.Request(testRulesfileName),
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
				testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName),
			},
			req:                 testutil.Request(testRulesfileName),
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
				testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName, withPreviousOCIInstallStatus()),
			},
			req:                 testutil.Request(testRulesfileName),
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
				testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName),
			},
			req:                 testutil.Request(testRulesfileName),
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
			for _, obj := range tt.objects {
				if rf, ok := obj.(*artifactv1alpha1.Rulesfile); ok {
					setCurrentRulesfileMetadata(t, rf, nil)
				}
			}
			r, _ := newReconcilerEnforcing(t, tt.enforceRequirements, tt.objects...)

			if tt.pullErr != nil {
				// The node does the fetching, and it shares this reconciler's fetcher; failing
				// the shared one is what makes the node's pull fail.
				r.fetcher.OCIErr = tt.pullErr
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
				testutil.RequireConditions(t, entryOf(t, r.node).Conditions, tt.wantConditions)
			}
		})
	}
}

func TestEnsureRulesfile(t *testing.T) {
	tests := []struct {
		name     string
		objects  []client.Object
		preRf    *artifactv1alpha1.Rulesfile
		rf       *artifactv1alpha1.Rulesfile
		writeErr error
		pullErr  error
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
		// checkInstalledOCISpecHash compares installed state with the actual OCI spec hash.
		checkInstalledOCISpecHash bool
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
			wantEvents: []string{"Normal ArtifactStored inline artifact stored successfully"},
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
			wantFiles: []string{testRulesData},
			wantEvents: []string{
				"Normal ReferenceResolved All references were resolved successfully", "Normal ArtifactStored configmap artifact stored successfully"},
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
				"Normal ReferenceResolved All references were resolved successfully",
				"Normal ArtifactStored inline artifact stored successfully",
				"Normal ArtifactStored configmap artifact stored successfully",
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
			wantEvents: []string{
				"Normal ReferenceResolved All references were resolved successfully",
				"Warning ConfigMapRulesStoreFailed Failed to store ConfigMap rules: mock write error",
			},
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
			wantEvents:     []string{"Normal ArtifactRemoved inline artifact removed successfully"},
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
			wantEvents:     []string{"Normal ArtifactRemoved configmap artifact removed successfully"},
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
			wantEvents:     []string{"Normal ArtifactRemoved oci artifact removed successfully"},
		},
		// SpecHash tests
		{
			name: "OCI: specHash written to InstalledArtifacts after install",
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
			checkInstalledOCISpecHash: true,
			wantOCIFetchCount:         new(1),
			wantEvents:                []string{"Normal ArtifactStored oci artifact stored successfully"},
		},
		{
			name: "OCI: skips fetch when specHash and resolved digest match and disk is intact",
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
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
			wantOCIFetchCount:         new(0), // must not hit the artifact server
			checkInstalledOCISpecHash: true,
			wantEvents:                []string{},
		},
		{
			name: "OCI: re-fetches when specHash changes",
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "v2"},
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
			},
			wantOCIFetchCount:         new(1),
			checkInstalledOCISpecHash: true,
			// StoreActionUnchanged because mock content is the same bytes; no store event
			wantEvents: []string{},
		},
		{
			name: "OCI: priority-only update moves the file without changing its resolved digest",
			preRf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					Priority: 50,
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					Priority: 20,
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionOCIArtifactProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonOCIArtifactProgrammed},
			},
			wantOCIFetchCount:         new(1),
			checkInstalledOCISpecHash: true,
			wantFiles:                 []string{"mock-oci-content"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			var mockFS *fsfake.MockFileSystem
			var tmpDir string

			if tt.useRealFS {
				tmpDir = t.TempDir()
				r.fetcher = &testutil.FakeFetcher{
					Delegate: &artifact.Fetcher{K8sClient: cl},
					OCIBytes: []byte("fake-rules-content"),
				}
				r.node = nodetest.NewTestNode(t, cl, nodetest.WithStore(&artifact.LocalStore{
					FS:   filesystem.NewOSFileSystem(),
					Dirs: artifact.ArtifactDirs{Rulesfile: tmpDir, Plugin: tmpDir, Config: tmpDir},
				}), nodetest.WithFetcher(r.fetcher),
					nodetest.WithRecorder(r.recorder),
					nodetest.WithFalcoFetcher(compatfake.NewMockVersionsFetcher(nil)))
			} else {
				mockFS = fsfake.NewMockFileSystem()
				if tt.writeErr != nil {
					mockFS.WriteErrFor = make(map[string]error)
					for _, medium := range []artifact.Medium{artifact.MediumOCI, artifact.MediumInline, artifact.MediumConfigMap} {
						path := testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), tt.rf.Name, tt.rf.Spec.Priority, medium, artifact.KindRulesfile)
						mockFS.WriteErrFor[artifact.StagingPath(path)] = tt.writeErr
					}
				}
				r.fetcher = &testutil.FakeFetcher{
					Delegate: &artifact.Fetcher{K8sClient: cl},
					OCIErr:   tt.pullErr,
				}
				r.node = nodetest.NewTestNodeOn(t, cl, mockFS, r.recorder, nodetest.WithFetcher(r.fetcher))
			}

			nodeObj := &artifactv1alpha1.NodeArtifactStatus{}
			if tt.preRf != nil {
				setCurrentRulesfileMetadata(t, tt.preRf, cl)
				preNode := &artifactv1alpha1.NodeArtifactStatus{}
				require.NoError(t, r.node.ApplyArtifact(t.Context(), tt.preRf, preNode), "preRf setup failed")
				r.node.PublishStatus(artifact.KindRulesfile, tt.preRf, preNode)
				testutil.DrainEvents(r.recorder.(*events.FakeRecorder).Events)
				*nodeObj = *preNode
			}

			setCurrentRulesfileMetadata(t, tt.rf, cl)
			tf := r.fetcher
			tf.OCICalls = 0 // reset counter before the main reconcile

			err := r.node.ApplyArtifact(t.Context(), tt.rf, nodeObj)
			// The installed files are derived when the reconcile publishes on its way out.
			r.node.PublishStatus(artifact.KindRulesfile, tt.rf, nodeObj)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// The apply reports its own compatibility assessment too, so this test asserts the conditions it
			// speaks for rather than the whole list.
			for _, exp := range tt.wantConditions {
				testutil.RequireCondition(t, nodeObj.Conditions, exp.Type, exp.Status, exp.Reason)
			}
			testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events, tt.wantEvents)

			if tt.wantOCIFetchCount != nil {
				assert.Equal(t, *tt.wantOCIFetchCount, tf.OCICalls, "unexpected FetchOCI call count")
			}
			if tt.checkInstalledOCISpecHash {
				ociEntry := artifact.FindInstalled(nodeObj.InstalledArtifacts, artifact.MediumOCI)
				require.NotNil(t, ociEntry, "expected OCI entry in InstalledArtifacts")
				assert.Equal(t, tt.rf.Status.ArtifactMeta.SpecHash, ociEntry.SpecHash, "OCI InstalledArtifact.SpecHash mismatch")
				assert.Equal(t, tt.rf.Spec.Priority, ociEntry.Priority)
				assert.Equal(t, testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), tt.rf.Name, tt.rf.Spec.Priority,
					artifact.MediumOCI, artifact.KindRulesfile), ociEntry.Path)
				assert.Equal(t, tt.rf.Status.ArtifactMeta.Digest, tf.OCIDigest, "fetch must use the resolved digest")
				if tt.preRf != nil && tt.preRf.Spec.Priority != tt.rf.Spec.Priority {
					oldPath := testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), tt.rf.Name, tt.preRf.Spec.Priority,
						artifact.MediumOCI, artifact.KindRulesfile)
					assert.NotContains(t, mockFS.Files, oldPath, "priority move must not leave a second active file")
					assert.Equal(t, tt.preRf.Status.ArtifactMeta.Digest, tt.rf.Status.ArtifactMeta.Digest)
					assert.Equal(t, testutil.SHA256Hex(mockFS.Files[ociEntry.Path]), ociEntry.ContentHash)
				}
			}

			if tt.wantFiles != nil {
				installed, err := r.node.ScanAll(t.Context(), artifact.KindRulesfile)
				require.NoError(t, err)
				require.Len(t, installed[tt.rf.Name], len(tt.wantFiles), "unexpected number of installed rulesfiles")
				gotContents := make([]string, 0, len(installed[tt.rf.Name]))
				for _, file := range installed[tt.rf.Name] {
					gotContents = append(gotContents, string(mockFS.Files[file.Path]))
				}
				assert.ElementsMatch(t, tt.wantFiles, gotContents)
			}

			if tt.wantDirEmpty {
				installed, err := r.node.ScanAll(t.Context(), artifact.KindRulesfile)
				require.NoError(t, err)
				assert.Empty(t, installed, "expected no installed rulesfiles after cleanup")
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
			nodeObj := &artifactv1alpha1.NodeArtifactStatus{}
			nodeObj.Conditions = []metav1.Condition{{
				Type:               commonv1alpha1.ConditionInlineArtifactProgrammed.String(),
				Status:             tt.initialStatus,
				Reason:             artifact.ReasonInlineArtifactProgrammed,
				Message:            artifact.MessageInlineArtifactProgrammed,
				LastTransitionTime: pinned,
			}}

			require.NoError(t, r.node.ApplyArtifact(t.Context(), rf, nodeObj))
			r.node.PublishStatus(artifact.KindRulesfile, rf, nodeObj)

			cond := apimeta.FindStatusCondition(nodeObj.Conditions, commonv1alpha1.ConditionInlineArtifactProgrammed.String())
			require.NotNil(t, cond)
			require.Equal(t, metav1.ConditionTrue, cond.Status)
			require.Equal(t, tt.wantPreserved, cond.LastTransitionTime.Equal(&pinned))
		})
	}
}

// TestEnsureRulesfile_OCI_SyncsStatusFromCacheEvenWhenStatusStartsEmpty covers the case where
// the node's record (recovered by the warm sync, or surviving a status patch dropped by an
// SSA conflict) already considers the OCI artifact installed and verified, but this specific
// status's InstalledArtifacts starts empty. The "already verified on disk, skip
// fetch" shortcut must still populate status from the cache before returning, not just set the
// condition True and leave installedArtifacts missing.
func TestEnsureRulesfile_OCI_SyncsStatusFromCacheEvenWhenStatusStartsEmpty(t *testing.T) {
	r, cl := newTestReconciler(t)
	mockFS := fsfake.NewMockFileSystem()
	r.node = nodetest.NewTestNodeOn(t, cl, mockFS, r.recorder, nodetest.WithFetcher(r.fetcher))

	content := []byte("- rule: test\n  condition: true\n")
	hash := testutil.SHA256Hex(content)
	path := testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), testRulesfileName, 50, artifact.MediumOCI, artifact.KindRulesfile)

	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: testRulesfileName}

	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.RulesfileSpec{
			Priority: 50,
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
			},
		},
	}
	setCurrentRulesfileMetadata(t, rf, nil)
	_, _, err := r.node.StoreRulesfile(t.Context(), rf.Name, rf.Spec.Priority, artifact.MediumOCI,
		artifact.FetchResult{Content: content, ContentHash: hash, Perm: testutil.MustPermFor(t, artifact.KindRulesfile)}, rf.Status.ArtifactMeta, false)
	require.NoError(t, err)
	r.node.UpdateInstalledSpecHash(key, artifact.MediumOCI, rf.Status.ArtifactMeta.SpecHash)
	nodeObj := &artifactv1alpha1.NodeArtifactStatus{} // InstalledArtifacts starts nil, unlike the cache.

	tf := r.fetcher
	require.NoError(t, r.node.ApplyArtifact(context.Background(), rf, nodeObj))
	r.node.PublishStatus(artifact.KindRulesfile, rf, nodeObj)

	assert.Zero(t, tf.OCICalls, "the cache already verified this content; no fetch should happen")
	entry := artifact.FindInstalled(nodeObj.InstalledArtifacts, artifact.MediumOCI)
	require.NotNil(t, entry, "status must be synced from the cache even on the skip-fetch path")
	assert.Equal(t, path, entry.Path)
	assert.Equal(t, hash, entry.ContentHash)
	assert.Equal(t, rf.Status.ArtifactMeta.SpecHash, entry.SpecHash)
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
					// The apply reads the ConfigMap after resolving it, so the fixture needs the
					// key as well as the object.
					Data: map[string]string{commonv1alpha1.ConfigMapRulesKey: testRulesData},
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
			name: "a registry auth secret is the instance operator's to resolve: none reported, even when missing",
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
			wantNoConditions: true,
		},
		{
			name: "ConfigMap and auth secret both exist sets ResolvedRefs true",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.TestNamespace},
					// The apply reads the ConfigMap after resolving it, so the fixture needs the
					// key as well as the object.
					Data: map[string]string{commonv1alpha1.ConfigMapRulesKey: testRulesData},
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
			name: "the ConfigMap is resolved and the registry auth secret, even missing, is not the node's",
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-rules-cm", Namespace: testutil.TestNamespace},
					// The apply reads the ConfigMap after resolving it, so the fixture needs the
					// key as well as the object.
					Data: map[string]string{commonv1alpha1.ConfigMapRulesKey: testRulesData},
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
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t, tt.objects...)

			nodeObj := &artifactv1alpha1.NodeArtifactStatus{}
			if len(tt.presetConditions) > 0 {
				nodeObj.Conditions = tt.presetConditions
			}

			err := r.node.ApplyArtifact(context.Background(), tt.rf, nodeObj)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantNoConditions {
				assert.Nil(t, apimeta.FindStatusCondition(nodeObj.Conditions, commonv1alpha1.ConditionResolvedRefs.String()),
					"nothing to resolve must leave no ResolvedRefs condition behind")
			}

			for _, exp := range tt.wantConditions {
				testutil.RequireCondition(t, nodeObj.Conditions, exp.Type, exp.Status, exp.Reason)
			}
		})
	}
}

func TestReconcile_ResyncsAllMediaFromCacheBeforePatching(t *testing.T) {
	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.RulesfileSpec{
			Priority: 50,
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules", Tag: "latest"},
			},
			// No InlineRules: this generation never configured it.
		},
	}
	nodeObj := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName, func(n *artifactv1alpha1.ArtifactNode) {
		// Stale status: as if read before a concurrent reconcile's removal of inline landed.
		n.Status.Artifacts[0].InstalledArtifacts = []artifactv1alpha1.InstalledArtifact{
			{Path: "/etc/falco/rules.d/50-03-test-rulesfile-inline.yaml", Medium: string(artifact.MediumInline)},
		}
	})

	r, _ := newTestReconciler(t, rf, nodeObj)
	// The cache already reflects inline having been removed (by the "newer" reconcile this test
	// doesn't simulate directly): nothing is seeded for it, unlike the stale status above.
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: testRulesfileName}
	r.node.SeedInstalled(key, nil)

	_, err := r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)

	got := entryOf(t, r.node)
	assert.Nil(t, artifact.FindInstalled(got.InstalledArtifacts, artifact.MediumInline),
		"the persisted status must be resynced from the cache, not left with a stale entry the cache no longer has")
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
	nodeObj := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName)

	setCurrentRulesfileMetadata(t, rf, nil)
	r, _ := newTestReconciler(t, rf, nodeObj)

	sharedManager := r.node
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: testutil.TestNamespace}}
	blockedBefore := sharedManager.RemovePluginConfig(context.Background(), plugin)
	require.NoError(t, blockedBefore, "nothing provides \"container\" yet, so removal (a no-op here) must not be blocked")

	_, _, err := sharedManager.AddPluginConfig(context.Background(), plugin)
	require.NoError(t, err)

	_, err = r.Reconcile(context.Background(), testutil.Request(testRulesfileName))
	require.NoError(t, err)

	err = sharedManager.RemovePluginConfig(context.Background(), plugin)
	require.Error(t, err, "Reconcile must have registered this rulesfile's dependency on \"container\"")
	blocked, ok := errors.AsType[*node.BlockedError](err)
	require.True(t, ok)
	wantKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: testRulesfileName}
	assert.Equal(t, wantKey, blocked.BlockedBy[0])
}

func TestReconcile_RulesUpdateKeepsInstalledDependenciesUntilReplacement(t *testing.T) {
	const updatedRevision = "v2"
	for _, tc := range []struct {
		name     string
		fetchErr error
	}{
		{name: "failed update keeps the installed dependency", fetchErr: errors.New("artifact server unavailable")},
		{name: "successful update releases the old dependency"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			rf := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 1},
				Spec: artifactv1alpha1.RulesfileSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{Repository: "example/rules", Tag: "v1"},
				}},
				Status: artifactv1alpha1.RulesfileStatus{
					ObservedGeneration: 1,
					ArtifactMeta: &commonv1alpha1.ArtifactMeta{
						Requirements: []commonv1alpha1.ArtifactMetaRequirement{{Name: "engine_version_semver", Version: "0.44.0"}},
						Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}},
					},
				},
			}
			artifactNode := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName)
			setCurrentRulesfileMetadata(t, rf, nil)
			r, cl := newReconcilerEnforcing(t, true, rf, artifactNode)
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: rf.Namespace}}
			_, _, err := r.node.AddPluginConfig(ctx, plugin)
			require.NoError(t, err)
			r.node.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
				"engine_version_semver": "0.44.1", "container": "1.0.0",
			}).Result)
			fetcher := r.fetcher
			fetcher.OCIBytes = []byte("- required_engine_version: 0.44.0\n" +
				"- required_plugin_versions:\n  - name: container\n    version: 1.0.0\n" + testRulesData)
			request := testutil.Request(testRulesfileName)
			_, err = r.Reconcile(ctx, request)
			require.NoError(t, err)
			key := artifact.RefOf(artifact.KindRulesfile, rf)
			oldFile := r.node.FindInstalled(key, artifact.MediumOCI)
			require.NotNil(t, oldFile, "setup must install the original rules through Reconcile")
			var blocked *node.BlockedError
			require.ErrorAs(t, r.node.RemovePluginConfig(ctx, plugin), &blocked)
			require.Contains(t, blocked.BlockedBy, key)

			// The new revision no longer needs container, but is not installed yet.
			require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(rf), rf))
			rf.Generation = 2
			rf.Spec.OCIArtifact.Image.Tag = updatedRevision
			rf.Status.ObservedGeneration = 2
			rf.Status.ArtifactMeta.Digest = digest.FromString("updated OCI manifest").String()
			rf.Status.ArtifactMeta.Dependencies = nil
			setCurrentRulesfileMetadata(t, rf, cl)
			require.NoError(t, cl.Update(ctx, rf))
			fetcher.OCIBytes = []byte("- required_engine_version: 0.44.0\n" + testRulesData)
			fetcher.OCIErr = tc.fetchErr
			_, reconcileErr := r.Reconcile(ctx, request)
			require.Equal(t, 2, fetcher.OCICalls, "both revisions must reach the fetch path")

			intact, err := r.node.Verify(ctx, oldFile)
			require.NoError(t, err)
			if tc.fetchErr != nil {
				require.ErrorIs(t, reconcileErr, tc.fetchErr)
				require.True(t, intact, "the failed update must leave the old rules on disk")
				require.ErrorAs(t, r.node.RemovePluginConfig(ctx, plugin), &blocked,
					"the plugin is still required by the rules left on disk")
				assert.Contains(t, blocked.BlockedBy, key)
			} else {
				require.NoError(t, reconcileErr)
				require.False(t, intact, "the successful update must replace the old rules")
				require.NoError(t, r.node.RemovePluginConfig(ctx, plugin),
					"the replaced rules must no longer block removal")
			}
		})
	}
}

func TestReconcile_PluginRemovedDuringRulesFetch(t *testing.T) {
	var status artifactv1alpha1.NodeArtifactStatus
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			ctx := t.Context()
			rf := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 1},
				Spec: artifactv1alpha1.RulesfileSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{Repository: "example/rules", Tag: "v1"},
				}},
				Status: artifactv1alpha1.RulesfileStatus{
					ObservedGeneration: 1,
					ArtifactMeta: &commonv1alpha1.ArtifactMeta{
						Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}},
					},
				},
			}
			artifactNode := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName)
			setCurrentRulesfileMetadata(t, rf, nil)
			r, _ := newReconcilerEnforcing(t, enforce, rf, artifactNode)
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: rf.Namespace}}
			_, _, err := r.node.AddPluginConfig(ctx, plugin)
			require.NoError(t, err)
			r.node.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
			fetcher := r.fetcher
			fetcher.OnFetchOCI = func() {
				// No rules have been installed yet, so deletion may legitimately win here.
				require.NoError(t, r.node.RemovePluginConfig(ctx, plugin))
			}
			request := testutil.Request(testRulesfileName)
			_, err = r.Reconcile(ctx, request)
			require.NoError(t, err)
			require.Equal(t, 1, fetcher.OCICalls)
			installed := r.node.FindInstalled(artifact.RefOf(artifact.KindRulesfile, rf), artifact.MediumOCI)
			if enforce {
				require.Nil(t, installed, "must recheck dependencies before writing fetched rules")
				status = entryOf(t, r.node)
				condition := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
				require.NotNil(t, condition)
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				assert.Contains(t, condition.Message, "container")
			} else {
				require.NotNil(t, installed, "advise mode must still allow installation")
			}
		})
	}
}

func TestReconcile_IncompatiblePluginVersion(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		for _, preInstalled := range []bool{false, true} {
			t.Run(fmt.Sprintf("enforce=%t installed=%t", enforce, preInstalled), func(t *testing.T) {
				var status artifactv1alpha1.NodeArtifactStatus
				ctx := t.Context()
				rf := &artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace},
					Spec: artifactv1alpha1.RulesfileSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "example/rules", Tag: "new"}},
					},
					Status: artifactv1alpha1.RulesfileStatus{ArtifactMeta: &commonv1alpha1.ArtifactMeta{
						Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}},
					}},
				}
				artifactNode := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName)
				setCurrentRulesfileMetadata(t, rf, nil)
				r, _ := newReconcilerEnforcing(t, enforce, rf, artifactNode)
				r.node.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "2.0.0"}).Result)
				var installedFile *artifact.File
				if preInstalled {
					result, err := r.fetcher.FetchInline(ctx, []byte(testRulesData))
					require.NoError(t, err)
					action, file, err := r.node.StoreRulesfile(ctx, rf.Name, 0, artifact.MediumOCI, result,
						rf.Status.ArtifactMeta, false)
					require.NoError(t, err)
					installedFile = file
					artifact.UpdateInstalledStatus(&status.InstalledArtifacts, action, artifact.MediumOCI, file)
					artifact.UpdateInstalledSpecHash(&status.InstalledArtifacts, artifact.MediumOCI, "old-spec")
					specHashKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: rf.Name}
					r.node.UpdateInstalledSpecHash(specHashKey, artifact.MediumOCI, "old-spec")
					r.node.PublishStatus(artifact.KindRulesfile, rf, &status)
				}
				oldInstalled := status.InstalledArtifacts
				request := testutil.Request(testRulesfileName)
				_, err := r.Reconcile(ctx, request)
				require.NoError(t, err)
				status = entryOf(t, r.node)
				condition := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
				require.NotNil(t, condition)
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				if enforce {
					assert.Zero(t, r.fetcher.OCICalls)
					assert.Equal(t, oldInstalled, status.InstalledArtifacts)
					if preInstalled {
						assert.Equal(t, artifact.ReasonDependenciesNotSatisfiedUpdateRejected, condition.Reason)
						intact, err := r.node.Verify(ctx, installedFile)
						require.NoError(t, err)
						assert.True(t, intact, "a rejected update must preserve installed rules")
					} else {
						assert.Equal(t, artifact.ReasonDependenciesNotSatisfied, condition.Reason)
					}
				} else {
					assert.Equal(t, 1, r.fetcher.OCICalls, "advise mode still permits installation")
					assert.Equal(t, artifact.ReasonDependenciesNotSatisfiedInstalledAnyway, condition.Reason)
				}
			})
		}
	}
}

func TestEnsureRulesfile_WaitsForExpectedOCIDigest(t *testing.T) {
	for _, alreadyInstalled := range []bool{false, true} {
		name := "first installation"
		if alreadyInstalled {
			name = "update preserves installed revision"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cache := artifactcache.NewCache(t.TempDir())
			require.NoError(t, cache.Load())
			goos, goarch, platform := "", "", ""
			oldDigest := digest.FromString("old OCI manifest").String()
			newDigest := digest.FromString("new OCI manifest").String()
			oldPath := artifactcache.BlobPath(cache.Dir(), string(artifact.KindRulesfile), "artifact:old", oldDigest, goos, goarch)
			newPath := artifactcache.BlobPath(cache.Dir(), string(artifact.KindRulesfile), "artifact:new", newDigest, goos, goarch)
			require.NoError(t, cache.Store(oldPath, []byte("old artifact bytes"), 0o755))
			require.NoError(t, cache.Set(string(artifact.KindRulesfile), "default", "artifact", platform, oldPath))

			srv := httptest.NewServer(artifactserver.New(cache).Handler())
			defer srv.Close()
			fs := fsfake.NewMockFileSystem()
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
				WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
			fetcher := &artifact.Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client()}
			recorder := events.NewFakeRecorder(20)
			// Only the node is exercised here.
			testNode := nodetest.NewTestNodeOn(t, cl, fs, recorder, nodetest.WithFetcher(fetcher))
			parent := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: "artifact", Namespace: "default", Generation: 1},
				Spec: artifactv1alpha1.RulesfileSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{Repository: "artifact", Tag: "old"},
				}},
				Status: artifactv1alpha1.RulesfileStatus{
					ObservedGeneration: 1,
					ArtifactMeta:       &commonv1alpha1.ArtifactMeta{Digest: oldDigest},
				},
			}
			setCurrentRulesfileMetadata(t, parent, nil)
			artifactNode := &artifactv1alpha1.NodeArtifactStatus{}
			if alreadyInstalled {
				require.NoError(t, testNode.ApplyArtifact(ctx, parent, artifactNode))
				testNode.PublishStatus(artifact.KindRulesfile, parent, artifactNode)
			}
			previous := artifactNode.DeepCopy().InstalledArtifacts

			// The parent metadata is published before the aggregator replaces the cache entry.
			parent.Generation = 2
			parent.Spec.OCIArtifact.Image.Tag = "new"
			parent.Status.ObservedGeneration = 2
			parent.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: newDigest}
			setCurrentRulesfileMetadata(t, parent, nil)

			err := testNode.ApplyArtifact(ctx, parent, artifactNode)
			testNode.PublishStatus(artifact.KindRulesfile, parent, artifactNode)
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
			require.NoError(t, cache.Set(string(artifact.KindRulesfile), "default", "artifact", platform, newPath))
			require.NoError(t, testNode.ApplyArtifact(ctx, parent, artifactNode))
			testNode.PublishStatus(artifact.KindRulesfile, parent, artifactNode)
			require.Len(t, artifactNode.InstalledArtifacts, 1)
			installed := artifactNode.InstalledArtifacts[0]
			require.Equal(t, parent.Status.ArtifactMeta.SpecHash, installed.SpecHash)
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

func TestReconcile_AdviseDoesNotInferUnverifiedDependencies(t *testing.T) {
	var status artifactv1alpha1.NodeArtifactStatus
	for _, medium := range []artifact.Medium{artifact.MediumInline, artifact.MediumConfigMap} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%t", medium, missing), func(t *testing.T) {
				ctx := t.Context()
				rf := &artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 1},
					Status: artifactv1alpha1.RulesfileStatus{ArtifactMeta: &commonv1alpha1.ArtifactMeta{
						Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}},
					}},
				}
				cm := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: rf.Namespace},
					Data: map[string]string{
						commonv1alpha1.ConfigMapRulesKey: "- required_plugin_versions:\n  - name: container\n    version: 1.0.0\n" + testRulesData,
					},
				}
				if medium == artifact.MediumInline {
					rf.Spec.InlineRules = &apiextensionsv1.JSON{Raw: []byte(
						`[{"required_plugin_versions":[{"name":"container","version":"1.0.0"}]},` + testInlineRulesJSON[1:])}
				} else {
					rf.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: cm.Name}
				}
				sourceClient := fake.NewClientBuilder().WithScheme(testutil.Scheme(t)).WithObjects(cm).Build()
				setCurrentRulesfileMetadata(t, rf, sourceClient)
				artifactNode := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName)
				r, cl := newTestReconciler(t, rf, cm, artifactNode)
				plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: rf.Namespace}}
				_, _, err := r.node.AddPluginConfig(ctx, plugin)
				require.NoError(t, err)
				r.node.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
				request := testutil.Request(testRulesfileName)
				_, err = r.Reconcile(ctx, request)
				require.NoError(t, err)
				key := artifact.RefOf(artifact.KindRulesfile, rf)
				oldFile := r.node.FindInstalled(key, medium)
				require.NotNil(t, oldFile)
				var blocked *node.BlockedError
				require.ErrorAs(t, r.node.RemovePluginConfig(ctx, plugin), &blocked)
				require.Contains(t, blocked.BlockedBy, key, "the initial installation has known metadata")

				// The source changes before the instance operator publishes matching metadata.
				require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(rf), rf))
				if medium == artifact.MediumInline {
					rf.Generation++
					rf.Spec.InlineRules.Raw = []byte(`[{"required_plugin_versions":[{"name":"container","version":"1.0.0"}]},` +
						`{"rule":"updated_rule","desc":"updated","condition":"always_true","output":"test","priority":"WARNING"}]`)
				} else {
					require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(cm), cm))
					cm.Data[commonv1alpha1.ConfigMapRulesKey] += "\n# updated source\n"
					require.NoError(t, cl.Update(ctx, cm))
				}
				if missing {
					rf.Status.ArtifactMeta = nil
				}
				require.NoError(t, cl.Update(ctx, rf))
				_, err = r.Reconcile(ctx, request)
				require.NoError(t, err, "advise mode still installs the changed local source")
				installed := r.node.FindInstalled(key, medium)
				require.NotNil(t, installed)
				require.NotEqual(t, oldFile.ContentHash, installed.ContentHash)
				intact, err := r.node.Verify(ctx, installed)
				require.NoError(t, err)
				require.True(t, intact)
				require.NoError(t, r.node.RemovePluginConfig(ctx, plugin),
					"unknown metadata cannot identify a dependency to block removal")
				status = entryOf(t, r.node)
				condition := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
				require.NotNil(t, condition)
				require.Equal(t, metav1.ConditionUnknown, condition.Status)
				require.Equal(t, artifact.ReasonArtifactMetaNotReady, condition.Reason)
				require.True(t, apimeta.IsStatusConditionTrue(status.Conditions, commonv1alpha1.ConditionProgrammed.String()))

				// Removing the source still removes the installed file.
				require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(rf), rf))
				rf.Generation++
				rf.Spec.InlineRules, rf.Spec.ConfigMapRef = nil, nil
				require.NoError(t, cl.Update(ctx, rf))
				_, err = r.Reconcile(ctx, request)
				require.NoError(t, err)
				require.Nil(t, r.node.FindInstalled(key, medium))
				intact, err = r.node.Verify(ctx, installed)
				require.NoError(t, err)
				require.False(t, intact)
				require.NoError(t, r.node.RemovePluginConfig(ctx, plugin))
			})
		}
	}
}

func TestReconcile_OCISpecReversionFetchesNewResolvedDigest(t *testing.T) {
	ctx := t.Context()
	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 1},
		Spec: artifactv1alpha1.RulesfileSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{
			Image: commonv1alpha1.ImageSpec{Repository: "example/rules", Tag: "latest"},
		}},
		Status: artifactv1alpha1.RulesfileStatus{ArtifactMeta: &commonv1alpha1.ArtifactMeta{
			Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}},
		}},
	}
	setCurrentRulesfileMetadata(t, rf, nil)
	originalSpecHash := rf.Status.ArtifactMeta.SpecHash
	artifactNode := testutil.NewReportingArtifactNode("Rulesfile", testRulesfileName)
	r, cl := newTestReconciler(t, rf, artifactNode)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: rf.Namespace}}
	_, _, err := r.node.AddPluginConfig(ctx, plugin)
	require.NoError(t, err)
	r.node.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
	fetcher := r.fetcher
	fetcher.OCIBytes = []byte("- required_plugin_versions:\n  - name: container\n    version: 1.0.0\n" + testRulesData)
	request := testutil.Request(testRulesfileName)
	_, err = r.Reconcile(ctx, request)
	require.NoError(t, err)
	key := artifact.RefOf(artifact.KindRulesfile, rf)
	oldFile := r.node.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, oldFile)

	// The intermediate spec is observed, but its content never replaces the installed file.
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(rf), rf))
	rf.Generation++
	rf.Spec.OCIArtifact.Image.Tag = "intermediate"
	rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("intermediate OCI manifest").String()}
	setCurrentRulesfileMetadata(t, rf, cl)
	require.NoError(t, cl.Update(ctx, rf))
	fetcher.OCIErr = errors.New("intermediate revision unavailable")
	_, err = r.Reconcile(ctx, request)
	require.ErrorIs(t, err, fetcher.OCIErr)
	intact, err := r.node.Verify(ctx, oldFile)
	require.NoError(t, err)
	require.True(t, intact)
	var blocked *node.BlockedError
	require.ErrorAs(t, r.node.RemovePluginConfig(ctx, plugin), &blocked)

	// Returning to the same floating-tag spec resolves a different manifest.
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(rf), rf))
	rf.Generation++
	rf.Spec.OCIArtifact.Image.Tag = "latest"
	rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("new latest OCI manifest").String()}
	setCurrentRulesfileMetadata(t, rf, cl)
	require.Equal(t, originalSpecHash, rf.Status.ArtifactMeta.SpecHash)
	require.NoError(t, cl.Update(ctx, rf))
	fetcher.OCIErr = nil
	fetcher.OCIBytes = []byte(testRulesData)
	_, err = r.Reconcile(ctx, request)
	require.NoError(t, err)
	require.Equal(t, 3, fetcher.OCICalls, "same spec hash cannot skip acquisition of a different resolved digest")
	require.Equal(t, rf.Status.ArtifactMeta.Digest, fetcher.OCIDigest)
	installed := r.node.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, installed)
	require.Equal(t, originalSpecHash, installed.SpecHash)
	require.Equal(t, testutil.SHA256Hex(fetcher.OCIBytes), installed.ContentHash)
	intact, err = r.node.Verify(ctx, installed)
	require.NoError(t, err)
	require.True(t, intact)
	require.NoError(t, r.node.RemovePluginConfig(ctx, plugin),
		"only the installed replacement releases the old dependency")
}

const assignedRulesfileUID = "rulesfile-uid"

func assignedRulesfile(uid string) *artifactv1alpha1.Rulesfile {
	return &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, UID: types.UID(uid), Generation: 2},
	}
}

func TestReconcile_RunsTheFlowAndPublishesWhenAssigned(t *testing.T) {
	// Enforcing: the flow waits for the instance operator to observe generation 2.
	r, cl := newReconcilerEnforcing(t, true, assignedRulesfile(assignedRulesfileUID),
		testutil.NewAssigningArtifactNode("Rulesfile", testRulesfileName, assignedRulesfileUID))

	result, err := r.Reconcile(t.Context(), testutil.Request(testRulesfileName))

	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter)
	got := testutil.RequirePublishedWhere(t, cl, "Rulesfile", testRulesfileName, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return apimeta.FindStatusCondition(e.Conditions, commonv1alpha1.ConditionProgrammed.String()) != nil
	})
	assert.Equal(t, assignedRulesfileUID, got.UID)
}

func TestReconcile_LeavesARulesfileAloneUnlessAssigned(t *testing.T) {
	r, _ := newTestReconciler(t, assignedRulesfile(assignedRulesfileUID), testutil.NewTestArtifactNode())

	result, err := r.Reconcile(t.Context(), testutil.Request(testRulesfileName))

	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter)
	_, held := r.node.StatusEntry(artifact.KindRulesfile, testRulesfileName)
	assert.False(t, held)
}

func TestReconcile_WaitsWhenTheSpecListsAnotherIncarnation(t *testing.T) {
	r, _ := newTestReconciler(t, assignedRulesfile("new-uid"), testutil.NewAssigningArtifactNode("Rulesfile", testRulesfileName, "old-uid"))

	result, err := r.Reconcile(t.Context(), testutil.Request(testRulesfileName))

	require.NoError(t, err)
	assert.Equal(t, shared.AssignmentRetryDelay, result.RequeueAfter)
	nodetest.AssertNothingDone(t, r.node, artifact.KindRulesfile, testRulesfileName, "never act for an incarnation the operator did not assign")
}

func TestReconcile_IgnoresAMissingOrDeletingRulesfile(t *testing.T) {
	r, _ := newTestReconciler(t, testutil.NewAssigningArtifactNode("Rulesfile", testRulesfileName, assignedRulesfileUID))
	_, err := r.Reconcile(t.Context(), testutil.Request("nonexistent"))
	require.NoError(t, err)

	now := metav1.Now()
	deleting := assignedRulesfile(assignedRulesfileUID)
	deleting.DeletionTimestamp = &now
	deleting.Finalizers = []string{"test/finalizer"}
	r, _ = newTestReconciler(t, deleting, testutil.NewAssigningArtifactNode("Rulesfile", testRulesfileName, assignedRulesfileUID))
	_, err = r.Reconcile(t.Context(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	nodetest.AssertNothingDone(t, r.node, artifact.KindRulesfile, testRulesfileName, "a deleting artifact is left alone")
}

func TestCleanup_IsIdempotentWhenNothingIsInstalled(t *testing.T) {
	r, _ := newTestReconciler(t)

	require.NoError(t, r.Cleanup(t.Context(), testRulesfileName))
	require.NoError(t, r.Cleanup(t.Context(), testRulesfileName))
}

// heldRulesfile returns a reconciler that has reconciled an assigned Rulesfile, so that the node holds an entry
// for it.
func heldRulesfile(t *testing.T) (*testReconciler, client.Client) {
	t.Helper()
	// Enforcing: the flow waits for the instance operator to observe generation 2.
	r, cl := newReconcilerEnforcing(t, true, assignedRulesfile(assignedRulesfileUID),
		testutil.NewAssigningArtifactNode("Rulesfile", testRulesfileName, assignedRulesfileUID))
	_, err := r.Reconcile(t.Context(), testutil.Request(testRulesfileName))
	require.NoError(t, err)
	_, held := r.node.StatusEntry(artifact.KindRulesfile, testRulesfileName)
	require.True(t, held)
	return r, cl
}

func TestReconcile_RemovesWhatItHoldsWhenTheRulesfileIsNoLongerAssigned(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, client.Client){
		"the ArtifactNode stops listing it": testutil.DropAssignments,
		"the Rulesfile is gone and the ArtifactNode stopped listing it": func(t *testing.T, cl client.Client) {
			testutil.DropAssignments(t, cl)
			require.NoError(t, cl.Delete(t.Context(), assignedRulesfile(assignedRulesfileUID)))
		},
		"there is no ArtifactNode": func(t *testing.T, cl client.Client) {
			require.NoError(t, cl.Delete(t.Context(), testutil.NewAssigningArtifactNode("Rulesfile", testRulesfileName, "")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, cl := heldRulesfile(t)
			prepare(t, cl)

			result, err := r.Reconcile(t.Context(), testutil.Request(testRulesfileName))

			require.NoError(t, err)
			assert.Equal(t, time.Duration(0), result.RequeueAfter)
			_, held := r.node.StatusEntry(artifact.KindRulesfile, testRulesfileName)
			assert.False(t, held, "an entry left behind would keep the parent's finalizer")
		})
	}
}

func TestReconcile_KeepsWhatItHoldsWhileTheArtifactNodeStillListsAGoneRulesfile(t *testing.T) {
	r, cl := heldRulesfile(t)
	require.NoError(t, cl.Delete(t.Context(), assignedRulesfile(assignedRulesfileUID)))

	_, err := r.Reconcile(t.Context(), testutil.Request(testRulesfileName))

	require.NoError(t, err)
	_, held := r.node.StatusEntry(artifact.KindRulesfile, testRulesfileName)
	assert.True(t, held, "the operator has yet to drop it from the ArtifactNode, which reconciles the Rulesfile again")
}

var errBoom = errors.New("boom")

func TestCleanup_ReportsWhatCannotBeRemoved(t *testing.T) {
	mockFS := fsfake.NewMockFileSystem()
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	n := nodetest.NewTestNodeOn(t, cl, mockFS, events.NewFakeRecorder(20), nodetest.WithFetcher(testutil.NewFakeFetcher(cl)))
	r := &RulesfileReconciler{node: n}
	_, _, err := n.StoreRulesfile(t.Context(), "rf", 50, artifact.MediumInline,
		artifact.FetchResult{Content: []byte("- rule: r\n"), ContentHash: "hash", Perm: 0o644}, nil, false)
	require.NoError(t, err)
	mockFS.RemoveErr = errBoom

	err = r.Cleanup(t.Context(), "rf")

	require.ErrorIs(t, err, errBoom)
}

// A ConfigMap event reconciles the Rulesfiles that reference it, and only those.
func TestFindRulesfilesForReferences(t *testing.T) {
	rulesfile := func(name, configMap, secret string) *artifactv1alpha1.Rulesfile {
		rf := &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: name}}
		if configMap != "" {
			rf.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: configMap}
		}
		if secret != "" {
			rf.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{Registry: &commonv1alpha1.RegistryConfig{
				Auth: &commonv1alpha1.RegistryAuth{SecretRef: &commonv1alpha1.SecretRef{Name: secret}},
			}}
		}
		return rf
	}
	request := func(name string) reconcile.Request {
		return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: testutil.TestNamespace, Name: name}}
	}
	objects := []client.Object{rulesfile("a", "shared", ""), rulesfile("b", "", "shared"), rulesfile("c", "other", "other"), rulesfile("d", "", "")}
	tests := []struct {
		name    string
		find    func(*RulesfileReconciler, context.Context, client.Object) []reconcile.Request
		object  client.Object
		listErr error
		want    []reconcile.Request
	}{
		{
			name: "a ConfigMap", find: (*RulesfileReconciler).findRulesfilesForConfigMap,
			object: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: "shared"}},
			want:   []reconcile.Request{request("a")},
		},
		{
			name: "the Rulesfiles cannot be listed", find: (*RulesfileReconciler).findRulesfilesForConfigMap,
			object:  &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: "shared"}},
			listErr: errBoom,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(objects...)
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
			r := &RulesfileReconciler{Client: builder.Build()}

			got := tt.find(r, t.Context(), tt.object)

			assert.ElementsMatch(t, tt.want, got)
		})
	}
}
