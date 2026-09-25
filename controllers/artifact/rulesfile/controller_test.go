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
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	instancerulesfile "github.com/falcosecurity/falco-operator/controllers/instance/artifact/rulesfile"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactserver"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

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

func TestVerifiedRulesfileMetadata(t *testing.T) {
	const staleHash = "stale"
	for _, tc := range []struct {
		name   string
		oci    bool
		mutate func(*artifactv1alpha1.Rulesfile)
		known  bool
	}{
		{name: "matching local sources", known: true},
		{name: "matching OCI revision", oci: true, known: true},
		{name: "missing metadata", mutate: func(rf *artifactv1alpha1.Rulesfile) { rf.Status.ArtifactMeta = nil }},
		{name: "stale sources", mutate: func(rf *artifactv1alpha1.Rulesfile) { rf.Status.ArtifactMetaSourcesHash = staleHash }},
		{name: "stale OCI spec", oci: true, mutate: func(rf *artifactv1alpha1.Rulesfile) { rf.Status.ArtifactMeta.SpecHash = staleHash }},
		{name: "missing OCI digest", oci: true, mutate: func(rf *artifactv1alpha1.Rulesfile) { rf.Status.ArtifactMeta.Digest = "" }},
		{name: "invalid OCI digest", oci: true, mutate: func(rf *artifactv1alpha1.Rulesfile) { rf.Status.ArtifactMeta.Digest = "sha256:invalid" }},
		{name: "priority change preserves metadata identity", oci: true, known: true, mutate: func(rf *artifactv1alpha1.Rulesfile) {
			rf.Generation++
			rf.Spec.Priority++
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rf := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Generation: 1},
				Spec: artifactv1alpha1.RulesfileSpec{
					InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
				},
			}
			if tc.oci {
				rf.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{Repository: "example/rules", Tag: "latest"},
				}
			}
			setCurrentRulesfileMetadata(t, rf, nil)
			if tc.mutate != nil {
				tc.mutate(rf)
			}
			sources, err := artifact.ResolveRulesfileSources(t.Context(), &artifact.Fetcher{}, rf)
			require.NoError(t, err)

			metadata, err := verifiedRulesfileMetadata(rf, sources)

			require.NoError(t, err)
			if tc.known {
				require.Same(t, rf.Status.ArtifactMeta, metadata)
			} else {
				require.Nil(t, metadata, "unverified metadata must not certify the absence of dependencies")
			}
		})
	}
}

// testFetcher implements artifact.ArtifactFetcher for controller unit tests.
// ConfigMap and Inline use the real artifact.Fetcher backed by the fake k8s client.
// FetchOCI returns in-memory bytes to avoid HTTP calls to a real artifact server.
type testFetcher struct {
	delegate           *artifact.Fetcher
	ociErr             error
	ociBytes           []byte
	ociCallCount       int // incremented on every FetchOCI call
	configMapCallCount int
	onFetchOCI         func()
	ociDigest          string
}

func newTestFetcher(cl client.Client) *testFetcher {
	return &testFetcher{delegate: &artifact.Fetcher{K8sClient: cl}}
}

func (f *testFetcher) FetchOCI(_ context.Context, _, _ string, _ artifact.Type, expectedDigest string) (artifact.FetchResult, error) {
	f.ociCallCount++
	f.ociDigest = expectedDigest
	if f.onFetchOCI != nil {
		f.onFetchOCI()
	}
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
	f.configMapCallCount++
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
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	mockFS := fsfake.NewMockFileSystem()
	store := nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	seedInstalledCacheFromObjs(store, objs)

	return &RulesfileReconciler{
		Client:    cl,
		Scheme:    s,
		recorder:  events.NewFakeRecorder(100),
		fetcher:   newTestFetcher(cl),
		store:     store,
		nodeName:  testutil.TestNodeName,
		namespace: testutil.TestNamespace,
	}, cl
}

func TestFindNodeObjects_UsesCanonicalNameWithoutLookup(t *testing.T) {
	parent := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "test--rules", Namespace: testutil.TestNamespace, UID: "owner"},
		Spec: artifactv1alpha1.RulesfileSpec{
			ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "source"},
			OCIArtifact: &commonv1alpha1.OCIArtifact{Registry: &commonv1alpha1.RegistryConfig{
				Auth: &commonv1alpha1.RegistryAuth{SecretRef: &commonv1alpha1.SecretRef{Name: "source"}}}},
		},
	}
	want := client.ObjectKey{
		Namespace: parent.Namespace,
		Name:      controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, parent.Name, testutil.TestNodeName),
	}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(parent).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				t.Fatal("event mapping must not fetch ArtifactNodes")
				return nil
			},
		}).
		WithIndex(&artifactv1alpha1.Rulesfile{}, index.ConfigMapOnRulesfile, index.RulesfileByConfigMapRef).
		WithIndex(&artifactv1alpha1.Rulesfile{}, index.SecretOnRulesfile, index.RulesfileBySecretRef).Build()
	r := &RulesfileReconciler{Client: cl, nodeName: testutil.TestNodeName}
	requests := r.findNodeObjectForRulesfile(t.Context(), parent)
	require.Len(t, requests, 1)
	assert.Equal(t, want, requests[0].NamespacedName)
	requests = r.findNodeObjectsForConfigMap(t.Context(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: parent.Namespace}})
	require.Len(t, requests, 1)
	assert.Equal(t, want, requests[0].NamespacedName)
	requests = r.findNodeObjectsForSecret(t.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: parent.Namespace}})
	require.Len(t, requests, 1)
	assert.Equal(t, want, requests[0].NamespacedName)
}

func TestFindAllNodeObjectsOnVersionChange_UsesFullNodeIdentity(t *testing.T) {
	nodeName := strings.Repeat("n", 64)
	parent := &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: testutil.TestNamespace}}
	wanted := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: controllerhelper.NodeObjectName("rulesfile", parent.Name, nodeName), Namespace: parent.Namespace,
			Labels:          controllerhelper.NodeObjectLabels("rulesfile", parent.Name, nodeName),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(parent, artifactv1alpha1.GroupVersion.WithKind("Rulesfile"))}},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: nodeName},
	}
	otherNode := wanted.DeepCopy()
	otherNode.Name = "other-node"
	otherNode.Spec.NodeName = "another-node"
	otherNamespace := wanted.DeepCopy()
	otherNamespace.Namespace = "another-namespace"
	r, _ := newTestReconciler(t, wanted, otherNode, otherNamespace)
	r.nodeName = nodeName
	requests := r.findAllNodeObjectsOnVersionChange(t.Context(), nil)
	require.Len(t, requests, 1)
	assert.Equal(t, client.ObjectKeyFromObject(wanted), requests[0].NamespacedName)
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

func TestNewRulesfileReconciler(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	store := nodeartifacts.NewManager(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
		compatfake.NewMockVersionsFetcher(nil))
	r := NewRulesfileReconciler(cl, s, events.NewFakeRecorder(10), "my-node", "my-namespace", false, &artifact.Fetcher{}, store)

	require.NotNil(t, r)
	assert.Equal(t, "my-node", r.nodeName)
	assert.Equal(t, "my-namespace", r.namespace)
	assert.NotNil(t, r.fetcher)
	assert.NotNil(t, r.store)
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
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent, cm, kubeNode, falco, pod).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}, &artifactv1alpha1.Rulesfile{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeOwnerKind, index.ArtifactNodeOwnerKindIndexer).Build()
	fs := fsfake.NewMockFileSystem()
	versions := compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.57.0"})
	store := nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, versions)
	store.OnFalcoVersionsObserved(versions.Result)
	fetcher := newTestFetcher(cl)
	r := NewRulesfileReconciler(cl, scheme, events.NewFakeRecorder(100), testutil.TestNodeName,
		testutil.TestNamespace, true, fetcher, store)
	aggregator := instancerulesfile.NewRulesfileAggregatorReconciler(cl, scheme, events.NewFakeRecorder(100), nil)
	_, err := aggregator.Reconcile(ctx, testutil.Request(parent.Name))
	require.NoError(t, err)
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(parent), parent))
	require.NotEmpty(t, parent.Status.ArtifactMetaSourcesHash)
	require.Equal(t, parent.Generation, parent.Status.ObservedGeneration)

	node := newTestNodeObj()
	// The first sidecar reconcile only adds its finalizer to the assignment created above.
	_, err = r.Reconcile(ctx, testutil.Request(node.Name))
	require.NoError(t, err)
	path := artifact.ArtifactPath(artifact.DefaultArtifactDirs(), parent.Name, parent.Spec.Priority, artifact.MediumConfigMap, artifact.TypeRulesfile)
	var previousContent []byte
	if installed {
		_, err = r.Reconcile(ctx, testutil.Request(node.Name))
		require.NoError(t, err)
		previousContent = []byte(oldContent)
		require.Equal(t, previousContent, fs.Files[path])
	}
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(node), node))
	previousInstalled := node.Status.DeepCopy().InstalledArtifacts

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
		fetcher.delegate.K8sClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(oldConfigMap).Build()
	}
	_, err = r.Reconcile(ctx, testutil.Request(node.Name))
	require.NoError(t, err)
	require.Equal(t, previousContent, fs.Files[path], "mismatching metadata must not authorize any write")
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(node), node))
	require.Equal(t, previousInstalled, node.Status.InstalledArtifacts)
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
	testutil.RequireConditions(t, node.Status.Conditions, wantConditions)

	// Once both controllers see matching inputs, resume without any spec/generation change.
	fetcher.delegate.K8sClient = cl
	_, err = aggregator.Reconcile(ctx, testutil.Request(parent.Name))
	require.NoError(t, err)
	_, err = r.Reconcile(ctx, testutil.Request(node.Name))
	require.NoError(t, err)
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(parent), parent))
	require.EqualValues(t, 1, parent.Generation)
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(node), node))
	if compatible {
		require.Equal(t, []byte(newContent), fs.Files[path])
		require.True(t, apimeta.IsStatusConditionTrue(node.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
	} else {
		require.Equal(t, previousContent, fs.Files[path], "incompatible update must leave the installed rules untouched")
		require.Equal(t, previousInstalled, node.Status.InstalledArtifacts)
		require.True(t, apimeta.IsStatusConditionFalse(node.Status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String()))
		require.True(t, apimeta.IsStatusConditionFalse(node.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
	}
}

func TestReconcile_ConfigMapSnapshot(t *testing.T) {
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
			node := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
				n.Finalizers = []string{rulesfileNodeFinalizer}
			})
			r, cl := newTestReconciler(t, parent, cm, node)
			r.enforceRequirements = tt.enforce
			fs := fsfake.NewMockFileSystem()
			versions := compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.57.0"})
			r.store = nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()},
				versions)
			r.store.OnFalcoVersionsObserved(versions.Result)
			fetcher := r.fetcher.(*testFetcher)
			fetcher.onFetchOCI = func() {
				// Fetching OCI can take time: a concurrent ConfigMap edit must not replace the
				// content whose requirements were checked earlier in this reconcile.
				cm.Data[commonv1alpha1.ConfigMapRulesKey] = "- required_engine_version: 999.0.0\n" + testRulesData
				require.NoError(t, cl.Update(ctx, cm))
			}
			_, err = r.Reconcile(ctx, testutil.Request(node.Name))
			if tt.missingKey {
				require.ErrorContains(t, err, commonv1alpha1.ConfigMapRulesKey)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(node), node))
			if tt.wantWrite {
				require.Equal(t, 1, fetcher.configMapCallCount, "install must consume the checked content without refetching")
				installed, err := r.store.ScanAll(ctx, artifact.TypeRulesfile)
				require.NoError(t, err)
				require.Len(t, installed[parent.Name], 3)
				path := artifact.ArtifactPath(artifact.DefaultArtifactDirs(), parent.Name, parent.Spec.Priority, artifact.MediumConfigMap, artifact.TypeRulesfile)
				require.Equal(t, []byte(content), fs.Files[path])
				require.Equal(t, 1, fetcher.ociCallCount)
				require.Equal(t, parent.Status.ArtifactMeta.Digest, fetcher.ociDigest, "floating tags must retain the resolved digest")
				require.True(t, apimeta.IsStatusConditionTrue(node.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
			} else {
				require.Empty(t, fs.Files)
				require.Empty(t, node.Status.InstalledArtifacts)
				require.Zero(t, fetcher.ociCallCount)
				require.True(t, apimeta.IsStatusConditionFalse(node.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
				if !tt.missingKey {
					for _, conditionType := range []commonv1alpha1.ConditionType{
						commonv1alpha1.ConditionOCIArtifactProgrammed,
						commonv1alpha1.ConditionInlineArtifactProgrammed,
						commonv1alpha1.ConditionConfigMapArtifactProgrammed,
					} {
						condition := apimeta.FindStatusCondition(node.Status.Conditions, conditionType.String())
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
	for _, installed := range []bool{false, true} {
		t.Run(fmt.Sprintf("installed=%t", installed), func(t *testing.T) {
			parent := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 2},
				Status:     artifactv1alpha1.RulesfileStatus{ObservedGeneration: 1},
			}
			node := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
				n.Finalizers = []string{rulesfileNodeFinalizer}
				if installed {
					n.Status.Conditions = []metav1.Condition{
						common.NewOCIArtifactProgrammedCondition(metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed, "old rules installed", 1),
					}
				}
			})
			r, cl := newTestReconciler(t, parent, node)
			r.enforceRequirements = true
			_, err := r.Reconcile(t.Context(), testutil.Request(node.Name))
			require.NoError(t, err)
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(node), node))
			programmed := apimeta.FindStatusCondition(node.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
			require.NotNil(t, programmed)
			require.Equal(t, metav1.ConditionUnknown, programmed.Status)
			require.Equal(t, "GenerationPending", programmed.Reason)
			require.Zero(t, r.fetcher.(*testFetcher).ociCallCount)
		})
	}
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
			for _, obj := range tt.objects {
				if rf, ok := obj.(*artifactv1alpha1.Rulesfile); ok {
					setCurrentRulesfileMetadata(t, rf, nil)
				}
			}
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

func TestReconcile_StaleSourceCleanupFailure(t *testing.T) {
	for _, tc := range []struct {
		medium        artifact.Medium
		conditionType commonv1alpha1.ConditionType
	}{
		{artifact.MediumOCI, commonv1alpha1.ConditionOCIArtifactProgrammed},
		{artifact.MediumInline, commonv1alpha1.ConditionInlineArtifactProgrammed},
		{artifact.MediumConfigMap, commonv1alpha1.ConditionConfigMapArtifactProgrammed},
	} {
		for _, missingCondition := range []bool{false, true} {
			for _, enforce := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/missing-condition=%t/enforce=%t", tc.medium, missingCondition, enforce), func(t *testing.T) {
					ctx := t.Context()
					cm := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: testutil.TestNamespace},
						Data:       map[string]string{commonv1alpha1.ConfigMapRulesKey: testRulesData},
					}
					rf := &artifactv1alpha1.Rulesfile{
						ObjectMeta: metav1.ObjectMeta{Name: testRulesfileName, Namespace: testutil.TestNamespace, Generation: 1},
						Spec:       artifactv1alpha1.RulesfileSpec{Priority: 50},
					}
					switch tc.medium {
					case artifact.MediumOCI:
						rf.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}}
					case artifact.MediumInline:
						rf.Spec.InlineRules = &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}
					case artifact.MediumConfigMap:
						rf.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: cm.Name}
					}
					node := newTestNodeObj(withOwnerRef())
					node.Finalizers = []string{rulesfileNodeFinalizer}
					r, cl := newTestReconciler(t, rf, cm, node)
					r.enforceRequirements = enforce
					fs := fsfake.NewMockFileSystem()
					versions := compatfake.NewMockVersionsFetcher(map[string]string{"engine_version_semver": "0.57.0"})
					r.store = nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, versions)
					r.store.OnFalcoVersionsObserved(versions.Result)
					setCurrentRulesfileMetadata(t, rf, cl)
					rf.Status.ArtifactMeta.Requirements = []commonv1alpha1.ArtifactMetaRequirement{{Name: "engine_version_semver", Version: "0.57.0"}}
					require.NoError(t, cl.Update(ctx, rf))
					key := nodeartifacts.KeyFromObj(nodeartifacts.KindRulesfile, rf)
					req := testutil.Request(node.Name)
					_, err := r.Reconcile(ctx, req)
					require.NoError(t, err)
					require.NoError(t, cl.Get(ctx, req.NamespacedName, node))
					require.True(t, apimeta.IsStatusConditionTrue(node.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
					previousInstalled := node.Status.DeepCopy().InstalledArtifacts
					require.Len(t, previousInstalled, 1)
					previousPath := previousInstalled[0].Path
					previousContent := append([]byte(nil), fs.Files[previousPath]...)
					if missingCondition {
						apimeta.RemoveStatusCondition(&node.Status.Conditions, tc.conditionType.String())
						require.NoError(t, cl.Status().Update(ctx, node))
					}

					// A source switch refreshes refs/dependencies, but cleanup must still gate Programmed.
					require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(rf), rf))
					rf.Generation++
					rf.Spec.OCIArtifact = nil
					rf.Spec.InlineRules = &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}
					rf.Spec.ConfigMapRef = nil
					nextMedium, nextContent := artifact.MediumInline, testInlineRulesYAML
					if tc.medium == artifact.MediumInline {
						rf.Spec.InlineRules = nil
						rf.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: cm.Name}
						nextMedium, nextContent = artifact.MediumConfigMap, testRulesData
					}
					setCurrentRulesfileMetadata(t, rf, cl)
					require.NoError(t, cl.Update(ctx, rf))
					nextPath := artifact.ArtifactPath(artifact.DefaultArtifactDirs(), rf.Name, rf.Spec.Priority, nextMedium, artifact.TypeRulesfile)
					removeErr := fmt.Errorf("injected stale rulesfile removal failure")
					fs.RemoveErr = removeErr
					for range 2 {
						_, err = r.Reconcile(ctx, req)
						require.ErrorIs(t, err, removeErr)
						require.NoError(t, cl.Get(ctx, req.NamespacedName, node))
						assert.True(t, apimeta.IsStatusConditionFalse(node.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()),
							"%+v", node.Status.Conditions)
						condition := apimeta.FindStatusCondition(node.Status.Conditions, tc.conditionType.String())
						require.NotNil(t, condition)
						assert.Equal(t, metav1.ConditionFalse, condition.Status)
						assert.Equal(t, artifact.ReasonArtifactRemoveFailed, condition.Reason)
						assert.Equal(t, rf.Generation, condition.ObservedGeneration)
						assert.Contains(t, condition.Message, removeErr.Error())
						assert.Equal(t, previousContent, fs.Files[previousPath])
						assert.NotContains(t, fs.Files, nextPath)
						assert.Equal(t, previousInstalled, node.Status.InstalledArtifacts)
						assert.Equal(t, previousInstalled, r.store.GetInstalled(key))
					}

					fs.RemoveErr = nil
					_, err = r.Reconcile(ctx, req)
					require.NoError(t, err)
					require.NoError(t, cl.Get(ctx, req.NamespacedName, node))
					assert.Nil(t, apimeta.FindStatusCondition(node.Status.Conditions, tc.conditionType.String()))
					require.True(t, apimeta.IsStatusConditionTrue(node.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()))
					assert.NotContains(t, fs.Files, previousPath)
					assert.Equal(t, []byte(nextContent), fs.Files[nextPath])
					require.Len(t, node.Status.InstalledArtifacts, 1)
					assert.Equal(t, nextPath, node.Status.InstalledArtifacts[0].Path)
					assert.Equal(t, node.Status.InstalledArtifacts, r.store.GetInstalled(key))

					stableStatus := node.Status.DeepCopy()
					writes, removes := len(fs.WriteCalls), len(fs.RemoveCalls)
					for _, staleCondition := range []bool{false, true} {
						if staleCondition {
							// A stale status condition must also clear when nothing remains installed.
							apimeta.SetStatusCondition(&node.Status.Conditions, common.NewCondition(tc.conditionType,
								metav1.ConditionFalse, artifact.ReasonArtifactRemoveFailed, removeErr.Error(), rf.Generation))
							require.NoError(t, cl.Status().Update(ctx, node))
						}
						_, err = r.Reconcile(ctx, req)
						require.NoError(t, err)
						require.NoError(t, cl.Get(ctx, req.NamespacedName, node))
						assert.Equal(t, *stableStatus, node.Status)
						assert.Len(t, fs.WriteCalls, writes)
						assert.Len(t, fs.RemoveCalls, removes)
					}
				})
			}
		}
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
			wantEvents:                []string{"Normal OCIArtifactStored OCI artifact stored successfully"},
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
				r.fetcher = &testFetcher{
					delegate: &artifact.Fetcher{K8sClient: cl},
					ociBytes: []byte("fake-rules-content"),
				}
				r.store = nodeartifacts.NewManager(&artifact.LocalStore{
					FS:   filesystem.NewOSFileSystem(),
					Dirs: artifact.ArtifactDirs{Rulesfile: tmpDir, Plugin: tmpDir, Config: tmpDir},
				}, compatfake.NewMockVersionsFetcher(nil))
			} else {
				mockFS = fsfake.NewMockFileSystem()
				if tt.writeErr != nil {
					mockFS.WriteErrFor = make(map[string]error)
					for _, medium := range []artifact.Medium{artifact.MediumOCI, artifact.MediumInline, artifact.MediumConfigMap} {
						path := artifact.ArtifactPath(artifact.DefaultArtifactDirs(), tt.rf.Name, tt.rf.Spec.Priority, medium, artifact.TypeRulesfile)
						mockFS.WriteErrFor[filepath.Join(filepath.Dir(path), ".tmp", filepath.Base(path)+".tmp")] = tt.writeErr
					}
				}
				r.fetcher = &testFetcher{
					delegate: &artifact.Fetcher{K8sClient: cl},
					ociErr:   tt.pullErr,
				}
				r.store = nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
			}

			nodeObj := newTestNodeObj()
			if tt.preRf != nil {
				setCurrentRulesfileMetadata(t, tt.preRf, cl)
				preNode := newTestNodeObj()
				sources, err := r.resolveRulesfileSources(t.Context(), tt.preRf, preNode)
				require.NoError(t, err)
				require.NoError(t, r.ensureRulesfile(t.Context(), tt.preRf, preNode, sources, tt.preRf.Status.ArtifactMeta), "preRf setup failed")
				testutil.DrainEvents(r.recorder.(*events.FakeRecorder).Events)
				nodeObj.Status = preNode.Status
			}

			setCurrentRulesfileMetadata(t, tt.rf, cl)
			tf := r.fetcher.(*testFetcher)
			tf.ociCallCount = 0 // reset counter before the main reconcile

			sources, err := r.resolveRulesfileSources(t.Context(), tt.rf, nodeObj)
			if err == nil {
				err = r.ensureRulesfile(t.Context(), tt.rf, nodeObj, sources, tt.rf.Status.ArtifactMeta)
			}

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
			if tt.checkInstalledOCISpecHash {
				ociEntry := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI)
				require.NotNil(t, ociEntry, "expected OCI entry in InstalledArtifacts")
				assert.Equal(t, tt.rf.Status.ArtifactMeta.SpecHash, ociEntry.SpecHash, "OCI InstalledArtifact.SpecHash mismatch")
				assert.Equal(t, tt.rf.Spec.Priority, ociEntry.Priority)
				assert.Equal(t, artifact.ArtifactPath(artifact.DefaultArtifactDirs(), tt.rf.Name, tt.rf.Spec.Priority,
					artifact.MediumOCI, artifact.TypeRulesfile), ociEntry.Path)
				assert.Equal(t, tt.rf.Status.ArtifactMeta.Digest, tf.ociDigest, "fetch must use the resolved digest")
				if tt.preRf != nil && tt.preRf.Spec.Priority != tt.rf.Spec.Priority {
					oldPath := artifact.ArtifactPath(artifact.DefaultArtifactDirs(), tt.rf.Name, tt.preRf.Spec.Priority,
						artifact.MediumOCI, artifact.TypeRulesfile)
					assert.NotContains(t, mockFS.Files, oldPath, "priority move must not leave a second active file")
					assert.Equal(t, tt.preRf.Status.ArtifactMeta.Digest, tt.rf.Status.ArtifactMeta.Digest)
					assert.Equal(t, sha256hexForTest(mockFS.Files[ociEntry.Path]), ociEntry.ContentHash)
				}
			}

			if tt.wantFiles != nil {
				installed, err := r.store.ScanAll(t.Context(), artifact.TypeRulesfile)
				require.NoError(t, err)
				require.Len(t, installed[tt.rf.Name], len(tt.wantFiles), "unexpected number of installed rulesfiles")
				gotContents := make([]string, 0, len(installed[tt.rf.Name]))
				for _, file := range installed[tt.rf.Name] {
					gotContents = append(gotContents, string(mockFS.Files[file.Path]))
				}
				assert.ElementsMatch(t, tt.wantFiles, gotContents)
			}

			if tt.wantDirEmpty {
				installed, err := r.store.ScanAll(t.Context(), artifact.TypeRulesfile)
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
			nodeObj := newTestNodeObj()
			nodeObj.Status.Conditions = []metav1.Condition{{
				Type:               commonv1alpha1.ConditionInlineArtifactProgrammed.String(),
				Status:             tt.initialStatus,
				Reason:             artifact.ReasonInlineArtifactProgrammed,
				Message:            artifact.MessageInlineArtifactProgrammed,
				LastTransitionTime: pinned,
			}}

			sources, err := r.resolveRulesfileSources(t.Context(), rf, nodeObj)
			require.NoError(t, err)
			require.NoError(t, r.ensureRulesfile(t.Context(), rf, nodeObj, sources, &commonv1alpha1.ArtifactMeta{}))

			cond := apimeta.FindStatusCondition(nodeObj.Status.Conditions, commonv1alpha1.ConditionInlineArtifactProgrammed.String())
			require.NotNil(t, cond)
			require.Equal(t, metav1.ConditionTrue, cond.Status)
			require.Equal(t, tt.wantPreserved, cond.LastTransitionTime.Equal(&pinned))
		})
	}
}

// TestEnsureRulesfile_OCI_SyncsStatusFromCacheEvenWhenStatusStartsEmpty covers the case where
// the manager's cache (restored by WarmSync, or surviving a status patch dropped by an
// SSA conflict) already considers the OCI artifact installed and verified, but this specific
// ArtifactNode's own Status.InstalledArtifacts starts empty. The "already verified on disk, skip
// fetch" shortcut must still populate status from the cache before returning, not just set the
// condition True and leave installedArtifacts missing.
func TestEnsureRulesfile_OCI_SyncsStatusFromCacheEvenWhenStatusStartsEmpty(t *testing.T) {
	r, _ := newTestReconciler(t)
	mockFS := fsfake.NewMockFileSystem()
	r.store = nodeartifacts.NewManager(&artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))

	content := []byte("- rule: test\n  condition: true\n")
	hash := sha256hexForTest(content)
	path := artifact.ArtifactPath(artifact.DefaultArtifactDirs(), testRulesfileName, 50, artifact.MediumOCI, artifact.TypeRulesfile)

	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: testutil.TestNamespace, Name: testRulesfileName}

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
	_, _, err := r.store.StoreRulesfile(t.Context(), rf.Namespace, rf.Name, rf.Spec.Priority, artifact.MediumOCI,
		artifact.FetchResult{Content: content, ContentHash: hash, Perm: artifact.PermFor(artifact.TypeRulesfile)}, rf.Status.ArtifactMeta, false)
	require.NoError(t, err)
	r.store.UpdateInstalledSpecHash(key, artifact.MediumOCI, rf.Status.ArtifactMeta.SpecHash)
	nodeObj := newTestNodeObj() // Status.InstalledArtifacts starts nil, unlike the cache.

	tf := r.fetcher.(*testFetcher)
	require.NoError(t, r.ensureOCIRulesfile(context.Background(), rf, nodeObj, rf.Status.ArtifactMeta))

	assert.Zero(t, tf.ociCallCount, "the cache already verified this content; no fetch should happen")
	entry := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI)
	require.NotNil(t, entry, "status must be synced from the cache even on the skip-fetch path")
	assert.Equal(t, path, entry.Path)
	assert.Equal(t, hash, entry.ContentHash)
	assert.Equal(t, rf.Status.ArtifactMeta.SpecHash, entry.SpecHash)
}

func sha256hexForTest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
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
		store: nodeartifacts.NewManager(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
			compatfake.NewMockVersionsFetcher(nil)),
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
		store: nodeartifacts.NewManager(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
			compatfake.NewMockVersionsFetcher(nil)),
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
				r.store.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.falcoCaps).Result)
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
			name:      "incompatible primary cannot be bypassed by an alternative",
			falcaCaps: map[string]string{"container": "0.3.0", "k8smeta": "0.1.0"},
			dep: commonv1alpha1.ArtifactMetaDependency{
				Name: "container", Version: "0.4.0",
				Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "k8smeta", Version: "0.1.0"}},
			},
			wantFailMsg: true,
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
				r.store.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.falcaCaps).Result)
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
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionUnknown, Reason: artifact.ReasonArtifactMetaNotReady},
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
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionUnknown, Reason: artifact.ReasonArtifactMetaNotReady},
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
				r.store.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.falcoCaps).Result)
			}

			tt.rf.Status.ArtifactMeta = tt.artifactMeta
			nodeObj := newTestNodeObj()
			if len(tt.presetConditions) > 0 {
				nodeObj.Status.Conditions = tt.presetConditions
			}
			if tt.preInstalled {
				installed := []artifactv1alpha1.InstalledArtifact{
					{Path: "/etc/falco/rules.d/test.yaml", Medium: string(artifact.MediumOCI)},
				}
				nodeObj.Status.InstalledArtifacts = installed
				// alreadyInstalled is read from the manager's cache, not status; seed it the way
				// WarmSync would from a real restart.
				r.store.SeedInstalled(nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: tt.rf.Namespace, Name: tt.rf.Name}, installed)
			}

			skip, err := r.enforceRulesfileCompatibility(t.Context(), tt.rf, nodeObj, tt.artifactMeta)

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

// TestReconcile_ResyncsAllMediaFromCacheBeforePatching covers an overlapping-reconcile race:
// two reconciles for different spec generations of the same Rulesfile race to patch status via
// SSA ForceOwnership. One reconcile (working off an older spec generation that still had an
// inline source) can finish its patch after a newer reconcile has already removed that source,
// resurrecting a stale InstalledArtifacts entry the newer reconcile had already cleared from the
// cache.
//
// This test doesn't simulate the race directly; it simulates its end state: an ArtifactNode whose
// persisted status still has a stale "inline" entry (as if an in-flight reconcile's Get read it
// before it was removed), while the cache — the actual source of truth for what's installed —
// already has none. A single Reconcile call must patch status back into agreement with the cache,
// not merely leave a stale entry alone because this reconcile's own ensureX calls never touched it
// (the current spec has no inline source at all, so cleanupStaleMedium's own cache-based check
// finds nothing to remove and would otherwise return without touching status).
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
	nodeObj := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{rulesfileNodeFinalizer}
		// Stale status: as if read before a concurrent reconcile's removal of inline landed.
		n.Status.InstalledArtifacts = []artifactv1alpha1.InstalledArtifact{
			{Path: "/etc/falco/rules.d/50-03-test-rulesfile-inline.yaml", Medium: string(artifact.MediumInline)},
		}
	})

	r, cl := newTestReconciler(t, rf, nodeObj)
	// The cache already reflects inline having been removed (by the "newer" reconcile this test
	// doesn't simulate directly) — nothing seeded for it, unlike the stale status above.
	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: testutil.TestNamespace, Name: testRulesfileName}
	r.store.SeedInstalled(key, nil)

	_, err := r.Reconcile(context.Background(), testutil.Request(testNodeObjectName()))
	require.NoError(t, err)

	got := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: testNodeObjectName(), Namespace: testutil.TestNamespace}, got))
	assert.Nil(t, artifact.FindInstalled(got.Status.InstalledArtifacts, artifact.MediumInline),
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
	nodeObj := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{rulesfileNodeFinalizer}
	})

	setCurrentRulesfileMetadata(t, rf, nil)
	r, _ := newTestReconciler(t, rf, nodeObj)

	sharedManager := r.store
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: testutil.TestNamespace}}
	blockedBefore := sharedManager.RemovePluginConfig(context.Background(), &artifact.Fetcher{}, plugin)
	require.NoError(t, blockedBefore, "nothing provides \"container\" yet, so removal (a no-op here) must not be blocked")

	_, _, err := sharedManager.AddPluginConfig(context.Background(), plugin, &artifact.Fetcher{})
	require.NoError(t, err)

	_, err = r.Reconcile(context.Background(), testutil.Request(testNodeObjectName()))
	require.NoError(t, err)

	err = sharedManager.RemovePluginConfig(context.Background(), &artifact.Fetcher{}, plugin)
	require.Error(t, err, "Reconcile must have registered this rulesfile's dependency on \"container\"")
	blocked, ok := errors.AsType[*nodeartifacts.BlockedError](err)
	require.True(t, ok)
	wantKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: testutil.TestNamespace, Name: testRulesfileName}
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
			node := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
				n.Finalizers = []string{rulesfileNodeFinalizer}
			})
			setCurrentRulesfileMetadata(t, rf, nil)
			r, cl := newTestReconciler(t, rf, node)
			r.enforceRequirements = true
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: rf.Namespace}}
			_, _, err := r.store.AddPluginConfig(ctx, plugin, r.fetcher)
			require.NoError(t, err)
			r.store.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(map[string]string{
				"engine_version_semver": "0.44.1", "container": "1.0.0",
			}).Result)
			fetcher := r.fetcher.(*testFetcher)
			fetcher.ociBytes = []byte("- required_engine_version: 0.44.0\n" +
				"- required_plugin_versions:\n  - name: container\n    version: 1.0.0\n" + testRulesData)
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(node)}
			_, err = r.Reconcile(ctx, request)
			require.NoError(t, err)
			key := nodeartifacts.KeyFromObj(nodeartifacts.KindRulesfile, rf)
			oldFile := r.store.FindInstalled(key, artifact.MediumOCI)
			require.NotNil(t, oldFile, "setup must install the original rules through Reconcile")
			var blocked *nodeartifacts.BlockedError
			require.ErrorAs(t, r.store.RemovePluginConfig(ctx, r.fetcher, plugin), &blocked)
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
			fetcher.ociBytes = []byte("- required_engine_version: 0.44.0\n" + testRulesData)
			fetcher.ociErr = tc.fetchErr
			_, reconcileErr := r.Reconcile(ctx, request)
			require.Equal(t, 2, fetcher.ociCallCount, "both revisions must reach the fetch path")

			intact, err := r.store.Verify(ctx, oldFile)
			require.NoError(t, err)
			if tc.fetchErr != nil {
				require.ErrorIs(t, reconcileErr, tc.fetchErr)
				require.True(t, intact, "the failed update must leave the old rules on disk")
				require.ErrorAs(t, r.store.RemovePluginConfig(ctx, r.fetcher, plugin), &blocked,
					"the plugin is still required by the rules left on disk")
				assert.Contains(t, blocked.BlockedBy, key)
			} else {
				require.NoError(t, reconcileErr)
				require.False(t, intact, "the successful update must replace the old rules")
				require.NoError(t, r.store.RemovePluginConfig(ctx, r.fetcher, plugin),
					"the replaced rules must no longer block removal")
			}
		})
	}
}

func TestReconcile_PluginRemovedDuringRulesFetch(t *testing.T) {
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
			node := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
				n.Finalizers = []string{rulesfileNodeFinalizer}
			})
			setCurrentRulesfileMetadata(t, rf, nil)
			r, cl := newTestReconciler(t, rf, node)
			r.enforceRequirements = enforce
			plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: rf.Namespace}}
			_, _, err := r.store.AddPluginConfig(ctx, plugin, r.fetcher)
			require.NoError(t, err)
			r.store.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
			fetcher := r.fetcher.(*testFetcher)
			fetcher.onFetchOCI = func() {
				// No rules have been installed yet, so deletion may legitimately win here.
				require.NoError(t, r.store.RemovePluginConfig(ctx, r.fetcher, plugin))
			}
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(node)}
			_, err = r.Reconcile(ctx, request)
			require.NoError(t, err)
			require.Equal(t, 1, fetcher.ociCallCount)
			installed := r.store.FindInstalled(nodeartifacts.KeyFromObj(nodeartifacts.KindRulesfile, rf), artifact.MediumOCI)
			if enforce {
				require.Nil(t, installed, "must recheck dependencies before writing fetched rules")
				require.NoError(t, cl.Get(ctx, request.NamespacedName, node))
				condition := apimeta.FindStatusCondition(node.Status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
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
				node := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{rulesfileNodeFinalizer}
				})
				setCurrentRulesfileMetadata(t, rf, nil)
				r, cl := newTestReconciler(t, rf, node)
				r.enforceRequirements = enforce
				r.store.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "2.0.0"}).Result)
				var installedFile *artifact.File
				if preInstalled {
					result, err := r.fetcher.FetchInline(ctx, []byte(testRulesData))
					require.NoError(t, err)
					action, file, err := r.store.StoreRulesfile(ctx, rf.Namespace, rf.Name, 0, artifact.MediumOCI, result,
						rf.Status.ArtifactMeta, false)
					require.NoError(t, err)
					installedFile = file
					artifact.UpdateInstalledStatus(&node.Status.InstalledArtifacts, action, artifact.MediumOCI, file)
					artifact.UpdateInstalledSpecHash(&node.Status.InstalledArtifacts, artifact.MediumOCI, "old-spec")
					specHashKey := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: rf.Namespace, Name: rf.Name}
					r.store.UpdateInstalledSpecHash(specHashKey, artifact.MediumOCI, "old-spec")
					require.NoError(t, cl.Status().Update(ctx, node))
				}
				oldInstalled := node.Status.InstalledArtifacts
				request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(node)}
				_, err := r.Reconcile(ctx, request)
				require.NoError(t, err)
				require.NoError(t, cl.Get(ctx, request.NamespacedName, node))
				condition := apimeta.FindStatusCondition(node.Status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
				require.NotNil(t, condition)
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				if enforce {
					assert.Zero(t, r.fetcher.(*testFetcher).ociCallCount)
					assert.Equal(t, oldInstalled, node.Status.InstalledArtifacts)
					if preInstalled {
						assert.Equal(t, artifact.ReasonDependenciesNotSatisfiedUpdateRejected, condition.Reason)
						intact, err := r.store.Verify(ctx, installedFile)
						require.NoError(t, err)
						assert.True(t, intact, "a rejected update must preserve installed rules")
					} else {
						assert.Equal(t, artifact.ReasonDependenciesNotSatisfied, condition.Reason)
					}
				} else {
					assert.Equal(t, 1, r.fetcher.(*testFetcher).ociCallCount, "advise mode still permits installation")
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
			oldPath := artifactcache.BlobPath(cache.Dir(), "rulesfile", "artifact:old", oldDigest, goos, goarch)
			newPath := artifactcache.BlobPath(cache.Dir(), "rulesfile", "artifact:new", newDigest, goos, goarch)
			require.NoError(t, cache.Store(oldPath, []byte("old artifact bytes"), 0o755))
			require.NoError(t, cache.Set("rulesfile", "default", "artifact", platform, oldPath))

			srv := httptest.NewServer(artifactserver.New(cache).Handler())
			defer srv.Close()
			fs := fsfake.NewMockFileSystem()
			reconciler := &RulesfileReconciler{
				recorder: events.NewFakeRecorder(20),
				fetcher:  &artifact.Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client()},
				store:    nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil)),
			}
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
			node := &artifactv1alpha1.ArtifactNode{}
			if alreadyInstalled {
				require.NoError(t, reconciler.ensureOCIRulesfile(ctx, parent, node, parent.Status.ArtifactMeta))
			}
			previous := node.DeepCopy().Status.InstalledArtifacts

			// The parent metadata is published before the aggregator replaces the cache entry.
			parent.Generation = 2
			parent.Spec.OCIArtifact.Image.Tag = "new"
			parent.Status.ObservedGeneration = 2
			parent.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: newDigest}
			setCurrentRulesfileMetadata(t, parent, nil)

			err := reconciler.ensureOCIRulesfile(ctx, parent, node, parent.Status.ArtifactMeta)
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
			require.NoError(t, cache.Set("rulesfile", "default", "artifact", platform, newPath))
			require.NoError(t, reconciler.ensureOCIRulesfile(ctx, parent, node, parent.Status.ArtifactMeta))
			require.Len(t, node.Status.InstalledArtifacts, 1)
			installed := node.Status.InstalledArtifacts[0]
			require.Equal(t, parent.Status.ArtifactMeta.SpecHash, installed.SpecHash)
			require.Equal(t, []byte("new artifact bytes"), fs.Files[installed.Path])
			condition = apimeta.FindStatusCondition(node.Status.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String())
			require.Equal(t, metav1.ConditionTrue, condition.Status)
			require.Equal(t, int64(2), condition.ObservedGeneration)

			// A verified, installed revision remains usable without another download.
			srv.Close()
			require.NoError(t, reconciler.ensureOCIRulesfile(ctx, parent, node, parent.Status.ArtifactMeta))
		})
	}
}

func TestReconcile_AdviseDoesNotInferUnverifiedDependencies(t *testing.T) {
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
				node := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
					n.Finalizers = []string{rulesfileNodeFinalizer}
				})
				r, cl := newTestReconciler(t, rf, cm, node)
				plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: rf.Namespace}}
				_, _, err := r.store.AddPluginConfig(ctx, plugin, r.fetcher)
				require.NoError(t, err)
				r.store.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
				request := testutil.Request(node.Name)
				_, err = r.Reconcile(ctx, request)
				require.NoError(t, err)
				key := nodeartifacts.KeyFromObj(nodeartifacts.KindRulesfile, rf)
				oldFile := r.store.FindInstalled(key, medium)
				require.NotNil(t, oldFile)
				var blocked *nodeartifacts.BlockedError
				require.ErrorAs(t, r.store.RemovePluginConfig(ctx, r.fetcher, plugin), &blocked)
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
				installed := r.store.FindInstalled(key, medium)
				require.NotNil(t, installed)
				require.NotEqual(t, oldFile.ContentHash, installed.ContentHash)
				intact, err := r.store.Verify(ctx, installed)
				require.NoError(t, err)
				require.True(t, intact)
				require.NoError(t, r.store.RemovePluginConfig(ctx, r.fetcher, plugin),
					"unknown metadata cannot identify a dependency to block removal")
				require.NoError(t, cl.Get(ctx, request.NamespacedName, node))
				condition := apimeta.FindStatusCondition(node.Status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
				require.NotNil(t, condition)
				require.Equal(t, metav1.ConditionUnknown, condition.Status)
				require.Equal(t, artifact.ReasonArtifactMetaNotReady, condition.Reason)
				require.True(t, apimeta.IsStatusConditionTrue(node.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()))

				// Removing the source still removes the installed file.
				require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(rf), rf))
				rf.Generation++
				rf.Spec.InlineRules, rf.Spec.ConfigMapRef = nil, nil
				require.NoError(t, cl.Update(ctx, rf))
				_, err = r.Reconcile(ctx, request)
				require.NoError(t, err)
				require.Nil(t, r.store.FindInstalled(key, medium))
				intact, err = r.store.Verify(ctx, installed)
				require.NoError(t, err)
				require.False(t, intact)
				require.NoError(t, r.store.RemovePluginConfig(ctx, r.fetcher, plugin))
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
	node := newTestNodeObj(withOwnerRef(), func(n *artifactv1alpha1.ArtifactNode) {
		n.Finalizers = []string{rulesfileNodeFinalizer}
	})
	r, cl := newTestReconciler(t, rf, node)
	plugin := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: rf.Namespace}}
	_, _, err := r.store.AddPluginConfig(ctx, plugin, r.fetcher)
	require.NoError(t, err)
	r.store.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
	fetcher := r.fetcher.(*testFetcher)
	fetcher.ociBytes = []byte("- required_plugin_versions:\n  - name: container\n    version: 1.0.0\n" + testRulesData)
	request := testutil.Request(node.Name)
	_, err = r.Reconcile(ctx, request)
	require.NoError(t, err)
	key := nodeartifacts.KeyFromObj(nodeartifacts.KindRulesfile, rf)
	oldFile := r.store.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, oldFile)

	// The intermediate spec is observed, but its content never replaces the installed file.
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(rf), rf))
	rf.Generation++
	rf.Spec.OCIArtifact.Image.Tag = "intermediate"
	rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("intermediate OCI manifest").String()}
	setCurrentRulesfileMetadata(t, rf, cl)
	require.NoError(t, cl.Update(ctx, rf))
	fetcher.ociErr = errors.New("intermediate revision unavailable")
	_, err = r.Reconcile(ctx, request)
	require.ErrorIs(t, err, fetcher.ociErr)
	intact, err := r.store.Verify(ctx, oldFile)
	require.NoError(t, err)
	require.True(t, intact)
	var blocked *nodeartifacts.BlockedError
	require.ErrorAs(t, r.store.RemovePluginConfig(ctx, r.fetcher, plugin), &blocked)

	// Returning to the same floating-tag spec resolves a different manifest.
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(rf), rf))
	rf.Generation++
	rf.Spec.OCIArtifact.Image.Tag = "latest"
	rf.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("new latest OCI manifest").String()}
	setCurrentRulesfileMetadata(t, rf, cl)
	require.Equal(t, originalSpecHash, rf.Status.ArtifactMeta.SpecHash)
	require.NoError(t, cl.Update(ctx, rf))
	fetcher.ociErr = nil
	fetcher.ociBytes = []byte(testRulesData)
	_, err = r.Reconcile(ctx, request)
	require.NoError(t, err)
	require.Equal(t, 3, fetcher.ociCallCount, "same spec hash cannot skip acquisition of a different resolved digest")
	require.Equal(t, rf.Status.ArtifactMeta.Digest, fetcher.ociDigest)
	installed := r.store.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, installed)
	require.Equal(t, originalSpecHash, installed.SpecHash)
	require.Equal(t, sha256hexForTest(fetcher.ociBytes), installed.ContentHash)
	intact, err = r.store.Verify(ctx, installed)
	require.NoError(t, err)
	require.True(t, intact)
	require.NoError(t, r.store.RemovePluginConfig(ctx, r.fetcher, plugin),
		"only the installed replacement releases the old dependency")
}
