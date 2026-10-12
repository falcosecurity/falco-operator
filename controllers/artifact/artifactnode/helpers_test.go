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

package artifactnode

import (
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
	"github.com/falcosecurity/falco-operator/internal/testutil"
	"github.com/falcosecurity/falco-operator/internal/testutil/nodetest"
)

var (
	errBoom = errors.New("api server error")

	artifactNodeResource = schema.GroupResource{Group: "artifact.falcosecurity.dev", Resource: "artifactnodes"}
	errConflict          = k8serrors.NewConflict(artifactNodeResource, testutil.TestNodeName, errors.New("stale"))
	errNotFound          = k8serrors.NewNotFound(artifactNodeResource, testutil.TestNodeName)
)

type fixture struct {
	r        *Reconciler
	cl       client.Client
	node     *node.Node
	recorder *events.FakeRecorder
}

func newFixture(t *testing.T, funcs *interceptor.Funcs, objs ...client.Object) *fixture {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{})
	if funcs != nil {
		builder = builder.WithInterceptorFuncs(*funcs)
	}
	cl := builder.Build()
	n := nodetest.NewTestNodeOn(t, cl, fsfake.NewMockFileSystem(), nil)

	recorder := events.NewFakeRecorder(50)
	r := NewReconciler(cl, recorder, n)
	return &fixture{r: r, cl: cl, node: n, recorder: recorder}
}

// listing is the test node's ArtifactNode. It holds the sidecar's finalizer and lists refs.
func listing(refs ...artifactv1alpha1.NodeArtifactRef) *artifactv1alpha1.ArtifactNode {
	an := testutil.NewTestArtifactNode()
	an.Finalizers = []string{controllerhelper.ArtifactNodeSidecarFinalizer}
	an.Spec.Artifacts = refs
	return an
}

// unfinalized is listing before the sidecar has put its finalizer on it.
func unfinalized(an *artifactv1alpha1.ArtifactNode) *artifactv1alpha1.ArtifactNode {
	an.Finalizers = nil
	return an
}

// deleting marks the ArtifactNode as being deleted, held by the finalizers it has.
func deleting(an *artifactv1alpha1.ArtifactNode) *artifactv1alpha1.ArtifactNode {
	now := metav1.Now()
	an.DeletionTimestamp = &now
	return an
}

// reporting gives the ArtifactNode status entries, as a previous sidecar process left them.
func reporting(an *artifactv1alpha1.ArtifactNode, entries ...artifactv1alpha1.NodeArtifactStatus) *artifactv1alpha1.ArtifactNode {
	an.Status.Artifacts = entries
	return an
}

func configRef(name string) artifactv1alpha1.NodeArtifactRef {
	return artifactv1alpha1.NodeArtifactRef{Kind: "Config", Name: name, UID: "u"}
}

func key(kind artifact.Kind, name string) artifact.Ref {
	return artifact.Ref{Kind: kind, Name: name}
}

func (f *fixture) install(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		nodetest.InstallConfig(t, f.cl, f.node, name)
	}
}

func (f *fixture) uninstall(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		err := f.node.Remove(t.Context(), key(artifact.KindConfig, name))
		require.NoError(t, err)
	}
}

// forget makes the node hold nothing for refs, as their reconcilers leave it once they have removed them.
func (f *fixture) forget(t *testing.T, refs ...artifactv1alpha1.NodeArtifactRef) {
	t.Helper()
	for _, ref := range refs {
		k := key(ref.Kind, ref.Name)
		require.NoError(t, f.node.Remove(t.Context(), k))
		f.node.WithdrawStatus(k)
	}
}

// report makes the node hold an entry for the artifact without files, as one a previous process published.
func (f *fixture) report(kind artifact.Kind, name string) {
	obj := &metav1.PartialObjectMetadata{
		ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: name, UID: "u"},
	}
	f.node.PublishStatus(kind, obj, &artifactv1alpha1.NodeArtifactStatus{})
}

func (f *fixture) reconcile(t *testing.T) (ctrl.Result, error) {
	t.Helper()
	return f.r.Reconcile(t.Context(), testutil.Request(testutil.TestNodeName))
}

func (f *fixture) requested() []string { return nodetest.RemovalsRequested(f.node) }

// artifactNodeNow returns the stored ArtifactNode, and whether it still exists.
func (f *fixture) artifactNodeNow(t *testing.T) (*artifactv1alpha1.ArtifactNode, bool) {
	t.Helper()
	an := &artifactv1alpha1.ArtifactNode{}
	err := f.cl.Get(t.Context(), client.ObjectKeyFromObject(testutil.NewTestArtifactNode()), an)
	if k8serrors.IsNotFound(err) {
		return nil, false
	}
	require.NoError(t, err)
	return an, true
}

func (f *fixture) finalizerHeld(t *testing.T) bool {
	t.Helper()
	an, exists := f.artifactNodeNow(t)
	return exists && slices.Contains(an.Finalizers, controllerhelper.ArtifactNodeSidecarFinalizer)
}
