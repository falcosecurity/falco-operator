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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

type refs = []artifactv1alpha1.NodeArtifactRef

func at(minutes int) metav1.Time {
	return metav1.NewTime(baseTime.Add(time.Duration(minutes) * time.Minute))
}

// ref, listing and reporting are the shared fixtures, under the names the tests of this package read best with.
var (
	ref       = testutil.NodeArtifactRef
	listing   = testutil.WithAssigned
	reporting = testutil.WithReported
)

var (
	baseTime = time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)

	errBoom = errors.New("api server error")

	artifactNodeResource = schema.GroupResource{Group: "artifact.falcosecurity.dev", Resource: "artifactnodes"}
	errConflict          = k8serrors.NewConflict(artifactNodeResource, testutil.TestNodeName, errors.New("stale"))
	errExists            = k8serrors.NewAlreadyExists(artifactNodeResource, testutil.TestNodeName)
	errNotFound          = k8serrors.NewNotFound(artifactNodeResource, testutil.TestNodeName)
)

// writes counts the mutating calls the reconciler made.
type writes struct{ creates, patches, deletes int }

func countingFuncs(w *writes) *interceptor.Funcs {
	return &interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			w.creates++
			return c.Create(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			w.patches++
			return c.Patch(ctx, obj, patch, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			w.deletes++
			return c.Delete(ctx, obj, opts...)
		},
	}
}

// failGet makes reading an object of type T fail with err.
func failGet[T client.Object](err error) interceptor.Funcs {
	return interceptor.Funcs{Get: func(
		ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
	) error {
		if _, ok := obj.(T); ok {
			return err
		}
		return c.Get(ctx, key, obj, opts...)
	}}
}

// failList makes listing objects of list type T fail with err.
func failList[T client.ObjectList](err error) interceptor.Funcs {
	return interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if _, ok := list.(T); ok {
			return err
		}
		return c.List(ctx, list, opts...)
	}}
}

func build(t *testing.T, funcs *interceptor.Funcs, objs ...client.Object) (*ArtifactNodeReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	builder := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&corev1.Pod{}, index.PodNodeName, index.PodByNodeName)
	if funcs != nil {
		builder = builder.WithInterceptorFuncs(*funcs)
	}
	cl := builder.Build()
	return NewArtifactNodeReconciler(cl, events.NewFakeRecorder(50)), cl
}

func newReconciler(t *testing.T, objs ...client.Object) (*ArtifactNodeReconciler, client.Client, *writes) {
	t.Helper()
	w := &writes{}
	r, cl := build(t, countingFuncs(w), objs...)
	return r, cl, w
}

func testNode() *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName}}
}

func testRulesfile(name string, mods ...func(*artifactv1alpha1.Rulesfile)) *artifactv1alpha1.Rulesfile {
	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testutil.TestNamespace, UID: types.UID("uid-" + name)},
	}
	for _, m := range mods {
		m(rf)
	}
	return rf
}

func testPlugin(name string, mods ...func(*artifactv1alpha1.Plugin)) *artifactv1alpha1.Plugin {
	p := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testutil.TestNamespace, UID: types.UID("uid-" + name)},
	}
	for _, m := range mods {
		m(p)
	}
	return p
}

func testConfig(name string) *artifactv1alpha1.Config {
	return &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testutil.TestNamespace, UID: types.UID("uid-" + name)},
	}
}

// selecting returns a selector that selects nodes labeled with pool=gpu, which the test node is not.
func selecting(pool string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"pool": pool}}
}

// terminating makes obj a terminating object held by a finalizer.
func terminating[T client.Object](obj T) T {
	now := metav1.Now()
	obj.SetDeletionTimestamp(&now)
	obj.SetFinalizers([]string{"test/finalizer"})
	return obj
}

// existingArtifactNode is an ArtifactNode as this controller would have created it.
func existingArtifactNode(mods ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	artifactNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testutil.TestNodeName,
			Namespace: testutil.TestNamespace,
			Labels:    controllerhelper.ArtifactNodeLabels(testutil.TestNodeName),
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: testutil.TestNodeName},
	}
	for _, m := range mods {
		m(artifactNode)
	}
	return artifactNode
}

// artifactNodeOf is the ArtifactNode of nodeName in namespace.
func artifactNodeOf(namespace, nodeName string) *artifactv1alpha1.ArtifactNode {
	return existingArtifactNode(func(s *artifactv1alpha1.ArtifactNode) {
		s.Namespace, s.Name, s.Spec.NodeName = namespace, nodeName, nodeName
		s.Labels = controllerhelper.ArtifactNodeLabels(nodeName)
	})
}

func sidecarFinalized() func(*artifactv1alpha1.ArtifactNode) {
	return func(s *artifactv1alpha1.ArtifactNode) {
		s.Finalizers = []string{controllerhelper.ArtifactNodeSidecarFinalizer}
	}
}

// hosted returns the objects that make the test node a Falco node.
func hosted(extra ...client.Object) []client.Object {
	return append([]client.Object{testNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod()}, extra...)
}

func reconcileNode(t *testing.T, r *ArtifactNodeReconciler) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(t.Context(), testutil.Request(testutil.TestNodeName))
}

func getArtifactNode(t *testing.T, cl client.Client) (*artifactv1alpha1.ArtifactNode, bool) {
	t.Helper()
	artifactNode := &artifactv1alpha1.ArtifactNode{}
	err := cl.Get(t.Context(), client.ObjectKey{Namespace: testutil.TestNamespace, Name: testutil.TestNodeName}, artifactNode)
	if k8serrors.IsNotFound(err) {
		return nil, false
	}
	require.NoError(t, err)
	return artifactNode, true
}

// fakeClock is a clock a test moves by hand.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// useClock gives r a clock the test controls, starting at baseTime.
func useClock(r *ArtifactNodeReconciler) *fakeClock {
	c := &fakeClock{t: baseTime}
	r.absences.now = c.now
	return c
}

func drainEvents(rec *events.FakeRecorder) []string {
	var got []string
	for {
		select {
		case e := <-rec.Events:
			got = append(got, e)
		default:
			return got
		}
	}
}

func key(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}
