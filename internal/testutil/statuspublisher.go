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

package testutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// NewTestArtifactNode returns the ArtifactNode of TestNodeName in TestNamespace, the object a
// node's status publisher writes to.
func NewTestArtifactNode() *artifactv1alpha1.ArtifactNode {
	return NewArtifactNode(TestNamespace, TestNodeName)
}

// NewArtifactNode returns the ArtifactNode of nodeName in namespace, changed by mods.
func NewArtifactNode(namespace, nodeName string, mods ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	artifactNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: namespace},
		Spec:       artifactv1alpha1.ArtifactNodeSpec{NodeName: nodeName},
	}
	for _, m := range mods {
		m(artifactNode)
	}
	return artifactNode
}

// EnsureArtifactNode makes sure the node's own ArtifactNode is among objs. The node persists a
// status entry before it installs anything, so without that object every apply fails on the first
// write. A test that supplies its own ArtifactNode keeps it.
func EnsureArtifactNode(objs []client.Object) []client.Object {
	for _, obj := range objs {
		if _, ok := obj.(*artifactv1alpha1.ArtifactNode); ok {
			return objs
		}
	}
	return append(append([]client.Object{}, objs...), NewTestArtifactNode())
}

// RequirePublished waits for the status entry of the artifact of the given kind and name to appear on
// the test node's ArtifactNode, and returns it. The first entry to appear may be the placeholder
// written before installing; use RequirePublishedWhere to wait for a particular status.
func RequirePublished(t *testing.T, cl client.Client, kind artifactv1alpha1.ArtifactKind, name string) artifactv1alpha1.NodeArtifactStatus {
	t.Helper()
	return RequirePublishedWhere(t, cl, kind, name, func(artifactv1alpha1.NodeArtifactStatus) bool { return true })
}

// RequirePublishedWhere waits for the status entry of the artifact to satisfy ok, and returns it.
func RequirePublishedWhere(
	t *testing.T, cl client.Client, kind artifactv1alpha1.ArtifactKind, name string, ok func(artifactv1alpha1.NodeArtifactStatus) bool,
) artifactv1alpha1.NodeArtifactStatus {
	t.Helper()
	var found artifactv1alpha1.NodeArtifactStatus
	require.Eventually(t, func() bool {
		artifactNode := &artifactv1alpha1.ArtifactNode{}
		if err := cl.Get(t.Context(), client.ObjectKey{Namespace: TestNamespace, Name: TestNodeName}, artifactNode); err != nil {
			return false
		}
		for _, e := range artifactNode.Status.Artifacts {
			if e.Kind == kind && e.Name == name && ok(e) {
				found = e
				return true
			}
		}
		return false
	}, 2*time.Second, 5*time.Millisecond, "the reconciler's status must reach the ArtifactNode status")
	return found
}

// DropAssignments makes the test node's ArtifactNode stop listing anything. A node's status publisher patches the
// ArtifactNode concurrently, so the update retries on a conflict.
func DropAssignments(t *testing.T, cl client.Client) {
	t.Helper()
	require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		artifactNode := &artifactv1alpha1.ArtifactNode{}
		if err := cl.Get(t.Context(), client.ObjectKey{Namespace: TestNamespace, Name: TestNodeName}, artifactNode); err != nil {
			return err
		}
		artifactNode.Spec.Artifacts = nil
		return cl.Update(t.Context(), artifactNode)
	}))
}

// NewAssigningArtifactNode returns the test node's ArtifactNode whose spec assigns the artifact of the given kind,
// name and UID.
func NewAssigningArtifactNode(kind artifactv1alpha1.ArtifactKind, name, uid string) *artifactv1alpha1.ArtifactNode {
	artifactNode := NewTestArtifactNode()
	artifactNode.Spec.Artifacts = []artifactv1alpha1.NodeArtifactRef{{Kind: kind, Name: name, UID: uid}}
	return artifactNode
}

// NewReportingArtifactNode returns the test node's ArtifactNode assigning the artifact of the given kind and name,
// with an empty status entry for it that opts may fill.
func NewReportingArtifactNode(kind artifactv1alpha1.ArtifactKind, name string, opts ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
	artifactNode := NewTestArtifactNode()
	artifactNode.Spec.Artifacts = []artifactv1alpha1.NodeArtifactRef{{Kind: kind, Name: name}}
	artifactNode.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{{Kind: kind, Name: name}}
	for _, o := range opts {
		o(artifactNode)
	}
	return artifactNode
}

// TestFalcoName is the name of the Falco instance of the tests.
const TestFalcoName = "test-falco"

// NewTestFalco returns the Falco instance TestFalcoName in TestNamespace.
func NewTestFalco() *instancev1alpha1.Falco {
	return &instancev1alpha1.Falco{ObjectMeta: metav1.ObjectMeta{Name: TestFalcoName, Namespace: TestNamespace}}
}

// NewRunningFalcoPod returns a running pod of TestFalcoName on the test node.
func NewRunningFalcoPod() *corev1.Pod {
	return NewFalcoPod("falco-pod", TestNodeName)
}

// NewFalcoPod returns a running pod of TestFalcoName called name, on nodeName.
func NewFalcoPod(name, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: TestNamespace,
			Labels:    map[string]string{"app.kubernetes.io/instance": TestFalcoName},
		},
		Spec:   corev1.PodSpec{NodeName: nodeName},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// WithAssigned makes an ArtifactNode's spec list refs.
func WithAssigned(refs ...artifactv1alpha1.NodeArtifactRef) func(*artifactv1alpha1.ArtifactNode) {
	return func(artifactNode *artifactv1alpha1.ArtifactNode) { artifactNode.Spec.Artifacts = refs }
}

// WithReported makes an ArtifactNode's status hold entries.
func WithReported(entries ...artifactv1alpha1.NodeArtifactStatus) func(*artifactv1alpha1.ArtifactNode) {
	return func(artifactNode *artifactv1alpha1.ArtifactNode) { artifactNode.Status.Artifacts = entries }
}

// NodeArtifactRef is the assignment of the artifact of kind named name, of uid.
func NodeArtifactRef(kind artifactv1alpha1.ArtifactKind, name, uid string) artifactv1alpha1.NodeArtifactRef {
	return artifactv1alpha1.NodeArtifactRef{Kind: kind, Name: name, UID: uid}
}

// NodeArtifactStatus is the status entry of the artifact of kind named name, of uid, with conds.
func NodeArtifactStatus(
	kind artifactv1alpha1.ArtifactKind, name, uid string, conds ...metav1.Condition,
) artifactv1alpha1.NodeArtifactStatus {
	return artifactv1alpha1.NodeArtifactStatus{Kind: kind, Name: name, UID: uid, Conditions: conds}
}

// ProgrammedCondition is a Programmed condition of status, observed at generation.
func ProgrammedCondition(status metav1.ConditionStatus, generation int64) metav1.Condition {
	return metav1.Condition{Type: "Programmed", Status: status, Reason: "R", Message: "m", ObservedGeneration: generation}
}
