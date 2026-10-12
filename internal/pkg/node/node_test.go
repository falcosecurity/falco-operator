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

package node

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestNode_HeldKeys_CoverFilesAndStatusEntries(t *testing.T) {
	m, _ := newStatusManager(t)
	installConfig(t, m, statusTestNamespace, "with-files")
	m.PublishStatus(artifact.KindPlugin, artifactObj("entry-only"), &artifactv1alpha1.NodeArtifactStatus{})
	m.PublishStatus(artifact.KindConfig, artifactObj("with-files"), &artifactv1alpha1.NodeArtifactStatus{})

	keys := m.HeldKeys()

	assert.ElementsMatch(t, []artifact.Ref{
		{Kind: artifact.KindConfig, Name: "with-files"},
		{Kind: artifact.KindPlugin, Name: "entry-only"},
	}, keys, "an artifact with both files and an entry appears once")
}

func TestNode_HeldKeys_IncludeWhatAPreviousProcessReported(t *testing.T) {
	m, _ := newStatusManager(t)
	previous := &artifactv1alpha1.ArtifactNode{
		Status: artifactv1alpha1.ArtifactNodeStatus{Artifacts: []artifactv1alpha1.NodeArtifactStatus{
			{Kind: "Rulesfile", Name: "reported", UID: "uid"},
		}},
	}

	assert.Empty(t, m.HeldKeys())
	m.ObserveArtifactNode(previous)

	assert.Equal(t, []artifact.Ref{{Kind: artifact.KindRulesfile, Name: "reported"}}, m.HeldKeys())
}

func TestNode_EnsureStatusEntry_PersistsTheEntry(t *testing.T) {
	m, published := newStatusManager(t)
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rf"}

	require.NoError(t, m.ensureStatusEntry(t.Context(), key, "uid", statusConditions()))

	assert.Equal(t, []string{"Rulesfile/rf"}, published(), "persisted before EnsureStatusEntry returned")
	got, ok := m.StatusEntry(artifact.KindRulesfile, "rf")
	require.True(t, ok)
	assert.Equal(t, "uid", got.UID)
}

func TestNode_WithdrawStatus_DropsAnEntryThatNeverHadFiles(t *testing.T) {
	m, published := newStatusManager(t)
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rf"}
	require.NoError(t, m.ensureStatusEntry(t.Context(), key, "uid", nil))

	m.WithdrawStatus(key)

	require.Eventually(t, func() bool { return len(published()) == 0 }, 2*time.Second, 5*time.Millisecond)
}

func TestNode_StatusHelpers_WithoutAPublisher(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rf"}

	require.NoError(t, m.ensureStatusEntry(t.Context(), key, "uid", []metav1.Condition{}))
	m.WithdrawStatus(key)
	m.ObserveArtifactNode(&artifactv1alpha1.ArtifactNode{})
	_, ok := m.StatusEntry(artifact.KindRulesfile, "rf")

	assert.False(t, ok)
	assert.Empty(t, m.HeldKeys())
}

func TestNode_PublishStatus_ForwardsArtifactKinds(t *testing.T) {
	m, published := newStatusManager(t)

	for _, kind := range []artifact.Kind{artifact.KindRulesfile, artifact.KindPlugin, artifact.KindConfig} {
		m.PublishStatus(kind, artifactObj("a"), &artifactv1alpha1.NodeArtifactStatus{Conditions: statusConditions()})
	}

	require.Eventually(t, func() bool { return len(published()) == 3 }, 2*time.Second, 5*time.Millisecond)
	assert.Equal(t, []string{"Config/a", "Plugin/a", "Rulesfile/a"}, published())
}

func TestNode_PublishStatus_IgnoresKindsThatAreNotArtifacts(t *testing.T) {
	m, published := newStatusManager(t)

	m.PublishStatus(artifact.Kind("Tracer"), artifactObj("tracer"), &artifactv1alpha1.NodeArtifactStatus{})
	m.PublishStatus(artifact.KindRulesfile, artifactObj("rf"), &artifactv1alpha1.NodeArtifactStatus{})

	require.Eventually(t, func() bool { return len(published()) == 1 }, 2*time.Second, 5*time.Millisecond)
	assert.Equal(t, []string{"Rulesfile/rf"}, published())
}

func TestNode_PublishStatus_WithoutAPublisherIsANoOp(t *testing.T) {
	m := newTestNode()
	assert.NotPanics(t, func() {
		m.PublishStatus(artifact.KindRulesfile, artifactObj("rf"), &artifactv1alpha1.NodeArtifactStatus{})
		require.NoError(t, removeArtifact(t.Context(), m, artifact.Ref{Kind: artifact.KindRulesfile, Name: "rf"}))
	})
}

// newTestNodeFor is the Node of the test node over cl, for a test that builds its own client and
// then waits on what the node publishes to the ArtifactNode in it. Its status publisher is started
// with timings short enough to wait on, and stops with the test.
func newTestNodeFor(t *testing.T, cl client.Client) *Node {
	t.Helper()
	n, err := New(&Config{
		Fetcher:        newTestFetcher(cl),
		Client:         cl,
		NodeName:       testutil.TestNodeName,
		Namespace:      testutil.TestNamespace,
		FalcoBaseURL:   compat.DefaultBaseURL,
		ReloadCooldown: DefaultReloadCooldown,
		Store:          &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
		FalcoFetcher:   compatfake.NewMockVersionsFetcher(nil),
		StatusTimings:  &StatusTimings{Debounce: 5 * time.Millisecond, Retry: 5 * time.Millisecond},
	})
	require.NoError(t, err)
	startNode(t, n)
	return n
}

// PublishStatus syncs every medium of the artifact's kind from what the node holds before publishing,
// so a reconciler never mirrors installed files itself: an entry the node has is upserted, and one it
// no longer has is cleared rather than left stale. The mediums come from the kind, not the caller.
func TestNode_PublishStatus_SyncsEveryMediumOfTheKind(t *testing.T) {
	n := newTestNode()
	rulesfile := &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns", UID: "uid"}}
	key := artifact.RefOf(artifact.KindRulesfile, rulesfile)
	n.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{
		{Path: "/oci", Medium: "oci", Priority: 50, ContentHash: "h-oci"},
		{Path: "/inline", Medium: "inline", Priority: 90, ContentHash: "h-inline"},
	})
	status := &artifactv1alpha1.NodeArtifactStatus{
		Kind: "Rulesfile", Name: "my-rules", UID: "uid",
		InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/stale", Medium: "configmap"}},
	}

	n.PublishStatus(artifact.KindRulesfile, rulesfile, status)

	ociEntry := artifact.FindInstalled(status.InstalledArtifacts, artifact.MediumOCI)
	require.NotNil(t, ociEntry)
	assert.Equal(t, "/oci", ociEntry.Path)
	inlineEntry := artifact.FindInstalled(status.InstalledArtifacts, artifact.MediumInline)
	require.NotNil(t, inlineEntry)
	assert.Equal(t, "/inline", inlineEntry.Path)
	assert.Nil(t, artifact.FindInstalled(status.InstalledArtifacts, artifact.MediumConfigMap),
		"a medium the node holds no file for must be cleared, not left stale")

	published, ok := n.StatusEntry(artifact.KindRulesfile, "my-rules")
	require.True(t, ok)
	assert.Len(t, published.InstalledArtifacts, 2, "what was synced is what is published")
}

func configKey(name string) artifact.Ref {
	return artifact.Ref{Kind: artifact.KindConfig, Name: name}
}

func TestNode_RequestRemovalReachesTheChannelOfTheKind(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindPlugin, Name: "a"}

	require.NoError(t, m.RequestRemoval(t.Context(), key))

	select {
	case ev := <-m.RemovalRequests(artifact.KindPlugin):
		assert.Equal(t, "a", ev.Object.GetName())
		assert.Equal(t, m.Namespace(), ev.Object.GetNamespace(), "the node's own namespace")
	default:
		t.Fatal("the request did not reach the channel of its kind")
	}
	select {
	case <-m.RemovalRequests(artifact.KindRulesfile):
		t.Fatal("a request for a plugin reached the rulesfile reconciler")
	default:
	}
}

func TestNode_RequestRemovalGivesUpWhenTheContextEnds(t *testing.T) {
	m := newTestNode()
	ctx, cancel := context.WithCancel(t.Context())
	key := artifact.Ref{Kind: artifact.KindPlugin, Name: "a"}
	cancel()

	require.ErrorIs(t, m.RequestRemoval(ctx, key), context.Canceled)
}

// A reconciler that is behind must not stall the caller's own reconcile: the request is refused and the
// caller, which polls, asks again.
func TestNode_RequestRemovalReportsABacklogInsteadOfBlocking(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindPlugin, Name: "a"}
	for range 2 * artifactv1alpha1.MaxNodeArtifacts { // nobody is consuming: fill the buffer
		require.NoError(t, m.RequestRemoval(t.Context(), key))
	}

	done := make(chan error, 1)
	go func() { done <- m.RequestRemoval(t.Context(), key) }()

	select {
	case err := <-done:
		require.ErrorContains(t, err, "the Plugin reconciler is behind")
	case <-time.After(5 * time.Second):
		t.Fatal("RequestRemoval blocked on a full channel instead of reporting the backlog")
	}

	// Draining one slot makes room again, so the next ask goes through.
	<-m.RemovalRequests(artifact.KindPlugin)
	require.NoError(t, m.RequestRemoval(t.Context(), key))
}

// Asking twice for the same artifact is what lets a caller poll without remembering what it has asked for.
func TestNode_RequestRemovalCanBeRepeatedForTheSameArtifact(t *testing.T) {
	m := newTestNode()
	key := artifact.Ref{Kind: artifact.KindConfig, Name: "a"}

	for range 3 {
		require.NoError(t, m.RequestRemoval(t.Context(), key))
	}

	assert.Len(t, m.RemovalRequests(artifact.KindConfig), 3, "each ask queues a request; the workqueue coalesces them")
}

func TestNode_Holds(t *testing.T) {
	m := newTestNode()

	assert.False(t, m.Holds(configKey("none")))
	assert.True(t, m.Holds(installConfig(t, m, testutil.TestNamespace, "installed")), "files count")
}

func TestNode_HoldsAnEntryWithoutFiles(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(testutil.NewTestArtifactNode()).WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).Build()
	m := newTestNodeFor(t, cl)
	require.NoError(t, m.ensureStatusEntry(t.Context(), configKey("ghost"), "uid", nil))

	assert.True(t, m.Holds(configKey("ghost")))
}
