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
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

const (
	spNamespace = "falco-ns"
	spNode      = "node-a"
)

// spStatus and spRef are the shared fixtures, under the names these tests read best with.
var (
	spStatus = testutil.NodeArtifactStatus
	spRef    = testutil.NodeArtifactRef
)

func spProgrammed(status metav1.ConditionStatus) []metav1.Condition {
	return []metav1.Condition{{
		Type: "Programmed", Status: status, Reason: "Programmed", Message: "ok",
		LastTransitionTime: metav1.NewTime(time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)),
	}}
}

func spInstalled() []artifactv1alpha1.InstalledArtifact {
	return []artifactv1alpha1.InstalledArtifact{{Path: "/etc/falco/rules.d/rf.yaml", Medium: "inline", Priority: 50, ContentHash: "abc"}}
}

// spFixture builds a publisher over a fake client. patches counts status patches.
type spFixture struct {
	pub     *statusPublisher
	cl      client.Client
	patches *atomic.Int32
}

func newSPFixture(t *testing.T, base *interceptor.Funcs, objs ...client.Object) *spFixture {
	t.Helper()
	patches := &atomic.Int32{}
	var funcs interceptor.Funcs
	if base != nil {
		funcs = *base
	}
	inner := funcs.SubResourcePatch
	funcs.SubResourcePatch = func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
		patches.Add(1)
		if inner != nil {
			return inner(ctx, c, sub, obj, patch, opts...)
		}
		return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
	}
	cl := fake.NewClientBuilder().
		WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithInterceptorFuncs(funcs).
		Build()
	pub := newStatusPublisher(cl, spNamespace, spNode,
		&StatusTimings{Debounce: 5 * time.Millisecond, Retry: 5 * time.Millisecond})
	return &spFixture{pub: pub, cl: cl, patches: patches}
}

func (f *spFixture) stored(t *testing.T) []artifactv1alpha1.NodeArtifactStatus {
	t.Helper()
	artifactNode := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, f.cl.Get(t.Context(), client.ObjectKey{Namespace: spNamespace, Name: spNode}, artifactNode))
	return artifactNode.Status.Artifacts
}

func TestStatusPublisher_FlushWritesEntriesSortedWithTheirState(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionTrue), spInstalled())
	f.pub.Set(artifact.KindConfig, "cfg", "uid-cfg", spProgrammed(metav1.ConditionFalse), nil)
	f.pub.Set(artifact.KindPlugin, "pl", "uid-pl", nil, nil)

	done, err := f.pub.flush(t.Context())
	require.NoError(t, err)
	require.True(t, done)

	got := f.stored(t)
	require.Len(t, got, 3)
	assert.Equal(t, []string{"Config/cfg", "Plugin/pl", "Rulesfile/rf"},
		[]string{string(got[0].Kind) + "/" + got[0].Name, string(got[1].Kind) + "/" + got[1].Name, string(got[2].Kind) + "/" + got[2].Name})
	assert.Equal(t, "uid-rf", got[2].UID)
	require.Len(t, got[2].Conditions, 1)
	assert.Equal(t, metav1.ConditionTrue, got[2].Conditions[0].Status)
	assert.Equal(t, spInstalled(), got[2].InstalledArtifacts)
}

func TestStatusPublisher_SetReplacesTheEntryOfTheSameArtifact(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-1", spProgrammed(metav1.ConditionFalse), nil)
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-2", spProgrammed(metav1.ConditionTrue), nil)

	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)

	got := f.stored(t)
	require.Len(t, got, 1)
	assert.Equal(t, "uid-2", got[0].UID)
	assert.Equal(t, metav1.ConditionTrue, got[0].Conditions[0].Status)
}

func TestStatusPublisher_KeepsTheStatusItFindsUntilTheArtifactIsRemoved(t *testing.T) {
	previous := testutil.NewArtifactNode(spNamespace, spNode, func(s *artifactv1alpha1.ArtifactNode) {
		s.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{
			spStatus("Rulesfile", "kept", "uid-kept"), spStatus("Rulesfile", "gone", "uid-gone"),
		}
	})
	f := newSPFixture(t, nil, previous)
	f.pub.Set(artifact.KindRulesfile, "new", "uid-new", nil, nil)

	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)
	names := func() []string {
		stored := f.stored(t)
		out := make([]string, 0, len(stored))
		for _, e := range stored {
			out = append(out, e.Name)
		}
		return out
	}
	assert.Equal(t, []string{"gone", "kept", "new"}, names(),
		"entries published by a previous process must survive until their artifact is removed")

	f.pub.Remove(artifact.KindRulesfile, "gone")
	_, err = f.pub.flush(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []string{"kept", "new"}, names())
}

func TestStatusPublisher_ANewEntryOverridesTheOneItFound(t *testing.T) {
	previous := testutil.NewArtifactNode(spNamespace, spNode, func(s *artifactv1alpha1.ArtifactNode) {
		s.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{spStatus("Rulesfile", "rf", "old-uid")}
	})
	f := newSPFixture(t, nil, previous)
	f.pub.Set(artifact.KindRulesfile, "rf", "new-uid", nil, nil)

	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)
	got := f.stored(t)
	require.Len(t, got, 1)
	assert.Equal(t, "new-uid", got[0].UID)
}

func TestStatusPublisher_RemovingBeforeTheFirstFlushIsRespected(t *testing.T) {
	previous := testutil.NewArtifactNode(spNamespace, spNode, func(s *artifactv1alpha1.ArtifactNode) {
		s.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{spStatus("Rulesfile", "gone", "uid-gone")}
	})
	f := newSPFixture(t, nil, previous)
	f.pub.Remove(artifact.KindRulesfile, "gone") // e.g. warm sync removes an orphan before the object is first read

	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)
	assert.Empty(t, f.stored(t))
}

func TestStatusPublisher_WaitsForTheObjectAndKeepsItsEntries(t *testing.T) {
	f := newSPFixture(t, nil)
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionTrue), nil)

	done, err := f.pub.flush(t.Context())
	require.NoError(t, err, "an ArtifactNode the operator has not created yet is not an error")
	assert.False(t, done)

	require.NoError(t, f.cl.Create(t.Context(), testutil.NewArtifactNode(spNamespace, spNode)))
	done, err = f.pub.flush(t.Context())
	require.NoError(t, err)
	assert.True(t, done)
	assert.Len(t, f.stored(t), 1)
}

func TestStatusPublisher_DoesNotWriteWhenNothingChanged(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionTrue), nil)

	for range 3 {
		_, err := f.pub.flush(t.Context())
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), f.patches.Load())
}

// Once an artifact's entry is on the ArtifactNode, ensuring it again writes nothing, even while another artifact's
// change waits for the batched write: every reconcile ensures its entry, and writing the whole status each time
// would turn a burst of reconciles into a write per reconcile.
func TestStatusPublisher_EnsuringAPersistedEntryDoesNotWrite(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "uid-rf", nil))
	require.Equal(t, int32(1), f.patches.Load())

	f.pub.Set(artifact.KindPlugin, "pl", "uid-pl", spProgrammed(metav1.ConditionTrue), nil)
	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "uid-rf", nil))
	assert.Equal(t, int32(1), f.patches.Load(), "the pending change of another artifact waits for the batched write")

	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "uid-new", nil))
	assert.Equal(t, int32(2), f.patches.Load(), "a new incarnation's entry is still persisted at once")
}

func TestStatusPublisher_ChangedStateIsWrittenAgain(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionFalse), nil)
	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)

	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionTrue), nil)
	_, err = f.pub.flush(t.Context())
	require.NoError(t, err)

	assert.Equal(t, int32(2), f.patches.Load())
	assert.Equal(t, metav1.ConditionTrue, f.stored(t)[0].Conditions[0].Status)
}

func TestStatusPublisher_ACacheShowingTheDesiredStateDoesNotSuppressAWrite(t *testing.T) {
	// The cache keeps returning the object as it was before the publisher's first write: no
	// entries. The publisher writes an entry, then removes it again. The desired list ([]) now
	// equals what the stale cache shows, but the server still holds the entry, so the write must
	// not be skipped.
	stale := true
	funcs := interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if artifactNode, ok := obj.(*artifactv1alpha1.ArtifactNode); ok && stale {
				artifactNode.Status.Artifacts = nil
			}
			return nil
		},
	}
	f := newSPFixture(t, &funcs, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", nil, nil)
	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)

	f.pub.Remove(artifact.KindRulesfile, "rf")
	_, err = f.pub.flush(t.Context())
	require.NoError(t, err)

	stale = false
	assert.Empty(t, f.stored(t), "the server must not keep an entry the sidecar removed")
}

func TestStatusPublisher_PatchReplacesOnlyTheArtifactsList(t *testing.T) {
	var body []byte
	funcs := interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			var err error
			body, err = patch.Data(obj)
			require.NoError(t, err)
			return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}
	f := newSPFixture(t, &funcs, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", nil, nil)
	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, []string{"status"}, slices.Collect(maps.Keys(got)), "no spec, metadata or resourceVersion: the sidecar owns only status")
	assert.Equal(t, []string{"artifacts"}, slices.Collect(maps.Keys(got["status"].(map[string]any))))
}

// Over the cap, the entry of an artifact the spec no longer assigns is what holds its parent: it is published
// before the entries of the assigned artifacts, which the spec holds.
func TestStatusPublisher_KeepsWithinTheSchemaCapPreferringArtifactsTheSpecNoLongerHolds(t *testing.T) {
	assigned := testutil.NewArtifactNode(spNamespace, spNode, func(s *artifactv1alpha1.ArtifactNode) {
		for i := range artifactv1alpha1.MaxNodeArtifacts {
			s.Spec.Artifacts = append(s.Spec.Artifacts,
				artifactv1alpha1.NodeArtifactRef{Kind: "Rulesfile", Name: fmt.Sprintf("rf-%03d", i), UID: "u"})
		}
	})
	f := newSPFixture(t, nil, assigned)
	for i := range artifactv1alpha1.MaxNodeArtifacts {
		f.pub.Set(artifact.KindRulesfile, fmt.Sprintf("rf-%03d", i), "u", nil, nil)
	}
	f.pub.Set(artifact.KindRulesfile, "zzz-removing", "u", nil, spInstalled()) // sorts last, and only its entry holds it

	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)

	got := f.stored(t)
	assert.Len(t, got, artifactv1alpha1.MaxNodeArtifacts)
	names := make([]string, 0, len(got))
	for _, e := range got {
		names = append(names, e.Name)
	}
	assert.Contains(t, names, "zzz-removing")
	assert.NotContains(t, names, "rf-099", "the assigned artifact left out waits for the removal")

	f.pub.Remove(artifact.KindRulesfile, "zzz-removing")
	_, err = f.pub.flush(t.Context())
	require.NoError(t, err)
	assert.Len(t, f.stored(t), artifactv1alpha1.MaxNodeArtifacts)
	assert.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf-099", "u", nil), "the removal made room")
}

func TestStatusPublisher_SetCopiesItsArguments(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	conds := spProgrammed(metav1.ConditionTrue)
	files := spInstalled()
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", conds, files)

	conds[0].Status = metav1.ConditionFalse // the reconciler goes on to mutate its own slices
	files[0].Path = "/changed"
	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)

	got := f.stored(t)[0]
	assert.Equal(t, metav1.ConditionTrue, got.Conditions[0].Status)
	assert.Equal(t, "/etc/falco/rules.d/rf.yaml", got.InstalledArtifacts[0].Path)
}

func TestStatusPublisher_StartPublishesAndCoalescesABurst(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = f.pub.Start(ctx) }()

	for i := range 20 {
		f.pub.Set(artifact.KindRulesfile, fmt.Sprintf("rf-%02d", i), "u", nil, nil)
	}

	require.Eventually(t, func() bool { return len(f.stored(t)) == 20 }, 2*time.Second, 5*time.Millisecond)
	assert.LessOrEqual(t, f.patches.Load(), int32(3), "a burst of updates is written in a few patches, not one per update")
}

func TestStatusPublisher_StartWaitsForTheObjectToAppear(t *testing.T) {
	f := newSPFixture(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = f.pub.Start(ctx) }()

	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", nil, nil)
	time.Sleep(30 * time.Millisecond)
	require.NoError(t, f.cl.Create(ctx, testutil.NewArtifactNode(spNamespace, spNode)))

	require.Eventually(t, func() bool { return len(f.stored(t)) == 1 }, 2*time.Second, 5*time.Millisecond)
}

func TestStatusPublisher_StartStopsWithItsContext(t *testing.T) {
	f := newSPFixture(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.pub.Start(ctx) }()

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after its context was canceled")
	}
}

// A write the API server rejects is tried again by the loop, after a delay that grows, until it lands.
func TestStatusPublisher_StartRetriesAFailedWriteUntilItLands(t *testing.T) {
	var calls atomic.Int32
	funcs := interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if calls.Add(1) <= 2 {
				return fmt.Errorf("apiserver unavailable")
			}
			return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}
	f := newSPFixture(t, &funcs, testutil.NewArtifactNode(spNamespace, spNode))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = f.pub.Start(ctx) }()

	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", nil, nil)

	require.Eventually(t, func() bool { return len(f.stored(t)) == 1 }, 3*time.Second, 5*time.Millisecond)
	assert.Equal(t, int32(3), calls.Load(), "two rejected writes, then the one that landed")
}

// What is pending when the publisher stops is written before it returns: here a removal, reported while the
// publisher was still letting the burst settle.
func TestStatusPublisher_PublishesWhatIsPendingWhenItStops(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.debounce = time.Hour
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", nil, nil)
	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)
	require.Len(t, f.stored(t), 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.pub.Start(ctx) }()

	f.pub.Remove(artifact.KindRulesfile, "rf")
	cancel()

	require.NoError(t, <-done)
	assert.Empty(t, f.stored(t))
}

// An ArtifactNode deleted and created again is another object, with an empty status: what the publisher wrote
// to the old one says nothing about it.
func TestStatusPublisher_WritesItsEntriesToARecreatedArtifactNode(t *testing.T) {
	first := testutil.NewArtifactNode(spNamespace, spNode)
	first.UID = "first"
	f := newSPFixture(t, nil, first)
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", nil, nil)
	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)

	require.NoError(t, f.cl.Delete(t.Context(), first))
	second := testutil.NewArtifactNode(spNamespace, spNode)
	second.UID = "second"
	require.NoError(t, f.cl.Create(t.Context(), second))
	select {
	case <-f.pub.wake: // the Set above
	default:
	}
	f.pub.Observe(second)
	select {
	case <-f.pub.wake:
	default:
		t.Fatal("seeing another object wakes the publisher")
	}
	_, err = f.pub.flush(t.Context())
	require.NoError(t, err)

	require.Len(t, f.stored(t), 1, "the entry is on the new object")
	assert.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "uid-rf", nil))
}

func TestStatusPublisher_ARejectedPatchIsRetried(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	funcs := interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if fail.Load() {
				return fmt.Errorf("apiserver unavailable")
			}
			return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}
	f := newSPFixture(t, &funcs, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", nil, nil)

	_, err := f.pub.flush(t.Context())
	require.Error(t, err)
	assert.Empty(t, f.stored(t))

	fail.Store(false)
	_, err = f.pub.flush(t.Context())
	require.NoError(t, err)
	assert.Len(t, f.stored(t), 1, "a failed write must not be remembered as written")
}

func TestStatusPublisher_DoesNotNeedLeaderElection(t *testing.T) {
	f := newSPFixture(t, nil)
	assert.False(t, f.pub.NeedLeaderElection(), "every node's sidecar publishes its own status")
}

func TestStatusPublisher_DoesNotRewriteWhatAPreviousProcessLeft(t *testing.T) {
	left := testutil.NewArtifactNode(spNamespace, spNode, func(n *artifactv1alpha1.ArtifactNode) {
		n.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{spStatus("Rulesfile", "rf", "uid-rf")}
	})
	f := newSPFixture(t, nil, left)

	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(0), f.patches.Load(), "a restart that changes nothing must not write")

	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionTrue), nil)
	_, err = f.pub.flush(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), f.patches.Load(), "a change is still written")
}

func TestStatusPublisher_WritesDrivenByABurstAreSpacedByTheMinimumInterval(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.minInterval = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = f.pub.Start(ctx) }()

	f.pub.Set(artifact.KindRulesfile, "a", "uid-a", nil, nil)
	require.Eventually(t, func() bool { return f.patches.Load() == 1 }, 2*time.Second, time.Millisecond)
	first := time.Now()

	f.pub.Set(artifact.KindRulesfile, "b", "uid-b", nil, nil)
	require.Eventually(t, func() bool { return f.patches.Load() == 2 }, 2*time.Second, time.Millisecond)

	assert.GreaterOrEqual(t, time.Since(first), 150*time.Millisecond)
}

func TestStatusPublisher_TheWriteBeforeAnInstallIsNotDelayedByTheMinimumInterval(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.minInterval = time.Hour

	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "a", "uid-a", nil))
	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "b", "uid-b", nil))

	assert.Equal(t, int32(2), f.patches.Load())
}

// storedNames lists the entries on the object as "Kind/name=uid".
func (f *spFixture) storedNames(t *testing.T) []string {
	t.Helper()
	stored := f.stored(t)
	names := make([]string, 0, len(stored))
	for _, e := range stored {
		names = append(names, string(e.Kind)+"/"+e.Name+"="+e.UID)
	}
	return names
}

// Every artifact the ArtifactNode lists gets an entry, in the one write, so the reconcilers find theirs persisted.
func TestStatusPublisher_ReservesAnEntryForEveryListedArtifact(t *testing.T) {
	listing := func(mods ...func(*artifactv1alpha1.ArtifactNode)) *artifactv1alpha1.ArtifactNode {
		return testutil.NewArtifactNode(spNamespace, spNode, append([]func(*artifactv1alpha1.ArtifactNode){func(n *artifactv1alpha1.ArtifactNode) {
			n.Spec.Artifacts = []artifactv1alpha1.NodeArtifactRef{spRef("Rulesfile", "a", "u1"), spRef("Plugin", "b", "u2")}
		}}, mods...)...)
	}
	tests := []struct {
		name        string
		node        *artifactv1alpha1.ArtifactNode
		prepare     func(*statusPublisher)
		want        []string
		wantPatches int32
	}{
		{name: "every listed artifact", node: listing(), want: []string{"Plugin/b=u2", "Rulesfile/a=u1"}, wantPatches: 1},
		{
			name: "an entry a reconciler has set is kept", node: listing(),
			prepare: func(p *statusPublisher) {
				p.Set(artifact.KindRulesfile, "a", "u1", spProgrammed(metav1.ConditionTrue), nil)
			},
			want:        []string{"Plugin/b=u2", "Rulesfile/a=u1"},
			wantPatches: 1,
		},
		{
			name: "an entry found on the object is kept, whatever the listing says",
			node: listing(func(n *artifactv1alpha1.ArtifactNode) {
				n.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{spStatus("Rulesfile", "a", "old-uid")}
			}),
			want:        []string{"Plugin/b=u2", "Rulesfile/a=old-uid"},
			wantPatches: 1,
		},
		{
			name: "an ArtifactNode being deleted gets none",
			node: listing(func(n *artifactv1alpha1.ArtifactNode) {
				n.Finalizers = []string{"test/finalizer"}
				now := metav1.Now()
				n.DeletionTimestamp = &now
			}),
			want:        []string{},
			wantPatches: 0,
		},
		{name: "nothing listed", node: testutil.NewArtifactNode(spNamespace, spNode), want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSPFixture(t, nil, tt.node)
			if tt.prepare != nil {
				tt.prepare(f.pub)
			}

			done, err := f.pub.flush(t.Context())

			require.NoError(t, err)
			require.True(t, done)
			assert.Equal(t, tt.want, f.storedNames(t))
			assert.Equal(t, tt.wantPatches, f.patches.Load())
		})
	}

	t.Run("a reconciler that ensures its entry finds it persisted", func(t *testing.T) {
		f := newSPFixture(t, nil, listing())
		_, err := f.pub.flush(t.Context())
		require.NoError(t, err)

		require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "a", "u1", nil))
		require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindPlugin, "b", "u2", nil))

		assert.Equal(t, int32(1), f.patches.Load(), "no further write for the entries that were reserved")
	})

	t.Run("observing the ArtifactNode reserves and asks for a write", func(t *testing.T) {
		f := newSPFixture(t, nil, listing())

		f.pub.Observe(listing())

		assert.True(t, f.pub.Has(artifact.KindRulesfile, "a"))
		assert.True(t, f.pub.Has(artifact.KindPlugin, "b"))
		select {
		case <-f.pub.wake:
		default:
			t.Fatal("a write must have been asked for")
		}
	})

	t.Run("observing an ArtifactNode again asks for nothing", func(t *testing.T) {
		f := newSPFixture(t, nil, listing())
		f.pub.Observe(listing())
		<-f.pub.wake

		f.pub.Observe(listing())

		select {
		case <-f.pub.wake:
			t.Fatal("nothing new to write")
		default:
		}
	})
}

func TestStatusPublisher_AReconcileThatChangedNothingAsksForNothing(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionTrue), spInstalled())
	_, err := f.pub.flush(t.Context())
	require.NoError(t, err)
	<-f.pub.wake
	version := f.pub.version

	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionTrue), spInstalled())

	assert.Equal(t, version, f.pub.version)
	select {
	case <-f.pub.wake:
		t.Fatal("nothing to write")
	default:
	}
	done, err := f.pub.flush(t.Context())
	require.NoError(t, err)
	assert.True(t, done)
	assert.Equal(t, int32(1), f.patches.Load())
}

func TestStatusPublisher_Has(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode, func(n *artifactv1alpha1.ArtifactNode) {
		n.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{spStatus("Config", "found", "u")}
	}))
	f.pub.Observe(testutil.NewArtifactNode(spNamespace, spNode, func(n *artifactv1alpha1.ArtifactNode) {
		n.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{spStatus("Config", "found", "u")}
	}))
	f.pub.Set(artifact.KindRulesfile, "set", "u", nil, nil)

	assert.True(t, f.pub.Has(artifact.KindConfig, "found"), "an entry a previous process left")
	assert.True(t, f.pub.Has(artifact.KindRulesfile, "set"), "an entry this process set")
	assert.False(t, f.pub.Has(artifact.KindPlugin, "none"))
}

func keyNames(keys []artifact.Ref) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = string(k.Kind) + "/" + k.Name
	}
	return out
}

func TestStatusPublisher_EntryReturnsWhatItHoldsAndWhatItFound(t *testing.T) {
	previous := testutil.NewArtifactNode(spNamespace, spNode, func(s *artifactv1alpha1.ArtifactNode) {
		s.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{spStatus("Rulesfile", "found", "uid-found")}
	})
	f := newSPFixture(t, nil, previous)
	f.pub.Set(artifact.KindRulesfile, "set", "uid-set", spProgrammed(metav1.ConditionTrue), nil)

	_, ok := f.pub.Entry(artifact.KindRulesfile, "found")
	assert.False(t, ok, "an entry on the object is not known until the object has been observed")

	got, ok := f.pub.Entry(artifact.KindRulesfile, "set")
	require.True(t, ok)
	assert.Equal(t, "uid-set", got.UID)

	f.pub.Observe(previous)
	got, ok = f.pub.Entry(artifact.KindRulesfile, "found")
	require.True(t, ok)
	assert.Equal(t, "uid-found", got.UID)

	_, ok = f.pub.Entry(artifact.KindPlugin, "found")
	assert.False(t, ok, "kind is part of the key")
}

func TestStatusPublisher_EntryIsACopy(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid", spProgrammed(metav1.ConditionTrue), nil)

	got, _ := f.pub.Entry(artifact.KindRulesfile, "rf")
	got.Conditions[0].Status = metav1.ConditionFalse

	again, _ := f.pub.Entry(artifact.KindRulesfile, "rf")
	assert.Equal(t, metav1.ConditionTrue, again.Conditions[0].Status)
}

func TestStatusPublisher_KeysCoverEntriesSetAndObserved(t *testing.T) {
	previous := testutil.NewArtifactNode(spNamespace, spNode, func(s *artifactv1alpha1.ArtifactNode) {
		s.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{
			spStatus("Rulesfile", "found", "u"), spStatus("Plugin", "both", "u"),
		}
	})
	f := newSPFixture(t, nil, previous)
	f.pub.Set(artifact.KindConfig, "set", "u", nil, nil)
	f.pub.Set(artifact.KindPlugin, "both", "u2", nil, nil)
	f.pub.Observe(previous)

	assert.ElementsMatch(t, []string{"Rulesfile/found", "Plugin/both", "Config/set"}, keyNames(f.pub.Keys()), "each artifact once")

	f.pub.Remove(artifact.KindRulesfile, "found")
	assert.NotContains(t, keyNames(f.pub.Keys()), "Rulesfile/found")
}

func TestStatusPublisher_EnsureEntryPersistsBeforeItReturns(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))

	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionFalse)))

	got := f.stored(t)
	require.Len(t, got, 1, "the entry must be on the server when ensureEntry returns, not merely queued")
	assert.Equal(t, "uid-rf", got[0].UID)
}

func TestStatusPublisher_EnsureEntryFailsWithoutTheObject(t *testing.T) {
	f := newSPFixture(t, nil)

	err := f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "uid-rf", nil)

	require.Error(t, err, "the caller must not install without an entry")
	_, held := f.pub.Entry(artifact.KindRulesfile, "rf")
	assert.True(t, held, "the entry is still held and reaches the object once it exists")
}

func TestStatusPublisher_EnsureEntryDoesNotWriteTwiceForTheSameEntry(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))

	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "uid-rf", nil))
	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "uid-rf", nil))

	assert.Equal(t, int32(1), f.patches.Load())
}

func TestStatusPublisher_EnsureEntryKeepsTheStateOfTheSameIncarnation(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	f.pub.Set(artifact.KindRulesfile, "rf", "uid-rf", spProgrammed(metav1.ConditionTrue), spInstalled())

	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "uid-rf", nil))

	got := f.stored(t)[0]
	assert.Equal(t, metav1.ConditionTrue, got.Conditions[0].Status, "an existing entry must not be reset")
	assert.NotEmpty(t, got.InstalledArtifacts)
}

func TestStatusPublisher_EnsureEntryReplacesAnEntryOfAnotherIncarnation(t *testing.T) {
	previous := testutil.NewArtifactNode(spNamespace, spNode, func(s *artifactv1alpha1.ArtifactNode) {
		s.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{spStatus("Rulesfile", "rf", "old-uid")}
	})
	f := newSPFixture(t, nil, previous)
	f.pub.Observe(previous)

	require.NoError(t, f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "rf", "new-uid", nil))

	assert.Equal(t, "new-uid", f.stored(t)[0].UID)
}

func TestStatusPublisher_EnsureEntryFailsWhenTheNodeIsOverTheCap(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	for i := range artifactv1alpha1.MaxNodeArtifacts {
		f.pub.Set(artifact.KindRulesfile, fmt.Sprintf("rf-%03d", i), "u", nil, nil)
	}

	err := f.pub.ensureEntry(t.Context(), artifact.KindRulesfile, "zzz-one-too-many", "u", nil)

	require.Error(t, err, "an entry that cannot be persisted must stop the install")
}

func TestStatusPublisher_EnsureEntryAndTheLoopCanRunTogether(t *testing.T) {
	f := newSPFixture(t, nil, testutil.NewArtifactNode(spNamespace, spNode))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = f.pub.Start(ctx) }()

	errs := make(chan error, 20)
	for i := range 20 {
		go func() {
			f.pub.Set(artifact.KindRulesfile, fmt.Sprintf("set-%02d", i), "u", nil, nil)
			errs <- f.pub.ensureEntry(ctx, artifact.KindPlugin, fmt.Sprintf("ensure-%02d", i), "u", nil)
		}()
	}
	for range 20 {
		require.NoError(t, <-errs)
	}
	require.Eventually(t, func() bool { return len(f.stored(t)) == 40 }, 2*time.Second, 5*time.Millisecond)
}

// A write that keeps failing is retried less and less often, up to a ceiling: every node has a publisher, and
// together they must not keep a failing API server busy.
func TestStatusPublisher_RetryDelayGrowsUpToACeiling(t *testing.T) {
	p := newStatusPublisher(nil, spNamespace, spNode, nil)
	p.retry, p.maxRetry = 2*time.Second, time.Minute

	var got []time.Duration
	for failures := 1; failures <= 8; failures++ {
		got = append(got, p.retryDelay(failures))
	}

	assert.Equal(t, []time.Duration{
		2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second,
		time.Minute, time.Minute, time.Minute,
	}, got)

	p.maxRetry = time.Second
	assert.Equal(t, 2*time.Second, p.retryDelay(5), "a ceiling below the retry delay does not shorten it")
}
