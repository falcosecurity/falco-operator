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

// Package nodetest provides the test helpers built on a node.Node. They are apart from testutil so that the
// node package's own tests can use testutil.
package nodetest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// NewTestNode returns the Node of the test node, over cl, with a status publisher whose timings are
// short enough for a test to wait on, already started. The publisher stops with the test.
//
// It is how a test gets the Node its reconcilers are built from: every artifact the reconcilers
// install is mirrored to the test node's ArtifactNode, which RequirePublished then waits on.
func NewTestNode(t *testing.T, cl client.Client, opts ...func(*node.Config)) *node.Node {
	t.Helper()
	cfg := node.Config{
		Client:         cl,
		NodeName:       testutil.TestNodeName,
		Namespace:      testutil.TestNamespace,
		FalcoBaseURL:   compat.DefaultBaseURL,
		ReloadCooldown: node.DefaultReloadCooldown,
		// A real Fetcher over the test client: inline resolves from the bytes it is given, and
		// a ConfigMap source reads through cl like production does. Tests that need the artifact
		// server stub one in with WithFetcher.
		Fetcher:       &artifact.Fetcher{K8sClient: cl},
		StatusTimings: &node.StatusTimings{Debounce: 5 * time.Millisecond, Retry: 5 * time.Millisecond},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	n, err := node.New(&cfg)
	require.NoError(t, err)
	StartNode(t, n)
	return n
}

// StartNode starts the node's status publisher, which is the only runnable a test needs: the rest
// are registered with a controller-runtime manager by Node.AddToManager. It stops with the test.
func StartNode(t *testing.T, n *node.Node) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = n.RunStatusPublisher(ctx) }()
}

// WithStore makes the test node write through store instead of the real filesystem.
func WithStore(store artifact.ArtifactStore) func(*node.Config) {
	return func(cfg *node.Config) { cfg.Store = store }
}

// WithRecorder makes the test node emit its Events through recorder. The node sets conditions and
// emits the Events that go with them, so a test asserting events has to give it the same recorder
// its reconciler uses.
func WithRecorder(recorder events.EventRecorder) func(*node.Config) {
	return func(cfg *node.Config) { cfg.Recorder = recorder }
}

// WithFetcher makes the test node resolve artifact content through fetcher.
func WithFetcher(fetcher artifact.ArtifactFetcher) func(*node.Config) {
	return func(cfg *node.Config) { cfg.Fetcher = fetcher }
}

// WithEnforceRequirements sets whether the test node blocks installs whose requirements Falco does not satisfy.
func WithEnforceRequirements(enforce bool) func(*node.Config) {
	return func(cfg *node.Config) { cfg.EnforceRequirements = enforce }
}

// WithFalcoFetcher makes the test node read Falco's capabilities from fetcher.
func WithFalcoFetcher(fetcher compat.VersionsFetcher) func(*node.Config) {
	return func(cfg *node.Config) { cfg.FalcoFetcher = fetcher }
}

// NewTestNodeOn is NewTestNode writing to fs, emitting its Events through recorder and reading no Falco
// capabilities, which is what most reconciler tests need; opts come on top.
func NewTestNodeOn(
	t *testing.T, cl client.Client, fs filesystem.FileSystem, recorder events.EventRecorder, opts ...func(*node.Config),
) *node.Node {
	t.Helper()
	all := make([]func(*node.Config), 0, 3+len(opts))
	all = append(all,
		WithStore(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}),
		WithRecorder(recorder),
		WithFalcoFetcher(compatfake.NewMockVersionsFetcher(nil)),
	)
	return NewTestNode(t, cl, append(all, opts...)...)
}

// Prime makes n know what the ArtifactNodes among objs say, as a warm sync would on startup: the installed
// files their status lists, and their spec.
func Prime(n *node.Node, objs []client.Object) {
	for _, obj := range objs {
		artifactNode, ok := obj.(*artifactv1alpha1.ArtifactNode)
		if !ok {
			continue
		}
		for _, entry := range artifactNode.Status.Artifacts {
			if len(entry.InstalledArtifacts) == 0 {
				continue
			}
			n.SeedInstalled(artifact.RefOfStatus(&entry), entry.InstalledArtifacts)
		}
	}
	for _, obj := range objs {
		if artifactNode, ok := obj.(*artifactv1alpha1.ArtifactNode); ok {
			n.ObserveArtifactNode(artifactNode)
		}
	}
}

// AssertNothingDone asserts that n holds no conditions and no installed files for the artifact.
func AssertNothingDone(t *testing.T, n *node.Node, kind artifact.Kind, name, why string) {
	t.Helper()
	entry, _ := n.StatusEntry(kind, name)
	assert.Empty(t, entry.Conditions, why)
	assert.Empty(t, entry.InstalledArtifacts, why)
}

// InstallConfig puts a Config's file on the node, as a reconcile of the Config would. The install persists
// the Config's status entry to the node's ArtifactNode first, so when cl holds none, one stands in for the
// install and is deleted afterwards.
func InstallConfig(t *testing.T, cl client.Client, n *node.Node, name string) {
	t.Helper()
	ctx := t.Context()
	standIn := testutil.NewTestArtifactNode()
	err := cl.Create(ctx, standIn)
	created := err == nil
	if !created {
		require.True(t, k8serrors.IsAlreadyExists(err), "creating the stand-in ArtifactNode: %v", err)
	}
	require.NoError(t, n.ApplyArtifact(ctx, &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: name, UID: types.UID(name + "-uid")},
		Spec:       artifactv1alpha1.ConfigSpec{Config: &apiextensionsv1.JSON{Raw: []byte(`{"a":"b"}`)}, Priority: 50},
	}, &artifactv1alpha1.NodeArtifactStatus{}))
	if created {
		require.NoError(t, cl.Delete(ctx, standIn))
	}
}

// RemovalsRequested returns, as "Kind/name", the removals asked of n's reconcilers since the last call.
func RemovalsRequested(n *node.Node) []string {
	var got []string
	for _, kind := range []artifact.Kind{artifact.KindRulesfile, artifact.KindConfig, artifact.KindPlugin} {
		ch := n.RemovalRequests(kind)
		for drained := false; !drained; {
			select {
			case ev := <-ch:
				got = append(got, string(kind)+"/"+ev.Object.GetName())
			default:
				drained = true
			}
		}
	}
	return got
}
