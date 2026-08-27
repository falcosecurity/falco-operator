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

package nodeartifacts_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

// TestPluginConfigRetrier_ForcesRewriteAfterMismatchPersists runs the retrier loop and verifies a
// persistent mismatch eventually triggers a forced rewrite, observed as a Rename call on the mock
// filesystem. It sleeps for a fixed duration and reads mockFS only after Start returns, since
// mockFS is not safe for concurrent access.
func TestPluginConfigRetrier_ForcesRewriteAfterMismatchPersists(t *testing.T) {
	mockFS := filesystem.NewMockFileSystem()
	store := &artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}
	m := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))
	fetcher := &artifact.Fetcher{}

	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)
	// Falco never reports "container" loaded: a permanent mismatch for this test's duration.
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcherWithPlugins(map[string]string{}).Result)
	require.True(t, m.PluginLoadMismatch())

	renamesBefore := len(mockFS.RenameCalls)

	retrier := nodeartifacts.NewPluginConfigRetrier(m, fetcher, time.Millisecond, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- retrier.Start(ctx) }()

	time.Sleep(200 * time.Millisecond) // ample margin over the 20ms grace period at a 1ms tick

	cancel()
	select {
	case startErr := <-done:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	assert.Greater(t, len(mockFS.RenameCalls), renamesBefore, "retrier never forced a rewrite for a persistent mismatch")
}

// TestPluginConfigRetrier_NoMismatchNeverRewrites verifies the retrier does not force a rewrite
// when desired and observed plugins already agree.
func TestPluginConfigRetrier_NoMismatchNeverRewrites(t *testing.T) {
	mockFS := filesystem.NewMockFileSystem()
	store := &artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}
	m := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))
	fetcher := &artifact.Fetcher{}

	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"}).Result)
	require.False(t, m.PluginLoadMismatch())

	renamesBefore := len(mockFS.RenameCalls)

	retrier := nodeartifacts.NewPluginConfigRetrier(m, fetcher, time.Millisecond, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- retrier.Start(ctx) }()

	// Let a good number of ticks pass; nothing should ever get rewritten.
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case startErr := <-done:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	assert.Len(t, mockFS.RenameCalls, renamesBefore, "no mismatch means no forced rewrite, ever")
}

// TestPluginConfigRetrier_ForceRewriteErrorIsLoggedAndRetried verifies a forced-rewrite failure
// does not stop the retrier loop; it retries on the next tick.
func TestPluginConfigRetrier_ForceRewriteErrorIsLoggedAndRetried(t *testing.T) {
	mockFS := filesystem.NewMockFileSystem()
	store := &artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}
	m := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))
	fetcher := &artifact.Fetcher{}

	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)
	m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcherWithPlugins(map[string]string{}).Result)
	mockFS.WriteErr = assert.AnError

	retrier := nodeartifacts.NewPluginConfigRetrier(m, fetcher, time.Millisecond, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- retrier.Start(ctx) }()

	time.Sleep(100 * time.Millisecond) // several failing attempts, must not crash the loop

	cancel()
	select {
	case startErr := <-done:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}
