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

package artifactcache_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
)

func TestCache_Sweep(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, dir string, c *artifactcache.Cache) (blobPath string)
		wantRemoved int
		wantGone    bool
	}{
		{
			name: "orphaned blob past the grace window is removed, .perm companion too",
			setup: func(t *testing.T, dir string, _ *artifactcache.Cache) string {
				t.Helper()
				blobPath := filepath.Join(dir, "blobs", "orphan-old")
				require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o755))
				old := time.Now().Add(-time.Hour)
				require.NoError(t, os.Chtimes(blobPath, old, old))
				return blobPath
			},
			wantRemoved: 1,
			wantGone:    true,
		},
		{
			name: "orphaned blob within the grace window is skipped",
			setup: func(t *testing.T, dir string, _ *artifactcache.Cache) string {
				t.Helper()
				blobPath := filepath.Join(dir, "blobs", "orphan-fresh")
				require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o755))
				return blobPath
			},
			wantRemoved: 0,
			wantGone:    false,
		},
		{
			name: "referenced blob is never touched regardless of age",
			setup: func(t *testing.T, dir string, c *artifactcache.Cache) string {
				t.Helper()
				blobPath := filepath.Join(dir, "blobs", "referenced")
				require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o755))
				old := time.Now().Add(-time.Hour)
				require.NoError(t, os.Chtimes(blobPath, old, old))
				require.NoError(t, c.Set("plugin", "ns", "json", "", blobPath))
				return blobPath
			},
			wantRemoved: 0,
			wantGone:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			c := artifactcache.NewCache(dir)
			require.NoError(t, c.Load())
			blobPath := tt.setup(t, dir, c)

			removed, err := c.Sweep(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.wantRemoved, removed)

			_, statErr := os.Stat(blobPath)
			if tt.wantGone {
				assert.True(t, os.IsNotExist(statErr))
				_, permErr := os.Stat(blobPath + artifactcache.PermSuffix)
				assert.True(t, os.IsNotExist(permErr), ".perm companion should be removed alongside its blob")
			} else {
				assert.NoError(t, statErr)
			}
		})
	}
}

func TestCache_Sweep_BlobsDirUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks are bypassed when running as root")
	}
	dir := t.TempDir()
	c := artifactcache.NewCache(dir)
	require.NoError(t, c.Load())

	blobsDir := filepath.Join(dir, artifactcache.BlobsDir)
	require.NoError(t, os.Chmod(blobsDir, 0o000))
	t.Cleanup(func() { _ = os.Chmod(blobsDir, 0o755) })

	_, err := c.Sweep(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "walk blobs dir")
}

func TestCache_Sweep_RemovesNowEmptyRefDirectory(t *testing.T) {
	dir := t.TempDir()
	c := artifactcache.NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := artifactcache.BlobPath(dir, "plugin", "orphan-ref", "sha256:old", "linux", "amd64")
	require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o755))
	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(blobPath, old, old))

	removed, err := c.Sweep(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	_, statErr := os.Stat(filepath.Dir(blobPath))
	assert.True(t, os.IsNotExist(statErr), "orphan-ref's now-empty directory should have been removed")
}

func TestCache_Sweep_RefDirectorySurvivesWithSiblingBlob(t *testing.T) {
	dir := t.TempDir()
	c := artifactcache.NewCache(dir)
	require.NoError(t, c.Load())

	// Same ref, two digests: one orphaned and old, one still referenced.
	orphan := artifactcache.BlobPath(dir, "plugin", "shared-ref", "sha256:old", "linux", "amd64")
	kept := artifactcache.BlobPath(dir, "plugin", "shared-ref", "sha256:new", "linux", "amd64")
	require.NoError(t, artifactcache.Store(orphan, []byte("x"), 0o755))
	require.NoError(t, artifactcache.Store(kept, []byte("y"), 0o755))
	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(orphan, old, old))
	require.NoError(t, c.Set("plugin", "ns", "json", "linux-amd64", kept))

	removed, err := c.Sweep(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	_, statErr := os.Stat(filepath.Dir(orphan))
	assert.NoError(t, statErr, "shared ref directory must survive: kept blob still lives in it")
	_, statErr = os.Stat(kept)
	assert.NoError(t, statErr, "referenced sibling blob must be untouched")
}

func TestCache_Sweep_NoBlobsDirYet(t *testing.T) {
	dir := t.TempDir()
	c := artifactcache.NewCache(dir)
	// Deliberately not calling Load, so blobs/ was never created.
	removed, err := c.Sweep(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, removed)
}

func TestSweeper_Start_SweepErrorIsLoggedAndRetried(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks are bypassed when running as root")
	}
	dir := t.TempDir()
	c := artifactcache.NewCache(dir)
	require.NoError(t, c.Load())

	blobsDir := filepath.Join(dir, artifactcache.BlobsDir)
	require.NoError(t, os.Chmod(blobsDir, 0o000))
	t.Cleanup(func() { _ = os.Chmod(blobsDir, 0o755) })

	sweeper := artifactcache.NewSweeper(c, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sweeper.Start(ctx) }()

	time.Sleep(100 * time.Millisecond) // let a few failing ticks fire without the loop dying

	cancel()
	select {
	case startErr := <-done:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestSweeper_Start(t *testing.T) {
	dir := t.TempDir()
	c := artifactcache.NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := filepath.Join(dir, "blobs", "orphan")
	require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o755))
	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(blobPath, old, old))

	sweeper := artifactcache.NewSweeper(c, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- sweeper.Start(ctx) }()

	require.Eventually(t, func() bool {
		_, statErr := os.Stat(blobPath)
		return os.IsNotExist(statErr)
	}, 2*time.Second, 20*time.Millisecond, "sweeper never removed the orphaned blob")

	cancel()
	select {
	case startErr := <-done:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

// TestSweeper_Start_DeferredEviction is the end-to-end counterpart to the white-box
// removeExpiredDerefsLocked tests: a dereferenced blob survives immediately (pending its
// grace period), then gets removed once both the grace period and a sweep tick have passed.
func TestSweeper_Start_DeferredEviction(t *testing.T) {
	dir := t.TempDir()
	c := artifactcache.NewCache(dir, artifactcache.WithEvictionGracePeriod(50*time.Millisecond))
	require.NoError(t, c.Load())

	oldBlob := filepath.Join(dir, "blobs", "v1")
	newBlob := filepath.Join(dir, "blobs", "v2")
	require.NoError(t, artifactcache.Store(oldBlob, []byte("v1"), 0o755))
	require.NoError(t, artifactcache.Store(newBlob, []byte("v2"), 0o755))
	require.NoError(t, c.Set("rulesfile", "ns", "rules", "", oldBlob))
	require.NoError(t, c.Set("rulesfile", "ns", "rules", "", newBlob)) // dereferences oldBlob

	_, err := os.Stat(oldBlob)
	require.NoError(t, err, "dereferenced blob must survive immediately, pending its grace period")

	sweeper := artifactcache.NewSweeper(c, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- sweeper.Start(ctx) }()

	require.Eventually(t, func() bool {
		_, statErr := os.Stat(oldBlob)
		return os.IsNotExist(statErr)
	}, 2*time.Second, 20*time.Millisecond, "sweeper never removed the dereferenced blob after its grace period elapsed")

	cancel()
	select {
	case startErr := <-done:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}
