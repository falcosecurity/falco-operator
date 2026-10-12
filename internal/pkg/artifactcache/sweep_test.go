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

package artifactcache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache_Sweep(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, dir string, c *Cache) (blobPath string)
		wantRemoved int
		wantGone    bool
	}{
		{
			name: "orphaned blob past the grace window is removed, .perm companion too",
			setup: func(t *testing.T, dir string, c *Cache) string {
				t.Helper()
				blobPath := filepath.Join(dir, "blobs", "orphan-old")
				require.NoError(t, c.Store(blobPath, []byte("x"), 0o755))
				old := time.Now().Add(-time.Hour)
				require.NoError(t, os.Chtimes(blobPath, old, old))
				return blobPath
			},
			wantRemoved: 1,
			wantGone:    true,
		},
		{
			name: "orphaned blob within the grace window is skipped",
			setup: func(t *testing.T, dir string, c *Cache) string {
				t.Helper()
				blobPath := filepath.Join(dir, "blobs", "orphan-fresh")
				require.NoError(t, c.Store(blobPath, []byte("x"), 0o755))
				return blobPath
			},
			wantRemoved: 0,
			wantGone:    false,
		},
		{
			name: "referenced blob is never touched regardless of age",
			setup: func(t *testing.T, dir string, c *Cache) string {
				t.Helper()
				blobPath := filepath.Join(dir, "blobs", "referenced")
				require.NoError(t, c.Store(blobPath, []byte("x"), 0o755))
				old := time.Now().Add(-time.Hour)
				require.NoError(t, os.Chtimes(blobPath, old, old))
				require.NoError(t, c.Set("Plugin", "ns", "json", "", blobPath))
				return blobPath
			},
			wantRemoved: 0,
			wantGone:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			c := NewCache(dir)
			require.NoError(t, c.Load())
			blobPath := tt.setup(t, dir, c)

			removed, err := c.Sweep(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.wantRemoved, removed)

			_, statErr := os.Stat(blobPath)
			if tt.wantGone {
				assert.True(t, os.IsNotExist(statErr))
				_, permErr := os.Stat(blobPath + PermSuffix)
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
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobsDir := filepath.Join(dir, BlobsDir)
	require.NoError(t, os.Chmod(blobsDir, 0o000))
	t.Cleanup(func() { _ = os.Chmod(blobsDir, 0o755) })

	_, err := c.Sweep(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "walk blobs dir")
}

func TestCache_Sweep_RemovesNowEmptyRefDirectory(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := BlobPath(dir, "Plugin", "orphan-ref", "sha256:old", "linux", "amd64")
	require.NoError(t, c.Store(blobPath, []byte("x"), 0o755))
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
	c := NewCache(dir)
	require.NoError(t, c.Load())

	// Same ref, two digests: one orphaned and old, one still referenced.
	orphan := BlobPath(dir, "Plugin", "shared-ref", "sha256:old", "linux", "amd64")
	kept := BlobPath(dir, "Plugin", "shared-ref", "sha256:new", "linux", "amd64")
	require.NoError(t, c.Store(orphan, []byte("x"), 0o755))
	require.NoError(t, c.Store(kept, []byte("y"), 0o755))
	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(orphan, old, old))
	require.NoError(t, c.Set("Plugin", "ns", "json", "linux-amd64", kept))

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
	c := NewCache(dir)
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
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobsDir := filepath.Join(dir, BlobsDir)
	require.NoError(t, os.Chmod(blobsDir, 0o000))
	t.Cleanup(func() { _ = os.Chmod(blobsDir, 0o755) })

	sweeper := NewSweeper(c, 10*time.Millisecond)
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
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := filepath.Join(dir, "blobs", "orphan")
	require.NoError(t, c.Store(blobPath, []byte("x"), 0o755))
	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(blobPath, old, old))

	sweeper := NewSweeper(c, 10*time.Millisecond)
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
	c := NewCache(dir, WithEvictionGracePeriod(50*time.Millisecond))
	require.NoError(t, c.Load())

	oldBlob := filepath.Join(dir, "blobs", "v1")
	newBlob := filepath.Join(dir, "blobs", "v2")
	require.NoError(t, c.Store(oldBlob, []byte("v1"), 0o755))
	require.NoError(t, c.Store(newBlob, []byte("v2"), 0o755))
	require.NoError(t, c.Set("Rulesfile", "ns", "rules", "", oldBlob))
	require.NoError(t, c.Set("Rulesfile", "ns", "rules", "", newBlob)) // dereferences oldBlob

	_, err := os.Stat(oldBlob)
	require.NoError(t, err, "dereferenced blob must survive immediately, pending its grace period")

	sweeper := NewSweeper(c, 10*time.Millisecond)
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

// TestRemoveOrphansLocked_SkipsReReferenced exercises the TOCTOU re-check inside
// removeOrphansLocked directly: a candidate that became referenced again after
// findOrphanCandidates took its snapshot (but before the write lock was acquired) must
// survive. This race window isn't reproducible deterministically through the public
// Sweep API, so it's tested white-box instead.
func TestRemoveOrphansLocked_SkipsReReferenced(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := filepath.Join(dir, BlobsDir, "reref")
	require.NoError(t, store(blobPath, []byte("x"), 0o755))

	c.mu.Lock()
	c.refs[blobPath] = 1
	c.mu.Unlock()

	removed := c.removeOrphansLocked(logr.Discard(), []string{blobPath})

	assert.Equal(t, 0, removed)
	_, err := os.Stat(blobPath)
	assert.NoError(t, err, "re-referenced blob must survive")
}

// TestRemoveOrphansLocked_SkipsFreshlyRewrittenCandidate covers the Store-to-Set window when
// Sweep discovered an old orphan immediately before a reconciler rewrote the same digest path.
func TestRemoveOrphansLocked_SkipsFreshlyRewrittenCandidate(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := filepath.Join(dir, BlobsDir, "rewritten")
	require.NoError(t, store(blobPath, []byte("old orphan"), 0o755))
	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(blobPath, old, old))

	candidates, err := c.findOrphanCandidates(map[string]int{}, map[string]time.Time{})
	require.NoError(t, err)
	require.Contains(t, candidates, blobPath)

	require.NoError(t, c.Store(blobPath, []byte("fresh content"), 0o755))
	c.mu.Lock()
	removed := c.removeOrphansLocked(logr.Discard(), candidates)
	c.mu.Unlock()

	assert.Equal(t, 0, removed)
	content, err := os.ReadFile(blobPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("fresh content"), content)
}

// TestRemoveOrphansLocked_RemovalFailureIsLoggedAndSkipped exercises the best-effort
// os.Remove-failure branch: a candidate that can't actually be unlinked (here, a
// non-empty directory masquerading as a blob path) is logged and left in place rather
// than treated as an error.
func TestRemoveOrphansLocked_RemovalFailureIsLoggedAndSkipped(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := filepath.Join(dir, BlobsDir, "undeletable")
	require.NoError(t, os.MkdirAll(blobPath, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(blobPath, "occupied"), []byte("x"), 0o600))

	removed := c.removeOrphansLocked(logr.Discard(), []string{blobPath})

	assert.Equal(t, 0, removed)
	_, err := os.Stat(blobPath)
	assert.NoError(t, err, "removal failure must not be fatal")
}

// TestRemoveExpiredDerefsLocked_RemovesExpiredEntry exercises the deferred-eviction deletion
// path directly, since waiting out a real evictionGracePeriod isn't practical in a test: a
// blob whose derefTimes entry is older than evictionGracePeriod is deleted, along with its
// .perm companion and now-empty ref directory.
func TestRemoveExpiredDerefsLocked_RemovesExpiredEntry(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir) // default evictionGracePeriod (DefaultEvictionGracePeriod)
	require.NoError(t, c.Load())

	blobPath := BlobPath(dir, "Plugin", "expired-ref", "sha256:old", "linux", "amd64")
	require.NoError(t, store(blobPath, []byte("x"), 0o755))

	c.mu.Lock()
	c.derefTimes[blobPath] = time.Now().Add(-time.Hour) // well past DefaultEvictionGracePeriod
	c.mu.Unlock()

	removed := c.removeExpiredDerefsLocked(logr.Discard())

	assert.Equal(t, 1, removed)
	_, err := os.Stat(blobPath)
	assert.True(t, os.IsNotExist(err), "expired blob should have been removed")
	_, err = os.Stat(blobPath + PermSuffix)
	assert.True(t, os.IsNotExist(err), ".perm companion should have been removed")
	_, err = os.Stat(filepath.Dir(blobPath))
	assert.True(t, os.IsNotExist(err), "now-empty ref directory should have been removed")

	c.mu.Lock()
	_, stillPending := c.derefTimes[blobPath]
	c.mu.Unlock()
	assert.False(t, stillPending)
}

// TestRemoveExpiredDerefsLocked_SkipsWithinGracePeriod ensures a blob that was only just
// dereferenced survives, the whole point of deferred eviction.
func TestRemoveExpiredDerefsLocked_SkipsWithinGracePeriod(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := filepath.Join(dir, BlobsDir, "fresh")
	require.NoError(t, store(blobPath, []byte("x"), 0o755))

	c.mu.Lock()
	c.derefTimes[blobPath] = time.Now()
	c.mu.Unlock()

	removed := c.removeExpiredDerefsLocked(logr.Discard())

	assert.Equal(t, 0, removed)
	_, err := os.Stat(blobPath)
	assert.NoError(t, err, "blob within its grace period must survive")
}

// TestRemoveExpiredDerefsLocked_RemovalFailureIsLoggedAndSkipped mirrors
// TestRemoveOrphansLocked_RemovalFailureIsLoggedAndSkipped: an expired entry that can't
// actually be unlinked (a non-empty directory masquerading as a blob path) is logged and
// dropped from derefTimes rather than treated as fatal: it falls through to the ordinary
// orphan-sweep path on the next cycle instead of being retried here forever.
func TestRemoveExpiredDerefsLocked_RemovalFailureIsLoggedAndSkipped(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := filepath.Join(dir, BlobsDir, "undeletable")
	require.NoError(t, os.MkdirAll(blobPath, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(blobPath, "occupied"), []byte("x"), 0o600))

	c.mu.Lock()
	c.derefTimes[blobPath] = time.Now().Add(-time.Hour)
	c.mu.Unlock()

	removed := c.removeExpiredDerefsLocked(logr.Discard())

	assert.Equal(t, 0, removed)
	_, err := os.Stat(blobPath)
	assert.NoError(t, err, "removal failure must not be fatal")

	c.mu.Lock()
	_, stillPending := c.derefTimes[blobPath]
	c.mu.Unlock()
	assert.False(t, stillPending, "entry is dropped from derefTimes regardless, falling through to the orphan sweep")
}

// TestFindOrphanCandidates_SkipsPendingDeref and TestRemoveOrphansLocked_SkipsPendingDeref
// together cover the interaction-safety guarantee described in Sweep's doc comment: a blob
// currently within its own eviction grace period must never be caught by the disk-orphan
// path, even though its file mtime is almost always already older than sweepGraceWindow by
// the time it's dereferenced (a long-lived blob was written well before it was ever
// dereferenced).
func TestFindOrphanCandidates_SkipsPendingDeref(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := filepath.Join(dir, BlobsDir, "pending")
	require.NoError(t, store(blobPath, []byte("x"), 0o755))
	old := time.Now().Add(-time.Hour) // mtime well past sweepGraceWindow
	require.NoError(t, os.Chtimes(blobPath, old, old))

	candidates, err := c.findOrphanCandidates(map[string]int{}, map[string]time.Time{blobPath: time.Now()})
	require.NoError(t, err)
	assert.NotContains(t, candidates, blobPath)
}

func TestRemoveOrphansLocked_SkipsPendingDeref(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	require.NoError(t, c.Load())

	blobPath := filepath.Join(dir, BlobsDir, "pending")
	require.NoError(t, store(blobPath, []byte("x"), 0o755))

	c.mu.Lock()
	c.derefTimes[blobPath] = time.Now() // within its own grace period
	c.mu.Unlock()

	// Simulate a stale pre-walk snapshot that missed the pending entry and wrongly included
	// this path as an orphan candidate anyway. removeOrphansLocked's live derefTimes check
	// must still catch it.
	removed := c.removeOrphansLocked(logr.Discard(), []string{blobPath})

	assert.Equal(t, 0, removed)
	_, err := os.Stat(blobPath)
	assert.NoError(t, err, "a blob pending its own eviction grace period must survive the orphan sweep")
}
