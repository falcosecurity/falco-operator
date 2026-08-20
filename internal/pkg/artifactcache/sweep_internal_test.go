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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	require.NoError(t, Store(blobPath, []byte("x"), 0o755))

	c.mu.Lock()
	c.refs[blobPath] = 1
	c.mu.Unlock()

	removed := c.removeOrphansLocked(logr.Discard(), []string{blobPath})

	assert.Equal(t, 0, removed)
	_, err := os.Stat(blobPath)
	assert.NoError(t, err, "re-referenced blob must survive")
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

	blobPath := BlobPath(dir, "plugin", "expired-ref", "sha256:old", "linux", "amd64")
	require.NoError(t, Store(blobPath, []byte("x"), 0o755))

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
	require.NoError(t, Store(blobPath, []byte("x"), 0o755))

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
	require.NoError(t, Store(blobPath, []byte("x"), 0o755))
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
	require.NoError(t, Store(blobPath, []byte("x"), 0o755))

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
