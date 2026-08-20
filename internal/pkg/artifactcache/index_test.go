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
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
)

func TestCache_Load(t *testing.T) {
	tests := []struct {
		name            string
		setup           func(t *testing.T, dir string)
		wantErrContains string
		check           func(t *testing.T, dir string, c *artifactcache.Cache)
	}{
		{
			name: "cold start with no snapshot file succeeds with an empty index",
			check: func(t *testing.T, _ string, c *artifactcache.Cache) {
				t.Helper()
				_, ok := c.Lookup("plugin", "ns", "json", "linux-amd64")
				assert.False(t, ok)
			},
		},
		{
			name: "creates the blobs directory if missing",
			check: func(t *testing.T, dir string, _ *artifactcache.Cache) {
				t.Helper()
				info, err := os.Stat(filepath.Join(dir, artifactcache.BlobsDir))
				require.NoError(t, err)
				assert.True(t, info.IsDir())
			},
		},
		{
			name: "corrupt snapshot file returns an error",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"), []byte("not json"), 0o600))
			},
			wantErrContains: "parse snapshot",
		},
		{
			name: "snapshot file that is actually a directory fails to read (not a missing-file case)",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(dir, "index.json"), 0o755))
			},
			wantErrContains: "read snapshot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			c := artifactcache.NewCache(dir)
			err := c.Load()

			if tt.wantErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, dir, c)
			}
		})
	}
}

func TestCache_Load_BlobsDirCannotBeCreated(t *testing.T) {
	base := t.TempDir()
	// cacheDir itself is a regular file, so MkdirAll(cacheDir/blobs) can't create anything
	// under it.
	cacheDir := filepath.Join(base, "not-a-dir")
	require.NoError(t, os.WriteFile(cacheDir, []byte("x"), 0o600))

	c := artifactcache.NewCache(cacheDir)
	err := c.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create blobs dir")
}

func TestCache_Dir(t *testing.T) {
	dir := t.TempDir()
	c := artifactcache.NewCache(dir)
	assert.Equal(t, dir, c.Dir())
}

func TestCache_Load_RestartResilience(t *testing.T) {
	dir := t.TempDir()

	first := artifactcache.NewCache(dir)
	require.NoError(t, first.Load())
	blobPath := filepath.Join(dir, "blobs", "plugin", "ref", "sha256-abc-linux-amd64")
	require.NoError(t, artifactcache.Store(blobPath, []byte("content"), 0o755))
	require.NoError(t, first.Set("plugin", "ns", "json", "linux-amd64", blobPath))

	second := artifactcache.NewCache(dir)
	require.NoError(t, second.Load())

	got, ok := second.Lookup("plugin", "ns", "json", "linux-amd64")
	require.True(t, ok)
	assert.Equal(t, blobPath, got)
}

func TestCache_Lookup(t *testing.T) {
	dir := t.TempDir()
	c := artifactcache.NewCache(dir)
	require.NoError(t, c.Load())

	blobAmd64 := filepath.Join(dir, "blobs", "amd64")
	blobArm64 := filepath.Join(dir, "blobs", "arm64")
	require.NoError(t, artifactcache.Store(blobAmd64, []byte("x"), 0o755))
	require.NoError(t, artifactcache.Store(blobArm64, []byte("x"), 0o755))
	require.NoError(t, c.Set("plugin", "ns", "json", "linux-amd64", blobAmd64))
	require.NoError(t, c.Set("plugin", "ns", "json", "linux-arm64", blobArm64))

	tests := []struct {
		name        string
		platformKey string
		wantBlob    string
		wantOK      bool
	}{
		{name: "amd64 hit", platformKey: "linux-amd64", wantBlob: blobAmd64, wantOK: true},
		{name: "arm64 hit, does not collide with amd64", platformKey: "linux-arm64", wantBlob: blobArm64, wantOK: true},
		{name: "miss on unknown platform key", platformKey: "linux-riscv64", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := c.Lookup("plugin", "ns", "json", tt.platformKey)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantBlob, got)
			}
		})
	}
}

func TestCache_Set(t *testing.T) {
	t.Run("first write indexes the blob and evicts nothing", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir)
		require.NoError(t, c.Load())

		blobPath := filepath.Join(dir, "blobs", "v1")
		require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o755))
		require.NoError(t, c.Set("rulesfile", "ns", "rules", "", blobPath))

		got, ok := c.Lookup("rulesfile", "ns", "rules", "")
		require.True(t, ok)
		assert.Equal(t, blobPath, got)
		assert.True(t, c.BlobExists(blobPath))
	})

	t.Run("overwrite evicts the old blob once nothing else references it (immediate eviction mode)", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir, artifactcache.WithEvictionGracePeriod(0))
		require.NoError(t, c.Load())

		oldBlob := filepath.Join(dir, "blobs", "v1")
		newBlob := filepath.Join(dir, "blobs", "v2")
		require.NoError(t, artifactcache.Store(oldBlob, []byte("v1"), 0o755))
		require.NoError(t, artifactcache.Store(newBlob, []byte("v2"), 0o755))

		require.NoError(t, c.Set("rulesfile", "ns", "rules", "", oldBlob))
		require.NoError(t, c.Set("rulesfile", "ns", "rules", "", newBlob))

		_, err := os.Stat(oldBlob)
		assert.True(t, os.IsNotExist(err), "old blob should have been removed")
		_, err = os.Stat(oldBlob + artifactcache.PermSuffix)
		assert.True(t, os.IsNotExist(err), "old blob's .perm companion should have been removed")
		assert.False(t, c.BlobExists(oldBlob))

		got, ok := c.Lookup("rulesfile", "ns", "rules", "")
		require.True(t, ok)
		assert.Equal(t, newBlob, got)
	})

	t.Run("evicting the last blob under a ref also removes the now-empty ref directory (immediate eviction mode)", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir, artifactcache.WithEvictionGracePeriod(0))
		require.NoError(t, c.Load())

		oldBlob := artifactcache.BlobPath(dir, "plugin", "old-ref", "sha256:old", "linux", "amd64")
		newBlob := artifactcache.BlobPath(dir, "plugin", "new-ref", "sha256:new", "linux", "amd64")
		require.NoError(t, artifactcache.Store(oldBlob, []byte("v1"), 0o755))
		require.NoError(t, artifactcache.Store(newBlob, []byte("v2"), 0o755))

		require.NoError(t, c.Set("plugin", "ns", "json", "linux-amd64", oldBlob))
		require.NoError(t, c.Set("plugin", "ns", "json", "linux-amd64", newBlob))

		_, err := os.Stat(filepath.Dir(oldBlob))
		assert.True(t, os.IsNotExist(err), "old-ref's now-empty directory should have been removed")
		_, err = os.Stat(filepath.Dir(newBlob))
		assert.NoError(t, err, "new-ref's directory (still holding newBlob) must survive")
	})

	t.Run("ref directory survives eviction while a sibling blob remains in it", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir)
		require.NoError(t, c.Load())

		// Same ref, different digests: both blobs share one ref directory.
		blob1 := artifactcache.BlobPath(dir, "plugin", "shared-ref", "sha256:aaa", "linux", "amd64")
		blob2 := artifactcache.BlobPath(dir, "plugin", "shared-ref", "sha256:bbb", "linux", "amd64")
		require.NoError(t, artifactcache.Store(blob1, []byte("v1"), 0o755))
		require.NoError(t, artifactcache.Store(blob2, []byte("v2"), 0o755))

		require.NoError(t, c.Set("plugin", "ns", "json", "linux-amd64", blob1))
		require.NoError(t, c.Set("plugin", "ns", "json", "linux-amd64", blob2))

		_, err := os.Stat(filepath.Dir(blob1))
		assert.NoError(t, err, "shared ref directory must survive: blob2 still lives in it")
		_, err = os.Stat(blob2)
		assert.NoError(t, err, "sibling blob must be untouched")
	})

	t.Run("overwrite keeps the old blob while another CR still references it", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir)
		require.NoError(t, c.Load())

		sharedBlob := filepath.Join(dir, "blobs", "shared")
		newBlob := filepath.Join(dir, "blobs", "new")
		require.NoError(t, artifactcache.Store(sharedBlob, []byte("x"), 0o755))
		require.NoError(t, artifactcache.Store(newBlob, []byte("y"), 0o755))

		require.NoError(t, c.Set("plugin", "ns", "a", "", sharedBlob))
		require.NoError(t, c.Set("plugin", "ns", "b", "", sharedBlob))
		require.NoError(t, c.Set("plugin", "ns", "a", "", newBlob))

		_, err := os.Stat(sharedBlob)
		require.NoError(t, err, "shared blob must survive: CR b still references it")
		assert.True(t, c.BlobExists(sharedBlob))

		got, ok := c.Lookup("plugin", "ns", "b", "")
		require.True(t, ok)
		assert.Equal(t, sharedBlob, got)
	})

	t.Run("old blob that can't be removed (non-empty directory) is logged and skipped (immediate eviction mode)", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir, artifactcache.WithEvictionGracePeriod(0))
		require.NoError(t, c.Load())

		// A blob path that's actually a non-empty directory: os.Remove fails, exercising
		// derefLocked's best-effort logged-and-swallowed branch.
		oldBlob := filepath.Join(dir, "blobs", "old-dir")
		require.NoError(t, os.MkdirAll(oldBlob, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(oldBlob, "occupied"), []byte("x"), 0o600))
		newBlob := filepath.Join(dir, "blobs", "v2")
		require.NoError(t, artifactcache.Store(newBlob, []byte("v2"), 0o755))

		require.NoError(t, c.Set("rulesfile", "ns", "rules", "", oldBlob))
		require.NoError(t, c.Set("rulesfile", "ns", "rules", "", newBlob))

		_, err := os.Stat(oldBlob)
		require.NoError(t, err, "removal failure must not be fatal, and the directory stays behind")
		assert.False(t, c.BlobExists(oldBlob), "refcount is still dropped even though the physical removal failed")
	})

	t.Run("overwrite dereferences the old blob but leaves it on disk pending eviction (default mode)", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir) // default: deferred eviction
		require.NoError(t, c.Load())

		oldBlob := filepath.Join(dir, "blobs", "v1")
		newBlob := filepath.Join(dir, "blobs", "v2")
		require.NoError(t, artifactcache.Store(oldBlob, []byte("v1"), 0o755))
		require.NoError(t, artifactcache.Store(newBlob, []byte("v2"), 0o755))

		require.NoError(t, c.Set("rulesfile", "ns", "rules", "", oldBlob))
		require.NoError(t, c.Set("rulesfile", "ns", "rules", "", newBlob))

		_, err := os.Stat(oldBlob)
		assert.NoError(t, err, "old blob must still be on disk, pending eviction by Sweep")
		assert.True(t, c.BlobExists(oldBlob),
			"a lingering blob must still report as existing so EnsureBlob can reuse it without a registry re-pull")

		got, ok := c.Lookup("rulesfile", "ns", "rules", "")
		require.True(t, ok)
		assert.Equal(t, newBlob, got)
	})

	t.Run("re-Set before eviction cancels the pending eviction (default mode)", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir) // default: deferred eviction
		require.NoError(t, c.Load())

		blob := filepath.Join(dir, "blobs", "v1")
		other := filepath.Join(dir, "blobs", "v2")
		require.NoError(t, artifactcache.Store(blob, []byte("v1"), 0o755))
		require.NoError(t, artifactcache.Store(other, []byte("v2"), 0o755))

		require.NoError(t, c.Set("rulesfile", "ns", "a", "", blob))
		require.NoError(t, c.Set("rulesfile", "ns", "a", "", other)) // dereferences blob, pending eviction
		require.NoError(t, c.Set("rulesfile", "ns", "b", "", blob))  // re-referenced by a different CR

		assert.True(t, c.BlobExists(blob))
		_, err := os.Stat(blob)
		assert.NoError(t, err)

		got, ok := c.Lookup("rulesfile", "ns", "b", "")
		require.True(t, ok)
		assert.Equal(t, blob, got)
	})

	t.Run("a blob path that can't be made relative to cacheDir is persisted as-is", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir)
		require.NoError(t, c.Load())

		// A relative blobPath can't be expressed relative to the (absolute) cacheDir via
		// filepath.Rel, exercising persistLocked's raw-fallback branch.
		require.NoError(t, c.Set("plugin", "ns", "json", "", "relative/blob"))

		got, ok := c.Lookup("plugin", "ns", "json", "")
		require.True(t, ok)
		assert.Equal(t, "relative/blob", got)
	})

	t.Run("snapshot write failure propagates", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission checks are bypassed when running as root")
		}
		dir := t.TempDir()
		c := artifactcache.NewCache(dir)
		require.NoError(t, c.Load())

		require.NoError(t, os.Chmod(dir, 0o500)) // read+execute only: no new files allowed
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		err := c.Set("plugin", "ns", "json", "", "/some/blob")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "write snapshot")
	})

	t.Run("snapshot rename failure propagates", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir)
		require.NoError(t, c.Load())

		// index.json is occupied by a directory, so the tmp-file rename can't land.
		require.NoError(t, os.Mkdir(filepath.Join(dir, "index.json"), 0o755))

		err := c.Set("plugin", "ns", "json", "", "/some/blob")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rename snapshot")
	})

	t.Run("-race: concurrent Lookup and Set", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir)
		require.NoError(t, c.Load())

		var wg sync.WaitGroup
		for range 20 {
			wg.Add(2)
			go func() {
				defer wg.Done()
				blobPath := filepath.Join(dir, "blobs", "concurrent")
				_ = artifactcache.Store(blobPath, []byte("x"), 0o755)
				_ = c.Set("plugin", "ns", "concurrent", "", blobPath)
			}()
			go func() {
				defer wg.Done()
				c.Lookup("plugin", "ns", "concurrent", "")
			}()
		}
		wg.Wait()
	})
}

func TestCache_RemoveAll(t *testing.T) {
	t.Run("removes every platform variant and evicts unreferenced blobs, leaves other CRs alone (immediate eviction mode)", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir, artifactcache.WithEvictionGracePeriod(0))
		require.NoError(t, c.Load())

		blobAmd64 := filepath.Join(dir, "blobs", "amd64")
		blobArm64 := filepath.Join(dir, "blobs", "arm64")
		otherBlob := filepath.Join(dir, "blobs", "other")
		require.NoError(t, artifactcache.Store(blobAmd64, []byte("x"), 0o755))
		require.NoError(t, artifactcache.Store(blobArm64, []byte("x"), 0o755))
		require.NoError(t, artifactcache.Store(otherBlob, []byte("x"), 0o755))
		require.NoError(t, c.Set("plugin", "ns", "json", "linux-amd64", blobAmd64))
		require.NoError(t, c.Set("plugin", "ns", "json", "linux-arm64", blobArm64))
		require.NoError(t, c.Set("plugin", "ns", "other-name", "", otherBlob))

		require.NoError(t, c.RemoveAll("plugin", "ns", "json"))

		_, ok := c.Lookup("plugin", "ns", "json", "linux-amd64")
		assert.False(t, ok)
		_, ok = c.Lookup("plugin", "ns", "json", "linux-arm64")
		assert.False(t, ok)
		_, err := os.Stat(blobAmd64)
		assert.True(t, os.IsNotExist(err))
		_, err = os.Stat(blobArm64)
		assert.True(t, os.IsNotExist(err))

		got, ok := c.Lookup("plugin", "ns", "other-name", "")
		require.True(t, ok, "unrelated CR's entry must survive RemoveAll for a different name")
		assert.Equal(t, otherBlob, got)
		_, err = os.Stat(otherBlob)
		assert.NoError(t, err)
	})

	t.Run("no-op when nothing is indexed for the CR", func(t *testing.T) {
		dir := t.TempDir()
		c := artifactcache.NewCache(dir)
		require.NoError(t, c.Load())

		require.NoError(t, c.RemoveAll("plugin", "ns", "missing"))
	})
}
