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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

const snapshotFile = "index.json"

const snapshotVersion = 1

// DefaultEvictionGracePeriod is how long a dereferenced blob lingers on disk, still servable via
// BlobExists, before Sweep deletes it. It lets a delete-then-recreate of the same artifact reuse
// the blob instead of triggering a fresh registry pull.
const DefaultEvictionGracePeriod = 10 * time.Minute

// indexKey identifies one CR's cache slot. PlatformKey is "" for rulesfiles.
type indexKey struct {
	ArtifactType string
	Namespace    string
	Name         string
	PlatformKey  string
}

// Cache is the in-memory index of cached OCI artifact blobs, backed by a single snapshot file
// under cacheDir for restart resilience. It is the shared coordination point between the writer
// reconcilers (Plugin/Rulesfile aggregator controllers) and the reader (artifactserver.Server),
// which run in the same process and share one *Cache instance. Blob content under blobs/ is
// addressed via BlobPath/Store/ReadPerm; Cache owns the index/refcount/eviction layer on top.
type Cache struct {
	mu       sync.RWMutex
	cacheDir string
	index    map[indexKey]string // -> absolute blobPath
	refs     map[string]int      // blobPath -> number of index entries pointing at it

	// derefTimes tracks blobs whose refcount just dropped to zero, so Sweep can delete them
	// once evictionGracePeriod has elapsed instead of derefLocked deleting them immediately.
	// Not persisted to the snapshot: entries still pending at a crash/restart just fall back
	// to the ordinary disk-orphan sweep path (findOrphanCandidates), which is self-healing.
	derefTimes          map[string]time.Time
	evictionGracePeriod time.Duration
}

// Option configures optional Cache behavior.
type Option func(*Cache)

// WithEvictionGracePeriod overrides how long a dereferenced blob lingers on disk before Sweep
// deletes it (default DefaultEvictionGracePeriod). Zero means immediate removal: derefLocked
// deletes the blob synchronously instead of deferring to Sweep.
func WithEvictionGracePeriod(d time.Duration) Option {
	return func(c *Cache) { c.evictionGracePeriod = d }
}

// NewCache creates a Cache rooted at cacheDir. Call Load once before any other method.
func NewCache(cacheDir string, opts ...Option) *Cache {
	c := &Cache{
		cacheDir:            cacheDir,
		index:               make(map[indexKey]string),
		refs:                make(map[string]int),
		derefTimes:          make(map[string]time.Time),
		evictionGracePeriod: DefaultEvictionGracePeriod,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Dir returns the cache root directory, for callers that still need to compute a blob
// path via BlobPath.
func (c *Cache) Dir() string {
	return c.cacheDir
}

// snapshot is the on-disk representation of the index, atomically rewritten on every
// mutation. Reference counts are not part of it: they're purely derived from Entries and
// are recomputed by Load.
type snapshot struct {
	Version int             `json:"version"`
	Entries []snapshotEntry `json:"entries"`
}

type snapshotEntry struct {
	ArtifactType string `json:"artifactType"`
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	PlatformKey  string `json:"platformKey,omitempty"`
	BlobPath     string `json:"blobPath"` // relative to cacheDir
}

// Load reads cacheDir's snapshot file into memory and recomputes reference counts from
// the loaded index. A missing snapshot file is not an error: Load starts empty. Load also
// ensures cacheDir/blobs exists.
// Not safe to call concurrently with other methods; call once at process startup.
func (c *Cache) Load() error {
	if err := os.MkdirAll(filepath.Join(c.cacheDir, BlobsDir), 0o750); err != nil {
		return fmt.Errorf("create blobs dir: %w", err)
	}

	data, err := os.ReadFile(filepath.Join(c.cacheDir, snapshotFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}

	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("parse snapshot: %w", err)
	}

	index := make(map[indexKey]string, len(snap.Entries))
	refs := make(map[string]int, len(snap.Entries))
	for _, e := range snap.Entries {
		blobPath := e.BlobPath
		if !filepath.IsAbs(blobPath) {
			blobPath = filepath.Join(c.cacheDir, blobPath)
		}
		index[indexKey{e.ArtifactType, e.Namespace, e.Name, e.PlatformKey}] = blobPath
		refs[blobPath]++
	}

	c.mu.Lock()
	c.index = index
	c.refs = refs
	c.derefTimes = make(map[string]time.Time)
	c.mu.Unlock()
	return nil
}

// Lookup returns the current absolute blob path indexed for (artifactType, namespace, name,
// platformKey), or ok=false if nothing is cached yet. Pure in-memory read with no filesystem
// access.
func (c *Cache) Lookup(artifactType, namespace, name, platformKey string) (blobPath string, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	blobPath, ok = c.index[indexKey{artifactType, namespace, name, platformKey}]
	return blobPath, ok
}

// BlobExists reports whether blobPath is still known to the cache: either actively referenced
// by an index entry, or dereferenced but still within its eviction grace period. A blob written
// to disk but not yet indexed (e.g. a crash between Store and Set) reports false.
func (c *Cache) BlobExists(blobPath string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.refs[blobPath] > 0 {
		return true
	}
	_, pending := c.derefTimes[blobPath]
	return pending
}

// Set records that (artifactType, namespace, name, platformKey) now resolves to blobPath, which
// must already exist on disk. If a different blob was previously indexed at this slot, its
// reference count is decremented and, if it drops to zero, becomes eligible for eviction (see
// derefLocked). blobPath itself is (re)referenced, canceling any pending eviction for it. The
// updated index is then persisted to the snapshot file.
func (c *Cache) Set(artifactType, namespace, name, platformKey, blobPath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := indexKey{artifactType, namespace, name, platformKey}
	if old, ok := c.index[key]; ok && old != blobPath {
		c.derefLocked(old)
	}
	c.index[key] = blobPath
	c.refs[blobPath]++
	delete(c.derefTimes, blobPath) // referenced again; cancel any pending eviction

	return c.persistLocked()
}

// RemoveAll removes every index entry for (artifactType, namespace, name), across all
// platformKey variants (a Plugin CR can have several (os,arch) entries under one name),
// evicting each now-unreferenced blob the same way Set does. No-op (no error, no persist)
// if nothing is indexed for this CR.
func (c *Cache) RemoveAll(artifactType, namespace, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var removedAny bool
	for key, blobPath := range c.index {
		if key.ArtifactType != artifactType || key.Namespace != namespace || key.Name != name {
			continue
		}
		delete(c.index, key)
		c.derefLocked(blobPath)
		removedAny = true
	}
	if !removedAny {
		return nil
	}
	return c.persistLocked()
}

// derefLocked decrements blobPath's reference count and, if it reaches zero, either defers its
// removal to Sweep (evictionGracePeriod > 0, the default: records the dereference time and
// leaves the blob on disk, still reported by BlobExists) or removes it immediately
// (evictionGracePeriod == 0). An immediate removal failure is logged and swallowed rather than
// propagated; the file is left for Sweep to clean up later. Caller must hold c.mu.
func (c *Cache) derefLocked(blobPath string) {
	c.refs[blobPath]--
	if c.refs[blobPath] > 0 {
		return
	}
	delete(c.refs, blobPath)

	if c.evictionGracePeriod > 0 {
		c.derefTimes[blobPath] = time.Now()
		return
	}

	if err := os.Remove(blobPath); err != nil && !os.IsNotExist(err) {
		ctrllog.Log.WithName("artifactcache").V(1).Info(
			"failed to remove unreferenced blob, will be swept later", "path", blobPath, "err", err)
		return
	}
	_ = os.Remove(blobPath + PermSuffix)
	// Best-effort: fails with ENOTEMPTY (silently) if other digests/platforms remain in this ref
	// directory.
	_ = os.Remove(filepath.Dir(blobPath))
}

// persistLocked writes the current index to the snapshot file atomically (tmp file, then
// rename), same pattern as Store's blob writes. Caller must hold c.mu.
func (c *Cache) persistLocked() error {
	entries := make([]snapshotEntry, 0, len(c.index))
	for key, blobPath := range c.index {
		rel, err := filepath.Rel(c.cacheDir, blobPath)
		if err != nil {
			rel = blobPath
		}
		entries = append(entries, snapshotEntry{
			ArtifactType: key.ArtifactType,
			Namespace:    key.Namespace,
			Name:         key.Name,
			PlatformKey:  key.PlatformKey,
			BlobPath:     rel,
		})
	}

	data, err := json.Marshal(snapshot{Version: snapshotVersion, Entries: entries})
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	path := filepath.Join(c.cacheDir, snapshotFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write snapshot: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename snapshot: %w", err)
	}
	return nil
}
