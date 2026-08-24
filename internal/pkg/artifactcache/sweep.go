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
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-logr/logr"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// sweepGraceWindow protects a blob that was just written but not yet indexed (the moment
// between Store and Set) from being mistaken for an orphan by a sweep that started
// walking in between. Distinct from Cache.evictionGracePeriod: this one is keyed off the
// blob file's own mtime (write time), that one off a deref timestamp. See
// findOrphanCandidates's doc comment for why conflating the two would defeat the latter.
const sweepGraceWindow = 10 * time.Minute

// DefaultSweepInterval is the polling cadence used by Sweeper when none is specified.
const DefaultSweepInterval = time.Hour

// Sweep does two things: (1) deletes any blob past its eviction grace period in derefTimes,
// which for deferred-eviction mode (evictionGracePeriod > 0, the default) is the sole
// mechanism that actually removes a dereferenced blob from disk, since derefLocked itself
// only records the timestamp; and (2) scans blobs/ for files unreferenced by any current
// index entry (and not pending in derefTimes either) and removes them as orphans, a
// backstop for a best-effort delete failure, or a process crash between Store writing a blob
// and Set indexing it. Returns the total number of blobs removed across both.
func (c *Cache) Sweep(ctx context.Context) (removed int, err error) {
	logger := ctrllog.FromContext(ctx)

	c.mu.RLock()
	refs := maps.Clone(c.refs)
	derefTimes := maps.Clone(c.derefTimes)
	c.mu.RUnlock()

	candidates, err := c.findOrphanCandidates(refs, derefTimes)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	removed = c.removeExpiredDerefsLocked(logger)
	removed += c.removeOrphansLocked(logger, candidates)
	return removed, nil
}

// findOrphanCandidates walks blobs/ and returns the paths of files that aren't in refs, aren't
// currently pending eviction in derefTimes (that's removeExpiredDerefsLocked's job, once its
// own grace period elapses, not this one, which uses sweepGraceWindow against file mtime and
// would otherwise immediately defeat a blob's eviction grace period on its very next tick),
// and are older than sweepGraceWindow. Read-only: takes no lock, since it only touches the
// filesystem and the caller-supplied snapshots.
func (c *Cache) findOrphanCandidates(refs map[string]int, derefTimes map[string]time.Time) ([]string, error) {
	blobsDir := filepath.Join(c.cacheDir, BlobsDir)
	var candidates []string
	walkErr := filepath.WalkDir(blobsDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || strings.HasSuffix(path, PermSuffix) {
			return nil
		}
		if refs[path] > 0 {
			return nil
		}
		if _, pending := derefTimes[path]; pending {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil //nolint:nilerr // stat failed for this one entry; skip it, don't abort the whole walk
		}
		if time.Since(info.ModTime()) < sweepGraceWindow {
			return nil
		}
		candidates = append(candidates, path)
		return nil
	})
	if walkErr != nil {
		if errors.Is(walkErr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("walk blobs dir: %w", walkErr)
	}
	return candidates, nil
}

// removeOrphansLocked re-checks each candidate against the live refs map, closing the gap
// against a Set that started referencing it since findOrphanCandidates took its snapshot,
// and removes it, its .perm companion, and its now-empty ref directory, if still
// unreferenced. It also skips anything currently in c.derefTimes and any candidate rewritten
// within sweepGraceWindow after discovery. Cache.Store shares this mutex, making that final
// freshness check atomic with production blob replacement. Caller must hold c.mu.
func (c *Cache) removeOrphansLocked(logger logr.Logger, candidates []string) int {
	removed := 0
	for _, path := range candidates {
		if c.refs[path] > 0 {
			continue // referenced again since the snapshot was taken
		}
		if _, pending := c.derefTimes[path]; pending {
			continue // now within its own eviction grace period; removeExpiredDerefsLocked owns it
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			if !os.IsNotExist(statErr) {
				logger.V(1).Info("sweep: failed to stat orphaned blob", "path", path, "err", statErr)
			}
			continue
		}
		if time.Since(info.ModTime()) < sweepGraceWindow {
			continue // rewritten after candidate discovery; protect the new Store-to-Set window
		}
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			logger.V(1).Info("sweep: failed to remove orphaned blob", "path", path, "err", removeErr)
			continue
		}
		_ = os.Remove(path + PermSuffix)
		// Best-effort: fails with ENOTEMPTY (silently) if other blobs remain in this ref dir.
		_ = os.Remove(filepath.Dir(path))
		removed++
	}
	return removed
}

// removeExpiredDerefsLocked deletes every blob in c.derefTimes whose eviction grace period
// has elapsed, along with its .perm companion and now-possibly-empty ref directory. No
// filesystem walk needed: c.derefTimes already precisely tracks every pending blob, so this
// runs directly against live state under the lock rather than a pre-walk snapshot. A removal
// failure is logged and swallowed (mirrors derefLocked's immediate-removal failure handling):
// the entry is dropped from derefTimes regardless, so a persistently-undeletable blob falls
// through to the ordinary orphan-sweep path (findOrphanCandidates) on the next cycle instead
// of being retried here forever. Caller must hold c.mu.
func (c *Cache) removeExpiredDerefsLocked(logger logr.Logger) int {
	removed := 0
	for path, derefAt := range c.derefTimes {
		if time.Since(derefAt) < c.evictionGracePeriod {
			continue
		}
		delete(c.derefTimes, path)
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			logger.V(1).Info("sweep: failed to remove dereferenced blob, will retry as an orphan", "path", path, "err", removeErr)
			continue
		}
		_ = os.Remove(path + PermSuffix)
		_ = os.Remove(filepath.Dir(path))
		removed++
	}
	return removed
}

// Sweeper periodically calls Cache.Sweep as a backstop against orphaned blobs. Mirrors
// compat.VersionsWatcher's Start(ctx) shape: ticker loop, errors logged and swallowed,
// returns nil on ctx.Done().
type Sweeper struct {
	cache    *Cache
	interval time.Duration
}

// NewSweeper creates a Sweeper that calls cache.Sweep every interval.
func NewSweeper(cache *Cache, interval time.Duration) *Sweeper {
	return &Sweeper{cache: cache, interval: interval}
}

// Start implements manager.Runnable. It sweeps until ctx is canceled.
func (s *Sweeper) Start(ctx context.Context) error {
	logger := ctrllog.FromContext(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			removed, err := s.cache.Sweep(ctx)
			if err != nil {
				logger.V(4).Info("artifact cache sweep failed, will retry", "err", err)
				continue
			}
			if removed > 0 {
				logger.V(2).Info("artifact cache sweep removed orphaned blobs", "removed", removed)
			}
		}
	}
}
