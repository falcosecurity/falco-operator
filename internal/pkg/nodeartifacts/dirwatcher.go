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

package nodeartifacts

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
)

// DefaultVerifyInterval is how often DirWatcher compares on-disk state against what Falco
// reports as loaded, as a backstop for events missed by fsnotify.
const DefaultVerifyInterval = 60 * time.Second

// DirWatcher watches Falco's config directories with fsnotify and calls notifyFn on any file
// Create or Remove event, driving ReloadCoordinator without coupling Manager to reload concerns.
//
// It also runs a periodic verification pass that compares on-disk artifact hashes/names against
// what Falco actually reports as loaded (via /metrics for rules files and /versions for plugins).
// A detected mismatch calls notifyFn to trigger a SIGHUP, replacing the deleted PluginConfigRetrier
// and extending the same backstop to rules files.
//
// DirWatcher registers its filesystem watches at construction time (not in Start), avoiding the
// TOCTOU window between New and Start where a write could otherwise go unobserved.
//
// DirWatcher implements manager.Runnable.
type DirWatcher struct {
	dirs            artifact.ArtifactDirs
	falcoBaseURL    string
	notifyFn        func()
	watcher         *fsnotify.Watcher
	verifyInterval  time.Duration
	versionsFetcher compat.VersionsFetcher // reused across verify ticks; avoids per-tick TCP setup
	metricsClient   *http.Client           // reused across verify ticks; field so tests can inject a custom transport
}

// NewDirWatcher creates a DirWatcher watching dirs. Watches are registered immediately so no
// event is missed during the gap between construction and Start. Returns an error if the
// underlying fsnotify watcher cannot be created or any directory cannot be added.
func NewDirWatcher(dirs artifact.ArtifactDirs, falcoBaseURL string, notifyFn func()) (*DirWatcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}
	for _, dir := range []string{dirs.Config, dirs.Rulesfile, dirs.Plugin} {
		if err := fw.Add(dir); err != nil {
			_ = fw.Close()
			return nil, fmt.Errorf("watch dir %s: %w", dir, err)
		}
	}
	return &DirWatcher{
		dirs:            dirs,
		falcoBaseURL:    falcoBaseURL,
		notifyFn:        notifyFn,
		watcher:         fw,
		verifyInterval:  DefaultVerifyInterval,
		versionsFetcher: compat.NewHTTPVersionsFetcher(falcoBaseURL),
		metricsClient:   &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// WithVerifyInterval overrides the default verification interval. Follows the same pattern as
// tlsutil.CAWatcher.WithWatchInterval; primarily for testing.
func (d *DirWatcher) WithVerifyInterval(interval time.Duration) *DirWatcher {
	d.verifyInterval = interval
	return d
}

// Start watches for filesystem events and runs the periodic verification pass until ctx is
// canceled. Implements manager.Runnable.
func (d *DirWatcher) Start(ctx context.Context) error {
	logger := ctrllog.FromContext(ctx)

	var wg sync.WaitGroup
	wg.Go(func() {
		d.watch(ctx)
	})

	ticker := time.NewTicker(d.verifyInterval)
	defer ticker.Stop()

	logger.Info("Starting Falco dir watcher", "dirs", []string{d.dirs.Config, d.dirs.Rulesfile, d.dirs.Plugin}, "verifyInterval", d.verifyInterval)
	for {
		select {
		case <-ctx.Done():
			_ = d.watcher.Close()
			wg.Wait() // ensure watch goroutine exits before Start returns
			return nil
		case <-ticker.C:
			d.verify(ctx)
		}
	}
}

// watch reads fsnotify events and reacts to file Create and Remove events.
func (d *DirWatcher) watch(ctx context.Context) {
	logger := ctrllog.FromContext(ctx)
	for {
		select {
		case event, ok := <-d.watcher.Events:
			if !ok {
				return
			}
			d.handleEvent(ctx, event)
		case err, ok := <-d.watcher.Errors:
			if !ok {
				return
			}
			logger.Error(err, "fsnotify watcher error")
		}
	}
}

// handleEvent reacts to a single fsnotify event. Ignored operations (Write, Chmod, Rename) and
// .tmp intermediate files are silently skipped.
func (d *DirWatcher) handleEvent(ctx context.Context, event fsnotify.Event) {
	logger := ctrllog.FromContext(ctx)
	if !event.Op.Has(fsnotify.Create) && !event.Op.Has(fsnotify.Remove) {
		return
	}
	// A directory itself was removed (e.g. volume remount). Attempt to re-register the watch.
	// The re-add nearly always fails immediately because the directory no longer exists; it may
	// succeed when the volume is fast-remounted. In both cases, always fall through to notifyFn:
	// if the directory was atomically replaced, pre-existing files in the new mount won't
	// generate fsnotify events and only a reload (plus the verify backstop) will detect them.
	if event.Op.Has(fsnotify.Remove) && slices.Contains(d.allDirs(), event.Name) {
		if err := d.watcher.Add(event.Name); err != nil {
			logger.Error(err, "watched dir removed; could not re-register watch", "dir", event.Name)
		}
		// fall through to notifyFn, always notify on dir removal
	}
	// Atomic writes land as Create on the tmp file and then Create on the final file; skip tmp.
	if strings.HasSuffix(event.Name, ".tmp") {
		return
	}
	logger.Info("Falco dir event; triggering reload", "op", event.Op, "file", event.Name)
	d.notifyFn()
}

// verify runs the periodic backstop: compares what's on disk against what Falco reports loaded.
// Calls notifyFn once if any mismatch is found (rules files or plugins), then returns so the
// resulting reload coalesces all mismatches into a single SIGHUP.
func (d *DirWatcher) verify(ctx context.Context) {
	logger := ctrllog.FromContext(ctx)
	if d.checkRulesFilesMismatch(ctx) {
		logger.V(1).Info("rules files mismatch detected; triggering reload")
		d.notifyFn()
		return
	}
	if d.checkPluginsMismatch(ctx) {
		logger.V(1).Info("plugins mismatch detected; triggering reload")
		d.notifyFn()
	}
}

// checkRulesFilesMismatch returns true when the set of sha256 hashes for .yaml files in the
// rules directory differs from the set Falco reports via the
// falcosecurity_falco_sha256_rules_files_info Prometheus metric.
func (d *DirWatcher) checkRulesFilesMismatch(ctx context.Context) bool {
	logger := ctrllog.FromContext(ctx)
	diskHashes, err := rulesFilesHashes(d.dirs.Rulesfile)
	if err != nil {
		logger.Error(err, "failed to hash rules files on disk; skipping verify tick")
		return false
	}
	falcoHashes := d.fetchRulesHashes(ctx)
	if falcoHashes == nil {
		return false // Falco not reachable or metrics disabled: skip this tick
	}
	if len(diskHashes) != len(falcoHashes) {
		return true
	}
	for h := range diskHashes {
		if _, ok := falcoHashes[h]; !ok {
			return true
		}
	}
	return false
}

// fetchRulesHashes scrapes Falco's /metrics endpoint and returns the set of sha256 values from
// falcosecurity_falco_sha256_rules_files_info lines. Returns nil if the endpoint is unreachable,
// returns a non-200 status (e.g. metrics disabled in Falco config), or the response times out.
func (d *DirWatcher) fetchRulesHashes(ctx context.Context) map[string]struct{} {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.falcoBaseURL+"/metrics", http.NoBody)
	if err != nil {
		return nil
	}
	resp, err := d.metricsClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil // metrics disabled or endpoint unavailable - skip this tick
	}

	const metricPrefix = "falcosecurity_falco_sha256_rules_files_info{"
	const sha256Key = `sha256="`
	hashes := make(map[string]struct{})
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, metricPrefix) {
			continue
		}
		// line looks like: falcosecurity_falco_sha256_rules_files_info{sha256="<hex>",path="..."} 1
		_, afterKey, ok := strings.Cut(line, sha256Key)
		if !ok {
			continue
		}
		value, _, ok := strings.Cut(afterKey, `"`)
		if !ok {
			continue
		}
		hashes[strings.ToLower(value)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil
	}
	return hashes
}

// checkPluginsMismatch returns true when the set of plugin names derived from .so files in the
// plugins directory differs from the set Falco reports via /versions plugin_versions.
func (d *DirWatcher) checkPluginsMismatch(ctx context.Context) bool {
	diskPlugins, err := pluginNames(d.dirs.Plugin)
	if err != nil {
		return false
	}
	versions, err := d.versionsFetcher.Fetch(ctx)
	if err != nil {
		return false // Falco not reachable: skip this tick
	}
	loaded := versions.PluginVersions()
	if len(diskPlugins) != len(loaded) {
		return true
	}
	for name := range diskPlugins {
		if _, ok := loaded[name]; !ok {
			return true
		}
	}
	return false
}

// NeedLeaderElection reports that the DirWatcher runs on every pod replica, not just the leader.
func (d *DirWatcher) NeedLeaderElection() bool { return false }

// allDirs returns the three watched directory paths as a slice for membership checks.
func (d *DirWatcher) allDirs() []string {
	return []string{d.dirs.Config, d.dirs.Rulesfile, d.dirs.Plugin}
}

// rulesFilesHashes returns the sha256 hex digest of each .yaml file in dir. Returns an error if
// any file cannot be read so that the caller skips the verify tick rather than producing a false
// mismatch (Falco's /metrics may still report the hash of a transiently unreadable file).
func rulesFilesHashes(dir string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	hashes := make(map[string]struct{})
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		h, err := fileSHA256(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		hashes[h] = struct{}{}
	}
	return hashes, nil
}

// pluginNames returns the set of plugin names (basename without .so) for every .so file in dir.
func pluginNames(dir string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make(map[string]struct{})
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".so") {
			continue
		}
		names[strings.TrimSuffix(e.Name(), ".so")] = struct{}{}
	}
	return names, nil
}

// fileSHA256 computes the lowercase sha256 hex digest of the file at path.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from our own directory listing, not user input
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
