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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
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
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// DefaultVerifyInterval is how often DirWatcher checks rules loaded by Falco and local plugin
// file changes, as a backstop for events missed by fsnotify.
const DefaultVerifyInterval = 60 * time.Second

// DirWatcher watches Falco's config directories with fsnotify and calls notifyFn on any file
// Create or Remove event, driving ReloadCoordinator without coupling Manager to reload concerns.
//
// Its periodic pass compares rules files against Falco's /metrics and detects changes to the
// shared plugin configuration and managed .so files. Plugin aliases cannot be matched to the ABI
// names in /versions, so this backstop detects missed file events, not plugin runtime drift.
// A plugin file change can cause one extra reload after its fsnotify event was already handled.
//
// DirWatcher registers its filesystem watches at construction time (not in Start), avoiding the
// TOCTOU window between New and Start where a write could otherwise go unobserved.
//
// DirWatcher implements manager.Runnable.
type DirWatcher struct {
	dirs           artifact.ArtifactDirs
	falcoBaseURL   string
	notifyFn       func()
	watcher        *fsnotify.Watcher
	verifyInterval time.Duration
	metricsClient  *http.Client // reused across verify ticks; field so tests can inject a custom transport
	// Only the verification goroutine updates these maps after construction. Removed rules
	// remain tracked until unloaded; pluginFiles is the last complete local snapshot, nil if unknown.
	trackedRules map[string]map[string]struct{}
	pluginFiles  map[string]string
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
	d := &DirWatcher{
		dirs:           dirs,
		falcoBaseURL:   falcoBaseURL,
		notifyFn:       notifyFn,
		watcher:        fw,
		verifyInterval: DefaultVerifyInterval,
		metricsClient:  &http.Client{Timeout: 5 * time.Second},
		trackedRules:   make(map[string]map[string]struct{}),
	}
	rules, err := rulesFilesHashes(dirs.Rulesfile)
	if err != nil {
		ctrllog.Log.Error(err, "could not read initial rules files; verification will retry")
	} else {
		d.rememberRules(rules)
	}
	plugins, err := pluginFilesHashes(dirs)
	if err != nil {
		ctrllog.Log.Error(err, "could not read initial plugin files; verification will retry")
	} else {
		d.pluginFiles = plugins
	}
	return d, nil
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
	// A startup reload also covers removals made while this sidecar was not running.
	d.notifyFn()
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

// verify requests a reload for mismatched runtime rules or changed local plugin files.
// Calls notifyFn once per pass; ReloadCoordinator coalesces requests and retries failed signals.
func (d *DirWatcher) verify(ctx context.Context) {
	logger := ctrllog.FromContext(ctx)
	if d.checkRulesFilesMismatch(ctx) {
		logger.V(1).Info("rules files mismatch detected; triggering reload")
		d.notifyFn()
		return
	}
	if d.checkPluginFilesChanged(ctx) {
		logger.V(1).Info("plugin files changed; triggering reload")
		d.notifyFn()
	}
}

// checkRulesFilesMismatch compares managed filenames and hashes, including pending removals.
// Falco exposes basenames only: identical name/hash pairs in different directories cannot be distinguished.
func (d *DirWatcher) checkRulesFilesMismatch(ctx context.Context) bool {
	logger := ctrllog.FromContext(ctx)
	diskHashes, err := rulesFilesHashes(d.dirs.Rulesfile)
	if err != nil {
		logger.Error(err, "failed to hash rules files on disk; skipping verify tick")
		return false
	}
	d.rememberRules(diskHashes)
	falcoHashes := d.fetchRulesHashes(ctx)
	if falcoHashes == nil {
		return false // Falco not reachable or metrics disabled: skip this tick
	}
	for name, hash := range diskHashes {
		if _, ok := falcoHashes[name][hash]; !ok {
			return true
		}
	}
	for name, hashes := range d.trackedRules {
		for hash := range hashes {
			if diskHashes[name] == hash {
				continue
			}
			if _, loaded := falcoHashes[name][hash]; loaded {
				return true
			}
			delete(hashes, hash)
		}
		if len(hashes) == 0 {
			delete(d.trackedRules, name)
		}
	}
	return false
}

func (d *DirWatcher) rememberRules(files map[string]string) {
	for name, hash := range files {
		if d.trackedRules[name] == nil {
			d.trackedRules[name] = make(map[string]struct{})
		}
		d.trackedRules[name][hash] = struct{}{}
	}
}

// fetchRulesHashes retains filename/hash pairs; a failed observation is not an empty runtime.
// Returns nil if the endpoint is unreachable, times out, or responds unsuccessfully.
func (d *DirWatcher) fetchRulesHashes(ctx context.Context) map[string]map[string]struct{} {
	metrics, err := fetchFalcoMetrics(ctx, d.metricsClient, d.falcoBaseURL)
	if err != nil {
		ctrllog.FromContext(ctx).V(1).Info("rules verification unavailable", "err", err)
		return nil
	}
	if metrics["falcosecurity_falco_sha256_rules_files_info"] == nil {
		// An empty or unrelated HTTP body is not proof that Falco unloaded every rule.
		if _, err := reloadTimestamp(metrics); err != nil {
			return nil
		}
	}
	hashes := make(map[string]map[string]struct{})
	for _, metric := range metrics["falcosecurity_falco_sha256_rules_files_info"].GetMetric() {
		var name, hash string
		for _, label := range metric.GetLabel() {
			switch label.GetName() {
			case "file_name":
				name = label.GetValue()
			case "sha256":
				hash = strings.ToLower(label.GetValue())
			}
		}
		if name == "" || hash == "" {
			return nil
		}
		if hashes[name] == nil {
			hashes[name] = make(map[string]struct{})
		}
		hashes[name][hash] = struct{}{}
	}
	return hashes
}

// checkPluginFilesChanged advances the local baseline only after a complete successful read.
func (d *DirWatcher) checkPluginFilesChanged(ctx context.Context) bool {
	files, err := pluginFilesHashes(d.dirs)
	if err != nil {
		ctrllog.FromContext(ctx).Error(err, "failed to read plugin files; skipping verify tick")
		return false
	}
	changed := d.pluginFiles == nil || !maps.Equal(d.pluginFiles, files)
	d.pluginFiles = files
	return changed
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
func rulesFilesHashes(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	hashes := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		h, err := fileSHA256(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		hashes[e.Name()] = h
	}
	return hashes, nil
}

// pluginFilesHashes includes the shared config and every managed .so, keyed by full path.
// Hash binary contents too: a library update need not change the shared configuration.
func pluginFilesHashes(dirs artifact.ArtifactDirs) (map[string]string, error) {
	entries, err := os.ReadDir(dirs.Plugin)
	if err != nil {
		return nil, err
	}
	hashes := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".so") {
			continue
		}
		path := filepath.Join(dirs.Plugin, entry.Name())
		hash, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		hashes[path] = hash
	}
	path := artifact.ArtifactPath(dirs, pluginConfigFileName, priority.MaxPriority, artifact.MediumInline, artifact.TypeConfig)
	hash, err := fileSHA256(path)
	if os.IsNotExist(err) {
		return hashes, nil
	}
	if err != nil {
		return nil, err
	}
	hashes[path] = hash
	return hashes, nil
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
