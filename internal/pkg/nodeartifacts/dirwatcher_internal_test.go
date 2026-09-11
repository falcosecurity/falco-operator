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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

const nonexistentDir = "/nonexistent-dir-xyzzy"

// internalThreeAlike returns ArtifactDirs with all three paths pointing to the same dir.
func internalThreeAlike(dir string) artifact.ArtifactDirs {
	return artifact.ArtifactDirs{Config: dir, Rulesfile: dir, Plugin: dir}
}

// newInternalDW creates a DirWatcher on three separate temp dirs and registers cleanup.
func newInternalDW(t *testing.T, falcoURL string, notify func()) (*DirWatcher, artifact.ArtifactDirs) {
	t.Helper()
	dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
	dw, err := NewDirWatcher(dirs, falcoURL, notify)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dw.watcher.Close() })
	return dw, dirs
}

func TestFileSHA256(t *testing.T) {
	content := []byte("hello world")
	h := sha256.Sum256(content)
	wantHash := hex.EncodeToString(h[:])

	tests := []struct {
		name     string
		path     func(*testing.T) string
		wantErr  bool
		wantHash string
	}{
		{
			name:    "nonexistent file returns error",
			path:    func(*testing.T) string { return "/nonexistent-file-xyzzy" },
			wantErr: true,
		},
		{
			name: "computes correct sha256",
			path: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "data.bin")
				require.NoError(t, os.WriteFile(p, content, 0o644))
				return p
			},
			wantHash: wantHash,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fileSHA256(tc.path(t))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantHash, got)
		})
	}
}

func TestRulesFilesHashes(t *testing.T) {
	content := []byte("rules: []")
	h := sha256.Sum256(content)
	wantHash := hex.EncodeToString(h[:])

	tests := []struct {
		name    string
		setup   func(*testing.T) string
		wantLen int
		wantErr bool
	}{
		{
			name:    "ReadDir fails on nonexistent dir",
			setup:   func(*testing.T) string { return nonexistentDir },
			wantErr: true,
		},
		{
			name:  "empty dir returns empty map",
			setup: func(t *testing.T) string { return t.TempDir() },
		},
		{
			name: "non-yaml file is skipped",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644))
				return dir
			},
		},
		{
			name: "subdirectory with .yaml suffix is skipped",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.Mkdir(filepath.Join(dir, "sub.yaml"), 0o755))
				return dir
			},
		},
		{
			name: "yaml file is hashed correctly",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.yaml"), content, 0o644))
				return dir
			},
			wantLen: 1,
		},
		{
			// rulesFilesHashes propagates read errors so the caller skips the verify tick
			// rather than producing a false mismatch against Falco's metric.
			name: "unreadable yaml file errors the tick",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				p := filepath.Join(dir, "rules.yaml")
				require.NoError(t, os.WriteFile(p, []byte("x"), 0o000))
				return dir
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "unreadable yaml file errors the tick" {
				if os.Getuid() == 0 {
					t.Skip("skipping permission test when running as root")
				}
			}
			hashes, err := rulesFilesHashes(tc.setup(t))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, hashes, tc.wantLen)
			if tc.wantLen == 1 {
				_, ok := hashes[wantHash]
				assert.True(t, ok, "expected hash %s in result", wantHash)
			}
		})
	}
}

func TestPluginNames(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) string
		wantKeys []string
		wantErr  bool
	}{
		{
			name:    "ReadDir fails on nonexistent dir",
			setup:   func(*testing.T) string { return nonexistentDir },
			wantErr: true,
		},
		{
			name: "non-so files and subdirs are skipped",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.txt"), nil, 0o644))
				require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0o755))
				return dir
			},
		},
		{
			name: "so files return plugin names without extension",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "container.so"), nil, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "cloudtrail.so"), nil, 0o755))
				return dir
			},
			wantKeys: []string{"container", "cloudtrail"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			names, err := pluginNames(tc.setup(t))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			for _, k := range tc.wantKeys {
				assert.Contains(t, names, k)
			}
		})
	}
}

func TestDirWatcher_HandleEvent(t *testing.T) {
	tests := []struct {
		name      string
		event     func(dirs artifact.ArtifactDirs) fsnotify.Event
		preSetup  func(dw *DirWatcher, dirs artifact.ArtifactDirs)
		wantCalls int32
	}{
		{
			name: "Write op is skipped",
			event: func(d artifact.ArtifactDirs) fsnotify.Event {
				return fsnotify.Event{Name: filepath.Join(d.Rulesfile, "r.yaml"), Op: fsnotify.Write}
			},
			wantCalls: 0,
		},
		{
			name: "Chmod op is skipped",
			event: func(d artifact.ArtifactDirs) fsnotify.Event {
				return fsnotify.Event{Name: filepath.Join(d.Rulesfile, "r.yaml"), Op: fsnotify.Chmod}
			},
			wantCalls: 0,
		},
		{
			name: "tmp file create is skipped",
			event: func(d artifact.ArtifactDirs) fsnotify.Event {
				return fsnotify.Event{Name: filepath.Join(d.Rulesfile, "r.yaml.tmp"), Op: fsnotify.Create}
			},
			wantCalls: 0,
		},
		{
			name: "non-tmp create triggers notify",
			event: func(d artifact.ArtifactDirs) fsnotify.Event {
				return fsnotify.Event{Name: filepath.Join(d.Rulesfile, "r.yaml"), Op: fsnotify.Create}
			},
			wantCalls: 1,
		},
		{
			name: "file Remove triggers notify",
			event: func(d artifact.ArtifactDirs) fsnotify.Event {
				return fsnotify.Event{Name: filepath.Join(d.Rulesfile, "r.yaml"), Op: fsnotify.Remove}
			},
			wantCalls: 1,
		},
		{
			// Dir Remove always notifies: even when re-add succeeds (fast remount), pre-existing
			// files in the new mount won't generate fsnotify events, so a reload is required.
			name: "dir Remove triggers notify even when dir still exists (re-add succeeds)",
			event: func(d artifact.ArtifactDirs) fsnotify.Event {
				return fsnotify.Event{Name: d.Config, Op: fsnotify.Remove}
			},
			wantCalls: 1,
		},
		{
			// When re-add fails (dir truly gone), still fall through to notifyFn.
			name:     "dir Remove triggers notify after failed re-add (dir missing)",
			preSetup: func(_ *DirWatcher, d artifact.ArtifactDirs) { _ = os.RemoveAll(d.Plugin) },
			event: func(d artifact.ArtifactDirs) fsnotify.Event {
				return fsnotify.Event{Name: d.Plugin, Op: fsnotify.Remove}
			},
			wantCalls: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			dw, dirs := newInternalDW(t, "", func() { calls.Add(1) })
			if tc.preSetup != nil {
				tc.preSetup(dw, dirs)
			}
			dw.handleEvent(context.Background(), tc.event(dirs))
			assert.Equal(t, tc.wantCalls, calls.Load())
		})
	}
}

func TestDirWatcher_Watch(t *testing.T) {
	waitDone := func(t *testing.T, done <-chan struct{}) {
		t.Helper()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("watch did not return within 2 seconds")
		}
	}

	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{
			name: "exits via Events !ok when Events channel is closed",
			fn: func(t *testing.T) {
				dw, err := NewDirWatcher(internalThreeAlike(t.TempDir()), "", func() {})
				require.NoError(t, err)
				// Stop the real watcher so fsnotify's goroutine exits safely.
				require.NoError(t, dw.watcher.Close())
				// Replace channels: closed Events fires immediately; nil Errors blocks forever.
				closedEvents := make(chan fsnotify.Event)
				close(closedEvents)
				dw.watcher.Events = closedEvents
				dw.watcher.Errors = nil

				done := make(chan struct{})
				go func() { dw.watch(context.Background()); close(done) }()
				waitDone(t, done)
			},
		},
		{
			name: "exits via Errors !ok when Errors channel is closed",
			fn: func(t *testing.T) {
				dw, err := NewDirWatcher(internalThreeAlike(t.TempDir()), "", func() {})
				require.NoError(t, err)
				require.NoError(t, dw.watcher.Close())
				// Replace channels: nil Events blocks forever; closed Errors fires immediately.
				dw.watcher.Events = nil
				closedErrors := make(chan error)
				close(closedErrors)
				dw.watcher.Errors = closedErrors

				done := make(chan struct{})
				go func() { dw.watch(context.Background()); close(done) }()
				waitDone(t, done)
			},
		},
		{
			name: "logs watcher error then exits on close",
			fn: func(t *testing.T) {
				dw, err := NewDirWatcher(internalThreeAlike(t.TempDir()), "", func() {})
				require.NoError(t, err)

				done := make(chan struct{})
				go func() { dw.watch(context.Background()); close(done) }()

				// Inject an error - covers the logger.Error branch.
				dw.watcher.Errors <- errors.New("injected watcher error")
				time.Sleep(30 * time.Millisecond)

				require.NoError(t, dw.watcher.Close())
				waitDone(t, done)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t) })
	}
}

func TestDirWatcher_FetchRulesHashes(t *testing.T) {
	tests := []struct {
		name     string
		falcoURL func(t *testing.T) string
		body     string
		wantNil  bool
		wantLen  int
	}{
		{
			name:     "invalid URL causes request creation to fail",
			falcoURL: func(*testing.T) string { return "\x00invalid" },
			wantNil:  true,
		},
		{
			name: "server error returns nil",
			falcoURL: func(t *testing.T) string {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				srv.Close()
				return srv.URL
			},
			wantNil: true,
		},
		{
			// Falco can have metrics disabled (metrics_enabled: false in falco.yaml).
			// The /metrics endpoint then returns 404; treat any non-200 as "skip this tick".
			name: "non-200 status (metrics disabled) returns nil",
			falcoURL: func(t *testing.T) string {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
				t.Cleanup(srv.Close)
				return srv.URL
			},
			wantNil: true,
		},
		{
			name:    "non-metric lines are skipped",
			body:    "# HELP foo\n# TYPE foo gauge\nsome_other_metric{} 1\n",
			wantLen: 0,
		},
		{
			name:    "metric line without sha256 key is skipped",
			body:    `falcosecurity_falco_sha256_rules_files_info{path="/etc/r.yaml"} 1`,
			wantLen: 0,
		},
		{
			name:    "metric line with unclosed sha256 value is skipped",
			body:    `falcosecurity_falco_sha256_rules_files_info{sha256="no_close_quote 1`,
			wantLen: 0,
		},
		{
			name:    "valid metric line returns hash",
			body:    `falcosecurity_falco_sha256_rules_files_info{sha256="abc123",path="/etc/r.yaml"} 1`,
			wantLen: 1,
		},
		{
			name:    "hash value is normalised to lowercase",
			body:    `falcosecurity_falco_sha256_rules_files_info{sha256="ABC123",path="/etc/r.yaml"} 1`,
			wantLen: 1,
		},
		{
			// Server claims Content-Length: 10000 but closes the connection after a few bytes.
			// The HTTP client returns io.ErrUnexpectedEOF, which scanner.Err() surfaces.
			name: "truncated response body causes scanner error and returns nil",
			falcoURL: func(t *testing.T) string {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", "10000")
					_, _ = fmt.Fprint(w, "partial line that is not 10000 bytes")
					// Handler returns without writing the claimed 10000 bytes.
				}))
				t.Cleanup(srv.Close)
				return srv.URL
			},
			wantNil: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var url string
			if tc.falcoURL != nil {
				url = tc.falcoURL(t)
			} else {
				body := tc.body
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = fmt.Fprint(w, body)
				}))
				defer srv.Close()
				url = srv.URL
			}

			dw, err := NewDirWatcher(internalThreeAlike(t.TempDir()), url, func() {})
			require.NoError(t, err)
			t.Cleanup(func() { _ = dw.watcher.Close() })

			result := dw.fetchRulesHashes(context.Background())
			if tc.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Len(t, result, tc.wantLen)
		})
	}
}

func TestDirWatcher_CheckRulesFilesMismatch(t *testing.T) {
	makeHash := func(data []byte) string {
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:])
	}

	tests := []struct {
		name       string
		setupRules func(*testing.T) string
		metrics    string
		want       bool
	}{
		{
			name: "count mismatch returns true",
			setupRules: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "r1.yaml"), []byte("a"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "r2.yaml"), []byte("b"), 0o644))
				return dir
			},
			// Falco reports only one hash but disk has two files.
			metrics: fmt.Sprintf(`falcosecurity_falco_sha256_rules_files_info{sha256=%q,path="r1.yaml"} 1`, makeHash([]byte("a"))),
			want:    true,
		},
		{
			name: "falco unreachable returns false",
			setupRules: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "r.yaml"), []byte("x"), 0o644))
				return dir
			},
			metrics: "", // served by a closed server -> HTTP error
			want:    false,
		},
		{
			// Empty rules dir on disk while Falco still reports a hash: mismatch should be detected.
			// Previously the len==0 guard fired before fetchRulesHashes, so this was a blind spot.
			name:       "empty disk but Falco reports rules returns true",
			setupRules: func(t *testing.T) string { return t.TempDir() },
			metrics:    fmt.Sprintf(`falcosecurity_falco_sha256_rules_files_info{sha256=%q,path="r.yaml"} 1`, makeHash([]byte("stale"))),
			want:       true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := tc.setupRules(t)

			var srv *httptest.Server
			if tc.metrics != "" {
				body := tc.metrics
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/metrics" {
						_, _ = fmt.Fprintln(w, body)
					}
				}))
				defer srv.Close()
			} else {
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				srv.Close()
			}

			dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: rulesDir, Plugin: t.TempDir()}
			dw, err := NewDirWatcher(dirs, srv.URL, func() {})
			require.NoError(t, err)
			t.Cleanup(func() { _ = dw.watcher.Close() })

			assert.Equal(t, tc.want, dw.checkRulesFilesMismatch(context.Background()))
		})
	}
}

func TestDirWatcher_CheckPluginsMismatch(t *testing.T) {
	tests := []struct {
		name         string
		setupPlugins func(*testing.T) string
		versionsBody string
		deletePlugin bool
		want         bool
	}{
		{
			name:         "pluginNames ReadDir fails returns false",
			setupPlugins: func(t *testing.T) string { return t.TempDir() },
			versionsBody: `{"engine_version_semver":"0.62.0","plugin_versions":{}}`,
			deletePlugin: true, // remove the dir after DirWatcher creation
			want:         false,
		},
		{
			name: "same count but different name returns true",
			setupPlugins: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "container.so"), nil, 0o755))
				return dir
			},
			// disk has "container" but Falco reports "json"
			versionsBody: `{"engine_version_semver":"0.62.0","plugin_versions":{"json":"1.0"}}`,
			want:         true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pluginDir := tc.setupPlugins(t)

			body := tc.versionsBody
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/versions" {
					_, _ = fmt.Fprint(w, body)
				}
			}))
			defer srv.Close()

			dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: pluginDir}
			dw, err := NewDirWatcher(dirs, srv.URL, func() {})
			require.NoError(t, err)
			t.Cleanup(func() { _ = dw.watcher.Close() })

			if tc.deletePlugin {
				os.RemoveAll(pluginDir)
			}

			assert.Equal(t, tc.want, dw.checkPluginsMismatch(context.Background()))
		})
	}
}

func TestDirWatcher_NeedLeaderElection(t *testing.T) {
	dw, _ := newInternalDW(t, "", func() {})
	assert.False(t, dw.NeedLeaderElection())
}
