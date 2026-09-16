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
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
				assert.Equal(t, wantHash, hashes["rules.yaml"])
			}
		})
	}
}

func TestPluginFilesHashes(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T, artifact.ArtifactDirs)
		wantLen int
		wantErr bool
	}{
		{name: "empty directories"},
		{
			name: "aggregate bytes are hashed without parsing aliases or init config",
			setup: func(t *testing.T, dirs artifact.ArtifactDirs) {
				path := artifact.ArtifactPath(dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.TypeConfig)
				require.NoError(t, os.WriteFile(path, []byte("load_plugins: ["), 0o644))
			},
			wantLen: 1,
		},
		{
			name: "binary inventory ignores temporary files and directories",
			setup: func(t *testing.T, dirs artifact.ArtifactDirs) {
				require.NoError(t, os.WriteFile(filepath.Join(dirs.Plugin, "container.so"), []byte("binary"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dirs.Plugin, "container.so.tmp"), []byte("pending"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dirs.Plugin, "readme.txt"), nil, 0o644))
				require.NoError(t, os.Mkdir(filepath.Join(dirs.Plugin, "directory.so"), 0o755))
			},
			wantLen: 1,
		},
		{
			name: "unreadable aggregate is not an empty snapshot",
			setup: func(t *testing.T, dirs artifact.ArtifactDirs) {
				path := artifact.ArtifactPath(dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.TypeConfig)
				require.NoError(t, os.Mkdir(path, 0o755))
			},
			wantErr: true,
		},
		{
			name: "unreadable binary is not an absent binary",
			setup: func(t *testing.T, dirs artifact.ArtifactDirs) {
				require.NoError(t, os.Symlink(filepath.Join(dirs.Plugin, "missing"), filepath.Join(dirs.Plugin, "container.so")))
			},
			wantErr: true,
		},
		{
			name: "missing plugin directory is not an empty snapshot",
			setup: func(t *testing.T, dirs artifact.ArtifactDirs) {
				require.NoError(t, os.Remove(dirs.Plugin))
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
			if tc.setup != nil {
				tc.setup(t, dirs)
			}
			hashes, err := pluginFilesHashes(dirs)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, hashes, "a partial snapshot must not be published")
				return
			}
			require.NoError(t, err)
			assert.Len(t, hashes, tc.wantLen)
			for path, hash := range hashes {
				want, err := fileSHA256(path)
				require.NoError(t, err)
				assert.Equal(t, want, hash)
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
				// Use inert channels: mutating a real watcher's channels races with its backend.
				closedEvents := make(chan fsnotify.Event)
				close(closedEvents)
				dw := &DirWatcher{watcher: &fsnotify.Watcher{Events: closedEvents}}

				done := make(chan struct{})
				go func() { dw.watch(context.Background()); close(done) }()
				waitDone(t, done)
			},
		},
		{
			name: "exits via Errors !ok when Errors channel is closed",
			fn: func(t *testing.T) {
				closedErrors := make(chan error)
				close(closedErrors)
				dw := &DirWatcher{watcher: &fsnotify.Watcher{Errors: closedErrors}}

				done := make(chan struct{})
				go func() { dw.watch(context.Background()); close(done) }()
				waitDone(t, done)
			},
		},
		{
			name: "logs watcher error then exits on close",
			fn: func(t *testing.T) {
				watchErrors := make(chan error, 1)
				watchErrors <- errors.New("injected watcher error")
				close(watchErrors)
				dw := &DirWatcher{watcher: &fsnotify.Watcher{Errors: watchErrors}}

				done := make(chan struct{})
				go func() { dw.watch(context.Background()); close(done) }()
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
			body:    "# HELP foo unrelated\n# TYPE foo gauge\nfoo 1\n# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds 1000\n",
			wantLen: 0,
		},
		{name: "empty response is not an empty runtime", wantNil: true},
		{
			name:    "metric without sha256 makes observation unavailable",
			body:    `falcosecurity_falco_sha256_rules_files_info{file_name="r.yaml"} 1`,
			wantNil: true,
		},
		{
			name:    "malformed metric makes observation unavailable",
			body:    `falcosecurity_falco_sha256_rules_files_info{sha256="no_close_quote 1`,
			wantNil: true,
		},
		{
			name:    "valid metric line returns hash",
			body:    `falcosecurity_falco_sha256_rules_files_info{sha256="abc123",file_name="r.yaml"} 1`,
			wantLen: 1,
		},
		{
			name:    "hash value is normalised to lowercase",
			body:    `falcosecurity_falco_sha256_rules_files_info{sha256="ABC123",file_name="r.yaml"} 1`,
			wantLen: 1,
		},
		{
			// Server claims Content-Length: 10000 but closes the connection after a few bytes.
			// The parser must preserve the HTTP client's unexpected EOF error.
			name: "truncated response body returns nil",
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
					_, _ = fmt.Fprintln(w, body)
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
			if tc.wantLen == 1 {
				assert.Contains(t, result["r.yaml"], "abc123")
			}
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
		removeRule bool
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
			metrics: fmt.Sprintf(`falcosecurity_falco_sha256_rules_files_info{sha256=%q,file_name="r1.yaml"} 1`, makeHash([]byte("a"))),
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
			name: "empty disk but Falco still reports a removed managed rule returns true",
			setupRules: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "r.yaml"), []byte("stale"), 0o644))
				return dir
			},
			metrics:    fmt.Sprintf(`falcosecurity_falco_sha256_rules_files_info{sha256=%q,file_name="r.yaml"} 1`, makeHash([]byte("stale"))),
			removeRule: true,
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
			if tc.removeRule {
				require.NoError(t, os.Remove(filepath.Join(rulesDir, "r.yaml")))
			}

			assert.Equal(t, tc.want, dw.checkRulesFilesMismatch(context.Background()))
		})
	}
}

func TestDirWatcher_CheckPluginFilesChanged(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, string, string)
		want   int32
	}{
		{name: "unchanged snapshot"},
		{
			name: "identical aggregate rewrite",
			change: func(t *testing.T, configPath, _ string) {
				require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: [custom-alias]\n"), 0o644))
			},
		},
		{
			name: "aggregate content changed",
			change: func(t *testing.T, configPath, _ string) {
				require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: []\n"), 0o644))
			},
			want: 1,
		},
		{
			name: "aggregate removed while binary remains",
			change: func(t *testing.T, configPath, _ string) {
				require.NoError(t, os.Remove(configPath))
			},
			want: 1,
		},
		{
			name: "binary content changed with same size and mtime",
			change: func(t *testing.T, _, pluginPath string) {
				info, err := os.Stat(pluginPath)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(pluginPath, []byte("binary-b"), 0o755))
				require.NoError(t, os.Chtimes(pluginPath, info.ModTime(), info.ModTime()))
			},
			want: 1,
		},
		{
			name: "binary added without changing aggregate",
			change: func(t *testing.T, _, pluginPath string) {
				require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(pluginPath), "second.so"), []byte("binary-a"), 0o755))
			},
			want: 1,
		},
		{
			name: "binary renamed without changing content",
			change: func(t *testing.T, _, pluginPath string) {
				require.NoError(t, os.Rename(pluginPath, filepath.Join(filepath.Dir(pluginPath), "renamed.so")))
			},
			want: 1,
		},
		{
			name: "binary removed without changing aggregate",
			change: func(t *testing.T, _, pluginPath string) {
				require.NoError(t, os.Remove(pluginPath))
			},
			want: 1,
		},
		{
			name: "external and temporary files ignored",
			change: func(t *testing.T, configPath, pluginPath string) {
				require.NoError(t, os.WriteFile(filepath.Join(t.TempDir(), "external.so"), []byte("external"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(configPath), "external.yaml"), []byte("external: config"), 0o644))
				require.NoError(t, os.WriteFile(pluginPath+".tmp", []byte("pending"), 0o755))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
			configPath := artifact.ArtifactPath(dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.TypeConfig)
			require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: [custom-alias]\n"), 0o644))
			pluginPath := filepath.Join(dirs.Plugin, "my-container.so")
			require.NoError(t, os.WriteFile(pluginPath, []byte("binary-a"), 0o755))
			var calls int32
			dw, err := NewDirWatcher(dirs, "", func() { calls++ })
			require.NoError(t, err)
			t.Cleanup(func() { _ = dw.watcher.Close() })
			if tc.change != nil {
				tc.change(t, configPath, pluginPath)
			}
			// Do not start the fsnotify consumer: these checks control the missed-event boundary.
			dw.verify(t.Context())
			assert.Equal(t, tc.want, calls)
			dw.verify(t.Context())
			assert.Equal(t, tc.want, calls, "the local change is notified once, not on every tick")
		})
	}
}

func TestDirWatcher_ManagedRulesIgnoreExternalFilesAndRetainRemovals(t *testing.T) {
	content := []byte("managed rules")
	hash := sha256.Sum256(content)
	loaded := fmt.Sprintf("falcosecurity_falco_sha256_rules_files_info{file_name=\"managed.yaml\",sha256=\"%x\"} 1\n", hash)
	external := "falcosecurity_falco_sha256_rules_files_info{file_name=\"external.yaml\",sha256=\"external-hash\"} 1\n"
	var metrics atomic.Value
	metrics.Store(loaded + external)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, metrics.Load().(string))
	}))
	defer srv.Close()
	dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
	path := filepath.Join(dirs.Rulesfile, "managed.yaml")
	require.NoError(t, os.WriteFile(path, content, 0o644))
	dw, err := NewDirWatcher(dirs, srv.URL, func() {})
	require.NoError(t, err)
	t.Cleanup(func() { _ = dw.watcher.Close() })

	assert.False(t, dw.checkRulesFilesMismatch(t.Context()), "a loaded external rule is not a managed-file mismatch")
	require.NoError(t, os.Remove(path))
	assert.True(t, dw.checkRulesFilesMismatch(t.Context()), "a removed managed rule must disappear from Falco too")
	assert.True(t, dw.checkRulesFilesMismatch(t.Context()), "another observation must not forget the pending removal")
	metrics.Store("not prometheus metrics")
	assert.False(t, dw.checkRulesFilesMismatch(t.Context()), "a failed observation skips the tick")
	metrics.Store(loaded + external)
	assert.True(t, dw.checkRulesFilesMismatch(t.Context()), "a failed observation must not clear the pending removal")
	metrics.Store(external)
	assert.False(t, dw.checkRulesFilesMismatch(t.Context()), "the external rule remains valid after managed cleanup")
}

func TestDirWatcher_ExternalRulesWithSameBasenameRemainDistinct(t *testing.T) {
	dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
	path := filepath.Join(dirs.Rulesfile, "rules.yaml")
	require.NoError(t, os.WriteFile(path, []byte("managed"), 0o644))
	managedHash := sha256.Sum256([]byte("managed"))
	var metrics atomic.Value
	metrics.Store(fmt.Sprintf("falcosecurity_falco_sha256_rules_files_info{file_name=\"rules.yaml\",sha256=\"%x\"} 1\nfalcosecurity_falco_sha256_rules_files_info{file_name=\"rules.yaml\",sha256=\"external\"} 1\n", managedHash))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, metrics.Load().(string))
	}))
	defer srv.Close()
	dw, err := NewDirWatcher(dirs, srv.URL, func() {})
	require.NoError(t, err)
	t.Cleanup(func() { _ = dw.watcher.Close() })
	assert.False(t, dw.checkRulesFilesMismatch(t.Context()))
	require.NoError(t, os.Remove(path))
	assert.True(t, dw.checkRulesFilesMismatch(t.Context()))
	metrics.Store("falcosecurity_falco_sha256_rules_files_info{file_name=\"rules.yaml\",sha256=\"external\"} 1\n")
	assert.False(t, dw.checkRulesFilesMismatch(t.Context()), "an external same-basename file is not a stale managed revision")
}

func TestFetchFalcoMetrics_RepeatedDefinitions(t *testing.T) {
	const timestamp = "# HELP falcosecurity_falco_reload_timestamp_nanoseconds https://falco.org/docs/metrics/\n" +
		"# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\n" +
		"falcosecurity_falco_reload_timestamp_nanoseconds 1789460410000000000\n"
	const rulesHeader = "# HELP falcosecurity_falco_sha256_rules_files_info https://falco.org/docs/metrics/\n" +
		"# TYPE falcosecurity_falco_sha256_rules_files_info gauge\n"
	const firstRule = "falcosecurity_falco_sha256_rules_files_info{file_name=\"managed.yaml\",sha256=\"abc\"} 1\n"
	const secondRule = "falcosecurity_falco_sha256_rules_files_info{file_name=\"external.yaml\",sha256=\"def\"} 1\n"
	tests := []struct {
		name      string
		body      string
		wantRules int
		wantErr   bool
		noEpoch   bool
	}{
		{
			// Falco 0.44.1 emits each file's sample with its own HELP/TYPE lines.
			name:      "repeated rules definitions retain every file",
			body:      rulesHeader + firstRule + rulesHeader + secondRule + timestamp,
			wantRules: 2,
		},
		{
			name: "unrelated duplicate definitions do not hide the epoch",
			body: "# HELP falcosecurity_scap_n_drops_buffer_total https://falco.org/docs/metrics/\n" +
				"# TYPE falcosecurity_scap_n_drops_buffer_total counter\n" +
				"falcosecurity_scap_n_drops_buffer_total 0\n" +
				"# HELP falcosecurity_scap_n_drops_buffer_total https://falco.org/docs/metrics/\n" +
				"# TYPE falcosecurity_scap_n_drops_buffer_total counter\n" +
				"falcosecurity_scap_n_drops_buffer_total 0\n" + timestamp,
		},
		{
			name: "conflicting target type is rejected",
			body: rulesHeader + firstRule + "# TYPE falcosecurity_falco_sha256_rules_files_info counter\n" +
				secondRule + timestamp,
			wantErr: true,
		},
		{
			name: "conflicting target help is rejected",
			body: rulesHeader + firstRule + "# HELP falcosecurity_falco_sha256_rules_files_info conflicting\n" +
				secondRule + timestamp,
			wantErr: true,
		},
		{
			name:    "malformed target sample is rejected",
			body:    rulesHeader + firstRule + rulesHeader + "falcosecurity_falco_sha256_rules_files_info{file_name=\"unclosed} 1\n" + timestamp,
			wantErr: true,
		},
		{
			name:    "malformed target value is rejected",
			body:    strings.Replace(timestamp, "1789460410000000000", "invalid", 1),
			wantErr: true,
		},
		{
			name:    "missing target type value is rejected",
			body:    "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds\n",
			wantErr: true,
		},
		{
			name:    "duplicate epoch samples are not coalesced",
			body:    timestamp + timestamp,
			noEpoch: true,
		},
		{
			name:    "definitions without samples do not prove a runtime",
			body:    rulesHeader,
			noEpoch: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			metrics, err := fetchFalcoMetrics(t.Context(), srv.Client(), srv.URL)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, metrics["falcosecurity_falco_sha256_rules_files_info"].GetMetric(), tc.wantRules)
			assert.NotContains(t, metrics, "falcosecurity_scap_n_drops_buffer_total")
			if tc.wantRules == 0 {
				assert.NotContains(t, metrics, "falcosecurity_falco_sha256_rules_files_info")
			}
			epoch, err := reloadTimestamp(metrics)
			if tc.noEpoch {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, float64(1789460410000000000), epoch) //nolint:testifylint // exact reload epoch
			if tc.wantRules == 2 {
				rules := metrics["falcosecurity_falco_sha256_rules_files_info"].GetMetric()
				assert.Equal(t, "managed.yaml", rules[0].GetLabel()[0].GetValue())
				assert.Equal(t, "external.yaml", rules[1].GetLabel()[0].GetValue())
			}
		})
	}
}

func TestReloadTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    float64
		wantErr bool
	}{
		{name: "nanosecond epoch", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds 1789460410000000000\n", want: 1789460410000000000},
		{name: "missing metric", body: "other_metric 1\n", wantErr: true},
		{name: "missing type", body: "falcosecurity_falco_reload_timestamp_nanoseconds 1000\n", wantErr: true},
		{name: "counter is not timestamp gauge", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds counter\nfalcosecurity_falco_reload_timestamp_nanoseconds 1000\n", wantErr: true},
		{name: "zero", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds 0\n", wantErr: true},
		{name: "negative", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds -1\n", wantErr: true},
		{name: "not a number", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds NaN\n", wantErr: true},
		{name: "infinity", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds +Inf\n", wantErr: true},
		{name: "ambiguous epochs", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds{instance=\"a\"} 1000\nfalcosecurity_falco_reload_timestamp_nanoseconds{instance=\"b\"} 2000\n", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			metrics, err := fetchFalcoMetrics(t.Context(), srv.Client(), srv.URL)
			require.NoError(t, err)
			got, err := reloadTimestamp(metrics)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got) //nolint:testifylint // reload epochs require exact comparison
		})
	}
}

func TestDirWatcher_PluginSnapshotReadFailure(t *testing.T) {
	const aggregate = "aggregate"
	for _, target := range []string{aggregate, "binary"} {
		t.Run(target, func(t *testing.T) {
			dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
			configPath := artifact.ArtifactPath(dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.TypeConfig)
			pluginPath := filepath.Join(dirs.Plugin, "container.so")
			require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: [container]\n"), 0o644))
			require.NoError(t, os.WriteFile(pluginPath, []byte("binary-a"), 0o755))
			dw, err := NewDirWatcher(dirs, "", func() {})
			require.NoError(t, err)
			t.Cleanup(func() { _ = dw.watcher.Close() })
			baseline := maps.Clone(dw.pluginFiles)

			if target == aggregate {
				require.NoError(t, os.Remove(configPath))
				require.NoError(t, os.Mkdir(configPath, 0o755))
				require.NoError(t, os.WriteFile(pluginPath, []byte("binary-b"), 0o755))
			} else {
				require.NoError(t, os.Remove(pluginPath))
				require.NoError(t, os.Symlink(filepath.Join(dirs.Plugin, "missing"), pluginPath))
				require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: []\n"), 0o644))
			}
			assert.False(t, dw.checkPluginFilesChanged(t.Context()), "read failure is not a successful empty snapshot")
			assert.Equal(t, baseline, dw.pluginFiles, "do not commit the readable portion of a failed snapshot")

			if target == aggregate {
				require.NoError(t, os.Remove(configPath))
				require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: []\n"), 0o644))
			} else {
				require.NoError(t, os.Remove(pluginPath))
				require.NoError(t, os.WriteFile(pluginPath, []byte("binary-b"), 0o755))
			}
			assert.True(t, dw.checkPluginFilesChanged(t.Context()), "retry must detect changes skipped during the failed read")
			assert.False(t, dw.checkPluginFilesChanged(t.Context()), "the successful snapshot becomes the new baseline")
		})
	}
}

func TestDirWatcher_PluginSnapshotInitiallyUnknown(t *testing.T) {
	dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
	configPath := artifact.ArtifactPath(dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.TypeConfig)
	require.NoError(t, os.Mkdir(configPath, 0o755))
	dw, err := NewDirWatcher(dirs, "", func() {})
	require.NoError(t, err, "initial plugin reads are best effort")
	t.Cleanup(func() { _ = dw.watcher.Close() })
	assert.Nil(t, dw.pluginFiles)
	assert.False(t, dw.checkPluginFilesChanged(t.Context()))
	assert.Nil(t, dw.pluginFiles)
	require.NoError(t, os.Remove(configPath))
	assert.True(t, dw.checkPluginFilesChanged(t.Context()), "unknown differs from a successfully observed empty snapshot")
	assert.NotNil(t, dw.pluginFiles)
	assert.Empty(t, dw.pluginFiles)
	assert.False(t, dw.checkPluginFilesChanged(t.Context()))
	require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: [container]\n"), 0o644))
	assert.True(t, dw.checkPluginFilesChanged(t.Context()), "creating the aggregate after an empty snapshot requires a reload")
	assert.False(t, dw.checkPluginFilesChanged(t.Context()))
}

func TestDirWatcher_PluginAliasDoesNotCauseReloads(t *testing.T) {
	var versionRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/versions" {
			versionRequests.Add(1)
			_, _ = fmt.Fprint(w, `{"plugin_versions":{"container":"0.7.1","external":"1.0.0"}}`)
		}
	}))
	defer srv.Close()
	dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
	pluginPath := filepath.Join(dirs.Plugin, "my-container.so")
	require.NoError(t, os.WriteFile(pluginPath, []byte("binary"), 0o755))
	configPath := artifact.ArtifactPath(dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.TypeConfig)
	config := fmt.Sprintf("plugins:\n- name: custom-alias\n  library_path: %s\nload_plugins: [custom-alias]\n", pluginPath)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o644))
	dw, err := NewDirWatcher(dirs, srv.URL, func() {})
	require.NoError(t, err)
	t.Cleanup(func() { _ = dw.watcher.Close() })

	assert.False(t, dw.checkPluginFilesChanged(t.Context()), "a config alias need not equal the library's ABI name")
	assert.False(t, dw.checkPluginFilesChanged(t.Context()), "unchanged plugin files must not cause periodic reloads")
	assert.Zero(t, versionRequests.Load(), "runtime names cannot prove which alias or library file was loaded")
}

func TestDirWatcher_NeedLeaderElection(t *testing.T) {
	dw, _ := newInternalDW(t, "", func() {})
	assert.False(t, dw.NeedLeaderElection())
}
