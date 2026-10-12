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

package node

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// threeAlike returns ArtifactDirs where all three paths point to the same temp dir.
func threeAlike(dir string) artifact.ArtifactDirs {
	return artifact.ArtifactDirs{Config: dir, Rulesfile: dir, Plugin: dir}
}

// startDirWatcher creates an artifactDirWatcher for dirs, starts it in a background goroutine, and returns cancel.
func startDirWatcher(t *testing.T, dirs artifact.ArtifactDirs, falcoURL string, calls *atomic.Int32) context.CancelFunc {
	t.Helper()
	dw, err := newArtifactDirWatcher(dirs, falcoURL, func() { calls.Add(1) })
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = dw.Start(ctx); close(done) }()
	waitForCall(t, calls)
	calls.Store(0) // Test subsequent events separately from the startup reload.
	return func() { cancel(); <-done }
}

// waitForCall blocks until calls reaches ≥1 or 3 seconds elapse.
func waitForCall(t *testing.T, calls *atomic.Int32) {
	t.Helper()
	require.Eventually(t, func() bool { return calls.Load() > 0 }, 3*time.Second, 10*time.Millisecond,
		"notifyFn was not called within 3 seconds")
}

// assertNoCall asserts that calls stays 0 for 200 ms.
func assertNoCall(t *testing.T, calls *atomic.Int32) {
	t.Helper()
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, int32(0), calls.Load(), "notifyFn should not have been called")
}

// metricsPath is the path of the Falco metrics endpoint the test server serves.
const metricsPath = "/metrics"

// falcoVersionsSrvWith returns an httptest server serving /metrics and /versions.
func falcoVersionsSrvWith(metrics, versions string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case metricsPath:
			_, _ = fmt.Fprintln(w, metrics)
		case versionsPath:
			_, _ = fmt.Fprint(w, versions)
		}
	}))
}

func TestNewDirWatcher(t *testing.T) {
	tests := []struct {
		name        string
		dirs        func(*testing.T) artifact.ArtifactDirs
		wantErr     bool
		errContains string
	}{
		{
			name: "success with valid dirs",
			dirs: func(t *testing.T) artifact.ArtifactDirs { return threeAlike(t.TempDir()) },
		},
		{
			name:        "fw.Add fails for nonexistent dir",
			dirs:        func(*testing.T) artifact.ArtifactDirs { return threeAlike("/nonexistent-dir-xyzzy") },
			wantErr:     true,
			errContains: "watch dir",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dw, err := newArtifactDirWatcher(tc.dirs(t), "", func() {})
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, dw)
		})
	}
}

func TestDirWatcher_NeedLeaderElection(t *testing.T) {
	dw, err := newArtifactDirWatcher(threeAlike(t.TempDir()), "", func() {})
	require.NoError(t, err)
	assert.False(t, dw.NeedLeaderElection())
}

func TestDirWatcher_Events(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{
			name: "fires on file create",
			fn: func(t *testing.T) {
				dir := t.TempDir()
				var calls atomic.Int32
				cancel := startDirWatcher(t, threeAlike(dir), "", &calls)
				defer cancel()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "myrule.yaml"), []byte("content"), 0o644))
				waitForCall(t, &calls)
			},
		},
		{
			name: "fires on file remove",
			fn: func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "myrule.yaml")
				require.NoError(t, os.WriteFile(path, []byte("content"), 0o644))
				var calls atomic.Int32
				cancel := startDirWatcher(t, threeAlike(dir), "", &calls)
				defer cancel()
				require.NoError(t, os.Remove(path))
				waitForCall(t, &calls)
			},
		},
		{
			name: "skips .tmp files",
			fn: func(t *testing.T) {
				dir := t.TempDir()
				var calls atomic.Int32
				cancel := startDirWatcher(t, threeAlike(dir), "", &calls)
				defer cancel()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "myrule.yaml.tmp"), []byte("temp"), 0o644))
				assertNoCall(t, &calls)
			},
		},
		{
			name: "stops on context cancel and returns nil",
			fn: func(t *testing.T) {
				dir := t.TempDir()
				dw, err := newArtifactDirWatcher(threeAlike(dir), "", func() {})
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(context.Background())
				errCh := make(chan error, 1)
				go func() { errCh <- dw.Start(ctx) }()
				cancel()
				select {
				case startErr := <-errCh:
					assert.NoError(t, startErr, "Start must return nil on context cancellation")
				case <-time.After(2 * time.Second):
					t.Fatal("artifactDirWatcher.Start did not return after context cancel")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t) })
	}
}

func TestDirWatcher_StartupReload(t *testing.T) {
	// Empty managed directories cannot identify artifacts removed while the sidecar was offline.
	srv := falcoVersionsSrvWith("", `{"plugin_versions":{"external":"1.0"}}`)
	defer srv.Close()
	var calls atomic.Int32
	dw, err := newArtifactDirWatcher(threeAlike(t.TempDir()), srv.URL, func() { calls.Add(1) })
	require.NoError(t, err)
	dw.verifyInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- dw.Start(ctx) }()
	waitForCall(t, &calls)
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, int32(1), calls.Load(), "startup requests one reload; external artifacts do not cause repeats")
	cancel()
	require.NoError(t, <-done)
}

func TestDirWatcher_Verify(t *testing.T) {
	startVerifying := func(t *testing.T, dirs artifact.ArtifactDirs, srv *httptest.Server, calls *atomic.Int32) context.CancelFunc {
		t.Helper()
		dw, err := newArtifactDirWatcher(dirs, srv.URL, func() { calls.Add(1) })
		require.NoError(t, err)
		dw.verifyInterval = 50 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { _ = dw.Start(ctx); close(done) }()
		waitForCall(t, calls)
		calls.Store(0)
		return func() { cancel(); <-done }
	}

	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{
			name: "rules files match - no notify",
			fn: func(t *testing.T) {
				rulesDir := t.TempDir()
				content := []byte("- rule: test")
				require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "rule.yaml"), content, 0o644))
				h := sha256.Sum256(content)
				hashHex := hex.EncodeToString(h[:])

				srv := falcoVersionsSrvWith(
					fmt.Sprintf(`falcosecurity_falco_sha256_rules_files_info{sha256=%q,file_name="rule.yaml"} 1`, hashHex),
					`{"engine_version_semver":"0.37.0","plugin_versions":{}}`,
				)
				defer srv.Close()

				var calls atomic.Int32
				cancel := startVerifying(t, artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: rulesDir, Plugin: t.TempDir()}, srv, &calls)
				defer cancel()
				time.Sleep(200 * time.Millisecond)
				assert.Equal(t, int32(0), calls.Load())
			},
		},
		{
			name: "rules files hash mismatch - notifies",
			fn: func(t *testing.T) {
				rulesDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "rule.yaml"), []byte("content"), 0o644))

				srv := falcoVersionsSrvWith(
					`falcosecurity_falco_sha256_rules_files_info{sha256="deadbeef",file_name="rule.yaml"} 1`,
					`{"engine_version_semver":"0.37.0","plugin_versions":{}}`,
				)
				defer srv.Close()

				var calls atomic.Int32
				cancel := startVerifying(t, artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: rulesDir, Plugin: t.TempDir()}, srv, &calls)
				defer cancel()
				waitForCall(t, &calls)
			},
		},
		{
			name: "rules files count mismatch - notifies",
			fn: func(t *testing.T) {
				rulesDir := t.TempDir()
				content1 := []byte("rule-a")
				content2 := []byte("rule-b")
				require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "r1.yaml"), content1, 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "r2.yaml"), content2, 0o644))
				h := sha256.Sum256(content1)

				// Falco reports only 1 hash; disk has 2.
				srv := falcoVersionsSrvWith(
					fmt.Sprintf(`falcosecurity_falco_sha256_rules_files_info{sha256=%q,file_name="r1.yaml"} 1`, hex.EncodeToString(h[:])),
					`{"engine_version_semver":"0.37.0","plugin_versions":{}}`,
				)
				defer srv.Close()

				var calls atomic.Int32
				cancel := startVerifying(t, artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: rulesDir, Plugin: t.TempDir()}, srv, &calls)
				defer cancel()
				waitForCall(t, &calls)
			},
		},
		{
			name: "unchanged plugin files - no notify",
			fn: func(t *testing.T) {
				pluginsDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(pluginsDir, "container.so"), nil, 0o755))
				configDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(configDir, "99-03-plugins-config-inline.yaml"), []byte("load_plugins: [container]\n"), 0o644))

				srv := falcoVersionsSrvWith(
					"",
					`{"engine_version_semver":"0.37.0","plugin_versions":{"container":"0.7.1"}}`,
				)
				defer srv.Close()

				var calls atomic.Int32
				cancel := startVerifying(t, artifact.ArtifactDirs{Config: configDir, Rulesfile: t.TempDir(), Plugin: pluginsDir}, srv, &calls)
				defer cancel()
				time.Sleep(200 * time.Millisecond)
				assert.Equal(t, int32(0), calls.Load())
			},
		},
		{
			name: "runtime-only plugin removal is not observable from the local snapshot",
			fn: func(t *testing.T) {
				pluginsDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(pluginsDir, "container.so"), nil, 0o755))
				configDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(configDir, "99-03-plugins-config-inline.yaml"), []byte("load_plugins: [container]\n"), 0o644))

				srv := falcoVersionsSrvWith("", `{"engine_version_semver":"0.37.0","plugin_versions":{}}`)
				defer srv.Close()

				var calls atomic.Int32
				cancel := startVerifying(t, artifact.ArtifactDirs{Config: configDir, Rulesfile: t.TempDir(), Plugin: pluginsDir}, srv, &calls)
				defer cancel()
				assertNoCall(t, &calls)
			},
		},
		{
			name: "different runtime plugin names do not prove a local mismatch",
			fn: func(t *testing.T) {
				pluginsDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(pluginsDir, "container.so"), nil, 0o755))
				configDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(configDir, "99-03-plugins-config-inline.yaml"), []byte("load_plugins: [container]\n"), 0o644))

				// Runtime names do not map configuration aliases to library identities.
				srv := falcoVersionsSrvWith("", `{"engine_version_semver":"0.37.0","plugin_versions":{"json":"1.0"}}`)
				defer srv.Close()

				var calls atomic.Int32
				cancel := startVerifying(t, artifact.ArtifactDirs{Config: configDir, Rulesfile: t.TempDir(), Plugin: pluginsDir}, srv, &calls)
				defer cancel()
				assertNoCall(t, &calls)
			},
		},
		{
			name: "periodic backstop detects writes ignored by the event handler",
			fn: func(t *testing.T) {
				for _, target := range []string{"aggregate", "binary"} {
					t.Run(target, func(t *testing.T) {
						dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
						configPath := filepath.Join(dirs.Config, "99-03-plugins-config-inline.yaml")
						pluginPath := filepath.Join(dirs.Plugin, "my-container.so")
						require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: [custom-alias]\n"), 0o644))
						require.NoError(t, os.WriteFile(pluginPath, []byte("binary-a"), 0o755))
						srv := falcoVersionsSrvWith("", `{"plugin_versions":{"container":"0.7.1"}}`)
						defer srv.Close()
						var calls atomic.Int32
						cancel := startVerifying(t, dirs, srv, &calls)
						defer cancel()
						// In-place Write events are intentionally ignored; the periodic scan must notice.
						if target == "aggregate" {
							require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: []\n"), 0o644))
						} else {
							require.NoError(t, os.WriteFile(pluginPath, []byte("binary-b"), 0o755))
						}
						waitForCall(t, &calls)
					})
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t) })
	}
}

const nonexistentDir = "/nonexistent-dir-xyzzy"

// internalThreeAlike returns ArtifactDirs with all three paths pointing to the same dir.
func internalThreeAlike(dir string) artifact.ArtifactDirs {
	return artifact.ArtifactDirs{Config: dir, Rulesfile: dir, Plugin: dir}
}

// newInternalDW creates an artifactDirWatcher on three separate temp dirs and registers cleanup.
func newInternalDW(t *testing.T, falcoURL string, notify func()) (*artifactDirWatcher, artifact.ArtifactDirs) {
	t.Helper()
	dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
	dw, err := newArtifactDirWatcher(dirs, falcoURL, notify)
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
				path := testutil.MustArtifactPath(t, dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.KindConfig)
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
				path := testutil.MustArtifactPath(t, dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.KindConfig)
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
		preSetup  func(dw *artifactDirWatcher, dirs artifact.ArtifactDirs)
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
			preSetup: func(_ *artifactDirWatcher, d artifact.ArtifactDirs) { _ = os.RemoveAll(d.Plugin) },
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
				dw := &artifactDirWatcher{watcher: &fsnotify.Watcher{Events: closedEvents}}

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
				dw := &artifactDirWatcher{watcher: &fsnotify.Watcher{Errors: closedErrors}}

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
				dw := &artifactDirWatcher{watcher: &fsnotify.Watcher{Errors: watchErrors}}

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

			dw, err := newArtifactDirWatcher(internalThreeAlike(t.TempDir()), url, func() {})
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
					if r.URL.Path == metricsPath {
						_, _ = fmt.Fprintln(w, body)
					}
				}))
				defer srv.Close()
			} else {
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				srv.Close()
			}

			dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: rulesDir, Plugin: t.TempDir()}
			dw, err := newArtifactDirWatcher(dirs, srv.URL, func() {})
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
			configPath := testutil.MustArtifactPath(t, dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.KindConfig)
			require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: [custom-alias]\n"), 0o644))
			pluginPath := filepath.Join(dirs.Plugin, "my-container.so")
			require.NoError(t, os.WriteFile(pluginPath, []byte("binary-a"), 0o755))
			var calls int32
			dw, err := newArtifactDirWatcher(dirs, "", func() { calls++ })
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
	dw, err := newArtifactDirWatcher(dirs, srv.URL, func() {})
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
	dw, err := newArtifactDirWatcher(dirs, srv.URL, func() {})
	require.NoError(t, err)
	t.Cleanup(func() { _ = dw.watcher.Close() })
	assert.False(t, dw.checkRulesFilesMismatch(t.Context()))
	require.NoError(t, os.Remove(path))
	assert.True(t, dw.checkRulesFilesMismatch(t.Context()))
	metrics.Store("falcosecurity_falco_sha256_rules_files_info{file_name=\"rules.yaml\",sha256=\"external\"} 1\n")
	assert.False(t, dw.checkRulesFilesMismatch(t.Context()), "an external same-basename file is not a stale managed revision")
}

func TestDirWatcher_PluginSnapshotReadFailure(t *testing.T) {
	const aggregate = "aggregate"
	for _, target := range []string{aggregate, "binary"} {
		t.Run(target, func(t *testing.T) {
			dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
			configPath := testutil.MustArtifactPath(t, dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.KindConfig)
			pluginPath := filepath.Join(dirs.Plugin, "container.so")
			require.NoError(t, os.WriteFile(configPath, []byte("load_plugins: [container]\n"), 0o644))
			require.NoError(t, os.WriteFile(pluginPath, []byte("binary-a"), 0o755))
			dw, err := newArtifactDirWatcher(dirs, "", func() {})
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
	configPath := testutil.MustArtifactPath(t, dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.KindConfig)
	require.NoError(t, os.Mkdir(configPath, 0o755))
	dw, err := newArtifactDirWatcher(dirs, "", func() {})
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
		if r.URL.Path == versionsPath {
			versionRequests.Add(1)
			_, _ = fmt.Fprint(w, `{"plugin_versions":{"container":"0.7.1","external":"1.0.0"}}`)
		}
	}))
	defer srv.Close()
	dirs := artifact.ArtifactDirs{Config: t.TempDir(), Rulesfile: t.TempDir(), Plugin: t.TempDir()}
	pluginPath := filepath.Join(dirs.Plugin, "my-container.so")
	require.NoError(t, os.WriteFile(pluginPath, []byte("binary"), 0o755))
	configPath := testutil.MustArtifactPath(t, dirs, pluginConfigFileName, 99, artifact.MediumInline, artifact.KindConfig)
	config := fmt.Sprintf("plugins:\n- name: custom-alias\n  library_path: %s\nload_plugins: [custom-alias]\n", pluginPath)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o644))
	dw, err := newArtifactDirWatcher(dirs, srv.URL, func() {})
	require.NoError(t, err)
	t.Cleanup(func() { _ = dw.watcher.Close() })

	assert.False(t, dw.checkPluginFilesChanged(t.Context()), "a config alias need not equal the library's ABI name")
	assert.False(t, dw.checkPluginFilesChanged(t.Context()), "unchanged plugin files must not cause periodic reloads")
	assert.Zero(t, versionRequests.Load(), "runtime names cannot prove which alias or library file was loaded")
}
