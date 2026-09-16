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

package nodeartifacts_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

// threeAlike returns ArtifactDirs where all three paths point to the same temp dir.
func threeAlike(dir string) artifact.ArtifactDirs {
	return artifact.ArtifactDirs{Config: dir, Rulesfile: dir, Plugin: dir}
}

// startDirWatcher creates a DirWatcher for dirs, starts it in a background goroutine, and returns cancel.
func startDirWatcher(t *testing.T, dirs artifact.ArtifactDirs, falcoURL string, calls *atomic.Int32) context.CancelFunc {
	t.Helper()
	dw, err := nodeartifacts.NewDirWatcher(dirs, falcoURL, func() { calls.Add(1) })
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

// falcoVersionsSrvWith returns an httptest server serving /metrics and /versions.
func falcoVersionsSrvWith(metrics, versions string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			_, _ = fmt.Fprintln(w, metrics)
		case "/versions":
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
			dw, err := nodeartifacts.NewDirWatcher(tc.dirs(t), "", func() {})
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
	dw, err := nodeartifacts.NewDirWatcher(threeAlike(t.TempDir()), "", func() {})
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
				dw, err := nodeartifacts.NewDirWatcher(threeAlike(dir), "", func() {})
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(context.Background())
				errCh := make(chan error, 1)
				go func() { errCh <- dw.Start(ctx) }()
				cancel()
				select {
				case startErr := <-errCh:
					assert.NoError(t, startErr, "Start must return nil on context cancellation")
				case <-time.After(2 * time.Second):
					t.Fatal("DirWatcher.Start did not return after context cancel")
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
	dw, err := nodeartifacts.NewDirWatcher(threeAlike(t.TempDir()), srv.URL, func() { calls.Add(1) })
	require.NoError(t, err)
	dw.WithVerifyInterval(20 * time.Millisecond)
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
		dw, err := nodeartifacts.NewDirWatcher(dirs, srv.URL, func() { calls.Add(1) })
		require.NoError(t, err)
		dw.WithVerifyInterval(50 * time.Millisecond)
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
