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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const versionsPath = "/versions"

// fakeProcFinder implements ProcFinder for tests.
type fakeProcFinder struct {
	pid int
	err error
}

func (f *fakeProcFinder) FindPID(_ string) (int, error) { return f.pid, f.err }

// newTestCoordinator builds a ReloadCoordinator with injected fakes and a short retry interval.
func newTestCoordinator(falcoURL string, finder ProcFinder, killFn func(int, syscall.Signal) error) *ReloadCoordinator {
	return &ReloadCoordinator{
		pending:       make(chan struct{}, 1),
		falcoURL:      falcoURL,
		procFinder:    finder,
		killFn:        killFn,
		retryInterval: 30 * time.Millisecond,
		waitTimeout:   200 * time.Millisecond,
	}
}

// falcoVersionsSrv returns an httptest server that responds to /versions with a minimal payload.
func falcoVersionsSrv() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == versionsPath {
			_, _ = fmt.Fprint(w, `{"engine_version_semver":"0.62.0","plugin_versions":{}}`)
		}
	}))
}

// makeFakeProc creates a minimal controlled /proc tree and returns its root path.
// It contains: a non-dir entry, a non-numeric dir, a numeric dir without a comm file,
// a numeric dir whose comm matches "myfalco", and one whose comm does not match.
func makeFakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "cmdline"), nil, 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(root, "self"), 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(root, "1234"), 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(root, "5678"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "5678", "comm"), []byte("myfalco\n"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(root, "9999"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "9999", "comm"), []byte("other\n"), 0o644))
	return root
}

func TestNewReloadCoordinator(t *testing.T) {
	tests := []struct {
		name     string
		falcoURL string
	}{
		{name: "empty URL", falcoURL: ""},
		{name: "http URL", falcoURL: "http://falco:8765"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := NewReloadCoordinator(tc.falcoURL)
			require.NotNil(t, rc)
			assert.Equal(t, tc.falcoURL, rc.falcoURL)
			assert.Equal(t, DefaultReloadRetryInterval, rc.retryInterval)
			assert.Equal(t, DefaultWaitForReadyTimeout, rc.waitTimeout)
			assert.Equal(t, 1, cap(rc.pending))
			_, isOSFinder := rc.procFinder.(*OSProcFinder)
			assert.True(t, isOSFinder, "procFinder should be *OSProcFinder")
			require.NotNil(t, rc.killFn)
			// Exercise the closure: signal 0 probes existence without delivering a signal.
			assert.NoError(t, rc.killFn(os.Getpid(), syscall.Signal(0)))
		})
	}
}

func TestOSProcFinder_FindPID(t *testing.T) {
	ownName := func() string {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", os.Getpid()))
		return strings.TrimSpace(string(b))
	}()

	tests := []struct {
		name         string
		procPath     func(*testing.T) string // returns procPath; empty string → real /proc
		search       string
		wantPID      int  // exact match; 0 = skip exact check
		wantPositive bool // accept any positive PID
		wantErr      bool
		errContains  string
	}{
		{
			name:        "ReadDir fails on nonexistent path",
			procPath:    func(*testing.T) string { return "/nonexistent-proc-path-xyzzy" },
			search:      "anything",
			wantErr:     true,
			errContains: "read /proc",
		},
		{
			name:        "process not found in real /proc",
			procPath:    func(*testing.T) string { return "" },
			search:      "this-process-does-not-exist-xyzzy-99999",
			wantErr:     true,
			errContains: "not found",
		},
		{
			name:         "current test process found in real /proc",
			procPath:     func(*testing.T) string { return "" },
			search:       ownName,
			wantPositive: true,
		},
		{
			name:     "fake proc - matching entry found (skips non-dir, non-numeric, no-comm entries)",
			procPath: makeFakeProc,
			search:   "myfalco",
			wantPID:  5678,
		},
		{
			name:        "fake proc - name not present",
			procPath:    makeFakeProc,
			search:      "does-not-exist",
			wantErr:     true,
			errContains: "not found",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &OSProcFinder{procPath: tc.procPath(t)}
			pid, err := f.FindPID(tc.search)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			if tc.wantPID != 0 {
				assert.Equal(t, tc.wantPID, pid)
			}
			if tc.wantPositive {
				assert.Positive(t, pid)
			}
		})
	}
}

func TestReloadCoordinator_Start(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{
			name: "context cancel exits immediately",
			fn: func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				rc := newTestCoordinator("", &fakeProcFinder{err: errors.New("no proc")}, nil)
				done := make(chan error, 1)
				go func() { done <- rc.Start(ctx) }()
				cancel()
				select {
				case err := <-done:
					assert.NoError(t, err)
				case <-time.After(2 * time.Second):
					t.Fatal("Start did not return after context cancel")
				}
			},
		},
		{
			name: "PID not found - retries without calling kill",
			fn: func(t *testing.T) {
				var calls atomic.Int32
				rc := newTestCoordinator("", &fakeProcFinder{err: errors.New("not found")}, func(int, syscall.Signal) error {
					calls.Add(1)
					return nil
				})
				rc.retryInterval = 20 * time.Millisecond
				go func() { _ = rc.Start(t.Context()) }()
				rc.NotifyWrite()
				time.Sleep(150 * time.Millisecond)
				assert.Equal(t, int32(0), calls.Load(), "kill should not be called when PID is not found")
			},
		},
		{
			name: "kill fails - retries at least twice",
			fn: func(t *testing.T) {
				var killCalls atomic.Int32
				rc := newTestCoordinator("", &fakeProcFinder{pid: 42}, func(int, syscall.Signal) error {
					killCalls.Add(1)
					return errors.New("operation not permitted")
				})
				rc.retryInterval = 20 * time.Millisecond
				go func() { _ = rc.Start(t.Context()) }()
				rc.NotifyWrite()
				require.Eventually(t, func() bool { return killCalls.Load() >= 2 }, 500*time.Millisecond, 10*time.Millisecond,
					"expected ≥2 kill attempts via retry")
			},
		},
		{
			name: "success - sends SIGHUP to correct PID",
			fn: func(t *testing.T) {
				srv := falcoVersionsSrv()
				defer srv.Close()
				var killedPID, killedSig atomic.Int32
				rc := newTestCoordinator(srv.URL, &fakeProcFinder{pid: 76}, func(pid int, sig syscall.Signal) error {
					killedPID.Store(int32(pid))
					killedSig.Store(int32(sig))
					return nil
				})
				go func() { _ = rc.Start(t.Context()) }()
				rc.NotifyWrite()
				require.Eventually(t, func() bool { return killedPID.Load() == 76 }, 3*time.Second, 10*time.Millisecond,
					"SIGHUP was not sent within 3 seconds")
				assert.Equal(t, int32(syscall.SIGHUP), killedSig.Load())
			},
		},
		{
			name: "20 concurrent writes coalesce to a single SIGHUP",
			fn: func(t *testing.T) {
				srv := falcoVersionsSrv()
				defer srv.Close()
				var killCalls atomic.Int32
				rc := newTestCoordinator(srv.URL, &fakeProcFinder{pid: 76}, func(int, syscall.Signal) error {
					killCalls.Add(1)
					return nil
				})
				go func() { _ = rc.Start(t.Context()) }()
				for range 20 {
					rc.NotifyWrite()
				}
				time.Sleep(300 * time.Millisecond)
				assert.Equal(t, int32(1), killCalls.Load(), "20 concurrent writes should coalesce to a single SIGHUP")
			},
		},
		{
			name: "write during WaitAndFetch triggers follow-up SIGHUP",
			fn: func(t *testing.T) {
				ready := make(chan struct{})
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == versionsPath {
						<-ready
						_, _ = fmt.Fprint(w, `{"engine_version_semver":"0.62.0","plugin_versions":{}}`)
					}
				}))
				defer srv.Close()
				var killCalls atomic.Int32
				rc := newTestCoordinator(srv.URL, &fakeProcFinder{pid: 76}, func(int, syscall.Signal) error {
					killCalls.Add(1)
					return nil
				})
				go func() { _ = rc.Start(t.Context()) }()
				rc.NotifyWrite()
				require.Eventually(t, func() bool { return killCalls.Load() >= 1 }, 2*time.Second, 10*time.Millisecond,
					"first SIGHUP should be sent")
				rc.NotifyWrite()
				close(ready)
				require.Eventually(t, func() bool { return killCalls.Load() >= 2 }, 3*time.Second, 10*time.Millisecond,
					"second write during WaitAndFetch should produce a follow-up SIGHUP")
			},
		},
		{
			name: "context cancel during WaitAndFetch returns nil",
			fn: func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				unblock := make(chan struct{})
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == versionsPath {
						select {
						case <-unblock:
						case <-time.After(10 * time.Second):
						}
						_, _ = fmt.Fprint(w, `{"engine_version_semver":"0.62.0","plugin_versions":{}}`)
					}
				}))
				defer srv.Close()
				defer close(unblock)
				var killCalls atomic.Int32
				rc := newTestCoordinator(srv.URL, &fakeProcFinder{pid: 123}, func(int, syscall.Signal) error {
					killCalls.Add(1)
					return nil
				})
				done := make(chan error, 1)
				go func() { done <- rc.Start(ctx) }()
				rc.NotifyWrite()
				require.Eventually(t, func() bool { return killCalls.Load() >= 1 }, 2*time.Second, 10*time.Millisecond,
					"SIGHUP should be sent before context cancel")
				cancel()
				select {
				case err := <-done:
					assert.NoError(t, err)
				case <-time.After(3 * time.Second):
					t.Fatal("Start did not exit after context cancellation during WaitAndFetch")
				}
			},
		},
		{
			name: "WaitAndFetch timeout unblocks coordinator so next write is processed",
			fn: func(t *testing.T) {
				blocked := make(chan struct{})
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == versionsPath {
						<-blocked // never unblocks within this test
					}
				}))
				defer srv.Close()
				defer close(blocked)
				var killCalls atomic.Int32
				rc := newTestCoordinator(srv.URL, &fakeProcFinder{pid: 77}, func(int, syscall.Signal) error {
					killCalls.Add(1)
					return nil
				})
				rc.waitTimeout = 50 * time.Millisecond
				go func() { _ = rc.Start(t.Context()) }()
				rc.NotifyWrite()
				require.Eventually(t, func() bool { return killCalls.Load() >= 1 }, 2*time.Second, 10*time.Millisecond,
					"first SIGHUP should be sent")
				rc.NotifyWrite()
				require.Eventually(t, func() bool { return killCalls.Load() >= 2 }, 2*time.Second, 10*time.Millisecond,
					"coordinator should unblock after WaitAndFetch timeout and process the pending write")
			},
		},
		{
			name: "write supersedes pending retry timer",
			fn: func(t *testing.T) {
				srv := falcoVersionsSrv()
				defer srv.Close()
				firstKillDone := make(chan struct{})
				var killCalls atomic.Int32
				rc := newTestCoordinator(srv.URL, &fakeProcFinder{pid: 55}, func(int, syscall.Signal) error {
					n := killCalls.Add(1)
					if n == 1 {
						close(firstKillDone)
						return errors.New("transient kill error")
					}
					return nil
				})
				rc.retryInterval = 5 * time.Second // long enough that the retry timer won't fire on its own
				go func() { _ = rc.Start(t.Context()) }()
				rc.NotifyWrite()
				<-firstKillDone  // wait for first (failing) kill attempt
				rc.NotifyWrite() // should supersede the 5-second retry timer
				require.Eventually(t, func() bool { return killCalls.Load() >= 2 }, 2*time.Second, 10*time.Millisecond,
					"second write should supersede the retry timer and trigger an immediate SIGHUP")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t) })
	}
}
