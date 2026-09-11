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
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
)

// DefaultReloadRetryInterval is the delay before retrying a failed PID-find or kill attempt.
const DefaultReloadRetryInterval = 5 * time.Second

// DefaultWaitForReadyTimeout is the maximum time to wait for Falco to become ready after a
// SIGHUP before giving up and continuing the loop. This prevents the coordinator from stalling
// indefinitely if Falco crashes (OOM kill, reload bug) and never recovers: after the timeout the
// coordinator logs a warning and re-enters the main loop so any queued write can be processed.
const DefaultWaitForReadyTimeout = 5 * time.Minute

// ProcFinder locates a running process by name.
type ProcFinder interface {
	FindPID(name string) (int, error)
}

// OSProcFinder implements ProcFinder using the Linux /proc filesystem. Requires the sidecar and
// Falco to share a PID namespace (shareProcessNamespace: true on the Pod spec).
type OSProcFinder struct {
	// procPath overrides the /proc root; empty means /proc. Set by tests only.
	procPath string
}

// FindPID scans /proc/[0-9]+/comm for a process whose name matches name (trimmed of whitespace).
// Returns an error when no match is found or /proc cannot be read.
func (f *OSProcFinder) FindPID(name string) (int, error) {
	root := f.procPath
	if root == "" {
		root = "/proc"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a numeric directory
		}
		commBytes, err := os.ReadFile(fmt.Sprintf("%s/%d/comm", root, pid))
		if err != nil {
			continue // process may have exited
		}
		if strings.TrimSpace(string(commBytes)) == name {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("process %q not found in /proc", name)
}

// ReloadCoordinator sends SIGHUP to the Falco process after all pending writes have landed on
// disk, then waits for Falco to come back up before processing the next reload request.
//
// It coordinates operator-controlled reloads on top of Falco's own inotify-based file watching
// (watch_config_files: true), eliminating the race where a file written during Falco's reload
// window (between file-enumeration and inotify re-registration) is silently missed: Falco's
// autonomous reload may be partial, but the SIGHUP from this coordinator fires only after all
// files are on disk, guaranteeing a correct final reload.
//
// Any number of concurrent NotifyWrite() calls collapse into at most one pending reload signal:
// the buffered pending channel has capacity 1. Writes that arrive while a reload is in flight are
// already on disk by the time the coordinator fires the follow-up SIGHUP after WaitAndFetch
// returns, so no file is ever missed.
//
// On FindPID or kill failure the coordinator arms a retry timer (retryInterval) so a reload is
// never permanently deferred if no new write ever arrives.
//
// ReloadCoordinator implements manager.Runnable.
type ReloadCoordinator struct {
	pending       chan struct{}
	falcoURL      string
	procFinder    ProcFinder
	killFn        func(pid int, sig syscall.Signal) error
	retryInterval time.Duration
	waitTimeout   time.Duration // max time to wait for Falco to become ready after SIGHUP
}

// NewReloadCoordinator returns a ReloadCoordinator that sends SIGHUP to the process named "falco"
// and polls falcoURL's /versions endpoint to detect when Falco has restarted.
func NewReloadCoordinator(falcoURL string) *ReloadCoordinator {
	return &ReloadCoordinator{
		pending:       make(chan struct{}, 1),
		falcoURL:      falcoURL,
		procFinder:    &OSProcFinder{},
		killFn:        syscall.Kill,
		retryInterval: DefaultReloadRetryInterval,
		waitTimeout:   DefaultWaitForReadyTimeout,
	}
}

// NotifyWrite signals that at least one file has been written to disk and Falco should reload.
// It is safe to call from multiple goroutines concurrently. If a reload signal is already pending
// (or a reload is in progress and will pick up the write anyway), the call is a no-op.
func (rc *ReloadCoordinator) NotifyWrite() {
	select {
	case rc.pending <- struct{}{}:
	default:
	}
}

// Start implements manager.Runnable. It blocks until ctx is canceled, sending SIGHUP to Falco
// whenever a write is pending and waiting for Falco to become ready before the next SIGHUP.
func (rc *ReloadCoordinator) Start(ctx context.Context) error {
	logger := ctrllog.FromContext(ctx)

	var (
		retryTimer *time.Timer
		retryC     <-chan time.Time
	)
	stopRetry := func() {
		if retryTimer != nil {
			retryTimer.Stop()
			retryTimer = nil
		}
		retryC = nil
	}

	for {
		select {
		case <-ctx.Done():
			stopRetry()
			return nil
		case <-rc.pending:
			stopRetry() // new write supersedes any pending retry timer
		case <-retryC:
			// timer fired; nil out so a nil channel blocks in the next iteration
			retryTimer = nil
			retryC = nil
		}

		pid, err := rc.procFinder.FindPID("falco")
		if err != nil {
			logger.Error(err, "failed to find Falco PID; will retry", "retryIn", rc.retryInterval)
			retryTimer = time.NewTimer(rc.retryInterval)
			retryC = retryTimer.C
			continue
		}

		logger.Info("Sending SIGHUP to Falco", "pid", pid)
		if err := rc.killFn(pid, syscall.SIGHUP); err != nil {
			logger.Error(err, "failed to send SIGHUP to Falco; will retry", "pid", pid, "retryIn", rc.retryInterval)
			retryTimer = time.NewTimer(rc.retryInterval)
			retryC = retryTimer.C
			continue
		}

		// Wait for Falco to restart and become ready. Any writes that arrived during the
		// reload are already on disk; the next pending signal picks them up.
		logger.V(1).Info("Waiting for Falco to become ready after SIGHUP")
		waitCtx, waitCancel := context.WithTimeout(ctx, rc.waitTimeout)
		_, waitErr := compat.WaitAndFetch(waitCtx, rc.falcoURL)
		waitCancel()
		if ctx.Err() != nil {
			stopRetry()
			return nil //nolint:nilerr // manager.Runnable must return nil on context cancellation, not the ctx error
		}
		if waitErr != nil {
			logger.Error(waitErr, "timed out waiting for Falco to become ready after SIGHUP; re-entering loop", "timeout", rc.waitTimeout)
			continue
		}
		logger.Info("Falco is ready after SIGHUP")
	}
}
