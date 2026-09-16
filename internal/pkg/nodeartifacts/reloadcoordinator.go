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

// DefaultReloadCooldown is the minimum pause after SIGHUP before checking HTTP availability
// or sending a follow-up signal. It limits repeated signals; it does not confirm a completed reload.
const DefaultReloadCooldown = 5 * time.Second

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
// (watch_config_files: true), requesting a follow-up reload for writes made while Falco's
// filesystem watches are being re-registered.
//
// Any number of concurrent NotifyWrite() calls collapse into at most one pending reload signal:
// the buffered pending channel has capacity 1. Writes that arrive while a reload is in flight are
// already on disk by the time the coordinator fires the follow-up SIGHUP after WaitAndFetch
// returns. HTTP availability alone does not confirm that the requested configuration was applied.
// A cooldown after each successful signal delays both HTTP checks and follow-up signals.
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
	cooldown      time.Duration
	waitTimeout   time.Duration // max time to wait for Falco to become ready after SIGHUP
}

// NewReloadCoordinator returns a ReloadCoordinator that sends SIGHUP to the process named "falco"
// and waits for falcoURL's /versions endpoint to become available.
func NewReloadCoordinator(falcoURL string) *ReloadCoordinator {
	return &ReloadCoordinator{
		pending:       make(chan struct{}, 1),
		falcoURL:      falcoURL,
		procFinder:    &OSProcFinder{},
		killFn:        syscall.Kill,
		retryInterval: DefaultReloadRetryInterval,
		cooldown:      DefaultReloadCooldown,
		waitTimeout:   DefaultWaitForReadyTimeout,
	}
}

// WithCooldown sets the positive pause after a successful SIGHUP. Call before Start.
func (rc *ReloadCoordinator) WithCooldown(cooldown time.Duration) *ReloadCoordinator {
	rc.cooldown = cooldown
	return rc
}

// NotifyWrite signals that at least one file has been written to disk and Falco should reload.
// It is safe to call from multiple goroutines concurrently. If a request is already pending,
// the call is a no-op. Writes during the wait queue a follow-up signal.
func (rc *ReloadCoordinator) NotifyWrite() {
	select {
	case rc.pending <- struct{}{}:
	default:
	}
}

// Start implements manager.Runnable. It blocks until ctx is canceled, sending SIGHUP to Falco
// whenever a write is pending and waiting for Falco to become ready before the next SIGHUP.
func (rc *ReloadCoordinator) Start(ctx context.Context) error {
	if rc.cooldown <= 0 {
		return fmt.Errorf("reload cooldown must be positive, got %s", rc.cooldown)
	}
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

		// The endpoint may still serve the old run immediately after SIGHUP.
		// Keep pending writes queued without shortening or extending the cooldown.
		cooldown := time.NewTimer(rc.cooldown)
		select {
		case <-ctx.Done():
			cooldown.Stop()
			stopRetry()
			return nil
		case <-cooldown.C:
		}

		// Wait for Falco's HTTP endpoint to become available. Any writes that arrived
		// during this wait remain queued for a follow-up signal.
		logger.V(1).Info("Waiting for Falco's HTTP endpoint after SIGHUP cooldown")
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
		logger.Info("Falco's HTTP endpoint is available after SIGHUP")
	}
}
