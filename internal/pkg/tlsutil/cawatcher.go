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

// Package tlsutil provides a hot-reloadable CA trust anchor, filling a gap
// sigs.k8s.io/controller-runtime/pkg/certwatcher doesn't cover: certwatcher.CertWatcher
// hot-reloads a cert+key pair, but there's no equivalent for a bare CA bundle used to verify
// a peer's certificate (mTLS client-cert verification on a server, or server-cert verification
// on a client using a private CA). This matters because a cert-manager-issued CA rotates on a
// schedule just like any other certificate; a CA loaded once at startup would silently start
// rejecting connections after a rotation until every pod restarted.
package tlsutil

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// defaultWatchInterval mirrors certwatcher's own polling fallback interval, used alongside
// fsnotify in case an fsnotify event is missed (e.g. some overlay filesystems, or a rename
// that fsnotify doesn't reliably surface).
const defaultWatchInterval = 10 * time.Second

// CAWatcher hot-reloads a PEM CA bundle from disk into an *x509.CertPool. New performs an
// initial synchronous load and fails if the file is missing or invalid; Start (a
// manager.Runnable) then watches the file via fsnotify plus a periodic poll fallback,
// keeping the last-good pool and logging on any reload failure rather than serving with an
// empty trust store.
type CAWatcher struct {
	mu   sync.RWMutex
	pool *x509.CertPool

	caFile   string
	interval time.Duration
	watcher  *fsnotify.Watcher
	log      logr.Logger
}

// NewCAWatcher reads and parses caFile once, returning an error if it's missing or contains
// no valid PEM certificates. The fsnotify watch on caFile is also registered here (not deferred
// to Start), so a change to the file is never missed during the window between construction and
// Start actually running (e.g. via mgr.Add, which may run well after New). Call Start to begin
// processing watch events and the poll fallback.
func NewCAWatcher(caFile string) (*CAWatcher, error) {
	w := &CAWatcher{
		caFile:   caFile,
		interval: defaultWatchInterval,
		log:      ctrllog.Log.WithName("cawatcher").WithValues("ca", caFile),
	}

	if err := w.reload(); err != nil {
		return nil, err
	}

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := fw.Add(caFile); err != nil {
		_ = fw.Close()
		return nil, fmt.Errorf("watch CA file: %w", err)
	}
	w.watcher = fw

	return w, nil
}

// WithWatchInterval sets the poll-fallback interval and returns w, mirroring
// certwatcher.CertWatcher.WithWatchInterval. The poll fallback matters because an atomic
// rename-over-an-existing-path (as a Secret volume's symlink swap, or a plain
// write-tmp-then-rename, produces) doesn't reliably fire an fsnotify event on every platform.
func (w *CAWatcher) WithWatchInterval(interval time.Duration) *CAWatcher {
	w.interval = interval
	return w
}

// CertPool returns the currently loaded trust pool. Safe for concurrent use.
func (w *CAWatcher) CertPool() *x509.CertPool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pool
}

// reload reads and parses caFile, replacing the current pool on success. On failure, the
// current pool is left untouched (caller decides whether that's the initial "no pool yet"
// error or a logged-and-ignored reload failure).
func (w *CAWatcher) reload() error {
	data, err := os.ReadFile(w.caFile)
	if err != nil {
		return fmt.Errorf("read CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("no valid certificates found in CA file %q", w.caFile)
	}

	w.mu.Lock()
	w.pool = pool
	w.mu.Unlock()
	return nil
}

// Start processes watch events on caFile until ctx is canceled, reloading the trust pool on
// every change (and periodically, as a fallback). Implements manager.Runnable.
func (w *CAWatcher) Start(ctx context.Context) error {
	go w.watch()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.log.Info("Starting CA poll+watcher", "interval", w.interval)
	for {
		select {
		case <-ctx.Done():
			return w.watcher.Close()
		case <-ticker.C:
			if err := w.reload(); err != nil {
				w.log.Error(err, "failed to reload CA file")
			}
		}
	}
}

// watch reads fsnotify events and reacts to changes, mirroring certwatcher.CertWatcher.Watch.
func (w *CAWatcher) watch() {
	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			w.handleEvent(event)
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.log.Error(err, "CA watch error")
		}
	}
}

func (w *CAWatcher) handleEvent(event fsnotify.Event) {
	switch {
	case event.Op.Has(fsnotify.Write):
	case event.Op.Has(fsnotify.Create):
	case event.Op.Has(fsnotify.Chmod), event.Op.Has(fsnotify.Remove):
		// The file was removed or renamed (e.g. a Secret volume's atomic symlink swap) —
		// re-add the watch on the same path.
		if err := w.watcher.Add(event.Name); err != nil {
			w.log.Error(err, "error re-watching CA file")
		}
	default:
		return
	}

	w.log.V(1).Info("CA file event", "event", event)
	if err := w.reload(); err != nil {
		w.log.Error(err, "error re-reading CA file")
		return
	}
	w.log.Info("Updated CA trust pool")
}

// NeedLeaderElection reports that the CA watcher runs on every replica, not just the leader.
func (w *CAWatcher) NeedLeaderElection() bool {
	return false
}
