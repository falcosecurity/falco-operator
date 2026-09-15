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

package compat

import (
	"context"
	"time"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// DefaultWatchInterval is the polling cadence used by VersionsWatcher when none is specified.
const DefaultWatchInterval = 5 * time.Second

// VersionsWatcher polls Falco's /versions endpoint and forwards successful observations to its sink.
// Register it with the manager as a Runnable.
type VersionsWatcher struct {
	fetcher  VersionsFetcher
	interval time.Duration
	sink     func(*Versions)
}

// NewVersionsWatcher creates a watcher that polls using fetcher every interval.
func NewVersionsWatcher(fetcher VersionsFetcher, interval time.Duration) *VersionsWatcher {
	return &VersionsWatcher{
		fetcher:  fetcher,
		interval: interval,
	}
}

// SetSink registers a callback for every successful poll, including unchanged versions.
// Call it during setup, before Start; it is not safe to change the sink while polling.
func (w *VersionsWatcher) SetSink(sink func(*Versions)) {
	w.sink = sink
}

// Start implements manager.Runnable. It polls until ctx is canceled.
func (w *VersionsWatcher) Start(ctx context.Context) error {
	logger := ctrllog.FromContext(ctx)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := w.poll(ctx); err != nil {
				logger.V(4).Info("Falco versions poll failed, will retry", "err", err)
			}
		}
	}
}

// poll forwards one successful observation without maintaining a second version cache.
func (w *VersionsWatcher) poll(ctx context.Context) error {
	versions, err := w.fetcher.Fetch(ctx)
	if err != nil {
		return err
	}

	if w.sink != nil {
		w.sink(versions)
	}

	return nil
}
