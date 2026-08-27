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
	"maps"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/event"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// DefaultWatchInterval is the polling cadence used by VersionsWatcher when none is specified.
const DefaultWatchInterval = 5 * time.Second

// VersionsWatcher polls the Falco /versions endpoint and publishes one GenericEvent whenever the
// capability set changes (plugin loaded/unloaded, version bump, Falco restart). Register it with
// the manager as a Runnable. Call Events() once per controller that needs to react to changes —
// each call returns an independent channel, so every subscriber gets its own copy of each event.
type VersionsWatcher struct {
	fetcher            VersionsFetcher
	interval           time.Duration
	mu                 sync.Mutex
	lastCapabilities   map[string]string
	lastPluginVersions map[string]string
	subscribers        []chan event.GenericEvent
	sink               func(*Versions)
}

// NewVersionsWatcher creates a watcher that polls using fetcher every interval.
func NewVersionsWatcher(fetcher VersionsFetcher, interval time.Duration) *VersionsWatcher {
	return &VersionsWatcher{
		fetcher:  fetcher,
		interval: interval,
	}
}

// SetSink registers a callback invoked with the freshly-fetched *Versions on every successful
// poll, regardless of whether the capability set changed (unlike the subscriber/GenericEvent
// mechanism, which only fires on an actual change). Intended for a consumer that wants to keep
// its own cache of Falco's latest reported state fresh (e.g. nodeartifacts.Manager). Not safe
// to call concurrently with Start; call it once during setup, before the watcher is registered
// with the manager.
func (w *VersionsWatcher) SetSink(sink func(*Versions)) {
	w.sink = sink
}

// Events returns a new channel that receives one GenericEvent each time Falco's capability set
// changes. Call this once per controller that needs to watch for changes — each call registers
// and returns a fresh, independent channel, so every subscriber sees every change event.
func (w *VersionsWatcher) Events() <-chan event.GenericEvent {
	ch := make(chan event.GenericEvent, 100)
	w.mu.Lock()
	w.subscribers = append(w.subscribers, ch)
	w.mu.Unlock()
	return ch
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

// poll fetches /versions once and sends a GenericEvent if the capability set changed. It diffs
// the full capability map, not just plugin_versions, so a change to any top-level capability
// (e.g. plugin_api_version in a mocked test endpoint) is also detected. On fetch error it resets
// cached state so the next successful fetch is treated as a change.
func (w *VersionsWatcher) poll(ctx context.Context) error {
	versions, err := w.fetcher.Fetch(ctx)
	if err != nil {
		w.mu.Lock()
		w.lastCapabilities = nil
		w.lastPluginVersions = nil
		w.mu.Unlock()
		return err
	}

	if w.sink != nil {
		w.sink(versions)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if maps.Equal(w.lastCapabilities, versions.capabilities) && maps.Equal(w.lastPluginVersions, versions.pluginVersions) {
		return nil
	}
	w.lastCapabilities = maps.Clone(versions.capabilities)
	w.lastPluginVersions = maps.Clone(versions.pluginVersions)

	// Non-blocking send to every subscriber: if a subscriber already has a pending event, the
	// controller will pick it up on its next work cycle, making the duplicate a no-op.
	for _, ch := range w.subscribers {
		select {
		case ch <- event.GenericEvent{}:
		default:
		}
	}
	return nil
}
