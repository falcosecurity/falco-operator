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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// versionsWithPlugins builds a Versions value with the given plugin_versions map.
func versionsWithPlugins(plugins map[string]string) *Versions {
	return &Versions{pluginVersions: plugins}
}

func TestVersionsWatcher_poll(t *testing.T) {
	t.Run("plugin loaded sends event", func(t *testing.T) {
		m := &MockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
		w := NewVersionsWatcher(m, time.Hour)
		ch := w.Events()
		require.NoError(t, w.poll(context.Background()))
		select {
		case <-ch:
		default:
			t.Fatal("expected event when plugin set changes from nil to non-empty")
		}
	})

	t.Run("same plugin set sends no event", func(t *testing.T) {
		m := &MockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
		w := NewVersionsWatcher(m, time.Hour)
		ch := w.Events()
		require.NoError(t, w.poll(context.Background()))
		<-ch // drain first event

		require.NoError(t, w.poll(context.Background()))
		select {
		case <-ch:
			t.Fatal("unexpected event when plugin set is unchanged")
		default:
		}
	})

	t.Run("plugin version bump sends event", func(t *testing.T) {
		m := &MockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
		w := NewVersionsWatcher(m, time.Hour)
		ch := w.Events()
		require.NoError(t, w.poll(context.Background()))
		<-ch // drain initial event

		m.Result = versionsWithPlugins(map[string]string{"container": "0.7.2"})
		require.NoError(t, w.poll(context.Background()))
		select {
		case <-ch:
		default:
			t.Fatal("expected event when plugin version changes")
		}
	})

	t.Run("unchanged capabilities send no event", func(t *testing.T) {
		m := &MockVersionsFetcher{Result: &Versions{
			capabilities:   map[string]string{"engine_version_semver": "0.62.0"},
			pluginVersions: map[string]string{},
		}}
		w := NewVersionsWatcher(m, time.Hour)
		ch := w.Events()
		require.NoError(t, w.poll(context.Background()))
		<-ch // drain first event (nil -> non-empty capabilities is a change)

		require.NoError(t, w.poll(context.Background()))
		select {
		case <-ch:
			t.Fatal("unexpected event: capabilities unchanged")
		default:
		}
	})

	t.Run("capability change alone sends event", func(t *testing.T) {
		// In practice engine/Falco version are fixed for a running binary, but a mocked
		// /versions endpoint (used in e2e tests) can change a top-level capability like
		// plugin_api_version without touching plugin_versions — this must still be detected.
		m := &MockVersionsFetcher{Result: &Versions{
			capabilities:   map[string]string{"plugin_api_version": "2.99.0"},
			pluginVersions: map[string]string{},
		}}
		w := NewVersionsWatcher(m, time.Hour)
		ch := w.Events()
		require.NoError(t, w.poll(context.Background()))
		<-ch // drain initial event

		m.Result = &Versions{
			capabilities:   map[string]string{"plugin_api_version": "3.10.0"},
			pluginVersions: map[string]string{},
		}
		require.NoError(t, w.poll(context.Background()))
		select {
		case <-ch:
		default:
			t.Fatal("expected event when a capability value changes")
		}
	})

	t.Run("fetch error resets cached state and returns error", func(t *testing.T) {
		m := &MockVersionsFetcher{FetchErr: errors.New("unreachable")}
		w := NewVersionsWatcher(m, time.Hour)
		w.lastPluginVersions = map[string]string{"container": "0.7.1"}
		w.lastCapabilities = map[string]string{"plugin_api_version": "3.10.0"}

		err := w.poll(context.Background())
		require.Error(t, err)
		w.mu.Lock()
		assert.Nil(t, w.lastPluginVersions, "cached plugin versions must be reset on fetch error")
		assert.Nil(t, w.lastCapabilities, "cached capabilities must be reset on fetch error")
		w.mu.Unlock()
	})

	t.Run("successful fetch after error triggers event", func(t *testing.T) {
		m := &MockVersionsFetcher{FetchErr: errors.New("unreachable")}
		w := NewVersionsWatcher(m, time.Hour)
		ch := w.Events()
		w.lastPluginVersions = map[string]string{"container": "0.7.1"}
		_ = w.poll(context.Background()) // error → lastPluginVersions reset to nil

		m.FetchErr = nil
		m.Result = versionsWithPlugins(map[string]string{"container": "0.7.1"})
		require.NoError(t, w.poll(context.Background()))
		select {
		case <-ch:
		default:
			t.Fatal("expected event: nil lastPluginVersions != recovered state")
		}
	})

	t.Run("full channel does not block", func(t *testing.T) {
		m := &MockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
		w := NewVersionsWatcher(m, time.Hour)
		ch := w.Events()
		require.NoError(t, w.poll(context.Background())) // fills channel (cap=1)

		// Force a second state change without draining.
		w.mu.Lock()
		w.lastPluginVersions = nil
		w.mu.Unlock()

		require.NoError(t, w.poll(context.Background())) // channel full → default branch
		// Channel still has the original event.
		select {
		case <-ch:
		default:
			t.Fatal("expected buffered event to still be present")
		}
	})

	t.Run("sink fires on every successful poll, including unchanged values", func(t *testing.T) {
		m := &MockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
		w := NewVersionsWatcher(m, time.Hour)
		var sinkCalls int
		var lastSeen *Versions
		w.SetSink(func(v *Versions) {
			sinkCalls++
			lastSeen = v
		})

		require.NoError(t, w.poll(context.Background()))
		assert.Equal(t, 1, sinkCalls)
		assert.Same(t, m.Result, lastSeen)

		// Unlike the subscriber/GenericEvent path, the sink must fire again even though
		// nothing changed — it's a "keep my cache fresh" callback, not a change notification.
		require.NoError(t, w.poll(context.Background()))
		assert.Equal(t, 2, sinkCalls)
	})

	t.Run("sink is not called on fetch error", func(t *testing.T) {
		m := &MockVersionsFetcher{FetchErr: errors.New("unreachable")}
		w := NewVersionsWatcher(m, time.Hour)
		var sinkCalls int
		w.SetSink(func(*Versions) { sinkCalls++ })

		err := w.poll(context.Background())

		require.Error(t, err)
		assert.Equal(t, 0, sinkCalls)
	})

	t.Run("multiple subscribers each receive every event", func(t *testing.T) {
		// Regression test: Events() used to return a single shared channel, so two
		// controllers each calling it would race as competing consumers — only one would
		// ever see a given event. Each call must now return an independent channel.
		m := &MockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
		w := NewVersionsWatcher(m, time.Hour)
		chA := w.Events()
		chB := w.Events()

		require.NoError(t, w.poll(context.Background()))
		select {
		case <-chA:
		default:
			t.Fatal("subscriber A did not receive the event")
		}
		select {
		case <-chB:
		default:
			t.Fatal("subscriber B did not receive the event")
		}
	})
}

func TestVersionsWatcher_Start(t *testing.T) {
	t.Run("logs fetch errors and keeps running", func(t *testing.T) {
		// Run Start synchronously until the context deadline so the ticker fires several
		// times through the error branch (line with logger.V(4).Info), confirming it does
		// not block or panic when every fetch fails.
		w := NewVersionsWatcher(&MockVersionsFetcher{FetchErr: errors.New("unreachable")}, time.Millisecond)
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		require.NoError(t, w.Start(ctx))
	})

	t.Run("stops cleanly on context cancellation", func(t *testing.T) {
		w := NewVersionsWatcher(&MockVersionsFetcher{FetchErr: errors.New("not ready")}, time.Millisecond)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- w.Start(ctx) }()
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("Start did not return after context cancellation")
		}
	})

	t.Run("publishes event when plugin set changes", func(t *testing.T) {
		m := &MockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
		w := NewVersionsWatcher(m, time.Millisecond)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() { _ = w.Start(ctx) }()

		select {
		case <-w.Events():
		case <-time.After(time.Second):
			t.Fatal("no event received within timeout")
		}
	})
}
