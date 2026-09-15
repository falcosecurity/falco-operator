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
	return NewVersions(nil, plugins)
}

// mockVersionsFetcher avoids importing compat/fake back into compat, which would form a cycle.
type mockVersionsFetcher struct {
	Result   *Versions
	FetchErr error
}

func (m *mockVersionsFetcher) Fetch(_ context.Context) (*Versions, error) {
	if m.FetchErr != nil {
		return nil, m.FetchErr
	}
	return m.Result, nil
}

func TestVersionsWatcher_poll(t *testing.T) {
	t.Run("sink fires on every successful poll, including unchanged values", func(t *testing.T) {
		m := &mockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
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

		// An unchanged observation still refreshes the consumer's current state.
		require.NoError(t, w.poll(context.Background()))
		assert.Equal(t, 2, sinkCalls)
		assert.Same(t, m.Result, lastSeen)
	})

	t.Run("sink is not called on fetch error", func(t *testing.T) {
		m := &mockVersionsFetcher{FetchErr: errors.New("unreachable")}
		w := NewVersionsWatcher(m, time.Hour)
		var sinkCalls int
		w.SetSink(func(*Versions) { sinkCalls++ })

		err := w.poll(context.Background())

		require.ErrorIs(t, err, m.FetchErr)
		assert.Equal(t, 0, sinkCalls)
	})

	t.Run("successful fetch after error reaches sink", func(t *testing.T) {
		m := &mockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
		w := NewVersionsWatcher(m, time.Hour)
		var seen []*Versions
		w.SetSink(func(v *Versions) { seen = append(seen, v) })

		require.NoError(t, w.poll(context.Background()))
		m.FetchErr = errors.New("unreachable")
		require.ErrorIs(t, w.poll(context.Background()), m.FetchErr)
		require.Len(t, seen, 1)

		m.FetchErr = nil
		require.NoError(t, w.poll(context.Background()))
		require.Len(t, seen, 2)
		assert.Same(t, m.Result, seen[0])
		assert.Same(t, m.Result, seen[1])
	})

	t.Run("successful fetch without sink is a no-op", func(t *testing.T) {
		w := NewVersionsWatcher(&mockVersionsFetcher{Result: &Versions{}}, time.Hour)
		require.NoError(t, w.poll(context.Background()))
	})
}

func TestVersionsWatcher_Start(t *testing.T) {
	t.Run("logs fetch errors and keeps running", func(t *testing.T) {
		// Run Start synchronously until the context deadline so the ticker fires several
		// times through the error branch (line with logger.V(4).Info), confirming it does
		// not block or panic when every fetch fails.
		w := NewVersionsWatcher(&mockVersionsFetcher{FetchErr: errors.New("unreachable")}, time.Millisecond)
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		require.NoError(t, w.Start(ctx))
	})

	t.Run("stops cleanly on context cancellation", func(t *testing.T) {
		w := NewVersionsWatcher(&mockVersionsFetcher{FetchErr: errors.New("not ready")}, time.Millisecond)
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

	t.Run("forwards observation to sink", func(t *testing.T) {
		m := &mockVersionsFetcher{Result: versionsWithPlugins(map[string]string{"container": "0.7.1"})}
		w := NewVersionsWatcher(m, time.Millisecond)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var seen *Versions
		w.SetSink(func(v *Versions) {
			seen = v
			cancel()
		})
		done := make(chan error, 1)
		go func() { done <- w.Start(ctx) }()

		select {
		case err := <-done:
			require.NoError(t, err)
			assert.Same(t, m.Result, seen)
		case <-time.After(time.Second):
			t.Fatal("sink did not stop the watcher within timeout")
		}
	})
}
