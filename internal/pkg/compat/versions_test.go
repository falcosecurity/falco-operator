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
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errBodyTransport returns a 200 response whose body always errors on read,
// exercising the io.ReadAll failure path in Fetch.
type errBodyTransport struct{}

func (e *errBodyTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(iotest.ErrReader(errors.New("body read error"))),
		Header:     make(http.Header),
	}, nil
}

func TestHTTPVersionsFetcher_Fetch(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		statusCode         int
		wantErr            bool
		wantCaps           map[string]string
		notWantKeys        []string
		wantPluginVersions map[string]string
	}{
		{
			name: "flat scalar values only",
			body: `{
				"engine_version_semver": "0.62.0",
				"falco_version": "0.44.1",
				"engine_version": "62"
			}`,
			wantCaps: map[string]string{
				"engine_version_semver": "0.62.0",
				"falco_version":         "0.44.1",
				"engine_version":        "62",
			},
			wantPluginVersions: map[string]string{},
		},
		{
			// JSON numbers unmarshal as float64; the fetcher must convert them to strings.
			name: "numeric JSON field is converted to string",
			body: `{"engine_version": 62, "falco_version": "0.44.1"}`,
			wantCaps: map[string]string{
				"engine_version": "62",
				"falco_version":  "0.44.1",
			},
			wantPluginVersions: map[string]string{},
		},
		{
			name: "plugin_versions nested object is flattened",
			body: `{
				"engine_version_semver": "0.62.0",
				"plugin_versions": {
					"container": "0.7.1",
					"k8smeta": "0.2.0"
				}
			}`,
			wantCaps: map[string]string{
				"engine_version_semver": "0.62.0",
				"container":             "0.7.1",
				"k8smeta":               "0.2.0",
			},
			notWantKeys: []string{"plugin_versions"},
			wantPluginVersions: map[string]string{
				"container": "0.7.1",
				"k8smeta":   "0.2.0",
			},
		},
		{
			name: "full real-world response",
			body: `{
				"default_driver_version": "10.2.0+driver",
				"driver_api_version": "10.0.0",
				"driver_schema_version": "4.3.0",
				"engine_version": "62",
				"engine_version_semver": "0.62.0",
				"falco_version": "0.44.1",
				"libs_version": "0.25.4",
				"plugin_api_version": "3.12.0",
				"plugin_versions": {
					"container": "0.7.1"
				}
			}`,
			wantCaps: map[string]string{
				"engine_version_semver": "0.62.0",
				"falco_version":         "0.44.1",
				"container":             "0.7.1",
			},
			notWantKeys:        []string{"plugin_versions"},
			wantPluginVersions: map[string]string{"container": "0.7.1"},
		},
		{
			name: "idle mode: empty plugin_versions is harmless",
			body: `{
				"engine_version_semver": "0.62.0",
				"plugin_versions": {}
			}`,
			wantCaps: map[string]string{
				"engine_version_semver": "0.62.0",
			},
			wantPluginVersions: map[string]string{},
		},
		{
			name:       "non-200 status returns error",
			body:       `{}`,
			statusCode: http.StatusServiceUnavailable,
			wantErr:    true,
		},
		{
			name:    "invalid JSON returns error",
			body:    `not-json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := http.StatusOK
			if tt.statusCode != 0 {
				code = tt.statusCode
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			f := NewHTTPVersionsFetcher(srv.URL)
			versions, err := f.Fetch(context.Background())

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			for k, wantV := range tt.wantCaps {
				got, found := versions.Capability(k)
				assert.True(t, found, "expected capability %q to be present", k)
				assert.Equal(t, wantV, got, "capability %q value mismatch", k)
			}
			for _, k := range tt.notWantKeys {
				_, found := versions.Capability(k)
				assert.False(t, found, "capability key %q should not be present (it is a container key, not a capability)", k)
			}
			if tt.wantPluginVersions != nil {
				assert.Equal(t, tt.wantPluginVersions, versions.pluginVersions)
			}
		})
	}
}

func TestHTTPVersionsFetcher_Fetch_Errors(t *testing.T) {
	t.Run("invalid URL triggers request build error", func(t *testing.T) {
		// A null byte makes url.Parse fail inside http.NewRequestWithContext.
		f := &HTTPVersionsFetcher{url: "\x00", client: http.DefaultClient}
		_, err := f.Fetch(context.Background())
		require.Error(t, err)
	})

	t.Run("body read error is propagated", func(t *testing.T) {
		f := &HTTPVersionsFetcher{
			url:    "http://example.com/versions",
			client: &http.Client{Transport: &errBodyTransport{}},
		}
		_, err := f.Fetch(context.Background())
		require.Error(t, err)
	})
}

func TestVersions_Capability(t *testing.T) {
	v := &Versions{capabilities: map[string]string{
		"engine_version_semver": "0.62.0",
		"container":             "0.7.1",
	}}

	val, ok := v.Capability("engine_version_semver")
	assert.True(t, ok)
	assert.Equal(t, "0.62.0", val)

	val, ok = v.Capability("container")
	assert.True(t, ok)
	assert.Equal(t, "0.7.1", val)

	_, ok = v.Capability("nonexistent")
	assert.False(t, ok)
}

func TestVersions_PluginVersions(t *testing.T) {
	v := &Versions{
		capabilities: map[string]string{
			"engine_version_semver": "0.62.0",
			"container":             "0.7.1",
		},
		pluginVersions: map[string]string{
			"container": "0.7.1",
		},
	}

	got := v.PluginVersions()
	assert.Equal(t, map[string]string{"container": "0.7.1"}, got)

	// Returned map must be a copy: mutating it must not affect the Versions' own state.
	got["container"] = "mutated"
	got2 := v.PluginVersions()
	assert.Equal(t, "0.7.1", got2["container"])
}

func TestVersions_PluginVersions_Empty(t *testing.T) {
	v := &Versions{capabilities: map[string]string{"engine_version_semver": "0.62.0"}}
	assert.Empty(t, v.PluginVersions())
}

func TestWaitAndFetch(t *testing.T) {
	orig := defaultInterval
	defaultInterval = time.Millisecond
	t.Cleanup(func() { defaultInterval = orig })

	t.Run("server immediately available", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"falco_version": "0.44.1"}`))
		}))
		defer srv.Close()

		v, err := WaitAndFetch(context.Background(), srv.URL)
		require.NoError(t, err)
		val, found := v.Capability("falco_version")
		assert.True(t, found)
		assert.Equal(t, "0.44.1", val)
	})

	t.Run("canceled context returns context error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := WaitAndFetch(ctx, "http://127.0.0.1:0")
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("retries on transient failure then succeeds", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if calls.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"falco_version": "0.44.1"}`))
		}))
		defer srv.Close()

		v, err := WaitAndFetch(context.Background(), srv.URL)
		require.NoError(t, err)
		val, found := v.Capability("falco_version")
		assert.True(t, found)
		assert.Equal(t, "0.44.1", val)
	})
}

func TestMockVersionsFetcher(t *testing.T) {
	t.Run("returns configured capabilities", func(t *testing.T) {
		m := NewMockVersionsFetcher(map[string]string{"falco_version": "0.44.1"})
		v, err := m.Fetch(context.Background())
		require.NoError(t, err)
		val, found := v.Capability("falco_version")
		assert.True(t, found)
		assert.Equal(t, "0.44.1", val)
	})

	t.Run("returns configured error", func(t *testing.T) {
		m := &MockVersionsFetcher{FetchErr: errors.New("fetch failed")}
		_, err := m.Fetch(context.Background())
		require.EqualError(t, err, "fetch failed")
	})
}

func TestNewMockVersionsFetcherWithPlugins(t *testing.T) {
	m := NewMockVersionsFetcherWithPlugins(map[string]string{"container": "0.7.1"})
	v, err := m.Fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"container": "0.7.1"}, v.PluginVersions())
	val, found := v.Capability("container")
	assert.True(t, found, "plugin entries must also be flattened into capabilities, matching real Fetch behavior")
	assert.Equal(t, "0.7.1", val)
}
