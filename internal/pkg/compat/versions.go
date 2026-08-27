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
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strconv"
	"time"
)

const (
	// DefaultBaseURL is the default base URL for the Falco REST API.
	DefaultBaseURL = "http://localhost:8765"

	versionsPath   = "/versions"
	defaultTimeout = 5 * time.Second
)

// defaultInterval is the wait between retries in WaitAndFetch.
// It is a package-level var so tests can override it.
var defaultInterval = 2 * time.Second

// VersionsFetcher fetches version capabilities from the Falco REST API.
type VersionsFetcher interface {
	Fetch(ctx context.Context) (*Versions, error)
}

// Versions holds the capability versions returned by the Falco REST API at /versions.
// Values are stored as strings; numeric JSON values are converted automatically.
type Versions struct {
	capabilities   map[string]string
	pluginVersions map[string]string // keys that came from the nested plugin_versions object
}

// Capability returns the version string for a named capability, and whether it was present.
func (v *Versions) Capability(name string) (string, bool) {
	val, ok := v.capabilities[name]
	return val, ok
}

// All returns a copy of every capability name to its version string, including both top-level
// capabilities (e.g. engine_version_semver, plugin_api_version) and the flattened plugin_versions
// entries (e.g. "container"). Callers must not assume any particular set of keys — it reflects
// whatever Falco reported.
func (v *Versions) All() map[string]string {
	out := make(map[string]string, len(v.capabilities))
	maps.Copy(out, v.capabilities)
	return out
}

// PluginVersions returns a copy of just the plugin_versions subset — the set of plugin names
// Falco currently reports as loaded, each with its version. Unlike All(), this never mixes in
// unrelated top-level capabilities (e.g. engine_version_semver), so it's safe to treat as "the
// set of currently loaded plugin names.".
func (v *Versions) PluginVersions() map[string]string {
	out := make(map[string]string, len(v.pluginVersions))
	maps.Copy(out, v.pluginVersions)
	return out
}

// HTTPVersionsFetcher queries the Falco REST API at /versions over HTTP.
type HTTPVersionsFetcher struct {
	url    string
	client *http.Client
}

// NewHTTPVersionsFetcher creates a fetcher that queries baseURL + "/versions".
// Pass falco.DefaultBaseURL to use the default Falco API endpoint.
func NewHTTPVersionsFetcher(baseURL string) *HTTPVersionsFetcher {
	return &HTTPVersionsFetcher{
		url:    baseURL + versionsPath,
		client: &http.Client{Timeout: defaultTimeout},
	}
}

// Fetch calls the Falco /versions endpoint and returns the parsed capability map.
func (f *HTTPVersionsFetcher) Fetch(ctx context.Context) (*Versions, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", f.url, err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", f.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", f.url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", f.url, err)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse response from %s: %w", f.url, err)
	}

	caps := make(map[string]string, len(raw))
	pluginCaps := make(map[string]string)
	for k, v := range raw {
		switch t := v.(type) {
		case string:
			caps[k] = t
		case float64:
			caps[k] = strconv.FormatFloat(t, 'f', -1, 64)
		case map[string]any:
			// Falco reports loaded plugin versions as a nested object:
			//   "plugin_versions": {"container": "0.7.1"}
			// Flatten into the top-level capability map and also record them separately in pluginCaps.
			for nk, nv := range t {
				if s, ok := nv.(string); ok {
					caps[nk] = s
					pluginCaps[nk] = s
				}
			}
		}
	}

	return &Versions{capabilities: caps, pluginVersions: pluginCaps}, nil
}

// WaitAndFetch blocks until the Falco /versions endpoint at baseURL responds successfully,
// retrying every defaultInterval. It returns immediately on context cancellation.
func WaitAndFetch(ctx context.Context, baseURL string) (*Versions, error) {
	f := NewHTTPVersionsFetcher(baseURL)
	for {
		v, err := f.Fetch(ctx)
		if err == nil {
			return v, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(defaultInterval):
		}
	}
}

// MockVersionsFetcher is a test double for VersionsFetcher.
type MockVersionsFetcher struct {
	Result   *Versions
	FetchErr error
}

// NewMockVersionsFetcher creates a MockVersionsFetcher that returns the given capabilities on Fetch.
func NewMockVersionsFetcher(caps map[string]string) *MockVersionsFetcher {
	return &MockVersionsFetcher{Result: &Versions{capabilities: caps}}
}

// NewMockVersionsFetcherWithPlugins creates a MockVersionsFetcher whose result reports pluginVersions
// as loaded plugins — flattened into capabilities too, matching HTTPVersionsFetcher's real behavior —
// for tests that need PluginVersions() populated, not just Capability()/All().
func NewMockVersionsFetcherWithPlugins(pluginVersions map[string]string) *MockVersionsFetcher {
	caps := make(map[string]string, len(pluginVersions))
	maps.Copy(caps, pluginVersions)
	return &MockVersionsFetcher{Result: &Versions{capabilities: caps, pluginVersions: pluginVersions}}
}

// Fetch returns the preset result or error.
func (m *MockVersionsFetcher) Fetch(_ context.Context) (*Versions, error) {
	if m.FetchErr != nil {
		return nil, m.FetchErr
	}
	return m.Result, nil
}
