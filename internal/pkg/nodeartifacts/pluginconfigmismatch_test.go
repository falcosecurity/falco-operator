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

package nodeartifacts_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

// TestManager_PluginLoadMismatch_NeverObserved uses a Manager whose falcoFetcher always fails,
// so lastFalcoPluginVersions stays nil instead of becoming an observed-but-empty set.
func TestManager_PluginLoadMismatch_NeverObserved(t *testing.T) {
	m := newTestManagerWithFetcher(&compat.MockVersionsFetcher{FetchErr: assert.AnError})
	fetcher := &artifact.Fetcher{}
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)

	assert.False(t, m.PluginLoadMismatch(), "must not flag a mismatch before Falco has ever been observed")
}

func TestManager_PluginLoadMismatch(t *testing.T) {
	tests := []struct {
		name           string
		desiredPlugins []string // added via AddPluginConfig before the check
		observe        map[string]string
		want           bool
	}{
		{
			name:           "desired and observed sets match",
			desiredPlugins: []string{"container"},
			observe:        map[string]string{"container": "0.7.1"},
			want:           false,
		},
		{
			name:           "both empty (observed, nothing desired) is not a mismatch",
			desiredPlugins: nil,
			observe:        map[string]string{},
			want:           false,
		},
		{
			name:           "desired plugin missing from Falco's report is a mismatch",
			desiredPlugins: []string{"container"},
			observe:        map[string]string{},
			want:           true,
		},
		{
			name:           "Falco reports a plugin no longer desired is a mismatch",
			desiredPlugins: nil,
			observe:        map[string]string{"container": "0.7.1"},
			want:           true,
		},
		{
			name:           "same set size but no overlap is still a mismatch",
			desiredPlugins: []string{"container"},
			observe:        map[string]string{"other-plugin": "1.0.0"},
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestManager()
			fetcher := &artifact.Fetcher{}
			for _, name := range tt.desiredPlugins {
				_, _, err := m.AddPluginConfig(context.Background(), testPlugin(name), nil, fetcher)
				require.NoError(t, err)
			}
			m.OnFalcoVersionsObserved(compat.NewMockVersionsFetcherWithPlugins(tt.observe).Result)

			assert.Equal(t, tt.want, m.PluginLoadMismatch())
		})
	}
}

func TestManager_ForceRewritePluginConfig_BypassesDedup(t *testing.T) {
	mockFS := filesystem.NewMockFileSystem()
	store := &artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}
	m := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))
	fetcher := &artifact.Fetcher{}

	_, file, err := m.AddPluginConfig(context.Background(), testPlugin("container"), nil, fetcher)
	require.NoError(t, err)
	require.NotNil(t, file)

	writesBefore := len(mockFS.WriteCalls)

	// An ordinary re-add with `current` set to what was just written is a no-op because the
	// content hash already matches what's on disk.
	action, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"), file, fetcher)
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action)
	assert.Len(t, mockFS.WriteCalls, writesBefore, "an unchanged re-add must not write")

	renamesBefore := len(mockFS.RenameCalls)
	require.NoError(t, m.ForceRewritePluginConfig(context.Background(), fetcher))
	assert.Greater(t, len(mockFS.WriteCalls), writesBefore,
		"ForceRewritePluginConfig must write even though the content is unchanged")
	assert.Greater(t, len(mockFS.RenameCalls), renamesBefore,
		"ForceRewritePluginConfig must perform the atomic rename Falco's file-watch relies on")
}

func TestManager_ForceRewritePluginConfig_PropagatesStoreError(t *testing.T) {
	mockFS := filesystem.NewMockFileSystem()
	store := &artifact.LocalStore{FS: mockFS, Dirs: artifact.DefaultArtifactDirs()}
	m := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))
	fetcher := &artifact.Fetcher{}

	mockFS.WriteErr = assert.AnError
	err := m.ForceRewritePluginConfig(context.Background(), fetcher)
	require.Error(t, err)
}
