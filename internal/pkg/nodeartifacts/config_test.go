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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

func TestManager_StoreConfig_PartialPriorityMoveTracksInstalledFileAndRetries(t *testing.T) {
	ctx := t.Context()
	fs := fsfake.NewMockFileSystem()
	dirs := artifact.DefaultArtifactDirs()
	m := nodeartifacts.NewManager(&artifact.LocalStore{FS: fs, Dirs: dirs}, compatfake.NewMockVersionsFetcher(nil))
	fetcher := &artifact.Fetcher{}
	key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Namespace: "ns", Name: "myfile"}
	oldContent, err := fetcher.FetchInline(ctx, []byte("old config"))
	require.NoError(t, err)
	updatedContent, err := fetcher.FetchInline(ctx, []byte("updated config"))
	require.NoError(t, err)
	_, original, err := m.StoreConfig(ctx, key.Namespace, key.Name, 50, artifact.MediumInline, oldContent)
	require.NoError(t, err)
	require.NotNil(t, original)
	newPath := artifact.ArtifactPath(dirs, key.Name, 20, artifact.MediumInline, artifact.TypeConfig)
	replaceErr := errors.New("cannot replace moved config")
	fs.RenameErrFor = map[string]error{newPath + ".tmp": replaceErr}

	action, relocated, err := m.StoreConfig(ctx, key.Namespace, key.Name, 20, artifact.MediumInline, updatedContent)

	require.ErrorIs(t, err, replaceErr)
	assert.Equal(t, artifact.StoreActionPriorityChanged, action)
	require.NotNil(t, relocated)
	assert.Equal(t, newPath, relocated.Path)
	assert.Equal(t, int32(20), relocated.Priority)
	assert.Equal(t, oldContent.ContentHash, relocated.ContentHash)
	assert.Equal(t, relocated, m.FindInstalled(key, artifact.MediumInline))
	assert.Equal(t, oldContent.Content, fs.Files[newPath])
	assert.NotContains(t, fs.Files, original.Path)
	assert.NotContains(t, fs.Files, newPath+".tmp")
	intact, err := m.Verify(ctx, relocated)
	require.NoError(t, err)
	assert.True(t, intact)

	delete(fs.RenameErrFor, newPath+".tmp")
	action, installed, err := m.StoreConfig(ctx, key.Namespace, key.Name, 20, artifact.MediumInline, updatedContent)

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUpdated, action)
	require.NotNil(t, installed)
	assert.Equal(t, newPath, installed.Path)
	assert.Equal(t, int32(20), installed.Priority)
	assert.Equal(t, updatedContent.ContentHash, installed.ContentHash)
	assert.Equal(t, installed, m.FindInstalled(key, artifact.MediumInline))
	assert.Equal(t, updatedContent.Content, fs.Files[newPath])
	assert.NotContains(t, fs.Files, original.Path)
	assert.NotContains(t, fs.Files, newPath+".tmp")
	intact, err = m.Verify(ctx, installed)
	require.NoError(t, err)
	assert.True(t, intact)

	action, _, err = m.StoreConfig(ctx, key.Namespace, key.Name, 20, artifact.MediumInline, updatedContent)
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action)
}

func TestManager_StoreConfigPassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}

	action, file, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)

	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionAdded, action)
	require.NotNil(t, file)

	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestManager_StoreConfig_OnlyWritesConfig(t *testing.T) {
	for _, medium := range []artifact.Medium{artifact.MediumInline, artifact.MediumConfigMap} {
		t.Run(string(medium), func(t *testing.T) {
			m := newTestManager()
			content, err := (&artifact.Fetcher{}).FetchInline(t.Context(), []byte("test artifact"))
			require.NoError(t, err)
			key := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Namespace: "ns", Name: "artifact"}

			action, file, err := m.StoreConfig(t.Context(), key.Namespace, key.Name, 50, medium, content)

			require.NoError(t, err)
			assert.Equal(t, artifact.StoreActionAdded, action)
			require.NotNil(t, file)
			assert.Equal(t, artifact.ArtifactPath(artifact.DefaultArtifactDirs(), key.Name, 50, medium, artifact.TypeConfig), file.Path)
			assert.Equal(t, file, m.FindInstalled(key, medium))
			for _, kind := range []nodeartifacts.Kind{nodeartifacts.KindRulesfile, nodeartifacts.KindPlugin} {
				assert.Empty(t, m.GetInstalled(nodeartifacts.Key{Kind: kind, Namespace: key.Namespace, Name: key.Name}))
			}
			for _, artifactType := range []artifact.Type{artifact.TypeRulesfile, artifact.TypePlugin} {
				disk, err := m.ScanAll(t.Context(), artifactType)
				require.NoError(t, err)
				assert.Empty(t, disk)
			}
		})
	}
}

func TestManager_StoreConfig_ProtectsSharedPluginConfigPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		priority int32
		medium   artifact.Medium
		wantErr  bool
	}{
		{name: "reserved path", priority: 99, medium: artifact.MediumInline, wantErr: true},
		{name: "different priority", priority: 50, medium: artifact.MediumInline},
		{name: "configmap medium", priority: 99, medium: artifact.MediumConfigMap},
		{name: "oci medium", priority: 99, medium: artifact.MediumOCI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			m := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))
			fetcher := &artifact.Fetcher{}
			_, shared, err := m.AddPluginConfig(ctx, testPlugin("container"), fetcher)
			require.NoError(t, err)
			before, err := store.Read(ctx, shared.Path)
			require.NoError(t, err)
			writes := len(fs.WriteCalls)
			content, err := fetcher.FetchInline(ctx, []byte("log_level: debug"))
			require.NoError(t, err)

			action, file, err := m.StoreConfig(ctx, "ns", nodeartifacts.PluginConfigKey.Name, tc.priority, tc.medium, content)

			if tc.wantErr {
				require.Error(t, err)
				assert.Equal(t, artifact.StoreActionNone, action)
				assert.Nil(t, file)
				assert.Len(t, fs.WriteCalls, writes)
			} else {
				require.NoError(t, err)
				require.NotNil(t, file)
				assert.NotEqual(t, shared.Path, file.Path)
				assert.Equal(t, content.Content, fs.Files[file.Path])
			}
			intact, err := m.Verify(ctx, shared)
			require.NoError(t, err)
			assert.True(t, intact)
			after, err := store.Read(ctx, shared.Path)
			require.NoError(t, err)
			assert.Equal(t, before, after)
		})
	}
}

func TestManager_StoreConfig_UsesCacheForCurrent_SecondIdenticalStoreIsUnchanged(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}

	action1, _, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)
	require.Equal(t, artifact.StoreActionAdded, action1)

	// No caller-supplied "current": Manager must derive it from its own cache, not from any
	// status object, to recognize the second call as a no-op.
	action2, _, err := m.StoreConfig(context.Background(), "", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action2)
}

// TestManager_StoreConfig_IsolatesByNamespace proves that two artifacts with the same Kind and Name
// but different Namespace are tracked as distinct cache entries, not merged into one.
func TestManager_StoreConfig_IsolatesByNamespace(t *testing.T) {
	m := newTestManager()
	result := artifact.FetchResult{
		Content: []byte("hello"), ContentHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Perm: 0o644,
	}

	_, _, err := m.StoreConfig(context.Background(), "ns-a", "myfile", 50, artifact.MediumInline, result)
	require.NoError(t, err)

	keyA := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Namespace: "ns-a", Name: "myfile"}
	keyB := nodeartifacts.Key{Kind: nodeartifacts.KindConfig, Namespace: "ns-b", Name: "myfile"}

	assert.NotNil(t, m.FindInstalled(keyA, artifact.MediumInline), "ns-a's artifact must be tracked under its own namespace")
	assert.Nil(t, m.FindInstalled(keyB, artifact.MediumInline), "ns-b must not see ns-a's artifact of the same kind+name")
}
