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

package node

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestNode_StoreRulesfile_ReplacesDependencies(t *testing.T) {
	m := newTestNode()
	_, _, err := m.AddPluginConfig(context.Background(), testPlugin("container"))
	require.NoError(t, err)
	rfKey := artifact.Ref{Kind: artifact.KindRulesfile, Name: "my-rulesfile"}

	installTestRulesfile(t, m, rfKey, []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})
	require.Error(t, m.RemovePluginConfig(context.Background(), testPlugin("container")),
		"blocked while rfKey requires it")

	installTestRulesfile(t, m, rfKey, nil)
	require.NoError(t, m.RemovePluginConfig(context.Background(), testPlugin("container")))
}

func TestNode_StoreRulesfile_PreservesOtherSourcesAndFailedWrites(t *testing.T) {
	for _, failure := range []string{writeFailure, "rename"} {
		t.Run(failure, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			m := newTestNodeOver(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
			_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"))
			require.NoError(t, addErr)
			m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
			fetcher := &artifact.Fetcher{}
			oldContent, err := fetcher.FetchInline(ctx, []byte("old rules"))
			require.NoError(t, err)
			newContent, err := fetcher.FetchInline(ctx, []byte("new rules"))
			require.NoError(t, err)
			key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
			metadata := &commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}
			for _, medium := range []artifact.Medium{artifact.MediumOCI, artifact.MediumInline, artifact.MediumConfigMap} {
				_, _, err := m.StoreRulesfile(ctx, key.Name, 50, medium, oldContent, metadata, true)
				require.NoError(t, err)
			}
			// One source is replaced; the other two still need the old plugin.
			_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, newContent, &commonv1alpha1.ArtifactMeta{}, true)
			require.NoError(t, err)
			oldInline := m.FindInstalled(key, artifact.MediumInline)
			storeErr := errors.New("filesystem unavailable")
			if failure == writeFailure {
				fs.WriteErrFor = map[string]error{artifact.StagingPath(oldInline.Path): storeErr}
			} else {
				fs.RenameErrFor = map[string]error{artifact.StagingPath(oldInline.Path): storeErr}
			}
			_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumInline, newContent, &commonv1alpha1.ArtifactMeta{}, true)
			require.ErrorIs(t, err, storeErr)
			fs.WriteErrFor, fs.RenameErrFor = nil, nil
			assert.Equal(t, oldInline, m.FindInstalled(key, artifact.MediumInline))
			intact, err := m.Verify(ctx, oldInline)
			require.NoError(t, err)
			require.True(t, intact)
			var blocked *BlockedError
			require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked)
			assert.Equal(t, []artifact.Ref{key}, blocked.BlockedBy, "report the CR once, even when two sources still require the plugin")

			_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumInline, newContent, &commonv1alpha1.ArtifactMeta{}, true)
			require.NoError(t, err)
			require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked)
			// A failed deletion must also retain the last source's protection.
			fs.RemoveErr = storeErr
			_, _, err = m.removeIfInstalled(ctx, key, artifact.MediumConfigMap)
			require.ErrorIs(t, err, storeErr)
			require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked)
			fs.RemoveErr = nil
			_, removed, err := m.removeIfInstalled(ctx, key, artifact.MediumConfigMap)
			require.NoError(t, err)
			require.True(t, removed)
			require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")))
		})
	}
}

func TestNode_StoreRulesfile_ChecksAndOwnsDependencies(t *testing.T) {
	ctx := t.Context()
	m := newTestNode()
	for _, name := range []string{"container", "container-alt"} {
		_, _, addErr := m.AddPluginConfig(ctx, testPlugin(name))
		require.NoError(t, addErr)
	}
	content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
	require.NoError(t, err)
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
	requires := []commonv1alpha1.ArtifactMetaDependency{{
		Name: "container", Version: "1.0.0",
		Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "1.0.0"}},
	}}
	metadata := &commonv1alpha1.ArtifactMeta{Dependencies: requires}
	_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content,
		&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{}}}, true)
	require.Error(t, err, "an empty dependency is invalid")
	_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content, metadata, true)
	var dependencyErr *dependencyError
	require.ErrorAs(t, err, &dependencyErr)
	assert.Nil(t, m.FindInstalled(key, artifact.MediumOCI), "failed check must not install a file")

	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
	_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content, metadata, true)
	require.NoError(t, err)
	requires[0].Name = mutatedMetadataValue
	var blocked *BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked,
		"mutating the caller's input must not change the installed dependencies")
	requires[0].Alternatives[0].Version = "2.0.0"
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{
		"container": "1.0.0", "container-alt": "1.0.0",
	}).Result)
	require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")),
		"mutating a caller-owned alternative must not replace the installed compatible alternative")
	require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container-alt")), &blocked)

	// Metadata may change without changing bytes: Unchanged still commits new dependencies.
	action, _, err := m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content, &commonv1alpha1.ArtifactMeta{}, true)
	require.NoError(t, err)
	assert.Equal(t, artifact.StoreActionUnchanged, action)
	require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container-alt")))
}

func TestNode_StoreRulesfile_PriorityFailureKeepsInstalledState(t *testing.T) {
	const replacementFailure = "replace"
	for _, failure := range []string{writeFailure, "move", replacementFailure} {
		for _, recovery := range []string{"retry", "delete"} {
			t.Run(failure+"/"+recovery, func(t *testing.T) {
				ctx := t.Context()
				fs := fsfake.NewMockFileSystem()
				store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
				m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil))
				_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"))
				require.NoError(t, addErr)
				m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
				fetcher := &artifact.Fetcher{}
				oldContent, err := fetcher.FetchInline(ctx, []byte("old rules"))
				require.NoError(t, err)
				newContent, err := fetcher.FetchInline(ctx, []byte("new rules"))
				require.NoError(t, err)
				key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
				_, oldFile, err := m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, oldContent,
					&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, true)
				require.NoError(t, err)
				newPath := testutil.MustArtifactPath(t, store.Dirs, key.Name, 20, artifact.MediumOCI, artifact.KindRulesfile)
				storeErr := errors.New("filesystem unavailable")
				switch failure {
				case writeFailure:
					fs.WriteErrFor = map[string]error{artifact.StagingPath(newPath): storeErr}
				case "move":
					fs.RenameErrFor = map[string]error{oldFile.Path: storeErr}
				case replacementFailure:
					fs.RenameErrFor = map[string]error{artifact.StagingPath(newPath): storeErr}
				}

				_, _, err = m.StoreRulesfile(ctx, key.Name, 20, artifact.MediumOCI, newContent, &commonv1alpha1.ArtifactMeta{}, true)

				require.ErrorIs(t, err, storeErr)
				fs.WriteErrFor, fs.RenameErrFor = nil, nil
				installed := m.FindInstalled(key, artifact.MediumOCI)
				require.NotNil(t, installed)
				assert.Equal(t, oldContent.ContentHash, installed.ContentHash)
				if failure == replacementFailure {
					assert.Equal(t, newPath, installed.Path, "the old content moved before replacement failed")
					assert.EqualValues(t, 20, installed.Priority)
				} else {
					assert.Equal(t, oldFile.Path, installed.Path)
				}
				intact, err := m.Verify(ctx, installed)
				require.NoError(t, err)
				require.True(t, intact)
				disk, err := m.ScanAll(ctx, artifact.KindRulesfile)
				require.NoError(t, err)
				require.Len(t, disk[key.Name], 1, "there must never be two active revisions of one source")
				var blocked *BlockedError
				require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked)

				if recovery == "retry" {
					_, _, err = m.StoreRulesfile(ctx, key.Name, 20, artifact.MediumOCI, newContent, &commonv1alpha1.ArtifactMeta{}, true)
					require.NoError(t, err)
					assert.Equal(t, newContent.Content, fs.Files[newPath])
				} else {
					_, removed, removeErr := m.removeIfInstalled(ctx, key, artifact.MediumOCI)
					require.NoError(t, removeErr)
					require.True(t, removed)
					assert.NotContains(t, fs.Files, installed.Path)
				}
				require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")))
			})
		}
	}
}

func TestNode_StoreRulesfile_DuplicateCleanupFailurePreservesDependencies(t *testing.T) {
	for _, sameContent := range []bool{false, true} {
		for _, recovery := range []string{"store", "sync"} {
			t.Run(fmt.Sprintf("same-content=%t/%s", sameContent, recovery), func(t *testing.T) {
				ctx := t.Context()
				fs := fsfake.NewMockFileSystem()
				store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
				m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil))
				fetcher := &artifact.Fetcher{}
				for _, name := range []string{"container", "json", "unrelated"} {
					_, _, err := m.AddPluginConfig(ctx, testPlugin(name))
					require.NoError(t, err)
				}
				key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
				oldContent, err := fetcher.FetchInline(ctx, []byte("old rules"))
				require.NoError(t, err)
				_, oldFile, err := m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, oldContent,
					&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, false)
				require.NoError(t, err)
				// Model duplicate paths carrying a revision already known in this process.
				installed := m.GetInstalled(key)
				duplicates := make([]string, 0, 2)
				for _, artifactPriority := range []int32{60, 70} {
					duplicate := installed[0]
					duplicate.Priority = artifactPriority
					duplicate.Path = testutil.MustArtifactPath(t, store.Dirs, key.Name, artifactPriority, artifact.MediumOCI, artifact.KindRulesfile)
					require.NoError(t, fs.WriteFile(duplicate.Path, oldContent.Content, oldContent.Perm))
					installed = append(installed, duplicate)
					duplicates = append(duplicates, duplicate.Path)
				}
				m.SeedInstalled(key, installed)
				content, err := fetcher.FetchInline(ctx, []byte("new rules"))
				require.NoError(t, err)
				if sameContent {
					content = oldContent
				}
				metadata := &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("candidate").String(),
					Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "json", Version: "1.0.0"}}}
				ioErr := errors.New("duplicate cleanup failed")
				fs.RemoveErrFor = map[string]error{duplicates[1]: ioErr}

				_, file, err := m.StoreRulesfile(ctx, key.Name, 20, artifact.MediumOCI, content, metadata, false)

				require.ErrorIs(t, err, ioErr)
				require.NotNil(t, file, "the replacement succeeded before cleanup failed")
				assert.Equal(t, content.ContentHash, file.ContentHash)
				assert.Equal(t, content.Content, fs.Files[file.Path])
				assert.NotContains(t, fs.Files, oldFile.Path)
				assert.NotContains(t, fs.Files, duplicates[0], "cleanup removed one duplicate before failing")
				assert.Equal(t, oldContent.Content, fs.Files[duplicates[1]])
				for _, name := range []string{"container", "json"} {
					var blocked *BlockedError
					require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin(name)), &blocked)
					assert.Equal(t, []artifact.Ref{key}, blocked.BlockedBy)
				}
				require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("unrelated")))

				// A later failed content update must not discard either surviving revision.
				failedContent, err := fetcher.FetchInline(ctx, []byte("rejected rules"))
				require.NoError(t, err)
				fs.WriteErrFor = map[string]error{artifact.StagingPath(file.Path): ioErr}
				_, _, err = m.StoreRulesfile(ctx, key.Name, 20, artifact.MediumOCI, failedContent, &commonv1alpha1.ArtifactMeta{}, false)
				require.ErrorIs(t, err, ioErr)
				for _, name := range []string{"container", "json"} {
					var blocked *BlockedError
					require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin(name)), &blocked)
				}
				fs.WriteErrFor, fs.RemoveErrFor = nil, nil
				if recovery == "store" {
					_, _, err = m.StoreRulesfile(ctx, key.Name, 20, artifact.MediumOCI, content, metadata, false)
					require.NoError(t, err)
				} else {
					synced, syncErr := m.syncRulesfileDependencies(ctx, key, artifact.MediumOCI, metadata, false)
					require.NoError(t, syncErr)
					require.True(t, synced)
				}
				require.Len(t, m.GetInstalled(key), 1)
				assert.NotContains(t, fs.Files, duplicates[1])
				assert.Equal(t, content.Content, fs.Files[file.Path])
				require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")),
					"successful cleanup must release only the old revision")
				var blocked *BlockedError
				require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("json")), &blocked)
				require.NoError(t, removeArtifact(ctx, m, key))
				require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("json")))
			})
		}
	}
}

func TestNode_SyncRulesfileDependencies_PreservesOtherSources(t *testing.T) {
	ctx := t.Context()
	m := newTestNode()
	_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"))
	require.NoError(t, addErr)
	content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
	require.NoError(t, err)
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
	metadata := &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("installed").String(), Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}
	m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
	for _, medium := range []artifact.Medium{artifact.MediumOCI, artifact.MediumInline} {
		_, _, err := m.StoreRulesfile(ctx, key.Name, 50, medium, content, metadata, true)
		require.NoError(t, err)
	}
	missing := &commonv1alpha1.ArtifactMeta{Digest: metadata.Digest, Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "missing", Version: "1.0.0"}}}
	var dependencyErr *dependencyError
	synced, err := m.syncRulesfileDependencies(ctx, key, artifact.MediumOCI, missing, true)
	require.ErrorAs(t, err, &dependencyErr)
	assert.False(t, synced)
	var blocked *BlockedError
	require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked)
	synced, err = m.syncRulesfileDependencies(ctx, key, artifact.MediumOCI, &commonv1alpha1.ArtifactMeta{Digest: metadata.Digest}, true)
	require.NoError(t, err)
	require.True(t, synced)
	require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked,
		"clearing OCI dependencies must preserve the installed inline source's dependencies")
	_, _, err = m.removeIfInstalled(ctx, key, artifact.MediumInline)
	require.NoError(t, err)
	require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")))
}

func TestNode_StoreRulesfile_MissingMetadata(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, enforce := range []bool{false, true} {
			t.Run(fmt.Sprintf("existing=%t/enforce=%t", existing, enforce), func(t *testing.T) {
				ctx := t.Context()
				fs := fsfake.NewMockFileSystem()
				store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
				m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil))
				_, _, addErr := m.AddPluginConfig(ctx, testPlugin("unrelated"))
				require.NoError(t, addErr)
				key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
				content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
				require.NoError(t, err)
				if existing {
					_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content, &commonv1alpha1.ArtifactMeta{}, true)
					require.NoError(t, err)
				}
				before := m.GetInstalled(key)
				writes := len(fs.WriteCalls)

				action, installed, err := m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content, nil, enforce)

				if enforce {
					require.Error(t, err)
					assert.Nil(t, installed)
					assert.Equal(t, artifact.StoreActionNone, action)
					assert.Len(t, fs.WriteCalls, writes)
					assert.Equal(t, before, m.GetInstalled(key))
					return
				}
				require.NoError(t, err)
				require.NotNil(t, m.FindInstalled(key, artifact.MediumOCI))
				if existing {
					assert.Equal(t, artifact.StoreActionUnchanged, action)
				}
				require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("unrelated")),
					"unknown metadata cannot prove a dependency on an unrelated plugin")
			})
		}
	}
}

func TestNode_StoreRulesfile_UnknownMetadataPreservesKnownDependenciesForSameBytes(t *testing.T) {
	for _, replacement := range []string{"different bytes", "known empty metadata"} {
		t.Run(replacement, func(t *testing.T) {
			ctx := t.Context()
			m := newTestNode()
			fetcher := &artifact.Fetcher{}
			for _, name := range []string{"container", "unrelated"} {
				_, _, err := m.AddPluginConfig(ctx, testPlugin(name))
				require.NoError(t, err)
			}
			key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
			content, err := fetcher.FetchInline(ctx, []byte("installed rules"))
			require.NoError(t, err)
			_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content,
				&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, false)
			require.NoError(t, err)

			action, _, err := m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content, nil, false)

			require.NoError(t, err)
			assert.Equal(t, artifact.StoreActionUnchanged, action)
			var blocked *BlockedError
			require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked,
				"known dependencies for unchanged bytes must survive missing metadata")
			assert.Equal(t, []artifact.Ref{key}, blocked.BlockedBy)
			require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("unrelated")),
				"retaining known dependencies must not invent other dependencies")

			var metadata *commonv1alpha1.ArtifactMeta
			if replacement == "different bytes" {
				content, err = fetcher.FetchInline(ctx, []byte("different rules"))
				require.NoError(t, err)
			} else {
				metadata = &commonv1alpha1.ArtifactMeta{}
			}
			_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content, metadata, false)
			require.NoError(t, err)
			require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")),
				"replaced bytes or verified empty metadata release the old dependency")
		})
	}
}

func TestNode_SyncRulesfileDependencies_RequiresVerifiedIdentity(t *testing.T) {
	const (
		nilPreservesUnknown = "nil metadata preserves unknown"
		inlineWithoutDigest = "inline without digest"
		readFailure         = "read failure"
	)
	for _, scenario := range []string{"nil metadata", nilPreservesUnknown, "unknown installed metadata", "empty digest", "different digest",
		"no installed file", "missing file", "corrupt file", readFailure, "same digest", inlineWithoutDigest} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil))
			_, _, addErr := m.AddPluginConfig(ctx, testPlugin("container"))
			require.NoError(t, addErr)
			key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
			content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
			require.NoError(t, err)
			medium := artifact.MediumOCI
			metadata := &commonv1alpha1.ArtifactMeta{Digest: digest.FromString("installed").String(), Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}
			candidate := &commonv1alpha1.ArtifactMeta{Digest: metadata.Digest}
			if scenario == inlineWithoutDigest {
				medium, metadata.Digest, candidate.Digest = artifact.MediumInline, "", ""
			}
			if scenario == "unknown installed metadata" || scenario == nilPreservesUnknown {
				metadata = nil
			}
			var installed *artifact.File
			if scenario != "no installed file" {
				_, installed, err = m.StoreRulesfile(ctx, key.Name, 50, medium, content, metadata, false)
				require.NoError(t, err)
			}
			ioErr := errors.New("filesystem unavailable")
			switch scenario {
			case "nil metadata", nilPreservesUnknown:
				candidate = nil
			case "empty digest":
				candidate.Digest = ""
			case "different digest":
				candidate.Digest = digest.FromString("other").String()
			case "missing file":
				require.NoError(t, fs.Remove(installed.Path))
			case "corrupt file":
				require.NoError(t, fs.WriteFile(installed.Path, []byte("corrupt"), 0o644))
			case readFailure:
				fs.ReadErrFor = map[string]error{installed.Path: ioErr}
			}
			before := m.GetInstalled(key)
			writes := len(fs.WriteCalls)

			synced, err := m.syncRulesfileDependencies(ctx, key, medium, candidate, true)

			if scenario == readFailure {
				require.ErrorIs(t, err, ioErr, "I/O failures must not be reported as a fetch fallback")
			} else {
				require.NoError(t, err)
			}
			if scenario == "same digest" || scenario == inlineWithoutDigest {
				require.True(t, synced)
				require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")))
				return
			}
			assert.False(t, synced)
			assert.Equal(t, before, m.GetInstalled(key), "fallback must not replace installed files")
			assert.Len(t, fs.WriteCalls, writes)
			if installed != nil && metadata != nil {
				var blocked *BlockedError
				require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container")), &blocked,
					"fallback must preserve the known installed dependency")
			} else {
				require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")),
					"missing metadata must not invent a dependency")
			}
		})
	}
}

func TestNode_RulesfileMetadata_IsOwned(t *testing.T) {
	const mutatedVersion = "99.0.0"
	for _, operation := range []string{"store", "sync"} {
		t.Run(operation, func(t *testing.T) {
			ctx := t.Context()
			store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
			m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil))
			for _, name := range []string{"container", "container-alt"} {
				_, _, err := m.AddPluginConfig(ctx, testPlugin(name))
				require.NoError(t, err)
			}
			metadata := &commonv1alpha1.ArtifactMeta{
				Digest: digest.FromString("installed").String(), SpecHash: "original-spec",
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{{Name: "engine_version_semver", Version: "0.42.0"}},
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0",
					Alternatives: []commonv1alpha1.ArtifactMetaDependencyVariant{{Name: "container-alt", Version: "1.0.0"}}}},
			}
			content, err := (&artifact.Fetcher{}).FetchInline(ctx, []byte("rules"))
			require.NoError(t, err)
			key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
			_, _, err = m.StoreRulesfile(ctx, key.Name, 50, artifact.MediumOCI, content, metadata, false)
			require.NoError(t, err)
			if operation == "sync" {
				metadata.SpecHash = "updated-spec"
				synced, syncErr := m.syncRulesfileDependencies(ctx, key, artifact.MediumOCI, metadata, false)
				require.NoError(t, syncErr)
				require.True(t, synced)
			}
			expected := metadata.DeepCopy()
			metadata.Digest, metadata.SpecHash = mutatedMetadataValue, mutatedMetadataValue
			metadata.Requirements[0].Version = mutatedVersion
			metadata.Dependencies[0].Name = mutatedMetadataValue
			metadata.Dependencies[0].Version = mutatedVersion
			metadata.Dependencies[0].Alternatives[0].Version = mutatedVersion
			versions := compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0", "container-alt": "1.0.0"}).Result
			m.OnFalcoVersionsObserved(versions)
			require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container-alt")),
				"the copied primary name and version must still satisfy the dependency")
			_, _, err = m.AddPluginConfig(ctx, testPlugin("container-alt"))
			require.NoError(t, err)
			m.OnFalcoVersionsObserved(versions)
			require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container")),
				"the copied alternative must remain compatible")
			var blocked *BlockedError
			require.ErrorAs(t, m.RemovePluginConfig(ctx, testPlugin("container-alt")), &blocked)
			expected.Dependencies = nil
			synced, err := m.syncRulesfileDependencies(ctx, key, artifact.MediumOCI, expected, true)
			require.NoError(t, err)
			require.True(t, synced, "the copied digest must still identify the installed source")
			require.NoError(t, m.RemovePluginConfig(ctx, testPlugin("container-alt")))
		})
	}
}

func TestNode_StoreRulesfile_ConcurrentPluginRemoval(t *testing.T) {
	ctx := t.Context()
	fetcher := &artifact.Fetcher{}
	content, err := fetcher.FetchInline(ctx, []byte("rules"))
	require.NoError(t, err)
	for range 20 {
		m := newTestNodeWithFetcher(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}))
		_, _, err := m.AddPluginConfig(ctx, testPlugin("container"))
		require.NoError(t, err)
		start := make(chan struct{})
		stored := make(chan error, 1)
		removed := make(chan error, 1)
		go func() {
			<-start
			_, _, err := m.StoreRulesfile(ctx, "rules", 50, artifact.MediumOCI, content,
				&commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}}}, true)
			stored <- err
		}()
		go func() {
			<-start
			removed <- m.RemovePluginConfig(ctx, testPlugin("container"))
		}()
		close(start)
		storeErr, removeErr := <-stored, <-removed
		if storeErr == nil {
			var blocked *BlockedError
			require.ErrorAs(t, removeErr, &blocked, "installed rules must protect their provider")
		} else {
			var dependencyErr *dependencyError
			require.ErrorAs(t, storeErr, &dependencyErr)
			require.NoError(t, removeErr, "removal won: installation must be rejected")
			assert.Nil(t, m.FindInstalled(artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}, artifact.MediumOCI))
		}
	}
}

func TestNode_StoreRepairsCorruptionWithoutChangingInstalledIdentity(t *testing.T) {
	fs := fsfake.NewMockFileSystem()
	manager := newTestNodeOver(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	fetcher := &artifact.Fetcher{}
	result, err := fetcher.FetchInline(t.Context(), []byte("expected rules"))
	require.NoError(t, err)
	key := artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"}
	_, file, err := manager.StoreRulesfile(t.Context(), key.Name, 10, artifact.MediumOCI, result, &commonv1alpha1.ArtifactMeta{}, true)
	require.NoError(t, err)
	manager.UpdateInstalledSpecHash(key, artifact.MediumOCI, "pinned-revision")
	fs.Files[file.Path] = []byte("corrupt")
	verified, err := manager.Verify(t.Context(), file)
	require.NoError(t, err)
	require.False(t, verified)

	action, repaired, err := manager.StoreRulesfile(t.Context(), key.Name, 10, artifact.MediumOCI, result, &commonv1alpha1.ArtifactMeta{}, true)
	require.NoError(t, err)
	require.Equal(t, artifact.StoreActionUpdated, action)
	require.Equal(t, file.Path, repaired.Path)
	require.Equal(t, result.Content, fs.Files[repaired.Path])
	manager.UpdateInstalledSpecHash(key, artifact.MediumOCI, "pinned-revision")
	current := manager.FindInstalled(key, artifact.MediumOCI)
	require.Equal(t, "pinned-revision", current.SpecHash)
	verified, err = manager.Verify(t.Context(), current)
	require.NoError(t, err)
	require.True(t, verified)
}
