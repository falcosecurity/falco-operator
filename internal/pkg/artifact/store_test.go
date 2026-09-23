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

package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
)

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func newTestStore() (*LocalStore, *fsfake.MockFileSystem) {
	mockFS := fsfake.NewMockFileSystem()
	dirs := ArtifactDirs{
		Plugin:    "/plugins",
		Rulesfile: "/rulesfiles",
		Config:    "/configs",
	}
	return &LocalStore{FS: mockFS, Dirs: dirs}, mockFS
}

// Stop after the real write, before Store can rename or clean up the candidate.
type interruptedWriteFS struct {
	filesystem.FileSystem
	partial bool
}

func (f interruptedWriteFS) WriteFile(name string, data []byte, perm os.FileMode) error {
	if f.partial {
		data = data[:len(data)/2]
	}
	if err := f.FileSystem.WriteFile(name, data, perm); err != nil {
		return err
	}
	panic("interrupted after staging write")
}

func TestLocalStore_InterruptedWrite(t *testing.T) {
	for _, artifactType := range []Type{TypeConfig, TypeRulesfile, TypePlugin} {
		for _, installed := range []bool{false, true} {
			for _, partial := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/installed=%t/partial=%t", artifactType, installed, partial), func(t *testing.T) {
					dir := t.TempDir()
					store := &LocalStore{FS: filesystem.NewOSFileSystem(), Dirs: ArtifactDirs{Config: dir, Rulesfile: dir, Plugin: dir}}
					medium := MediumInline
					if artifactType == TypePlugin {
						medium = MediumOCI
					}
					old := FetchResult{Content: []byte("old"), ContentHash: sha256hex([]byte("old")), Perm: PermFor(artifactType)}
					updated := FetchResult{Content: []byte("new"), ContentHash: sha256hex([]byte("new")), Perm: old.Perm}
					reference := filepath.Join(t.TempDir(), "permissions")
					require.NoError(t, os.WriteFile(reference, old.Content, old.Perm))
					referenceInfo, err := os.Stat(reference)
					require.NoError(t, err)
					var current *File
					if installed {
						_, file, err := store.Store(t.Context(), nil, "test", 50, artifactType, medium, old)
						require.NoError(t, err)
						current = file
					}
					store.FS = interruptedWriteFS{FileSystem: store.FS, partial: partial}
					require.PanicsWithValue(t, "interrupted after staging write", func() {
						_, _, _ = store.Store(t.Context(), current, "test", 50, artifactType, medium, updated)
					})

					finalPath := ArtifactPath(store.Dirs, "test", 50, medium, artifactType)
					stagedPath := filepath.Join(dir, ".tmp", filepath.Base(finalPath)+".tmp")
					staged, err := os.ReadFile(stagedPath)
					require.NoError(t, err)
					expected := updated.Content
					if partial {
						expected = expected[:len(expected)/2]
					}
					assert.Equal(t, expected, staged)
					entries, err := os.ReadDir(dir)
					require.NoError(t, err)
					for _, entry := range entries {
						if entry.Type().IsRegular() {
							require.True(t, installed)
							assert.Equal(t, filepath.Base(finalPath), entry.Name(), "only committed files may be visible to Falco")
						}
					}

					// A fresh store discovers committed files only, without promoting the candidate.
					store = &LocalStore{FS: filesystem.NewOSFileSystem(), Dirs: store.Dirs}
					snapshot, err := store.ScanAll(t.Context(), artifactType)
					require.NoError(t, err)
					if installed {
						require.Len(t, snapshot["test"], 1)
						assert.Equal(t, old.ContentHash, snapshot["test"][0].ContentHash)
						current = FindInstalled(snapshot["test"], medium)
					} else {
						assert.Empty(t, snapshot)
						require.NoFileExists(t, finalPath)
					}
					_, file, err := store.Store(t.Context(), current, "test", 50, artifactType, medium, updated)
					require.NoError(t, err)
					require.NotNil(t, file)
					data, err := os.ReadFile(finalPath)
					require.NoError(t, err)
					assert.Equal(t, updated.Content, data)
					info, err := os.Stat(finalPath)
					require.NoError(t, err)
					assert.Equal(t, referenceInfo.Mode().Perm(), info.Mode().Perm(), "preserve WriteFile permissions, including the process umask")
					require.NoFileExists(t, stagedPath)
					action, _, err := store.Store(t.Context(), file, "test", 50, artifactType, medium, updated)
					require.NoError(t, err)
					assert.Equal(t, StoreActionUnchanged, action)
					require.NoError(t, store.Remove(t.Context(), []artifactv1alpha1.InstalledArtifact{{Path: finalPath}}))
					require.NoFileExists(t, finalPath)
				})
			}
		}
	}
}

func TestLocalStore_RemoveAfterInterruptedWrite(t *testing.T) {
	for _, tc := range []struct {
		name         string
		artifactType Type
		medium       Medium
	}{
		{name: "configuration", artifactType: TypeConfig, medium: MediumInline},
		{name: "rulesfile", artifactType: TypeRulesfile, medium: MediumInline},
		{name: "plugin", artifactType: TypePlugin, medium: MediumOCI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store := &LocalStore{FS: filesystem.NewOSFileSystem(), Dirs: ArtifactDirs{Config: dir, Rulesfile: dir, Plugin: dir}}
			old := FetchResult{Content: []byte("old"), ContentHash: sha256hex([]byte("old")), Perm: PermFor(tc.artifactType)}
			_, current, err := store.Store(t.Context(), nil, "test", 50, tc.artifactType, tc.medium, old)
			require.NoError(t, err)
			store.FS = interruptedWriteFS{FileSystem: store.FS}
			require.Panics(t, func() {
				_, _, _ = store.Store(t.Context(), current, "test", 50, tc.artifactType, tc.medium,
					FetchResult{Content: []byte("new"), ContentHash: sha256hex([]byte("new")), Perm: old.Perm})
			})
			store = &LocalStore{FS: filesystem.NewOSFileSystem(), Dirs: store.Dirs}
			snapshot, err := store.ScanAll(t.Context(), tc.artifactType)
			require.NoError(t, err)
			require.Len(t, snapshot["test"], 1)
			require.NoError(t, store.Remove(t.Context(), snapshot["test"]))
			remaining, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, remaining, 1)
			assert.True(t, remaining[0].IsDir(), "deleting the committed file must leave no active artifact")
			require.FileExists(t, filepath.Join(dir, ".tmp", filepath.Base(current.Path)+".tmp"))
			snapshot, err = store.ScanAll(t.Context(), tc.artifactType)
			require.NoError(t, err)
			assert.Empty(t, snapshot)
		})
	}
}

func TestLocalStore_StagingDirectoryFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		priority int32
	}{
		{name: "replacement at the same priority", priority: 50},
		{name: "replacement at a different priority", priority: 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, mockFS := newTestStore()
			old := FetchResult{Content: []byte("old"), ContentHash: sha256hex([]byte("old")), Perm: 0o644}
			_, current, err := store.Store(t.Context(), nil, "test", 50, TypeConfig, MediumInline, old)
			require.NoError(t, err)
			mockFS.MkdirErr = assert.AnError
			updated := FetchResult{Content: []byte("new"), ContentHash: sha256hex([]byte("new")), Perm: old.Perm}
			action, file, err := store.Store(t.Context(), current, "test", tc.priority, TypeConfig, MediumInline, updated)
			require.ErrorIs(t, err, assert.AnError)
			assert.Equal(t, StoreActionNone, action)
			assert.Nil(t, file)
			assert.Equal(t, old.Content, mockFS.Files[current.Path])
			assert.Len(t, mockFS.Files, 1)
			mockFS.MkdirErr = nil
			_, file, err = store.Store(t.Context(), current, "test", tc.priority, TypeConfig, MediumInline, updated)
			require.NoError(t, err)
			require.NotNil(t, file)
			if tc.priority != current.Priority {
				assert.NotContains(t, mockFS.Files, current.Path)
			}
			assert.Equal(t, updated.Content, mockFS.Files[file.Path])
		})
	}
}

func TestLocalStore_Read(t *testing.T) {
	store, fs := newTestStore()
	path := "/configs/plugins.yaml"
	fs.Files[path] = []byte("plugins: []")
	data, err := store.Read(t.Context(), path)
	require.NoError(t, err)
	assert.Equal(t, "plugins: []", string(data))
	_, err = store.Read(t.Context(), "/configs/missing.yaml")
	require.ErrorIs(t, err, os.ErrNotExist)
	fs.ReadErrFor = map[string]error{path: assert.AnError}
	_, err = store.Read(t.Context(), path)
	require.ErrorIs(t, err, assert.AnError)
}
func TestSetInstalled_PreservesExistingConfigSubEntry(t *testing.T) {
	artifacts := []artifactv1alpha1.InstalledArtifact{
		{
			Path: "/old", Medium: "oci", Priority: 50, ContentHash: "old-hash",
			Config: &artifactv1alpha1.InstalledArtifactConfig{Path: "/etc/falco/config.d/99-03-plugins-config-inline.yaml"},
		},
	}

	SetInstalled(&artifacts, File{Path: "/new", Medium: MediumOCI, Priority: 50, ContentHash: "new-hash"})

	require.Len(t, artifacts, 1)
	assert.Equal(t, "/new", artifacts[0].Path)
	assert.Equal(t, "new-hash", artifacts[0].ContentHash)
	require.NotNil(t, artifacts[0].Config, "updating the main fields must not drop the Config sub-entry")
	assert.Equal(t, "/etc/falco/config.d/99-03-plugins-config-inline.yaml", artifacts[0].Config.Path)
}

func TestLocalStore_Store_PriorityChange(t *testing.T) {
	store, mockFS := newTestStore()

	content := []byte("- rule: test\n  condition: true\n")
	hash := sha256hex(content)

	oldPriority := int32(50)
	newPriority := int32(10)
	oldPath := ArtifactPath(store.Dirs, "test", oldPriority, MediumOCI, TypeRulesfile)
	newPath := ArtifactPath(store.Dirs, "test", newPriority, MediumOCI, TypeRulesfile)
	require.NotEqual(t, oldPath, newPath)

	mockFS.Files[oldPath] = content

	current := &File{Path: oldPath, Medium: MediumOCI, Priority: oldPriority, ContentHash: hash}

	action, newFile, err := store.Store(context.Background(), current, "test", newPriority, TypeRulesfile, MediumOCI, FetchResult{
		Content:     content,
		ContentHash: hash,
		Perm:        0o644,
	})

	require.NoError(t, err)
	assert.Equal(t, StoreActionPriorityChanged, action)
	require.NotNil(t, newFile)
	assert.Equal(t, newPath, newFile.Path)
	assert.Equal(t, hash, newFile.ContentHash)
	assert.Equal(t, newPriority, newFile.Priority)
	_, oldExists := mockFS.Files[oldPath]
	assert.False(t, oldExists, "old path should have been removed")
	_, newExists := mockFS.Files[newPath]
	assert.True(t, newExists, "new path should exist")
}

func TestLocalStore_Store_ContentAndPriorityChangeTogether(t *testing.T) {
	store, mockFS := newTestStore()

	oldContent := []byte("- rule: old\n  condition: true\n")
	newContent := []byte("- rule: new\n  condition: false\n")
	oldHash := sha256hex(oldContent)
	newHash := sha256hex(newContent)

	oldPriority := int32(50)
	newPriority := int32(20)
	oldPath := ArtifactPath(store.Dirs, "test", oldPriority, MediumOCI, TypeRulesfile)
	newPath := ArtifactPath(store.Dirs, "test", newPriority, MediumOCI, TypeRulesfile)
	require.NotEqual(t, oldPath, newPath)

	mockFS.Files[oldPath] = oldContent

	current := &File{Path: oldPath, Medium: MediumOCI, Priority: oldPriority, ContentHash: oldHash}

	action, newFile, err := store.Store(context.Background(), current, "test", newPriority, TypeRulesfile, MediumOCI, FetchResult{
		Content:     newContent,
		ContentHash: newHash,
		Perm:        0o644,
	})

	require.NoError(t, err)
	assert.Equal(t, StoreActionUpdated, action)
	require.NotNil(t, newFile)
	assert.Equal(t, newPath, newFile.Path)
	assert.Equal(t, newHash, newFile.ContentHash)
	assert.Equal(t, newPriority, newFile.Priority)
	_, oldExists := mockFS.Files[oldPath]
	assert.False(t, oldExists, "old path should have been removed")
	assert.Equal(t, newContent, mockFS.Files[newPath])
}

func TestLocalStore_Store_PriorityChangeDoesNotLeaveOldPath(t *testing.T) {
	for _, artifactType := range []Type{TypeRulesfile, TypeConfig} {
		t.Run(string(artifactType), func(t *testing.T) {
			store, mockFS := newTestStore()
			old := FetchResult{Content: []byte("old"), ContentHash: sha256hex([]byte("old")), Perm: 0o644}
			updated := FetchResult{Content: []byte("new"), ContentHash: sha256hex([]byte("new")), Perm: 0o644}
			_, current, err := store.Store(t.Context(), nil, "test", 50, artifactType, MediumInline, old)
			require.NoError(t, err)
			mockFS.RemoveErrFor = map[string]error{current.Path: errors.New("cannot unlink old file")}

			_, file, err := store.Store(t.Context(), current, "test", 20, artifactType, MediumInline, updated)

			require.NoError(t, err)
			require.NotNil(t, file)
			assert.NotContains(t, mockFS.Files, current.Path, "a successful replacement must not leave the old rules/config active")
			assert.Equal(t, updated.Content, mockFS.Files[file.Path])
		})
	}
}

func TestLocalStore_StoreRepairsTrackedContent(t *testing.T) {
	for _, source := range []struct {
		artifactType Type
		medium       Medium
	}{{TypePlugin, MediumOCI}, {TypeConfig, MediumInline}, {TypeRulesfile, MediumConfigMap}} {
		for _, state := range []string{"intact", "corrupt", "missing", "unreadable"} {
			t.Run(string(source.artifactType)+"/"+state, func(t *testing.T) {
				store, mockFS := newTestStore()
				result := FetchResult{Content: []byte("expected"), ContentHash: sha256hex([]byte("expected")), Perm: PermFor(source.artifactType)}
				_, current, err := store.Store(t.Context(), nil, "artifact", 10, source.artifactType, source.medium, result)
				require.NoError(t, err)
				switch state {
				case "corrupt":
					mockFS.Files[current.Path] = []byte("corrupt")
				case "missing":
					delete(mockFS.Files, current.Path)
				case "unreadable":
					mockFS.ReadErr = fmt.Errorf("read failed")
				}
				action, updated, err := store.Store(t.Context(), current, "artifact", 10, source.artifactType, source.medium, result)
				require.NoError(t, err)
				if state == "intact" {
					require.Equal(t, StoreActionUnchanged, action)
					require.Nil(t, updated)
				} else {
					require.NotEqual(t, StoreActionUnchanged, action)
					require.NotNil(t, updated)
				}
				require.Equal(t, result.Content, mockFS.Files[current.Path])
			})
		}
	}
}
