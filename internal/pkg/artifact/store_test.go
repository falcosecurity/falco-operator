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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
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

// TestSetInstalled_PreservesExistingConfigSubEntry reproduces a real regression: SetInstalled
// used to overwrite the whole InstalledArtifact struct when updating an existing medium entry,
// silently dropping its Config sub-field (set separately by UpdateInstalledConfig, e.g. for a
// Plugin's shared config-file linkage) because File has no Config field to carry it forward.
// Any caller that re-syncs a medium's main fields from a source that only knows about File (like
// Manager's installed-artifact cache) must never destroy a Config sub-entry nothing else tracks.
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
