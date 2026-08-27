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

	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
)

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func newTestStore() (*LocalStore, *filesystem.MockFileSystem) {
	mockFS := filesystem.NewMockFileSystem()
	dirs := ArtifactDirs{
		Plugin:    "/plugins",
		Rulesfile: "/rulesfiles",
		Config:    "/configs",
	}
	return &LocalStore{FS: mockFS, Dirs: dirs}, mockFS
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
