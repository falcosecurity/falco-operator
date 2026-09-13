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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
)

func TestLocalStore_ScanAll_Rulesfile_GroupsByName(t *testing.T) {
	store, mockFS := newTestStore()

	myRulesOCI := ArtifactPath(store.Dirs, "my-rules", 50, MediumOCI, TypeRulesfile)
	myRulesInline := ArtifactPath(store.Dirs, "my-rules", 50, MediumInline, TypeRulesfile)
	otherOCI := ArtifactPath(store.Dirs, "other", 20, MediumOCI, TypeRulesfile)

	mockFS.Files[myRulesOCI] = []byte("oci content")
	mockFS.Files[myRulesInline] = []byte("inline content")
	mockFS.Files[otherOCI] = []byte("other content")
	// Unrelated file in the same directory must be ignored.
	mockFS.Files[store.Dirs.Rulesfile+"/notes.txt"] = []byte("not an artifact")

	found, err := store.ScanAll(context.Background(), TypeRulesfile)
	require.NoError(t, err)

	require.Len(t, found["my-rules"], 2)
	require.Len(t, found["other"], 1)

	byMedium := map[Medium]artifactv1alpha1.InstalledArtifact{}
	for _, f := range found["my-rules"] {
		byMedium[Medium(f.Medium)] = f
	}
	assert.Equal(t, myRulesOCI, byMedium[MediumOCI].Path)
	assert.Equal(t, int32(50), byMedium[MediumOCI].Priority)
	assert.Equal(t, sha256hex([]byte("oci content")), byMedium[MediumOCI].ContentHash)
	assert.Equal(t, myRulesInline, byMedium[MediumInline].Path)

	assert.Equal(t, otherOCI, found["other"][0].Path)
	assert.Equal(t, int32(20), found["other"][0].Priority)
}

func TestLocalStore_ScanAll_Plugin_OneFilePerName(t *testing.T) {
	store, mockFS := newTestStore()

	containerPath := ArtifactPath(store.Dirs, "container", 50, MediumOCI, TypePlugin)
	mockFS.Files[containerPath] = []byte("binary")
	// Unrelated file must be ignored.
	mockFS.Files[store.Dirs.Plugin+"/README.md"] = []byte("not a plugin")

	found, err := store.ScanAll(context.Background(), TypePlugin)
	require.NoError(t, err)

	require.Len(t, found, 1)
	require.Len(t, found["container"], 1)
	assert.Equal(t, containerPath, found["container"][0].Path)
	assert.Equal(t, string(MediumOCI), found["container"][0].Medium)
	assert.Equal(t, sha256hex([]byte("binary")), found["container"][0].ContentHash)
}

func TestLocalStore_ScanAll_NoFiles_ReturnsEmpty(t *testing.T) {
	store, _ := newTestStore()

	found, err := store.ScanAll(context.Background(), TypeConfig)
	require.NoError(t, err)
	assert.Empty(t, found)
}
