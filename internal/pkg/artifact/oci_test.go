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
	"fmt"
	"io/fs"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

func TestFetchOCIAuthSecret(t *testing.T) {
	const namespace = "test-namespace"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: namespace},
	}

	tests := []struct {
		name     string
		objects  []client.Object
		ref      *commonv1alpha1.SecretRef
		wantName string
		wantErr  string
	}{
		{
			name: "returns nil when reference is nil",
		},
		{
			name:     "returns referenced secret",
			objects:  []client.Object{secret},
			ref:      &commonv1alpha1.SecretRef{Name: "pull-secret"},
			wantName: "pull-secret",
		},
		{
			name:    "returns error when secret is missing",
			ref:     &commonv1alpha1.SecretRef{Name: "missing"},
			wantErr: "failed to get pull secret missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(createTestScheme(t))
			if len(tt.objects) > 0 {
				builder = builder.WithObjects(tt.objects...)
			}
			manager := NewManager(builder.Build(), namespace)

			got, err := manager.fetchOCIAuthSecret(context.Background(), tt.ref)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			if tt.wantName == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantName, got.Name)
		})
	}
}

func TestGetCurrentOCIFile(t *testing.T) {
	tests := []struct {
		name             string
		file             *File
		files            map[string][]byte
		statErr          error
		wantPath         string
		wantErr          string
		wantCacheCleared bool
		wantCopy         bool
	}{
		{
			name: "returns nil when file is not tracked",
		},
		{
			name:     "returns tracked file when it exists",
			file:     &File{Path: "/old", Medium: MediumOCI, Priority: 50},
			files:    map[string][]byte{"/old": []byte("content")},
			wantPath: "/old",
			wantCopy: true,
		},
		{
			name:             "clears stale cache when tracked file is missing",
			file:             &File{Path: "/old", Medium: MediumOCI, Priority: 50},
			wantErr:          "not found on filesystem",
			wantCacheCleared: true,
		},
		{
			name:    "returns error when existence check fails",
			file:    &File{Path: "/old", Medium: MediumOCI, Priority: 50},
			statErr: fmt.Errorf("permission denied"),
			wantErr: "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS := filesystem.NewMockFileSystem()
			mockFS.StatErr = tt.statErr
			maps.Copy(mockFS.Files, tt.files)

			manager := NewManagerWithOptions(
				fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build(),
				"test-namespace",
				WithFS(mockFS),
			)
			if tt.file != nil {
				manager.files["rules"] = []File{*tt.file}
			}

			got, err := manager.getCurrentOCIFile(context.Background(), "rules")
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				if tt.wantCacheCleared {
					assert.Nil(t, manager.getArtifactFile("rules", MediumOCI))
				}
				return
			}
			require.NoError(t, err)
			if tt.wantPath == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantPath, got.Path)
			if tt.wantCopy {
				got.Priority = 60
				assert.Equal(t, int32(50), manager.files["rules"][0].Priority)
			}
		})
	}
}

func TestPullOCIFile(t *testing.T) {
	validLayer, err := puller.MakeTarGz("rules.yaml", []byte("rules-content"))
	require.NoError(t, err)

	tests := []struct {
		name        string
		result      *puller.RegistryResult
		layer       []byte
		nilResult   bool
		wantErr     string
		wantContent string
	}{
		{
			name:        "pulls and extracts single file",
			result:      &puller.RegistryResult{Type: puller.Rulesfile},
			layer:       validLayer,
			wantContent: "rules-content",
		},
		{
			name:    "rejects mismatched artifact type",
			result:  &puller.RegistryResult{Type: puller.Plugin},
			layer:   validLayer,
			wantErr: "does not match expected type",
		},
		{
			name:    "rejects empty artifact type",
			result:  &puller.RegistryResult{},
			layer:   validLayer,
			wantErr: "does not match expected type",
		},
		{
			name:      "rejects nil puller result",
			nilResult: true,
			wantErr:   "nil result",
		},
		{
			name:    "rejects invalid gzip layer",
			result:  &puller.RegistryResult{Type: puller.Rulesfile},
			layer:   []byte("not-gzip"),
			wantErr: "unexpected EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManagerWithOptions(
				fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build(),
				"test-namespace",
				WithOCIPuller(&puller.MockOCIPuller{
					Result:         tt.result,
					LayerContent:   tt.layer,
					AllowNilResult: tt.nilResult,
				}),
			)

			file, err := manager.pullOCIFile(
				context.Background(),
				"registry.example.test/falco/rules:latest",
				TypeRulesfile,
				&commonv1alpha1.OCIArtifact{},
				nil,
			)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantContent, string(file.Content))
			assert.Equal(t, fs.FileMode(0o644), file.Perm)
		})
	}
}

func TestRemoveReplacedOCIFile(t *testing.T) {
	tests := []struct {
		name          string
		oldFile       *File
		newPath       string
		files         map[string][]byte
		removeErrFor  map[string]error
		wantErr       string
		wantRemoveLen int
		wantFiles     map[string]bool
	}{
		{
			name:    "does nothing when old file is nil",
			newPath: "/new",
		},
		{
			name:    "does nothing when path is unchanged",
			oldFile: &File{Path: "/same"},
			newPath: "/same",
		},
		{
			name:          "removes replaced old path",
			oldFile:       &File{Path: "/old"},
			newPath:       "/new",
			files:         map[string][]byte{"/old": []byte("old"), "/new": []byte("new")},
			wantRemoveLen: 1,
			wantFiles:     map[string]bool{"/old": false, "/new": true},
		},
		{
			name:          "rolls back new file when old path cannot be removed",
			oldFile:       &File{Path: "/old"},
			newPath:       "/new",
			files:         map[string][]byte{"/old": []byte("old"), "/new": []byte("new")},
			removeErrFor:  map[string]error{"/old": fmt.Errorf("device busy")},
			wantErr:       "device busy",
			wantRemoveLen: 2,
			wantFiles:     map[string]bool{"/old": true, "/new": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS := filesystem.NewMockFileSystem()
			mockFS.RemoveErrFor = tt.removeErrFor
			maps.Copy(mockFS.Files, tt.files)

			manager := NewManagerWithOptions(
				fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build(),
				"test-namespace",
				WithFS(mockFS),
			)

			err := manager.removeReplacedOCIFile(context.Background(), tt.oldFile, tt.newPath)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveLen)
			for path, exists := range tt.wantFiles {
				if exists {
					assert.Contains(t, mockFS.Files, path)
				} else {
					assert.NotContains(t, mockFS.Files, path)
				}
			}
		})
	}
}

func TestInstallOCIFile(t *testing.T) {
	tests := []struct {
		name           string
		writeErr       error
		renameErr      error
		wantErr        string
		wantFinalFile  bool
		wantWriteLen   int
		wantRenameLen  int
		wantRemoveLen  int
		wantFinalBytes []byte
	}{
		{
			name:           "writes temp file and renames it to final path",
			wantFinalFile:  true,
			wantWriteLen:   1,
			wantRenameLen:  1,
			wantFinalBytes: []byte("rules-content"),
		},
		{
			name:          "cleans temp path when write fails",
			writeErr:      fmt.Errorf("disk full"),
			wantErr:       "disk full",
			wantWriteLen:  1,
			wantRemoveLen: 1,
		},
		{
			name:          "cleans temp path when rename fails",
			renameErr:     fmt.Errorf("rename failed"),
			wantErr:       "rename failed",
			wantWriteLen:  1,
			wantRenameLen: 1,
			wantRemoveLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS := filesystem.NewMockFileSystem()
			mockFS.WriteErr = tt.writeErr
			mockFS.RenameErr = tt.renameErr
			manager := NewManagerWithOptions(
				fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build(),
				"test-namespace",
				WithFS(mockFS),
			)

			err := manager.installOCIFile(context.Background(), "/artifact.yaml", common.ExtractedFile{
				Content: []byte("rules-content"),
				Perm:    0o640,
			})
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			if tt.wantFinalFile {
				assert.Equal(t, tt.wantFinalBytes, mockFS.Files["/artifact.yaml"])
			} else {
				assert.NotContains(t, mockFS.Files, "/artifact.yaml")
			}
			assert.NotContains(t, mockFS.Files, "/artifact.yaml.tmp")
			assert.Len(t, mockFS.WriteCalls, tt.wantWriteLen)
			assert.Len(t, mockFS.RenameCalls, tt.wantRenameLen)
			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveLen)
		})
	}
}

func TestIsExpectedOCIArtifactType(t *testing.T) {
	tests := []struct {
		name     string
		expected Type
		actual   puller.ArtifactType
		want     bool
	}{
		{name: "rulesfile matches", expected: TypeRulesfile, actual: puller.Rulesfile, want: true},
		{name: "plugin matches", expected: TypePlugin, actual: puller.Plugin, want: true},
		{name: "rulesfile rejects plugin", expected: TypeRulesfile, actual: puller.Plugin},
		{name: "plugin rejects rulesfile", expected: TypePlugin, actual: puller.Rulesfile},
		{name: "unsupported expected type", expected: TypeConfig, actual: puller.Rulesfile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isExpectedOCIArtifactType(tt.expected, tt.actual))
		})
	}
}
