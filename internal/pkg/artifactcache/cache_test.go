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

package artifactcache_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
)

func TestBlobPath(t *testing.T) {
	tests := []struct {
		name         string
		cacheDir     string
		artifactType string
		ref          string
		digest       string
		goos, goarch string
		want         string
	}{
		{
			name:         "platform-specific artifact includes os/arch suffix",
			cacheDir:     "cache",
			artifactType: "plugin",
			ref:          "ghcr.io/falcosecurity/plugins/json:0.7.0",
			digest:       "sha256:abcdef",
			goos:         "linux",
			goarch:       "amd64",
			want: filepath.Join("cache", "blobs", "plugin",
				"ghcr.io-falcosecurity-plugins-json-0.7.0", "sha256-abcdef-linux-amd64"),
		},
		{
			name:         "platform-agnostic artifact has no os/arch suffix",
			cacheDir:     "cache",
			artifactType: "rulesfile",
			ref:          "ghcr.io/falcosecurity/rules/default:1.0.0",
			digest:       "sha256:123456",
			want: filepath.Join("cache", "blobs", "rulesfile",
				"ghcr.io-falcosecurity-rules-default-1.0.0", "sha256-123456"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := artifactcache.BlobPath(tt.cacheDir, tt.artifactType, tt.ref, tt.digest, tt.goos, tt.goarch)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRefToPath(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{
			name: "slashes and colon",
			ref:  "ghcr.io/falcosecurity/plugins/cloudtrail:0.12.0",
			want: "ghcr.io-falcosecurity-plugins-cloudtrail-0.12.0",
		},
		{
			name: "digest reference with at-sign",
			ref:  "ghcr.io/falcosecurity/plugins/json@sha256:abc123",
			want: "ghcr.io-falcosecurity-plugins-json-sha256-abc123",
		},
		{
			name: "no special characters is unchanged",
			ref:  "simplename",
			want: "simplename",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, artifactcache.RefToPath(tt.ref))
		})
	}
}

func TestStore(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		perm    fs.FileMode
		// setup prepares dir and returns the blobPath to pass to Store.
		setup func(t *testing.T, dir string) string
		// wantErrContains, when set, means Store must fail with an error containing this text;
		// wantPermDecimal is checked instead when it's empty.
		wantErrContains string
		wantPermDecimal string
	}{
		{
			name:    "writes content and a decimal perm companion file",
			content: []byte("hello world"),
			perm:    0o750,
			setup: func(_ *testing.T, dir string) string {
				return filepath.Join(dir, "nested", "blob")
			},
			wantPermDecimal: "488", // 0o750
		},
		{
			name:    "overwrites an existing blob",
			content: []byte("v2"),
			perm:    0o600,
			setup: func(t *testing.T, dir string) string {
				blobPath := filepath.Join(dir, "blob")
				require.NoError(t, artifactcache.Store(blobPath, []byte("v1"), 0o644))
				return blobPath
			},
			wantPermDecimal: "384", // 0o600
		},
		{
			name:    "error when the blob directory cannot be created",
			content: []byte("data"),
			perm:    0o644,
			setup: func(t *testing.T, dir string) string {
				// "blocker" exists as a regular file, so it can't be used as a directory component.
				blocker := filepath.Join(dir, "blocker")
				require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
				return filepath.Join(blocker, "blob")
			},
			wantErrContains: "create blob dir",
		},
		{
			name:    "error when the temp file cannot be written",
			content: []byte("data"),
			perm:    0o644,
			setup: func(t *testing.T, dir string) string {
				if os.Geteuid() == 0 {
					t.Skip("permission checks are bypassed when running as root")
				}
				require.NoError(t, os.Chmod(dir, 0o500)) // read+execute only: no new files allowed
				t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
				return filepath.Join(dir, "blob")
			},
			wantErrContains: "write blob",
		},
		{
			name:    "error when the rename target is a non-empty directory",
			content: []byte("data"),
			perm:    0o644,
			setup: func(t *testing.T, dir string) string {
				blobPath := filepath.Join(dir, "blob")
				require.NoError(t, os.Mkdir(blobPath, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(blobPath, "occupied"), []byte("x"), 0o600))
				return blobPath
			},
			wantErrContains: "rename blob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			blobPath := tt.setup(t, dir)

			err := artifactcache.Store(blobPath, tt.content, tt.perm)

			if tt.wantErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				// No case leaves a usable temp file behind: either it was never created (the
				// blob dir itself couldn't be made, so stat fails with "not a directory"), or it
				// was created and then removed on failure (stat fails with "not exist").
				_, statErr := os.Stat(blobPath + ".tmp")
				assert.Error(t, statErr, "temp file must be cleaned up on failure")
				return
			}
			require.NoError(t, err)

			content, err := os.ReadFile(blobPath)
			require.NoError(t, err)
			assert.Equal(t, string(tt.content), string(content))

			perm, err := os.ReadFile(blobPath + artifactcache.PermSuffix)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPermDecimal, string(perm))
		})
	}
}

func TestReadPerm(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, blobPath string)
		want  fs.FileMode
	}{
		{
			name: "reads a valid perm file",
			setup: func(t *testing.T, blobPath string) {
				require.NoError(t, artifactcache.Store(blobPath, []byte("x"), 0o700))
			},
			want: 0o700,
		},
		{
			name: "missing perm file defaults to 0o755",
			setup: func(t *testing.T, blobPath string) {
				require.NoError(t, os.WriteFile(blobPath, []byte("x"), 0o600)) // no .perm companion
			},
			want: 0o755,
		},
		{
			name: "unparseable perm file defaults to 0o755",
			setup: func(t *testing.T, blobPath string) {
				require.NoError(t, os.WriteFile(blobPath+artifactcache.PermSuffix, []byte("not-a-number"), 0o600))
			},
			want: 0o755,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob")
			tt.setup(t, blobPath)
			assert.Equal(t, tt.want, artifactcache.ReadPerm(blobPath))
		})
	}
}
