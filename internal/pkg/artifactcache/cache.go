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

// Package artifactcache manages the on-disk layout for the central OCI artifact cache
// shared between the instance-level aggregator controllers (writers) and the artifact
// HTTP server (reader). Both run as goroutines in the same process.
//
// Blob content is content-addressed on disk:
//
//	blobs/{type}/{safe-oci-ref}/{digest}-{os}-{arch}   extracted binary (plugins, platform-specific)
//	blobs/{type}/{safe-oci-ref}/{digest}               extracted binary (rulesfiles, platform-agnostic)
//	blobs/.../<blobname>.perm                          decimal fs.FileMode companion file
//
// The index mapping (namespace, name, platform) to its current blob path is owned by the
// Cache type (index.go): an in-memory map backed by a single index.json snapshot file for
// restart resilience, with reference-counted eviction of superseded/removed blobs and a
// periodic Sweeper (sweep.go) as a backstop against orphans.
package artifactcache

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	BlobsDir   = "blobs"
	PermSuffix = ".perm"
)

// BlobPath returns the filesystem path for a cached binary blob.
// For platform-specific artifacts (plugins) pass goos and goarch; for platform-agnostic
// artifacts (rulesfiles) pass empty strings.
func BlobPath(cacheDir, artifactType, ref, digest, goos, goarch string) string {
	name := strings.ReplaceAll(digest, ":", "-")
	if goos != "" && goarch != "" {
		name = fmt.Sprintf("%s-%s-%s", name, goos, goarch)
	}
	return filepath.Join(cacheDir, BlobsDir, artifactType, RefToPath(ref), name)
}

// Store atomically writes content to blobPath and records perm in the companion .perm file.
// Each writer uses a unique temporary file, then renames it into place.
// Call Cache.Store when the write belongs to a live Cache that may be swept concurrently.
func Store(blobPath string, content []byte, perm fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o750); err != nil {
		return fmt.Errorf("create blob dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(blobPath), "."+filepath.Base(blobPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("write blob: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("write blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close blob: %w", err)
	}
	if err := os.Rename(tmpPath, blobPath); err != nil {
		return fmt.Errorf("rename blob: %w", err)
	}
	// Best-effort: clients fall back to 0o755 if the .perm file is missing.
	_ = os.WriteFile(blobPath+PermSuffix,
		[]byte(strconv.FormatUint(uint64(perm), 10)), 0o600)
	return nil
}

// Store writes a blob while holding the cache mutex so the sweeper cannot delete the same
// path between the write and its final freshness check. Index registration remains the caller's
// responsibility through Set.
func (c *Cache) Store(blobPath string, content []byte, perm fs.FileMode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Store(blobPath, content, perm)
}

// ReadPerm reads the file mode from the companion .perm file.
// Returns 0o755 if the file is absent or cannot be parsed.
func ReadPerm(blobPath string) fs.FileMode {
	if data, err := os.ReadFile(blobPath + PermSuffix); err == nil { //nolint:gosec // blobPath is derived from BlobPath(), not raw external input
		if p, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32); err == nil {
			return fs.FileMode(p)
		}
	}
	return 0o755
}

// RefToPath converts an OCI reference to a safe directory name by replacing characters
// that are illegal or ambiguous in filesystem paths.
// Example: "ghcr.io/falcosecurity/plugins/cloudtrail:0.12.0" becomes "ghcr.io-falcosecurity-plugins-cloudtrail-0.12.0".
func RefToPath(ref string) string {
	return strings.NewReplacer("/", "-", ":", "-", "@", "-").Replace(ref)
}
