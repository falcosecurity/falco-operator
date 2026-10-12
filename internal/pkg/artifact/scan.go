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
	"fmt"
	"path/filepath"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
)

// ScanAll discovers every artifact file on disk for kind by listing the relevant
// directory and parsing each filename back into name, medium, and priority. Unlike a per-name
// lookup, this does not require already knowing which artifact names exist: it is the primitive
// that lets a caller (e.g. a restart-time warm sync) discover names it has no other record of,
// such as an artifact whose parent CR was removed while this was the only place its existence
// was recorded. Files that don't match the naming convention are skipped rather than erroring,
// since a foreign or partially-written (e.g. leftover ".tmp") file is not this artifact type's
// concern. Returned entries have ContentHash from disk; SpecHash is always empty, since it isn't
// recoverable from file content alone.
//
// An unregistered kind is an error. Returning no files for it would make it indistinguishable from
// a kind with nothing installed: warm sync would conclude the node was clean and never recover the
// files that are actually on disk.
func (s *LocalStore) ScanAll(_ context.Context, kind Kind) (map[string][]artifactv1alpha1.InstalledArtifact, error) {
	info, err := InfoForKind(kind)
	if err != nil {
		return nil, err
	}
	return s.scanDir(&info)
}

// scanDir globs the kind's directory and groups the files it can parse by artifact name.
func (s *LocalStore) scanDir(info *KindInfo) (map[string][]artifactv1alpha1.InstalledArtifact, error) {
	dir := info.Dir(s.Dirs)
	matches, err := s.FS.Glob(filepath.Join(dir, info.Glob))
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", dir, err)
	}
	result := map[string][]artifactv1alpha1.InstalledArtifact{}
	for _, match := range matches {
		parsed, ok := info.ParseName(filepath.Base(match))
		if !ok {
			continue
		}
		hash, err := s.hashFile(match)
		if err != nil {
			return nil, err
		}
		result[parsed.Name] = append(result[parsed.Name], artifactv1alpha1.InstalledArtifact{
			Path:        match,
			Medium:      string(parsed.Medium),
			Priority:    parsed.Priority,
			ContentHash: hash,
		})
	}
	return result, nil
}

func (s *LocalStore) hashFile(path string) (string, error) {
	data, err := s.FS.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
