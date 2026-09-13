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
	"regexp"
	"strings"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// yamlFilenamePattern matches the "PP-SS-{name}-{medium}.yaml" convention produced by
// priority.NameFromPriorityAndSubPriority, recovering priority, name, and medium from the
// filename alone. Anchored so it only matches the exact convention this package writes.
var yamlFilenamePattern = regexp.MustCompile(`^(\d{2})-\d{2}-(.+)-(oci|inline|configmap)\.yaml$`)

// ScanAll discovers every artifact file on disk for artifactType by listing the relevant
// directory and parsing each filename back into name, medium, and priority. Unlike a per-name
// lookup, this does not require already knowing which artifact names exist: it is the primitive
// that lets a caller (e.g. a restart-time warm sync) discover names it has no other record of,
// such as an artifact whose parent CR was removed while this was the only place its existence
// was recorded. Files that don't match the naming convention are skipped rather than erroring,
// since a foreign or partially-written (e.g. leftover ".tmp") file is not this artifact type's
// concern. Returned entries have ContentHash from disk; SpecHash is always empty, since it isn't
// recoverable from file content alone.
func (s *LocalStore) ScanAll(_ context.Context, artifactType Type) (map[string][]artifactv1alpha1.InstalledArtifact, error) {
	switch artifactType {
	case TypeRulesfile:
		return s.scanYAMLDir(s.Dirs.Rulesfile)
	case TypeConfig:
		return s.scanYAMLDir(s.Dirs.Config)
	case TypePlugin:
		return s.scanPluginDir(s.Dirs.Plugin)
	default:
		return nil, nil
	}
}

// scanYAMLDir globs every "*.yaml" file directly under dir and groups the ones matching the
// naming convention by artifact name.
func (s *LocalStore) scanYAMLDir(dir string) (map[string][]artifactv1alpha1.InstalledArtifact, error) {
	matches, err := s.FS.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", dir, err)
	}
	result := map[string][]artifactv1alpha1.InstalledArtifact{}
	for _, match := range matches {
		sub := yamlFilenamePattern.FindStringSubmatch(filepath.Base(match))
		if sub == nil {
			continue
		}
		var prio int32
		if _, err := fmt.Sscanf(sub[1], "%d", &prio); err != nil {
			continue
		}
		name, medium := sub[2], sub[3]
		hash, err := s.hashFile(match)
		if err != nil {
			return nil, err
		}
		result[name] = append(result[name], artifactv1alpha1.InstalledArtifact{
			Path:        match,
			Medium:      medium,
			Priority:    prio,
			ContentHash: hash,
		})
	}
	return result, nil
}

// scanPluginDir globs every "*.so" file directly under dir. Plugin filenames encode only the
// name (see ArtifactPath's TypePlugin case): priority isn't part of the filename because plugin
// binaries are always installed at priority.DefaultPriority, and medium is always MediumOCI
// (plugins have no other source today).
func (s *LocalStore) scanPluginDir(dir string) (map[string][]artifactv1alpha1.InstalledArtifact, error) {
	matches, err := s.FS.Glob(filepath.Join(dir, "*.so"))
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", dir, err)
	}
	result := map[string][]artifactv1alpha1.InstalledArtifact{}
	for _, match := range matches {
		name := strings.TrimSuffix(filepath.Base(match), ".so")
		hash, err := s.hashFile(match)
		if err != nil {
			return nil, err
		}
		result[name] = append(result[name], artifactv1alpha1.InstalledArtifact{
			Path:        match,
			Medium:      string(MediumOCI),
			Priority:    priority.DefaultPriority,
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
