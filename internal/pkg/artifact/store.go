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
	"io/fs"
	"path/filepath"

	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/mounts"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// ArtifactDirs holds the on-disk directories where each artifact type is stored.
type ArtifactDirs struct {
	Plugin    string
	Rulesfile string
	Config    string
}

// DefaultArtifactDirs returns the production mount-point directories.
func DefaultArtifactDirs() ArtifactDirs {
	return ArtifactDirs{
		Plugin:    mounts.PluginDirPath,
		Rulesfile: mounts.RulesfileDirPath,
		Config:    mounts.ConfigDirPath,
	}
}

// ArtifactStore writes artifact files to the local filesystem with content-hash deduplication
// and removes stale files.
type ArtifactStore interface {
	// Verify returns true if f's file exists on disk and its SHA-256 matches f.ContentHash.
	// A nil f or a missing/corrupted file returns false with a nil error.
	Verify(ctx context.Context, f *File) (bool, error)

	// Store idempotently ensures content is on disk at the correct path for (name, priority, type, medium).
	// current is the previously installed file from status (nil = nothing tracked for this medium).
	// Returns the newly written File on Add/Update, or nil on Unchanged/error.
	Store(ctx context.Context, current *File, name string, artifactPriority int32,
		artifactType Type, medium Medium, result FetchResult) (StoreAction, *File, error)

	// Remove deletes every path listed in installed from disk.
	Remove(ctx context.Context, installed []artifactv1alpha1.InstalledArtifact) error
}

// LocalStore implements ArtifactStore against the local filesystem.
type LocalStore struct {
	FS   filesystem.FileSystem
	Dirs ArtifactDirs
}

// NewLocalStore returns a LocalStore backed by the OS filesystem with production directories.
func NewLocalStore() *LocalStore {
	return &LocalStore{
		FS:   filesystem.NewOSFileSystem(),
		Dirs: DefaultArtifactDirs(),
	}
}

// Store idempotently writes artifact content to the final on-disk path.
// It uses a write-then-rename pattern so the file is never partially visible.
func (s *LocalStore) Store(ctx context.Context, current *File, name string, artifactPriority int32,
	artifactType Type, medium Medium, result FetchResult) (StoreAction, *File, error) {
	logger := log.FromContext(ctx)

	// If status points to a file no longer on disk, treat as fresh install.
	if current != nil {
		if ok, err := s.FS.Exists(current.Path); err != nil {
			return StoreActionNone, nil, fmt.Errorf("check existing artifact path: %w", err)
		} else if !ok {
			logger.V(3).Info("Tracked artifact missing from disk; reinstalling", "path", current.Path)
			current = nil
		}
	}

	newPath := ArtifactPath(s.Dirs, name, artifactPriority, medium, artifactType)

	// Detect unchanged: same content hash and same final path.
	if current != nil && current.ContentHash == result.ContentHash && current.Path == newPath {
		return StoreActionUnchanged, nil, nil
	}

	// Priority rename: content is the same but the file needs to move.
	priorityChanged := current != nil && current.ContentHash == result.ContentHash && current.Path != newPath

	// Write content to a sibling temp path then rename atomically.
	tmpPath := newPath + ".tmp"
	if err := s.FS.WriteFile(tmpPath, result.Content, result.Perm); err != nil {
		logger.Error(err, "unable to write artifact temp file", "tmp", tmpPath)
		_ = s.FS.Remove(tmpPath)
		return StoreActionNone, nil, err
	}
	if err := s.FS.Rename(tmpPath, newPath); err != nil {
		logger.Error(err, "unable to rename artifact to final path", "tmp", tmpPath, "final", newPath)
		_ = s.FS.Remove(tmpPath)
		return StoreActionNone, nil, err
	}

	// Remove the old file if it was at a different path (priority change).
	if current != nil && current.Path != newPath {
		if err := s.FS.Remove(current.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Error(err, "unable to remove old artifact path", "oldPath", current.Path)
		}
	}

	newFile := &File{
		Path:        newPath,
		Medium:      medium,
		Priority:    artifactPriority,
		ContentHash: result.ContentHash,
	}

	if current == nil {
		logger.Info("Artifact installed", "path", newPath)
		return StoreActionAdded, newFile, nil
	}
	if priorityChanged {
		logger.Info("Artifact moved due to priority change", "old", current.Path, "new", newPath)
		return StoreActionPriorityChanged, newFile, nil
	}
	logger.Info("Artifact updated", "path", newPath)
	return StoreActionUpdated, newFile, nil
}

// Verify returns true if the on-disk file at f.Path exists and its SHA-256 matches f.ContentHash.
// Returns false (nil error) when f is nil, the file is absent, or the hash does not match.
func (s *LocalStore) Verify(_ context.Context, f *File) (bool, error) {
	if f == nil {
		return false, nil
	}
	data, err := s.FS.ReadFile(f.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]) == f.ContentHash, nil
}

// Remove deletes every installed artifact path from disk, ignoring not-found errors.
func (s *LocalStore) Remove(ctx context.Context, installed []artifactv1alpha1.InstalledArtifact) error {
	logger := log.FromContext(ctx)
	for _, a := range installed {
		if err := s.FS.Remove(a.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Error(err, "unable to remove artifact", "path", a.Path)
			return err
		}
		logger.Info("Artifact removed", "path", a.Path)
	}
	return nil
}

// ArtifactPath computes the on-disk path for an artifact.
func ArtifactPath(dirs ArtifactDirs, name string, artifactPriority int32, medium Medium, artifactType Type) string {
	switch artifactType {
	case TypeRulesfile:
		var sub int32
		switch medium {
		case MediumOCI:
			sub = priority.OCISubPriority
		case MediumInline:
			sub = priority.InLineRulesSubPriority
		case MediumConfigMap:
			sub = priority.CMSubPriority
		default:
			sub = priority.MaxPriority
		}
		return filepath.Clean(filepath.Join(dirs.Rulesfile,
			priority.NameFromPriorityAndSubPriority(artifactPriority, sub, fmt.Sprintf("%s-%s.yaml", name, medium))))
	case TypePlugin:
		return filepath.Clean(filepath.Join(dirs.Plugin, fmt.Sprintf("%s.so", name)))
	case TypeConfig:
		var sub int32
		switch medium {
		case MediumInline:
			sub = priority.InLineRulesSubPriority
		case MediumConfigMap:
			sub = priority.CMSubPriority
		default:
			sub = priority.MaxPriority
		}
		return filepath.Clean(filepath.Join(dirs.Config,
			priority.NameFromPriorityAndSubPriority(artifactPriority, sub, fmt.Sprintf("%s-%s.yaml", name, medium))))
	default:
		return priority.NameFromPriority(artifactPriority, name)
	}
}

// StatusHelpers: small helpers used by controllers to read/write InstalledArtifacts in status.

// FindInstalled returns the *File from status for the given medium, or nil.
func FindInstalled(artifacts []artifactv1alpha1.InstalledArtifact, medium Medium) *File {
	for _, a := range artifacts {
		if a.Medium == string(medium) {
			return &File{
				Path:        a.Path,
				Medium:      medium,
				Priority:    a.Priority,
				ContentHash: a.ContentHash,
				SpecHash:    a.SpecHash,
			}
		}
	}
	return nil
}

// SetInstalled upserts a File into the InstalledArtifacts slice (matched by Medium).
func SetInstalled(artifacts *[]artifactv1alpha1.InstalledArtifact, f File) {
	for i, a := range *artifacts {
		if a.Medium == string(f.Medium) {
			(*artifacts)[i] = artifactv1alpha1.InstalledArtifact{
				Path:        f.Path,
				Medium:      string(f.Medium),
				Priority:    f.Priority,
				ContentHash: f.ContentHash,
				SpecHash:    f.SpecHash,
			}
			return
		}
	}
	*artifacts = append(*artifacts, artifactv1alpha1.InstalledArtifact{
		Path:        f.Path,
		Medium:      string(f.Medium),
		Priority:    f.Priority,
		ContentHash: f.ContentHash,
		SpecHash:    f.SpecHash,
	})
}

// ClearInstalled removes the entry matching medium from the InstalledArtifacts slice.
func ClearInstalled(artifacts *[]artifactv1alpha1.InstalledArtifact, medium Medium) {
	s := *artifacts
	for i, a := range s {
		if a.Medium == string(medium) {
			s[i] = s[len(s)-1]
			*artifacts = s[:len(s)-1]
			return
		}
	}
}

// UpdateInstalledStatus applies the Store result to the InstalledArtifacts slice.
func UpdateInstalledStatus(artifacts *[]artifactv1alpha1.InstalledArtifact, action StoreAction, medium Medium, newFile *File) {
	switch action {
	case StoreActionAdded, StoreActionUpdated, StoreActionPriorityChanged:
		if newFile != nil {
			SetInstalled(artifacts, *newFile)
		}
	case StoreActionRemoved:
		ClearInstalled(artifacts, medium)
	case StoreActionNone, StoreActionUnchanged:
	}
}

// UpdateInstalledSpecHash sets SpecHash on the entry matching medium; no-op if not found.
// Used when StoreActionUnchanged is returned but the spec still changed, since the content
// hash alone doesn't capture that.
func UpdateInstalledSpecHash(artifacts *[]artifactv1alpha1.InstalledArtifact, medium Medium, specHash string) {
	for i, a := range *artifacts {
		if a.Medium == string(medium) {
			(*artifacts)[i].SpecHash = specHash
			return
		}
	}
}

// FindInstalledConfig returns the config sub-entry for the artifact matching medium, or nil.
// The returned File uses MediumInline and priority.MaxPriority (fixed for plugin config files).
// ContentHash is always empty; callers must populate it via Verify before passing to Store.
func FindInstalledConfig(artifacts []artifactv1alpha1.InstalledArtifact, medium Medium) *File {
	for _, a := range artifacts {
		if a.Medium == string(medium) && a.Config != nil {
			return &File{
				Path:     a.Config.Path,
				Medium:   MediumInline,
				Priority: priority.MaxPriority,
			}
		}
	}
	return nil
}

// UpdateInstalledConfig sets the Config sub-entry on the artifact matching medium.
// No-op when f is nil or no entry matches medium.
func UpdateInstalledConfig(artifacts *[]artifactv1alpha1.InstalledArtifact, medium Medium, f *File) {
	if f == nil {
		return
	}
	for i, a := range *artifacts {
		if a.Medium == string(medium) {
			(*artifacts)[i].Config = &artifactv1alpha1.InstalledArtifactConfig{
				Path: f.Path,
			}
			return
		}
	}
}
