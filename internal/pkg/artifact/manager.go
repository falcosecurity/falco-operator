// Copyright (C) 2025 The Falco Authors
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
	"os"
	"path/filepath"
	"runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/credentials"
	"github.com/falcosecurity/falco-operator/internal/pkg/mounts"
	ociClient "github.com/falcosecurity/falco-operator/internal/pkg/oci/client"
	ocipuller "github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// Type represents different types of artifacts.
type Type string

const (
	// TypeRulesfile represents a rulesFile artifact.
	TypeRulesfile Type = "rulesfile"
	// TypePlugin represents a plugin artifact.
	TypePlugin Type = "plugin"
	// TypeConfig represents a config artifact.
	TypeConfig Type = "config"
)

// Medium represents how the artifact is distributed.
type Medium string

const (
	// MediumInline represents an inline artifact.
	MediumInline Medium = "inline"
	// MediumOCI represents an OCI artifact.
	MediumOCI Medium = "oci"
)

// File represents a tracked file for any artifact type.
type File struct {
	Path     string // Full Path on filesystem
	Medium   Medium // How the artifact is stored/distributed
	Priority int32  // Priority when created
}

// Exists checks if the artifact file exists on the filesystem.
func (af *File) Exists() (bool, error) {
	// Check if the file exists on the filesystem
	if _, err := os.Stat(af.Path); err != nil && !os.IsNotExist(err) {
		return false, err
	} else if os.IsNotExist(err) {
		return false, nil
	}

	return true, nil
}

// Manager manages the lifecycle of artifacts on the filesystem.
type Manager struct {
	files     map[string][]File
	client    client.Client
	namespace string
}

// NewManager creates a new manager.
func NewManager(cl client.Client, namespace string) *Manager {
	return &Manager{
		client:    cl,
		namespace: namespace,
		files:     make(map[string][]File),
	}
}

// StoreFromInLineYaml stores an artifact from an inline YAML to the local filesystem.
func (am *Manager) StoreFromInLineYaml(ctx context.Context, name string, artifactPriority int32, data *string, artifactType Type) error {
	logger := log.FromContext(ctx)

	// If the data is nil, we remove the artifact from the manager and from filesystem.
	// It means that the instance has been updated and the artifact has been removed from the spec.
	if data == nil {
		// Get artifact from the manager.
		if file := am.getArtifactFile(name, MediumInline); file != nil {
			logger.Info("Removing artifact from filesystem", "artifact", file.Path)
			if err := am.removeArtifact(ctx, name, MediumInline); err != nil {
				logger.Error(err, "Failed to remove artifact from filesystem", "artifact", file.Path)
				return err
			}
		}
		return nil
	}

	newFile := File{
		Path:     Path(name, artifactPriority, MediumInline, artifactType),
		Medium:   MediumInline,
		Priority: artifactPriority,
	}

	// Check if the artifact is already stored.
	if file := am.getArtifactFile(name, MediumInline); file != nil {
		logger.V(4).Info("Artifact already stored", "artifact", file)
		// Check if the file already exists on the filesystem.
		ok, err := file.Exists()
		if err != nil {
			logger.Error(err, "Failed to check if file exists", "file", file.Path)
			return err
		}
		// If the file exists we check if the priority has changed or the content has been updated.
		if ok {
			logger.V(4).Info("File already exists, checking if is up to date", "file", file.Path)
			// Read the file.
			content, err := os.ReadFile(file.Path)
			if err != nil {
				logger.Error(err, "unable to read file", "file", file.Path)
				return err
			}
			// Check if the content is the same and the priority has not changed.
			if string(content) == *data && file.Priority == artifactPriority {
				logger.V(3).Info("file is up to date", "file", file.Path)
				return nil
			}

			if file.Priority != artifactPriority {
				logger.Info("Updating artifact file due to priority change",
					"oldPriority", file.Priority, "newPriority", artifactPriority, "oldFile", file.Path, "newFile", newFile.Path)
			}

			logger.Info("File is outdated, updating", "file", file.Path)
			// The content is different, remove the file.
			if err := os.Remove(file.Path); err != nil {
				logger.Error(err, "unable to remove rulesfile", "file", file.Path)
				return err
			}
			// Remove the file from the manager.
			am.removeArtifactFile(name, MediumInline)
		}
	}

	// Write the raw YAML to the filesystem.
	if err := os.WriteFile(newFile.Path, []byte(*data), 0o600); err != nil {
		logger.Error(err, "unable to write file", "file", newFile.Path)
		return err
	}

	// Add the artifact to the manager.
	am.addArtifactFile(name, newFile)
	logger.Info("file correctly written to filesystem", "file", newFile.Path)
	return nil
}

// StoreFromOCI stores an artifact from an OCI registry to the local filesystem.
func (am *Manager) StoreFromOCI(ctx context.Context, name string, artifactPriority int32, artifactType Type, artifact *commonv1alpha1.OCIArtifact) error {
	logger := log.FromContext(ctx)

	// If the artifact is nil, we remove the artifact from the manager and from filesystem.
	// It means that the instance has been updated and the artifact has been removed from the spec.
	if artifact == nil {
		// Get artifact from the manager.
		if file := am.getArtifactFile(name, MediumOCI); file != nil {
			logger.Info("Removing artifact from filesystem", "artifact", file.Path)
			if err := am.removeArtifact(ctx, name, MediumOCI); err != nil {
				logger.Error(err, "Failed to remove artifact from filesystem", "artifact", file.Path)
				return err
			}
		}
		return nil
	}
	newFile := File{
		Path:     Path(name, artifactPriority, MediumOCI, artifactType),
		Medium:   MediumOCI,
		Priority: artifactPriority,
	}

	// Check if the artifact is already stored.
	if file := am.getArtifactFile(name, MediumOCI); file != nil {
		logger.V(4).Info("Artifact already stored", "artifact", file)
		// Check if the file already exists on the filesystem.
		ok, err := file.Exists()
		if err != nil {
			logger.Error(err, "Failed to check if file exists", "file", file.Path)
			return err
		}
		// If the file exists and the priority has changed, we rename the file reflecting the new priority.
		if ok && file.Priority != artifactPriority {
			logger.Info("Renaming artifact file due to priority change",
				"oldPriority", file.Priority, "newPriority", artifactPriority, "oldFile", file.Path, "newFile", newFile.Path)
			if err := os.Rename(file.Path, newFile.Path); err != nil {
				logger.Error(err, "Failed to rename file", "oldFile", file.Path, "newFile", newFile.Path)
				return err
			}
		}
		// If the file does not exist on the filesystem, we remove it from the manager and return an error.
		// Next time the artifact is requested, it will be fetched from the OCI registry.
		if !ok {
			am.removeArtifactFile(name, MediumOCI)
			err := fmt.Errorf("artifact %q not found on filesystem", file.Path)
			logger.Error(err, "Failed to find file on filesystem", "file", newFile.Path)
			return err
		}

		return nil
	}

	var dstDir string
	switch artifactType {
	case TypeRulesfile:
		dstDir = mounts.RulesfileDirPath
	case TypePlugin:
		dstDir = mounts.PluginDirPath
	default:
		dstDir = ""
	}

	logger.V(4).Info("Getting credentials from pull secret", "pullSecret", artifact.PullSecret)
	// File does not exist on the filesystem, we store it.
	// Retrieve registry credentials.
	creds, err := credentials.GetCredentialsFromSecret(ctx, am.client, am.namespace, artifact.PullSecret)
	if err != nil {
		logger.Error(err, "unable to get credentials for the OCI artifact", "pullSecret", artifact.PullSecret)
		return err
	}

	puller := ocipuller.NewPuller(ociClient.NewClient(ociClient.WithCredentialFunc(creds)), false)
	logger.Info("Pulling OCI artifact", "reference", artifact.Reference)
	res, err := puller.Pull(ctx, artifact.Reference, dstDir, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		logger.Error(err, "unable to pull artifact", "reference", artifact.Reference)
		return err
	}

	archiveFile := filepath.Clean(filepath.Join(dstDir, res.Filename))

	// Extract the rulesfile from the archive.
	f, err := os.Open(archiveFile)
	if err != nil {
		return err
	}

	logger.V(4).Info("Extracting OCI artifact", "archive", archiveFile)

	// Extract artifact and move it to its destination directory
	files, err := common.ExtractTarGz(ctx, f, dstDir, 0)
	if err != nil {
		logger.Error(err, "unable to extract OCI artifact", "filename", archiveFile)
		return err
	}

	// Clean up the archive.
	if err = os.Remove(archiveFile); err != nil {
		logger.Error(err, "unable to remove OCI artifact", "filename", archiveFile)
		return err
	}

	logger.V(4).Info("Writing OCI artifact", "filename", newFile.Path)
	// Rename the artifact to the generated name.
	if err = os.Rename(files[0], newFile.Path); err != nil {
		logger.Error(err, "unable to rename artifact", "source", files[0], "destination", newFile.Path)
		return err
	}
	logger.Info("OCI artifact downloaded and saved", "artifact", newFile.Path)

	// Add the artifact to the manager.
	am.files[name] = append(am.files[name], newFile)

	return nil
}

func (am *Manager) removeArtifact(ctx context.Context, name string, medium Medium) error {
	logger := log.FromContext(ctx)

	// Check if there are artifacts for the given instance name.
	files, ok := am.files[name]
	if !ok {
		logger.V(4).Info("No artifacts found on filesystem for instance", "instance", name)
		return nil
	}

	for _, file := range files {
		// Remove the artifacts from the filesystem.
		if file.Medium == medium {
			if err := os.Remove(file.Path); err != nil {
				logger.Error(err, "unable to remove artifact", "file", file.Path)
				return err
			}
			am.removeArtifactFile(name, medium)
		}
	}

	return nil
}

// RemoveAll removes all artifacts for a given instance name.
func (am *Manager) RemoveAll(ctx context.Context, name string) error {
	logger := log.FromContext(ctx)

	// Check if there are artifacts for the given instance name.
	files, ok := am.files[name]
	if !ok {
		logger.V(4).Info("No artifacts found on filesystem for instance", "instance", name)
		return nil
	}

	for _, file := range files {
		// Remove the artifacts from the filesystem.
		logger.Info("Removing artifact", "file", file.Path)
		if err := os.Remove(file.Path); err != nil && !os.IsNotExist(err) {
			logger.Error(err, "unable to remove artifact", "file", file.Path)
			return err
		}
		am.removeArtifactFile(name, file.Medium)
	}

	// Remove the instance from the manager.
	delete(am.files, name)

	return nil
}

func (am *Manager) getArtifactFile(name string, medium Medium) *File {
	// Check if there are artifacts for the given instance name.
	files, ok := am.files[name]
	if !ok {
		return nil
	}

	// Check if there is an artifact for the given medium.
	for _, file := range files {
		if file.Medium == medium {
			return &file
		}
	}

	// No artifact found for the given medium.
	return nil
}

// addArtifactFile adds an artifact file to the manager.
func (am *Manager) addArtifactFile(name string, file File) {
	// Check if there are artifacts for the given instance name.
	files, ok := am.files[name]
	if !ok {
		am.files[name] = []File{file}
		return
	}

	// Add the artifact to the list of artifacts.
	am.files[name] = append(files, file)
}

// removeArtifactFile removes an artifact file from the manager.
func (am *Manager) removeArtifactFile(name string, medium Medium) {
	// Check if there are artifacts for the given instance name.
	files, ok := am.files[name]
	if !ok {
		return
	}

	// Remove the artifact for the given medium.
	for i, file := range files {
		if file.Medium == medium {
			am.files[name] = append(files[:i], files[i+1:]...)
			return
		}
	}
}

// Path returns the full Path for an artifact file based on its name, priority, and type.
func Path(name string, artifactPriority int32, medium Medium, artifactType Type) string {
	switch artifactType {
	case TypeRulesfile:
		var subPriority int32
		switch medium {
		case MediumOCI:
			subPriority = priority.OCISubPriority
		case MediumInline:
			subPriority = priority.InLineRulesSubPriority
		default:
			// Default to 0 if medium is not OCI or Inline.
			subPriority = priority.MaxPriority
		}
		return filepath.Clean(
			filepath.Join(
				mounts.RulesfileDirPath,
				priority.NameFromPriorityAndSubPriority(artifactPriority, subPriority, fmt.Sprintf("%s-%s.yaml", name, medium)),
			),
		)
	case TypePlugin:
		return filepath.Clean(
			filepath.Join(
				mounts.PluginDirPath,
				fmt.Sprintf("%s.so", name)),
		)
	case TypeConfig:
		return filepath.Clean(
			filepath.Join(
				mounts.ConfigDirPath,
				priority.NameFromPriority(artifactPriority, fmt.Sprintf("%s.yaml", name))),
		)

	default:
		return priority.NameFromPriority(artifactPriority, name)
	}
}
