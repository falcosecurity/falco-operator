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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/credentials"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/mounts"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
	"oras.land/oras-go/v2/registry/remote/auth"
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

// Manager manages the lifecycle of artifacts on the filesystem.
type Manager struct {
	files        map[string][]File
	client       client.Client
	namespace    string
	fs           filesystem.FileSystem
	ociPuller    puller.Puller
	rulesfileDir string
	pluginDir    string
	configDir    string
}

// NewManager creates a new manager.
func NewManager(cl client.Client, namespace string) *Manager {
	return &Manager{
		client:       cl,
		namespace:    namespace,
		files:        make(map[string][]File),
		fs:           filesystem.NewOSFileSystem(),
		ociPuller:    puller.NewOciPuller(nil),
		rulesfileDir: mounts.RulesfileDirPath,
		pluginDir:    mounts.PluginDirPath,
		configDir:    mounts.ConfigDirPath,
	}
}

// ManagerOption is a function that configures a Manager.
type ManagerOption func(*Manager)

// WithFS sets a filesystem.
func WithFS(fileSystem filesystem.FileSystem) ManagerOption {
	return func(m *Manager) {
		m.fs = fileSystem
	}
}

// WithOCIPuller sets a OCI puller.
func WithOCIPuller(p puller.Puller) ManagerOption {
	return func(m *Manager) {
		m.ociPuller = p
	}
}

// WithRulesfileDir overrides the directory used to store rulesfile artifacts (default: mounts.RulesfileDirPath).
// Useful in tests to redirect output to a temporary directory.
func WithRulesfileDir(dir string) ManagerOption {
	return func(m *Manager) {
		m.rulesfileDir = dir
	}
}

// WithPluginDir overrides the directory used to store plugin artifacts (default: mounts.PluginDirPath).
// Useful in tests to redirect output to a temporary directory.
func WithPluginDir(dir string) ManagerOption {
	return func(m *Manager) {
		m.pluginDir = dir
	}
}

// WithConfigDir overrides the directory used to store config artifacts (default: mounts.ConfigDirPath).
// Useful in tests to redirect output to a temporary directory.
func WithConfigDir(dir string) ManagerOption {
	return func(m *Manager) {
		m.configDir = dir
	}
}

// NewManagerWithOptions creates a new manager with custom options (for testing).
func NewManagerWithOptions(cl client.Client, namespace string, opts ...ManagerOption) *Manager {
	m := NewManager(cl, namespace)
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Path returns the artifact path using the manager's configurable directories.
func (am *Manager) Path(name string, artifactPriority int32, medium Medium, artifactType Type) string {
	switch artifactType {
	case TypeRulesfile:
		var subPriority int32
		switch medium {
		case MediumOCI:
			subPriority = priority.OCISubPriority
		case MediumInline:
			subPriority = priority.InLineRulesSubPriority
		case MediumConfigMap:
			subPriority = priority.CMSubPriority
		default:
			subPriority = priority.MaxPriority
		}
		return filepath.Clean(
			filepath.Join(
				am.rulesfileDir,
				priority.NameFromPriorityAndSubPriority(artifactPriority, subPriority, fmt.Sprintf("%s-%s.yaml", name, medium)),
			),
		)
	case TypePlugin:
		return filepath.Clean(filepath.Join(am.pluginDir, fmt.Sprintf("%s.so", name)))
	case TypeConfig:
		var subPriority int32
		switch medium {
		case MediumInline:
			subPriority = priority.InLineRulesSubPriority
		case MediumConfigMap:
			subPriority = priority.CMSubPriority
		default:
			subPriority = priority.MaxPriority
		}
		return filepath.Clean(
			filepath.Join(
				am.configDir,
				priority.NameFromPriorityAndSubPriority(artifactPriority, subPriority, fmt.Sprintf("%s-%s.yaml", name, medium)),
			),
		)
	default:
		return priority.NameFromPriority(artifactPriority, name)
	}
}

// StoreFromInLineYaml stores an artifact from an inline YAML to the local filesystem.
func (am *Manager) StoreFromInLineYaml(ctx context.Context, name string, artifactPriority int32, data *string, artifactType Type) (StoreAction, error) {
	logger := log.FromContext(ctx)

	// If the data is nil, we remove the artifact from the manager and from filesystem.
	// It means that the instance has been updated and the artifact has been removed from the spec.
	if data == nil {
		// Get artifact from the manager.
		if file := am.getArtifactFile(name, MediumInline); file != nil {
			logger.Info("Removing artifact from filesystem", "artifact", file.Path)
			if err := am.removeArtifact(ctx, name, MediumInline); err != nil {
				logger.Error(err, "Failed to remove artifact from filesystem", "artifact", file.Path)
				return StoreActionNone, err
			}
			return StoreActionRemoved, nil
		}
		return StoreActionNone, nil
	}

	newFile := File{
		Path:     am.Path(name, artifactPriority, MediumInline, artifactType),
		Medium:   MediumInline,
		Priority: artifactPriority,
	}

	// wasUpdate tracks whether we replaced an existing file (vs writing a brand-new one).
	wasUpdate := false
	// priorityOnlyChange tracks whether only the priority changed (content is the same).
	priorityOnlyChange := false

	// Check if the artifact is already stored.
	if file := am.getArtifactFile(name, MediumInline); file != nil {
		logger.V(4).Info("Artifact already stored", "artifact", file)
		// Check if the file already exists on the filesystem.
		ok, err := am.fs.Exists(file.Path)
		if err != nil {
			logger.Error(err, "Failed to check if file exists", "file", file.Path)
			return StoreActionNone, err
		}
		// If the file exists we check if the priority has changed or the content has been updated.
		if ok {
			logger.V(4).Info("File already exists, checking if is up to date", "file", file.Path)
			// Read the file.
			content, err := am.fs.ReadFile(file.Path)
			if err != nil {
				logger.Error(err, "unable to read file", "file", file.Path)
				return StoreActionNone, err
			}
			contentSame := string(content) == *data
			// Check if the content is the same and the priority has not changed.
			if contentSame && file.Priority == artifactPriority {
				logger.V(3).Info("file is up to date", "file", file.Path)
				return StoreActionUnchanged, nil
			}

			priorityOnlyChange = contentSame && file.Priority != artifactPriority
			if priorityOnlyChange {
				logger.Info("Updating artifact file due to priority change",
					"oldPriority", file.Priority, "newPriority", artifactPriority, "oldFile", file.Path, "newFile", newFile.Path)
			} else {
				logger.Info("File is outdated, updating", "file", file.Path)
			}

			// Remove the old file before writing the new one.
			if err := am.fs.Remove(file.Path); err != nil {
				logger.Error(err, "unable to remove rulesfile", "file", file.Path)
				return StoreActionNone, err
			}
			// Remove the file from the manager.
			am.removeArtifactFile(name, MediumInline)
			wasUpdate = true
		} else {
			// The file is registered in the manager but missing from disk.
			// Clear the stale registration so addArtifactFile below does not create a duplicate entry.
			am.removeArtifactFile(name, MediumInline)
		}
	}

	// Write the raw YAML to the filesystem.
	if err := am.fs.WriteFile(newFile.Path, []byte(*data), 0o600); err != nil {
		logger.Error(err, "unable to write file", "file", newFile.Path)
		return StoreActionNone, err
	}

	// Add the artifact to the manager.
	am.addArtifactFile(name, newFile)
	logger.Info("file correctly written to filesystem", "file", newFile.Path)
	if wasUpdate {
		if priorityOnlyChange {
			return StoreActionPriorityChanged, nil
		}
		return StoreActionUpdated, nil
	}
	return StoreActionAdded, nil
}

// StoreFromOCI stores an artifact from an OCI registry to the local filesystem.
func (am *Manager) StoreFromOCI(ctx context.Context, name string, artifactPriority int32, artifactType Type, artifact *commonv1alpha1.OCIArtifact) (StoreAction, error) {
	logger := log.FromContext(ctx)

	// If the artifact is nil, we remove the artifact from the manager and from filesystem.
	// It means that the instance has been updated and the artifact has been removed from the spec.
	if artifact == nil {
		// Get artifact from the manager.
		if file := am.getArtifactFile(name, MediumOCI); file != nil {
			logger.Info("Removing artifact from filesystem", "artifact", file.Path)
			if err := am.removeArtifact(ctx, name, MediumOCI); err != nil {
				logger.Error(err, "Failed to remove artifact from filesystem", "artifact", file.Path)
				return StoreActionNone, err
			}
			return StoreActionRemoved, nil
		}
		return StoreActionNone, nil
	}
	newFile := File{
		Path:     am.Path(name, artifactPriority, MediumOCI, artifactType),
		Medium:   MediumOCI,
		Priority: artifactPriority,
	}

	// Check if the artifact is already stored.
	if file := am.getArtifactFile(name, MediumOCI); file != nil {
		logger.V(4).Info("Artifact already stored", "artifact", file)
		// Check if the file already exists on the filesystem.
		ok, err := am.fs.Exists(file.Path)
		if err != nil {
			logger.Error(err, "Failed to check if file exists", "file", file.Path)
			return StoreActionNone, err
		}
		// If the file exists and the priority has changed, we rename the file reflecting the new priority.
		if ok && file.Priority != artifactPriority {
			logger.Info("Renaming artifact file due to priority change",
				"oldPriority", file.Priority, "newPriority", artifactPriority, "oldFile", file.Path, "newFile", newFile.Path)
			if err := am.fs.Rename(file.Path, newFile.Path); err != nil {
				logger.Error(err, "Failed to rename file", "oldFile", file.Path, "newFile", newFile.Path)
				return StoreActionNone, err
			}
			am.removeArtifactFile(name, MediumOCI)
			am.addArtifactFile(name, newFile)
			return StoreActionPriorityChanged, nil
		}
		// If the file does not exist on the filesystem, we remove it from the manager and return an error.
		// Next time the artifact is requested, it will be fetched from the OCI registry.
		if !ok {
			am.removeArtifactFile(name, MediumOCI)
			err := fmt.Errorf("artifact %q not found on filesystem", file.Path)
			logger.Error(err, "Failed to find file on filesystem", "file", newFile.Path)
			return StoreActionNone, err
		}

		return StoreActionUnchanged, nil
	}

	var dstDir string
	switch artifactType {
	case TypeRulesfile:
		dstDir = am.rulesfileDir
	case TypePlugin:
		dstDir = mounts.PluginDirPath
	default:
		dstDir = ""
	}

	creds, registryOpts, err := am.resolvePullConfig(ctx, artifact)
	if err != nil {
		return StoreActionNone, err
	}

	ref := ResolveReference(artifact)
	logger.Info("Pulling OCI artifact", "reference", ref)
	res, err := am.ociPuller.Pull(ctx, ref, dstDir, runtime.GOOS, runtime.GOARCH, creds, registryOpts)
	if err != nil {
		logger.Error(err, "unable to pull artifact", "reference", ref)
		return StoreActionNone, err
	}
	if res == nil {
		return StoreActionNone, fmt.Errorf("puller returned nil result for reference %q", ref)
	}

	archiveFile := filepath.Clean(filepath.Join(dstDir, res.Filename))

	// Extract the rulesfile from the archive.
	f, err := am.fs.Open(archiveFile)
	if err != nil {
		return StoreActionNone, err
	}

	logger.V(4).Info("Extracting OCI artifact", "archive", archiveFile)

	// Extract artifact and move it to its destination directory
	files, err := common.ExtractTarGz(ctx, f, dstDir, 0)
	if err != nil {
		logger.Error(err, "unable to extract OCI artifact", "filename", archiveFile)
		return StoreActionNone, err
	}

	// Clean up the archive.
	if err = am.fs.Remove(archiveFile); err != nil {
		logger.Error(err, "unable to remove OCI artifact", "filename", archiveFile)
		return StoreActionNone, err
	}

	logger.V(4).Info("Writing OCI artifact", "filename", newFile.Path)
	// Rename the artifact to the generated name.
	if err = am.fs.Rename(files[0], newFile.Path); err != nil {
		logger.Error(err, "unable to rename artifact", "source", files[0], "destination", newFile.Path)
		return StoreActionNone, err
	}
	logger.Info("OCI artifact downloaded and saved", "artifact", newFile.Path)

	// Add the artifact to the manager.
	am.files[name] = append(am.files[name], newFile)

	return StoreActionAdded, nil
}

// InspectOCI fetches artifact metadata (type, config, digest information) for the OCI artifact.
func (am *Manager) InspectOCI(ctx context.Context, artifact *commonv1alpha1.OCIArtifact) (*puller.RegistryResult, error) {
	if artifact == nil {
		return nil, nil
	}
	return am.InspectFromReference(ctx, ResolveReference(artifact), artifact)
}

// InspectFromReference fetches artifact metadata for an explicit OCI reference using credentials/options
// sourced from the provided OCIArtifact registry config.
func (am *Manager) InspectFromReference(ctx context.Context, ref string, artifact *commonv1alpha1.OCIArtifact) (*puller.RegistryResult, error) {
	logger := log.FromContext(ctx)

	creds, registryOpts, err := am.resolvePullConfig(ctx, artifact)
	if err != nil {
		return nil, err
	}

	logger.V(4).Info("Inspecting OCI artifact", "reference", ref)
	res, err := am.ociPuller.Inspect(ctx, ref, runtime.GOOS, runtime.GOARCH, creds, registryOpts)
	if err != nil {
		logger.Error(err, "unable to inspect OCI artifact", "reference", ref)
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("puller returned nil result while inspecting reference %q", ref)
	}

	return res, nil
}

// StoreFromConfigMap stores an artifact from a ConfigMap to the local filesystem.
// The ConfigMap is fetched from the specified namespace (typically the same namespace as the Rulesfile CR).
func (am *Manager) StoreFromConfigMap(ctx context.Context, name, namespace string, artifactPriority int32, configMapRef *commonv1alpha1.ConfigMapRef, artifactType Type) (StoreAction, error) {
	logger := log.FromContext(ctx)

	// If the configMapRef is nil, we remove the artifact from the manager and from filesystem.
	// It means that the instance has been updated and the artifact has been removed from the spec.
	if configMapRef == nil {
		// Get artifact from the manager.
		if file := am.getArtifactFile(name, MediumConfigMap); file != nil {
			logger.Info("Removing artifact from filesystem", "artifact", file.Path)
			if err := am.removeArtifact(ctx, name, MediumConfigMap); err != nil {
				logger.Error(err, "Failed to remove artifact from filesystem", "artifact", file.Path)
				return StoreActionNone, err
			}
			return StoreActionRemoved, nil
		}
		return StoreActionNone, nil
	}

	newFile := File{
		Path:     am.Path(name, artifactPriority, MediumConfigMap, artifactType),
		Medium:   MediumConfigMap,
		Priority: artifactPriority,
	}

	// Fetch the ConfigMap from the same namespace as the artifact CR.
	configMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Name:      configMapRef.Name,
		Namespace: namespace,
	}

	if err := am.client.Get(ctx, configMapKey, configMap); err != nil {
		// If ConfigMap not found, remove the artifact file from filesystem if it exists.
		// This is an expected state when user deletes the ConfigMap or the ConfigMap is in a different namespace, not a failure.
		filePath := am.Path(name, artifactPriority, MediumConfigMap, artifactType)
		removed := false
		if exists, _ := am.fs.Exists(filePath); exists {
			logger.Info("ConfigMap not found, removing artifact from filesystem", "configMap", configMapRef.Name, "artifact", filePath)
			if removeErr := am.fs.Remove(filePath); removeErr != nil {
				logger.Error(removeErr, "Failed to remove artifact from filesystem", "artifact", filePath)
				return StoreActionNone, removeErr
			}
			am.removeArtifactFile(name, MediumConfigMap)
			removed = true
		}
		// Don't return error for "not found" - the ConfigMap was likely deleted intentionally.
		// The watch will trigger reconciliation when it's recreated.
		if k8serrors.IsNotFound(err) {
			logger.V(3).Info("ConfigMap not found, artifact cleaned up", "configMap", configMapRef.Name)
			if removed {
				return StoreActionRemoved, nil
			}
			return StoreActionNone, nil
		}
		// Return other errors (network issues, permission errors, etc.)
		logger.Error(err, "Failed to get ConfigMap", "configMap", configMapRef.Name)
		return StoreActionNone, err
	}

	// Get the data from the ConfigMap using the key appropriate for the artifact type.
	var dataKey string
	switch artifactType {
	case TypeConfig:
		dataKey = commonv1alpha1.ConfigMapConfigKey
	case TypeRulesfile:
		dataKey = commonv1alpha1.ConfigMapRulesKey
	default:
		return StoreActionNone, fmt.Errorf("unsupported artifact type for ConfigMap store: %q", artifactType)
	}
	data, ok := configMap.Data[dataKey]
	if !ok {
		// ConfigMap exists but doesn't have the expected key - this is a user misconfiguration.
		// Remove any existing artifact and log a warning (not error to avoid log spam).
		filePath := am.Path(name, artifactPriority, MediumConfigMap, artifactType)
		if exists, _ := am.fs.Exists(filePath); exists {
			logger.Info("ConfigMap key not found, removing artifact from filesystem",
				"configMap", configMapRef.Name, "expectedKey", dataKey, "artifact", filePath)
			if removeErr := am.fs.Remove(filePath); removeErr != nil {
				logger.Error(removeErr, "Failed to remove artifact from filesystem", "artifact", filePath)
				return StoreActionNone, removeErr
			}
			am.removeArtifactFile(name, MediumConfigMap)
			// Don't return error - user needs to fix the ConfigMap, retrying won't help.
			// The watch will trigger reconciliation when ConfigMap is updated.
			return StoreActionRemoved, nil
		}
		logger.Info("ConfigMap missing expected key",
			"configMap", configMapRef.Name, "expectedKey", dataKey)
		return StoreActionNone, nil
	}

	// wasUpdate tracks whether we replaced an existing file (vs writing a brand-new one).
	wasUpdate := false
	// priorityOnlyChange tracks whether only the priority changed (content is the same).
	priorityOnlyChange := false

	// Check if the artifact is already stored.
	if file := am.getArtifactFile(name, MediumConfigMap); file != nil {
		logger.V(4).Info("Artifact already stored", "artifact", file)
		// Check if the file already exists on the filesystem.
		ok, err := am.fs.Exists(file.Path)
		if err != nil {
			logger.Error(err, "Failed to check if file exists", "file", file.Path)
			return StoreActionNone, err
		}
		// If the file exists we check if the priority has changed or the content has been updated.
		if ok {
			logger.V(4).Info("File already exists, checking if is up to date", "file", file.Path)
			// Read the file.
			content, err := am.fs.ReadFile(file.Path)
			if err != nil {
				logger.Error(err, "unable to read file", "file", file.Path)
				return StoreActionNone, err
			}
			contentSame := string(content) == data
			// Check if the content is the same and the priority has not changed.
			if contentSame && file.Priority == artifactPriority {
				logger.V(3).Info("file is up to date", "file", file.Path)
				return StoreActionUnchanged, nil
			}

			priorityOnlyChange = contentSame && file.Priority != artifactPriority
			if priorityOnlyChange {
				logger.Info("Updating artifact file due to priority change",
					"oldPriority", file.Priority, "newPriority", artifactPriority, "oldFile", file.Path, "newFile", newFile.Path)
			} else {
				logger.Info("File is outdated, updating", "file", file.Path)
			}

			// Remove the old file before writing the new one.
			if err := am.fs.Remove(file.Path); err != nil {
				logger.Error(err, "unable to remove file", "file", file.Path)
				return StoreActionNone, err
			}
			// Remove the file from the manager.
			am.removeArtifactFile(name, MediumConfigMap)
			wasUpdate = true
		} else {
			// The file is registered in the manager but missing from disk.
			// Clear the stale registration so addArtifactFile below does not create a duplicate entry.
			am.removeArtifactFile(name, MediumConfigMap)
		}
	}

	// Write the data to the filesystem.
	if err := am.fs.WriteFile(newFile.Path, []byte(data), 0o600); err != nil {
		logger.Error(err, "unable to write file", "file", newFile.Path)
		return StoreActionNone, err
	}

	// Add the artifact to the manager.
	am.addArtifactFile(name, newFile)
	logger.Info("ConfigMap data correctly written to filesystem", "file", newFile.Path, "configMap", configMapRef.Name)
	if wasUpdate {
		if priorityOnlyChange {
			return StoreActionPriorityChanged, nil
		}
		return StoreActionUpdated, nil
	}
	return StoreActionAdded, nil
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
			if err := am.fs.Remove(file.Path); err != nil {
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
		if err := am.fs.Remove(file.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Error(err, "unable to remove artifact", "file", file.Path)
			return err
		}
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
			files[i] = files[len(files)-1]
			files = files[:len(files)-1]
			if len(files) == 0 {
				delete(am.files, name)
			} else {
				am.files[name] = files
			}
			return
		}
	}
}

// CheckReferenceResolution checks if a specific Kubernetes resource exists.
// Returns an error if the resource does not exist or cannot be retrieved.
func (am *Manager) CheckReferenceResolution(ctx context.Context, namespace, name string, obj client.Object) error {
	logger := log.FromContext(ctx)

	key := client.ObjectKey{
		Name:      name,
		Namespace: namespace,
	}

	if err := am.client.Get(ctx, key, obj); err != nil {
		logger.Error(err, "Failed to get resource", "name", name, "namespace", namespace)
		return err
	}

	return nil
}

func (am *Manager) resolvePullConfig(ctx context.Context, artifact *commonv1alpha1.OCIArtifact) (auth.CredentialFunc, *puller.RegistryOptions, error) {
	logger := log.FromContext(ctx)

	// Resolve auth credentials.
	var authSecretRef *commonv1alpha1.SecretRef
	if artifact != nil && artifact.Registry != nil && artifact.Registry.Auth != nil {
		authSecretRef = artifact.Registry.Auth.SecretRef
	}

	logger.V(4).Info("Getting credentials from auth secret ref", "authSecretRef", authSecretRef)
	creds, err := credentials.GetCredentialsFromSecret(ctx, am.client, am.namespace, authSecretRef)
	if err != nil {
		logger.Error(err, "unable to get credentials for the OCI artifact", "authSecretRef", authSecretRef)
		return nil, nil, err
	}

	// Resolve registry TLS options.
	registryOpts := ResolveRegistryOptions(artifact)

	return creds, registryOpts, nil
}
