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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime"

	corev1 "k8s.io/api/core/v1"
	"oras.land/oras-go/v2/registry/remote/auth"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

func (am *Manager) fetchOCIAuthSecret(ctx context.Context, ref *commonv1alpha1.SecretRef) (*corev1.Secret, error) {
	if ref == nil {
		return nil, nil
	}

	secret := &corev1.Secret{}
	key := client.ObjectKey{Name: ref.Name, Namespace: am.namespace}
	if err := am.client.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("failed to get pull secret %s: %w", ref.Name, err)
	}
	return secret, nil
}

func (am *Manager) getCurrentOCIFile(ctx context.Context, name string) (*File, error) {
	logger := log.FromContext(ctx)
	file := am.getArtifactFile(name, MediumOCI)
	if file == nil {
		return nil, nil
	}

	ok, err := am.fs.Exists(file.Path)
	if err != nil {
		logger.Error(err, "Failed to check if file exists", "file", file.Path)
		return nil, err
	}
	if !ok {
		am.removeArtifactFile(name, MediumOCI)
		err := fmt.Errorf("artifact %q not found on filesystem", file.Path)
		logger.Error(err, "Failed to find file on filesystem", "file", file.Path)
		return nil, err
	}

	current := *file
	return &current, nil
}

func (am *Manager) pullOCIFile(ctx context.Context, ref string, artifactType Type, artifact *commonv1alpha1.OCIArtifact, creds auth.CredentialFunc) (common.ExtractedFile, error) {
	var compressed bytes.Buffer
	res, err := am.ociPuller.Pull(ctx, ref, runtime.GOOS, runtime.GOARCH, creds, ResolveRegistryOptions(artifact), &compressed)
	if err != nil {
		return common.ExtractedFile{}, err
	}
	if res == nil {
		return common.ExtractedFile{}, fmt.Errorf("puller returned nil result for reference %q", ref)
	}
	if !isExpectedOCIArtifactType(artifactType, res.Type) {
		return common.ExtractedFile{}, fmt.Errorf("pulled OCI artifact type %q does not match expected type %q", res.Type, artifactType)
	}

	file, err := common.ExtractSingleFileFromTarGz(ctx, &compressed, 0)
	if err != nil {
		return common.ExtractedFile{}, err
	}
	return file, nil
}

func isExpectedOCIArtifactType(expected Type, actual puller.ArtifactType) bool {
	switch expected {
	case TypeRulesfile:
		return actual == puller.Rulesfile
	case TypePlugin:
		return actual == puller.Plugin
	default:
		return false
	}
}

func (am *Manager) removeReplacedOCIFile(ctx context.Context, oldFile *File, newPath string) error {
	if oldFile == nil || oldFile.Path == newPath {
		return nil
	}

	logger := log.FromContext(ctx)
	if err := am.fs.Remove(oldFile.Path); err != nil {
		logger.Error(err, "unable to remove previous artifact at old path", "oldFile", oldFile.Path)
		if rollbackErr := am.fs.Remove(newPath); rollbackErr != nil && !errors.Is(rollbackErr, fs.ErrNotExist) {
			logger.Error(rollbackErr, "unable to roll back newly installed artifact", "file", newPath)
			return fmt.Errorf("remove previous artifact %q: %w; rollback new artifact %q: %w", oldFile.Path, err, newPath, rollbackErr)
		}
		return fmt.Errorf("remove previous artifact %q: %w", oldFile.Path, err)
	}
	return nil
}

func (am *Manager) installOCIFile(ctx context.Context, path string, file common.ExtractedFile) error {
	logger := log.FromContext(ctx)
	tmpPath := path + ".tmp"

	if err := am.fs.WriteFile(tmpPath, file.Content, file.Perm); err != nil {
		logger.Error(err, "unable to write artifact temp file", "file", tmpPath)
		if removeErr := am.fs.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			logger.Error(removeErr, "unable to remove leftover temp file", "file", tmpPath)
		}
		return err
	}

	if err := am.fs.Rename(tmpPath, path); err != nil {
		logger.Error(err, "unable to rename temp artifact to final path", "tmp", tmpPath, "final", path)
		if removeErr := am.fs.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			logger.Error(removeErr, "unable to remove leftover temp file", "file", tmpPath)
		}
		return err
	}
	return nil
}
