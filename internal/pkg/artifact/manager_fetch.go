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

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/credentials"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// FetchConfig fetches the OCI artifact config layer for ociArtifact without downloading the binary.
// It returns the parsed ArtifactConfig (which contains plugin requirements) and the root manifest digest.
func (am *Manager) FetchConfig(ctx context.Context, ociArtifact *commonv1alpha1.OCIArtifact) (*puller.ArtifactConfig, string, error) {
	secretRef := authSecretRef(ociArtifact)
	authSecret, err := am.fetchOCIAuthSecret(ctx, secretRef)
	if err != nil {
		return nil, "", fmt.Errorf("fetch auth secret: %w", err)
	}
	creds, err := credentials.FromSecret(ResolveRegistryHost(ociArtifact), authSecret)
	if err != nil {
		return nil, "", fmt.Errorf("derive credentials: %w", err)
	}
	ref := ResolveReference(ociArtifact)
	return am.ociPuller.FetchConfig(ctx, ref, creds, ResolveRegistryOptions(ociArtifact))
}

// FetchContent downloads the artifact content layer for ociArtifact and returns the extracted file bytes.
func (am *Manager) FetchContent(ctx context.Context, ociArtifact *commonv1alpha1.OCIArtifact) ([]byte, error) {
	secretRef := authSecretRef(ociArtifact)
	authSecret, err := am.fetchOCIAuthSecret(ctx, secretRef)
	if err != nil {
		return nil, fmt.Errorf("fetch auth secret: %w", err)
	}
	creds, err := credentials.FromSecret(ResolveRegistryHost(ociArtifact), authSecret)
	if err != nil {
		return nil, fmt.Errorf("derive credentials: %w", err)
	}
	ref := ResolveReference(ociArtifact)
	return am.ociPuller.FetchContent(ctx, ref, creds, ResolveRegistryOptions(ociArtifact))
}
