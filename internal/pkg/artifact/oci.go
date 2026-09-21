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
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"oras.land/oras-go/v2/registry/remote/auth"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/credentials"
	"github.com/falcosecurity/falco-operator/internal/pkg/credentials/azure"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// ComputeOCIArtifactSpecHash returns the SHA-256 hex digest of the JSON-marshaled OCIArtifact spec.
// A change in the hash signals that the spec changed and any cached config must be re-fetched.
func ComputeOCIArtifactSpecHash(ociArtifact *commonv1alpha1.OCIArtifact) (string, error) {
	data, err := json.Marshal(ociArtifact)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// ArtifactMetaCacheHit reports whether cached is still valid for the given specHash.
// The check is purely in-memory: a hit requires cached to be non-nil and its SpecHash to
// equal specHash. The registry is never consulted; to pick up a new image pushed to the
// same tag, users must change the OCIArtifact spec (e.g. pin a new digest or bump the tag),
// which bumps Generation and invalidates the spec hash.
func ArtifactMetaCacheHit(cached *commonv1alpha1.ArtifactMeta, specHash string) bool {
	return cached != nil && cached.SpecHash == specHash
}

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

func (am *Manager) fetchOCICredentials(ctx context.Context, ociArtifact *commonv1alpha1.OCIArtifact) (auth.CredentialFunc, error) {
	if azureCfg := authAzure(ociArtifact); azureCfg != nil {
		creds, err := azure.CredentialFunc(am.client, am.namespace, azureCfg)
		if err != nil {
			return nil, fmt.Errorf("derive azure credentials: %w", err)
		}
		return creds, nil
	}

	secret, err := am.fetchOCIAuthSecret(ctx, authSecretRef(ociArtifact))
	if err != nil {
		return nil, fmt.Errorf("fetch auth secret: %w", err)
	}
	creds, err := credentials.FromSecret(ResolveRegistryHost(ociArtifact), secret)
	if err != nil {
		return nil, fmt.Errorf("derive credentials: %w", err)
	}
	return creds, nil
}
