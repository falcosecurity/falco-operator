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
	"strings"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

const (
	// DefaultRegistry is the default OCI registry hostname.
	DefaultRegistry = "ghcr.io"
)

// ResolveReference builds the full OCI reference string from an OCIArtifact.
// Defaults to "ghcr.io" when no registry name is specified and "latest" when no tag is set.
func ResolveReference(artifact *commonv1alpha1.OCIArtifact) string {
	ref := ResolveRegistryHost(artifact) + "/" + artifact.Image.Repository

	tag := artifact.Image.Tag
	if tag == "" {
		tag = "latest"
	}

	if strings.HasPrefix(tag, "sha256:") {
		ref += "@" + tag
	} else {
		ref += ":" + tag
	}

	return ref
}

// ResolveRegistryHost returns the registry hostname used for an OCIArtifact.
func ResolveRegistryHost(artifact *commonv1alpha1.OCIArtifact) string {
	if artifact != nil && artifact.Registry != nil && artifact.Registry.Name != "" {
		return artifact.Registry.Name
	}
	return DefaultRegistry
}

func authSecretRefName(artifact *commonv1alpha1.OCIArtifact) string {
	ref := authSecretRef(artifact)
	if ref == nil {
		return ""
	}
	return ref.Name
}

func authSecretRef(artifact *commonv1alpha1.OCIArtifact) *commonv1alpha1.SecretRef {
	if artifact == nil || artifact.Registry == nil || artifact.Registry.Auth == nil {
		return nil
	}
	return artifact.Registry.Auth.SecretRef
}

// ResolveRegistryOptions builds a RegistryOptions from the registry configuration of an OCIArtifact.
// Returns nil when no transport configuration is present (use system defaults: HTTPS with system CAs).
func ResolveRegistryOptions(artifact *commonv1alpha1.OCIArtifact) *puller.RegistryOptions {
	if artifact == nil || artifact.Registry == nil {
		return nil
	}

	reg := artifact.Registry

	// plainHTTP and tls are mutually exclusive (enforced by CEL validation).
	if reg.PlainHTTP != nil && *reg.PlainHTTP {
		return &puller.RegistryOptions{
			PlainHTTP: true,
		}
	}

	if reg.TLS != nil {
		return &puller.RegistryOptions{
			InsecureSkipVerify: reg.TLS.InsecureSkipVerify,
		}
	}

	return nil
}
