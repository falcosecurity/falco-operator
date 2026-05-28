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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func TestComputeOCISourceSignatureNormalizesDefaults(t *testing.T) {
	implicitDefaults := &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{Repository: "falcosecurity/rules/falco-rules"},
	}
	explicitDefaults := &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{
			Repository: "falcosecurity/rules/falco-rules",
			Tag:        "latest",
		},
		Registry: &commonv1alpha1.RegistryConfig{
			Name:      DefaultRegistry,
			PlainHTTP: new(false),
			TLS:       &commonv1alpha1.TLSConfig{},
		},
	}

	assert.Equal(t,
		computeOCISourceSignature(implicitDefaults, nil),
		computeOCISourceSignature(explicitDefaults, nil),
	)
}

func TestComputeOCISourceSignatureUsesSecretDataOnly(t *testing.T) {
	artifact := &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "v1"},
		Registry: &commonv1alpha1.RegistryConfig{
			Auth: &commonv1alpha1.RegistryAuth{
				SecretRef: &commonv1alpha1.SecretRef{Name: "pull-secret"},
			},
		},
	}
	secret := pullSecret("pull-secret", "user", "password")
	sameDataDifferentMetadata := secret.DeepCopy()
	sameDataDifferentMetadata.ResourceVersion = "2"
	sameDataDifferentMetadata.Labels = map[string]string{"rotated-at": "metadata-only"}

	rotated := pullSecret("pull-secret", "user", "new-password")

	assert.Equal(t,
		computeOCISourceSignature(artifact, secret),
		computeOCISourceSignature(artifact, sameDataDifferentMetadata),
	)
	assert.NotEqual(t,
		computeOCISourceSignature(artifact, secret),
		computeOCISourceSignature(artifact, rotated),
	)
}

func pullSecret(name, username, password string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Data: map[string][]byte{
			commonv1alpha1.SecretUsernameKey: []byte(username),
			commonv1alpha1.SecretPasswordKey: []byte(password),
		},
	}
}
