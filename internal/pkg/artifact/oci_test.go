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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	pullerfake "github.com/falcosecurity/falco-operator/internal/pkg/oci/puller/fake"
)

func TestFetchOCIAuthSecret(t *testing.T) {
	const namespace = "test-namespace"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: namespace},
	}

	tests := []struct {
		name     string
		objects  []client.Object
		ref      *commonv1alpha1.SecretRef
		wantName string
		wantErr  string
	}{
		{
			name: "returns nil when reference is nil",
		},
		{
			name:     "returns referenced secret",
			objects:  []client.Object{secret},
			ref:      &commonv1alpha1.SecretRef{Name: "pull-secret"},
			wantName: "pull-secret",
		},
		{
			name:    "returns error when secret is missing",
			ref:     &commonv1alpha1.SecretRef{Name: "missing"},
			wantErr: "failed to get pull secret missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(createTestScheme(t))
			if len(tt.objects) > 0 {
				builder = builder.WithObjects(tt.objects...)
			}
			manager := NewManager(builder.Build(), namespace)

			got, err := manager.fetchOCIAuthSecret(context.Background(), tt.ref)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			if tt.wantName == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantName, got.Name)
		})
	}
}

func TestFetchOCICredentials(t *testing.T) {
	const namespace = "test-namespace"

	t.Run("dispatches to secretRef when azure is not set", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: namespace},
			Data: map[string][]byte{
				commonv1alpha1.SecretUsernameKey: []byte("user"),
				commonv1alpha1.SecretPasswordKey: []byte("pass"),
			},
		}
		manager := NewManager(fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build(), namespace)
		ociArtifact := &commonv1alpha1.OCIArtifact{
			Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"},
			Registry: &commonv1alpha1.RegistryConfig{
				Auth: &commonv1alpha1.RegistryAuth{SecretRef: &commonv1alpha1.SecretRef{Name: "pull-secret"}},
			},
		}

		credFunc, err := manager.fetchOCICredentials(context.Background(), ociArtifact)
		require.NoError(t, err)
		cred, err := credFunc(context.Background(), "ghcr.io")
		require.NoError(t, err)
		assert.Equal(t, "user", cred.Username)
		assert.Equal(t, "pass", cred.Password)
	})

	t.Run("dispatches to azure when set, ignoring any secretRef", func(t *testing.T) {
		manager := NewManager(fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build(), namespace)
		ociArtifact := &commonv1alpha1.OCIArtifact{
			Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"},
			Registry: &commonv1alpha1.RegistryConfig{
				Auth: &commonv1alpha1.RegistryAuth{
					// Both set: Azure must win, per fetchOCICredentials checking Azure first
					// (the CRD's own CEL validation forbids this combination in practice, but
					// the Go dispatch order is worth pinning down independently of that).
					SecretRef: &commonv1alpha1.SecretRef{Name: "should-not-be-used"},
					Azure:     &commonv1alpha1.AzureAuth{Method: "unsupportedForThisTest"},
				},
			},
		}

		// azure.CredentialFunc only validates cfg != nil eagerly; the method-specific
		// resolution (and its errors) happen when the returned CredentialFunc is actually
		// invoked, matching how oras-go itself calls it.
		credFunc, err := manager.fetchOCICredentials(context.Background(), ociArtifact)
		require.NoError(t, err)

		_, err = credFunc(context.Background(), "myregistry.azurecr.io")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolve azure credential")
		assert.NotContains(t, err.Error(), "should-not-be-used")
	})
}

func TestIsExpectedOCIArtifactType(t *testing.T) {
	tests := []struct {
		name     string
		expected Type
		actual   puller.ArtifactType
		want     bool
	}{
		{name: "rulesfile matches", expected: TypeRulesfile, actual: puller.Rulesfile, want: true},
		{name: "plugin matches", expected: TypePlugin, actual: puller.Plugin, want: true},
		{name: "rulesfile rejects plugin", expected: TypeRulesfile, actual: puller.Plugin},
		{name: "plugin rejects rulesfile", expected: TypePlugin, actual: puller.Rulesfile},
		{name: "unsupported expected type", expected: TypeConfig, actual: puller.Rulesfile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isExpectedOCIArtifactType(tt.expected, tt.actual))
		})
	}
}

func TestFetchContent(t *testing.T) {
	const namespace = "test-namespace"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: namespace},
		Data: map[string][]byte{
			commonv1alpha1.SecretUsernameKey: []byte("user"),
			commonv1alpha1.SecretPasswordKey: []byte("pass"),
		},
	}

	tests := []struct {
		name            string
		objects         []client.Object
		ociArtifact     *commonv1alpha1.OCIArtifact
		contentResult   []byte
		fetchContentErr error
		wantErr         string
		wantContent     []byte
	}{
		{
			name:          "returns content bytes from puller",
			ociArtifact:   &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
			contentResult: []byte("- rule: test\n"),
			wantContent:   []byte("- rule: test\n"),
		},
		{
			name:            "propagates puller FetchContent error",
			ociArtifact:     &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
			fetchContentErr: fmt.Errorf("registry unavailable"),
			wantErr:         "registry unavailable",
		},
		{
			name: "returns error when auth secret is missing",
			ociArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"},
				Registry: &commonv1alpha1.RegistryConfig{
					Auth: &commonv1alpha1.RegistryAuth{SecretRef: &commonv1alpha1.SecretRef{Name: "missing-secret"}},
				},
			},
			wantErr: "missing-secret",
		},
		{
			name:    "succeeds with auth secret present",
			objects: []client.Object{secret},
			ociArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"},
				Registry: &commonv1alpha1.RegistryConfig{
					Auth: &commonv1alpha1.RegistryAuth{SecretRef: &commonv1alpha1.SecretRef{Name: "pull-secret"}},
				},
			},
			contentResult: []byte("rules-content"),
			wantContent:   []byte("rules-content"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(createTestScheme(t))
			if len(tt.objects) > 0 {
				builder = builder.WithObjects(tt.objects...)
			}
			mockPuller := &pullerfake.MockOCIPuller{
				ContentResult:   tt.contentResult,
				FetchContentErr: tt.fetchContentErr,
			}
			manager := NewManagerWithOptions(builder.Build(), namespace,
				WithOCIPuller(mockPuller),
			)

			got, err := manager.FetchContent(context.Background(), tt.ociArtifact, testDigest)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantContent, got)
		})
	}
}

func TestArtifactMetaCacheHit(t *testing.T) {
	t.Run("nil cached is a miss", func(t *testing.T) {
		assert.False(t, ArtifactMetaCacheHit(nil, "hash-1"))
	})

	t.Run("spec hash mismatch is a miss", func(t *testing.T) {
		cached := &commonv1alpha1.ArtifactMeta{SpecHash: "hash-old", Digest: "sha256:current"}
		assert.False(t, ArtifactMetaCacheHit(cached, "hash-new"))
	})

	t.Run("spec hash matches is a hit regardless of stored digest", func(t *testing.T) {
		cached := &commonv1alpha1.ArtifactMeta{SpecHash: "hash-1", Digest: "sha256:old"}
		assert.True(t, ArtifactMetaCacheHit(cached, "hash-1"))
	})
}
