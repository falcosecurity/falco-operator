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
			mockPuller := &puller.MockOCIPuller{
				ContentResult:   tt.contentResult,
				FetchContentErr: tt.fetchContentErr,
			}
			manager := NewManagerWithOptions(builder.Build(), namespace,
				WithOCIPuller(mockPuller),
			)

			got, err := manager.FetchContent(context.Background(), tt.ociArtifact)
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
