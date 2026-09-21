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

package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func TestValidateMethod(t *testing.T) {
	t.Run("clientSecret: passes when every required field is present", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientSecret, ClientSecretRef: &commonv1alpha1.SecretRef{Name: "s"}}
		assert.NoError(t, validateMethod(cfg, "tenant", "client"))
	})

	t.Run("clientSecret: reports every missing field at once, not just the first", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientSecret}

		err := validateMethod(cfg, "" /* tenantID */, "" /* clientID */)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenantId (config) or AZURE_TENANT_ID (environment variable) is required for method clientSecret")
		assert.Contains(t, err.Error(), "clientId (config) or AZURE_CLIENT_ID (environment variable) is required for method clientSecret")
		assert.Contains(t, err.Error(), "clientSecretRef (config) or AZURE_CLIENT_SECRET (environment variable) is required for method clientSecret")
	})

	t.Run("clientCertificate: passes when every required field is present", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientCertificate, ClientCertificateRef: &commonv1alpha1.SecretRef{Name: "s"}}
		assert.NoError(t, validateMethod(cfg, "tenant", "client"))
	})

	t.Run("clientCertificate: reports every missing field at once", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientCertificate}

		err := validateMethod(cfg, "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenantId (config) or AZURE_TENANT_ID (environment variable) is required for method clientCertificate")
		assert.Contains(t, err.Error(), "clientId (config) or AZURE_CLIENT_ID (environment variable) is required for method clientCertificate")
		assert.Contains(t, err.Error(), "clientCertificateRef (config) or AZURE_CLIENT_CERTIFICATE_PATH (environment variable) is required for method clientCertificate")
	})

	t.Run("managedIdentity: nothing is required, even with empty tenantId/clientId", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodManagedIdentity}
		assert.NoError(t, validateMethod(cfg, "", ""))
	})

	t.Run("workloadIdentity: passes when every required field is present", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodWorkloadIdentity, ServiceAccountRef: &corev1.LocalObjectReference{Name: "sa"}}
		assert.NoError(t, validateMethod(cfg, "tenant", "client"))
	})

	t.Run("workloadIdentity: reports every missing field at once, serviceAccountRef included", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodWorkloadIdentity}

		err := validateMethod(cfg, "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenantId (config) or AZURE_TENANT_ID (environment variable) is required for method workloadIdentity")
		assert.Contains(t, err.Error(), "clientId (config) or AZURE_CLIENT_ID (environment variable) is required for method workloadIdentity")
		assert.Contains(t, err.Error(), "serviceAccountRef is required for method workloadIdentity")
		assert.Contains(t, err.Error(), "no environment variable fallback")
	})

	t.Run("workloadIdentity: serviceAccountRef alone is still reported when tenantId/clientId are present", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodWorkloadIdentity}

		err := validateMethod(cfg, "tenant", "client")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "tenantId (config)")
		assert.NotContains(t, err.Error(), "clientId (config)")
		assert.Contains(t, err.Error(), "serviceAccountRef is required")
	})

	t.Run("unsupported method", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: "somethingElse"}

		err := validateMethod(cfg, "tenant", "client")
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unsupported azure auth method "somethingElse"`)
	})
}
