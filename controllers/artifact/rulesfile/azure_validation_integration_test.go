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

package rulesfile

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
)

// These exercise the CRD's own XValidation rule on AzureAuth (api/common/v1alpha1/types.go) --
// "serviceAccountRef.name is required when method is workloadIdentity" -- against the real
// envtest API server started by TestMain in controller_integration_test.go. This is admission-time
// enforcement, upstream of and independent from the Go-level checks in
// internal/pkg/credentials/azure.validateMethod (which are covered by that package's own unit
// tests): a misconfigured CR should never reach a reconcile loop at all.
func azureRulesfile(name string, azure *commonv1alpha1.AzureAuth) *artifactv1alpha1.Rulesfile {
	return &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.RulesfileSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "example/rules"},
				Registry: &commonv1alpha1.RegistryConfig{
					Name: "example.azurecr.io",
					Auth: &commonv1alpha1.RegistryAuth{Azure: azure},
				},
			},
		},
	}
}

func TestIntegration_Rulesfile_AzureWorkloadIdentity_RejectsMissingServiceAccountRef(t *testing.T) {
	ctx := context.Background()
	rf := azureRulesfile("azure-workload-identity-no-sa", &commonv1alpha1.AzureAuth{
		Method:   commonv1alpha1.AzureMethodWorkloadIdentity,
		TenantID: "11111111-1111-1111-1111-111111111111",
		ClientID: "22222222-2222-2222-2222-222222222222",
	})

	err := k8sClient.Create(ctx, rf)
	require.Error(t, err, "the API server must reject a workloadIdentity AzureAuth with no serviceAccountRef")
	require.True(t, k8serrors.IsInvalid(err), "expected a CRD validation (Invalid) error, got: %v", err)
	require.Contains(t, err.Error(), "serviceAccountRef.name is required when method is workloadIdentity")
}

func TestIntegration_Rulesfile_AzureWorkloadIdentity_RejectsEmptyServiceAccountRefName(t *testing.T) {
	ctx := context.Background()
	rf := azureRulesfile("azure-workload-identity-empty-sa-name", &commonv1alpha1.AzureAuth{
		Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
		TenantID:          "11111111-1111-1111-1111-111111111111",
		ClientID:          "22222222-2222-2222-2222-222222222222",
		ServiceAccountRef: &corev1.LocalObjectReference{Name: ""},
	})

	err := k8sClient.Create(ctx, rf)
	require.Error(t, err, "a present-but-empty serviceAccountRef.name must not satisfy the CEL rule's has() check")
	require.True(t, k8serrors.IsInvalid(err), "expected a CRD validation (Invalid) error, got: %v", err)
	require.Contains(t, err.Error(), "serviceAccountRef.name is required when method is workloadIdentity")
}

func TestIntegration_Rulesfile_AzureWorkloadIdentity_AcceptsValidConfig(t *testing.T) {
	ctx := context.Background()
	rf := azureRulesfile("azure-workload-identity-valid", &commonv1alpha1.AzureAuth{
		Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
		TenantID:          "11111111-1111-1111-1111-111111111111",
		ClientID:          "22222222-2222-2222-2222-222222222222",
		ServiceAccountRef: &corev1.LocalObjectReference{Name: "registry-federator"},
	})

	createRulesfile(t, ctx, rf)
}

// A non-workloadIdentity method must never be blocked by this rule -- the CEL expression's
// self.method != 'workloadIdentity' short-circuit is the only thing standing between "every
// AzureAuth requires serviceAccountRef" and "only workloadIdentity does".
func TestIntegration_Rulesfile_AzureManagedIdentity_DoesNotRequireServiceAccountRef(t *testing.T) {
	ctx := context.Background()
	rf := azureRulesfile("azure-managed-identity-no-sa", &commonv1alpha1.AzureAuth{
		Method: commonv1alpha1.AzureMethodManagedIdentity,
	})

	createRulesfile(t, ctx, rf)
}
