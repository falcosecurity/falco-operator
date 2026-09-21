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
	"errors"
	"fmt"
	"os"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// validateMethod checks that every field cfg.Method requires is present, from config or its
// environment variable fallback, before resolveCredential does any actual work (a Secret fetch,
// an IMDS round trip, or minting a ServiceAccount token) -- "validate eagerly, as explicit code"
// rather than discovering one missing field, fixing it, and hitting the next. tenantID and
// clientID are passed in already resolved (config-or-environment) so this doesn't recompute
// them or re-read the environment for values resolveCredential already has.
//
// Every problem found is joined into one error via errors.Join, not just the first, so a
// misconfigured CR reports everything wrong with it in one shot -- fixing them one at a time
// via repeated apply/observe/fix cycles is exactly the friction this avoids.
func validateMethod(cfg *commonv1alpha1.AzureAuth, tenantID, clientID string) error {
	var errs []error
	require := func(configField, envVar, resolved string) {
		if err := requireForMethod(cfg.Method, configField, envVar, resolved); err != nil {
			errs = append(errs, err)
		}
	}

	switch cfg.Method {
	case commonv1alpha1.AzureMethodClientSecret:
		require("tenantId", envTenantID, tenantID)
		require("clientId", envClientID, clientID)
		if cfg.ClientSecretRef == nil && os.Getenv(envClientSecret) == "" {
			errs = append(errs, fmt.Errorf("clientSecretRef (config) or %s (environment variable) is required for method clientSecret", envClientSecret))
		}

	case commonv1alpha1.AzureMethodClientCertificate:
		require("tenantId", envTenantID, tenantID)
		require("clientId", envClientID, clientID)
		if cfg.ClientCertificateRef == nil && os.Getenv(envClientCertificatePath) == "" {
			errs = append(errs, fmt.Errorf("clientCertificateRef (config) or %s (environment variable) is required for method clientCertificate", envClientCertificatePath))
		}

	case commonv1alpha1.AzureMethodManagedIdentity:
		// Nothing required: tenantId is unused (IMDS resolves it), and clientId is genuinely
		// optional (its absence means system-assigned, not a missing value).

	case commonv1alpha1.AzureMethodWorkloadIdentity:
		require("tenantId", envTenantID, tenantID)
		require("clientId", envClientID, clientID)
		if cfg.ServiceAccountRef == nil {
			errs = append(errs, fmt.Errorf("serviceAccountRef is required for method workloadIdentity (no environment variable fallback: it identifies which ServiceAccount to federate, not a credential value)"))
		}

	default:
		return fmt.Errorf("unsupported azure auth method %q", cfg.Method)
	}

	return errors.Join(errs...)
}
