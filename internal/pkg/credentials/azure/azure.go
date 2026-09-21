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

// Package azure resolves OCI registry credentials from an Azure identity (a client
// secret/certificate, a system- or user-assigned managed identity, or a Kubernetes
// ServiceAccount federated via Microsoft Entra workload identity), for registries -- Azure
// Container Registry today -- that support the distribution-spec OAuth2 token exchange.
package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	corev1 "k8s.io/api/core/v1"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

const (
	// managementScope is the AAD resource scope requested for the access token that gets
	// exchanged for a registry refresh token. Not registry-specific -- the registry's own
	// /oauth2/exchange endpoint determines which registry the resulting token is scoped to via
	// the "service" form parameter, not the token's own scope.
	managementScope = "https://management.azure.com/.default"

	// workloadIdentityAudience is the audience Microsoft Entra's workload identity federation
	// expects on the federated Kubernetes token. Fixed by Microsoft (see
	// https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation), not
	// configurable per instance.
	workloadIdentityAudience = "api://AzureADTokenExchange"
)

// CredentialFunc returns an ORAS auth.CredentialFunc that authenticates using the Azure
// identity described by cfg. The credential is resolved fresh on every call: each call re-runs
// AzureAuth's configured method (a Secret read for clientSecret/clientCertificate, an IMDS
// round trip for managedIdentity, or a TokenRequest + AAD exchange for workloadIdentity) and
// the AAD-to-registry-token exchange below. Given falco-operator's own call pattern --
// (*artifact.Manager).fetchOCICredentials is invoked per artifact reconcile, not per HTTP
// request within a pull -- this keeps the implementation simple rather than adding
// invalidation-prone caching ahead of evidence it's needed; ORAS's own auth.Client already
// caches the resulting registry bearer tokens for the lifetime of a single pull.
func CredentialFunc(c client.Client, namespace string, cfg *commonv1alpha1.AzureAuth) (auth.CredentialFunc, error) {
	if cfg == nil {
		return nil, fmt.Errorf("azure auth configuration is required")
	}
	return func(ctx context.Context, registry string) (auth.Credential, error) {
		cred, err := resolveCredential(ctx, c, namespace, cfg)
		if err != nil {
			return auth.EmptyCredential, fmt.Errorf("resolve azure credential (method %s): %w", cfg.Method, err)
		}
		return exchangeForRegistryToken(ctx, retry.DefaultClient, cred, registry)
	}, nil
}

// resolveCredential builds an azcore.TokenCredential for cfg.Method. All four methods converge
// on this one interface, so exchangeForRegistryToken below needs no per-method branching.
func resolveCredential(ctx context.Context, c client.Client, namespace string, cfg *commonv1alpha1.AzureAuth) (azcore.TokenCredential, error) {
	switch cfg.Method {
	case commonv1alpha1.AzureMethodClientSecret:
		secret, err := getSecret(ctx, c, namespace, cfg.ClientSecretRef)
		if err != nil {
			return nil, err
		}
		clientSecret, ok := secret.Data[commonv1alpha1.AzureClientSecretKey]
		if !ok {
			return nil, fmt.Errorf("key %q not found in secret %s/%s", commonv1alpha1.AzureClientSecretKey, namespace, cfg.ClientSecretRef.Name)
		}
		return azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, string(clientSecret), nil)

	case commonv1alpha1.AzureMethodClientCertificate:
		secret, err := getSecret(ctx, c, namespace, cfg.ClientCertificateRef)
		if err != nil {
			return nil, err
		}
		certData, ok := secret.Data[commonv1alpha1.AzureClientCertificateKey]
		if !ok {
			return nil, fmt.Errorf("key %q not found in secret %s/%s", commonv1alpha1.AzureClientCertificateKey, namespace, cfg.ClientCertificateRef.Name)
		}
		// Absent password is fine: ParseCertificates accepts a nil/empty password for
		// certificates that aren't password-protected.
		password := secret.Data[commonv1alpha1.AzureClientCertificatePasswordKey]
		certs, key, err := azidentity.ParseCertificates(certData, password)
		if err != nil {
			return nil, fmt.Errorf("parse client certificate from secret %s/%s: %w", namespace, cfg.ClientCertificateRef.Name, err)
		}
		return azidentity.NewClientCertificateCredential(cfg.TenantID, cfg.ClientID, certs, key, nil)

	case commonv1alpha1.AzureMethodManagedIdentity:
		opts := &azidentity.ManagedIdentityCredentialOptions{}
		if cfg.ClientID != "" {
			// User-assigned. Absent ClientID leaves opts.ID unset, which selects the node's
			// system-assigned identity -- azidentity's own documented default.
			opts.ID = azidentity.ClientID(cfg.ClientID)
		}
		return azidentity.NewManagedIdentityCredential(opts)

	case commonv1alpha1.AzureMethodWorkloadIdentity:
		if cfg.ServiceAccountRef == nil {
			return nil, fmt.Errorf("serviceAccountRef is required for method workloadIdentity")
		}
		saName := cfg.ServiceAccountRef.Name
		// NewClientAssertionCredential, not azidentity's own NewWorkloadIdentityCredential:
		// the latter reads a static token file tied to this process's own pod identity, which
		// would limit every workloadIdentity AzureAuth cluster-wide to the one identity the
		// operator's own pod happens to carry. Minting per call via mintServiceAccountToken
		// (token.go) lets each AzureAuth reference its own ServiceAccount/identity instead.
		return azidentity.NewClientAssertionCredential(cfg.TenantID, cfg.ClientID,
			func(ctx context.Context) (string, error) {
				return mintServiceAccountToken(ctx, c, namespace, saName, workloadIdentityAudience)
			}, nil)

	default:
		return nil, fmt.Errorf("unsupported azure auth method %q", cfg.Method)
	}
}

// exchangeForRegistryToken exchanges an AAD access token for a registry-scoped refresh token
// via the registry's own OAuth2 distribution-spec exchange endpoint. Documented by Azure
// Container Registry at https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md; the same
// registry-vendor-owned endpoint regardless of which of the four methods produced cred.
//
// httpClient is a parameter (rather than always retry.DefaultClient directly) purely so tests
// can point it at an httptest server instead of a real registry; CredentialFunc always passes
// retry.DefaultClient in production.
func exchangeForRegistryToken(ctx context.Context, httpClient *http.Client, cred azcore.TokenCredential, registry string) (auth.Credential, error) {
	aadToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{managementScope}})
	if err != nil {
		return auth.EmptyCredential, fmt.Errorf("get AAD access token: %w", err)
	}

	form := url.Values{
		"grant_type":   {"access_token"},
		"service":      {registry},
		"access_token": {aadToken.Token},
	}
	exchangeURL := "https://" + registry + "/oauth2/exchange"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return auth.EmptyCredential, fmt.Errorf("build registry token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return auth.EmptyCredential, fmt.Errorf("exchange AAD token with %s: %w", registry, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return auth.EmptyCredential, fmt.Errorf("registry %s returned %d exchanging AAD token: %s", registry, resp.StatusCode, body)
	}

	var result struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return auth.EmptyCredential, fmt.Errorf("decode registry token exchange response from %s: %w", registry, err)
	}
	if result.RefreshToken == "" {
		return auth.EmptyCredential, fmt.Errorf("registry %s did not return a refresh token", registry)
	}

	return auth.Credential{RefreshToken: result.RefreshToken}, nil
}

func getSecret(ctx context.Context, c client.Client, namespace string, ref *commonv1alpha1.SecretRef) (*corev1.Secret, error) {
	if ref == nil {
		return nil, fmt.Errorf("secret reference is required")
	}
	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: namespace}, secret); err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", namespace, ref.Name, err)
	}
	return secret, nil
}
