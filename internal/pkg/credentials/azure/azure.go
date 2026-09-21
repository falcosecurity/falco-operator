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
// ServiceAccount federated via Microsoft Entra workload identity), specifically for Azure
// Container Registry (ACR) today. This implements ACR's own documented AAD token exchange
// (https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md) -- POSTing an AAD access token
// scoped to https://management.azure.com/.default to the registry's /oauth2/exchange endpoint
// for an ACR refresh token. The exchange endpoint *shape* (POST .../oauth2/exchange, form-
// encoded) happens to be one some other registries also expose, but managementScope below is
// an Azure AAD resource, not a distribution-spec concept -- a non-ACR registry using the same
// endpoint shape may require a different AAD resource/scope, a different exchange endpoint, or
// reject an Azure management-plane token outright. Treat "works with ACR" as the supported
// claim, not "works with any distribution-spec-compatible registry", until scope/endpoint
// becomes its own piece of configuration.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	corev1 "k8s.io/api/core/v1"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

const (
	// managementScope is the AAD resource scope requested for the access token that gets
	// exchanged for a registry refresh token via ACR's own /oauth2/exchange endpoint. This is
	// ACR's own documented convention, not a distribution-spec or registry-agnostic value -- see
	// the package doc comment above. The "service" form parameter (not this scope) is what
	// determines which registry the resulting refresh token is scoped to.
	managementScope = "https://management.azure.com/.default"

	// workloadIdentityAudience is the audience Microsoft Entra's workload identity federation
	// expects on the federated Kubernetes token. Fixed by Microsoft (see
	// https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation), not
	// configurable per instance.
	workloadIdentityAudience = "api://AzureADTokenExchange"

	// azureClientIDAnnotation is the ServiceAccount annotation method: workloadIdentity requires,
	// recording the exact AzureAuth.ClientID that ServiceAccount is opted in to be federated as.
	// See authorizeServiceAccountForWorkloadIdentity for why this exists: without it, anyone
	// able to create or edit a Rulesfile/Plugin/Config resource in a namespace could reference
	// *any* ServiceAccount already federated to *any* Azure identity in that namespace, not just
	// one their own resource is meant to use -- a materially different privilege than reading a
	// Secret they still have to be granted access to. Setting this annotation is a deliberate
	// act by whoever administers ServiceAccounts in the namespace (not necessarily the same
	// people who can create artifact resources), naming exactly which client ID that
	// ServiceAccount consents to being minted a token for.
	azureClientIDAnnotation = "azure.falcosecurity.dev/client-id"
)

// Environment variable names deliberately match the wider Azure SDK ecosystem's own
// EnvironmentCredential/DefaultAzureCredential conventions (az CLI, other language SDKs), not
// project-specific names, so operators already familiar with Azure tooling don't have to learn
// new ones. Read from this process's own environment -- the falco-operator Deployment's -- so
// they act as a cluster-wide default identity for any AzureAuth that leaves a field unset, not
// as a per-resource mechanism.
const (
	envTenantID              = "AZURE_TENANT_ID"
	envClientID              = "AZURE_CLIENT_ID"
	envClientCertificatePath = "AZURE_CLIENT_CERTIFICATE_PATH"
	//nolint:gosec // G101: variable NAME, not a credential value
	envClientSecret = "AZURE_CLIENT_SECRET"
	//nolint:gosec // G101: variable NAME, not a credential value
	envClientCertificatePassword  = "AZURE_CLIENT_CERTIFICATE_PASSWORD"
	envClientSendCertificateChain = "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN"
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
//
// registryOpts carries the same RegistryConfig.PlainHTTP/TLS settings the OCI puller already
// honors for the actual blob pull (see (*artifact.Manager).ResolveRegistryOptions) -- the AAD/
// ACR token exchange is a separate HTTP call to the same registry and needs to agree with it,
// rather than always assuming HTTPS with default TLS regardless of how the registry is
// configured. nil means "no override": HTTPS, system CA pool.
//
// The returned auth.CredentialFunc's registry argument -- supplied by ORAS itself, not by this
// package -- is used directly and unmodified both as the exchange URL's host (optionally with a
// port, e.g. "myregistry.local:5000") and as the "service" form parameter ACR's exchange
// endpoint expects. For ACR this is always correct: ORAS derives that argument from the
// request's own host, which for an ACR pull is already the registry's login server, the same
// value ACR's own "service" parameter expects. There's no separate "authentication host" or
// "service name" concept layered on top of it here.
func CredentialFunc(c client.Client, namespace string, cfg *commonv1alpha1.AzureAuth, registryOpts *puller.RegistryOptions) (auth.CredentialFunc, error) {
	if cfg == nil {
		return nil, fmt.Errorf("azure auth configuration is required")
	}
	httpClient := exchangeHTTPClient(registryOpts)
	plainHTTP := registryOpts != nil && registryOpts.PlainHTTP
	return func(ctx context.Context, registry string) (auth.Credential, error) {
		cred, err := resolveCredential(ctx, c, namespace, cfg)
		if err != nil {
			return auth.EmptyCredential, fmt.Errorf("resolve azure credential (method %s): %w", cfg.Method, err)
		}
		return exchangeForRegistryToken(ctx, httpClient, cred, registry, plainHTTP)
	}, nil
}

// exchangeHTTPClient builds the *http.Client used for the AAD-to-registry exchange, honoring
// RegistryConfig.TLS.InsecureSkipVerify when set. Still wrapped in retry.NewTransport either
// way, for the same retry/backoff behavior retry.DefaultClient gives the common case.
func exchangeHTTPClient(registryOpts *puller.RegistryOptions) *http.Client {
	// puller.TransportFor builds the exact same InsecureSkipVerify-wrapping RoundTripper
	// Pull/FetchConfig/ResolveDigest/FetchContent use for the blob pull itself -- one
	// implementation instead of two that could silently drift apart. nil means "no override
	// needed" (registryOpts is nil, or InsecureSkipVerify is false).
	if transport := puller.TransportFor(registryOpts); transport != nil {
		return &http.Client{Transport: transport}
	}
	return retry.DefaultClient
}

// resolveCredential builds an azcore.TokenCredential for cfg.Method. All four methods converge
// on this one interface, so exchangeForRegistryToken below needs no per-method branching.
//
// tenantId and clientId fall back to AZURE_TENANT_ID/AZURE_CLIENT_ID (this process's own
// environment, i.e. the falco-operator Deployment's -- a cluster-wide default identity, not a
// per-resource mechanism) when left empty in cfg; config always wins when both are set. The one
// deliberate exception is workloadIdentity's serviceAccountRef, which has no environment
// equivalent -- see its godoc on AzureAuth for why.
//
// validateMethod runs first and unconditionally: every required field for cfg.Method is checked
// before any Secret fetch, IMDS round trip, or token mint happens below, so a misconfigured CR
// fails fast with everything wrong named at once, not one field at a time as each resolution
// step is reached.
func resolveCredential(ctx context.Context, c client.Client, namespace string, cfg *commonv1alpha1.AzureAuth) (azcore.TokenCredential, error) {
	tenantID := resolveString(cfg.TenantID, envTenantID)
	clientID := resolveString(cfg.ClientID, envClientID)

	if err := validateMethod(cfg, tenantID, clientID); err != nil {
		return nil, err
	}

	switch cfg.Method {
	case commonv1alpha1.AzureMethodClientSecret:
		clientSecret, err := resolveClientSecret(ctx, c, namespace, cfg)
		if err != nil {
			return nil, err
		}
		return azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)

	case commonv1alpha1.AzureMethodClientCertificate:
		certData, password, err := resolveClientCertificate(ctx, c, namespace, cfg)
		if err != nil {
			return nil, err
		}
		certs, key, err := azidentity.ParseCertificates(certData, password)
		if err != nil {
			return nil, fmt.Errorf("parse client certificate: %w", err)
		}
		return azidentity.NewClientCertificateCredential(tenantID, clientID, certs, key, clientCertificateOptions(cfg))

	case commonv1alpha1.AzureMethodManagedIdentity:
		opts := &azidentity.ManagedIdentityCredentialOptions{}
		if clientID != "" {
			// User-assigned. Absent clientID leaves opts.ID unset, which selects the node's
			// system-assigned identity -- azidentity's own documented default.
			opts.ID = azidentity.ClientID(clientID)
		}
		return azidentity.NewManagedIdentityCredential(opts)

	case commonv1alpha1.AzureMethodWorkloadIdentity:
		saName := cfg.ServiceAccountRef.Name
		// Checked eagerly, here, rather than deferred into the assertion callback below: a CR
		// author who can create/edit a Rulesfile/Plugin/Config resource in a namespace can name
		// *any* ServiceAccount in that namespace, not just one meant for their own resource --
		// without this check, that's enough to get a token minted for any ServiceAccount
		// already federated to any Azure identity in the namespace. See
		// authorizeServiceAccountForWorkloadIdentity and azureClientIDAnnotation's doc comment.
		if err := authorizeServiceAccountForWorkloadIdentity(ctx, c, namespace, saName, clientID); err != nil {
			return nil, err
		}
		// NewClientAssertionCredential, not azidentity's own NewWorkloadIdentityCredential:
		// the latter reads a static token file tied to this process's own pod identity, which
		// would limit every workloadIdentity AzureAuth cluster-wide to the one identity the
		// operator's own pod happens to carry. Minting per call via mintServiceAccountToken
		// (token.go) lets each AzureAuth reference its own ServiceAccount/identity instead.
		return azidentity.NewClientAssertionCredential(tenantID, clientID,
			func(ctx context.Context) (string, error) {
				return mintServiceAccountToken(ctx, c, namespace, saName, workloadIdentityAudience)
			}, nil)

	default:
		// Unreachable: validateMethod above already rejects an unsupported method. Kept as a
		// defensive default rather than a panic, in case the two ever drift.
		return nil, fmt.Errorf("unsupported azure auth method %q", cfg.Method)
	}
}

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
		// LocalObjectReference.Name is a plain string with no CRD-level "required" marker (K8s
		// API convention: it's technically optional for backwards compatibility), so a
		// serviceAccountRef: {} with no name would pass "has(self.serviceAccountRef)" in the
		// CEL rule and reach here with a non-nil ServiceAccountRef but an empty Name -- checking
		// only for nil misses that case and would only fail later, confusingly, inside
		// mintServiceAccountToken's TokenRequest call.
		if cfg.ServiceAccountRef == nil || cfg.ServiceAccountRef.Name == "" {
			errs = append(errs, fmt.Errorf("serviceAccountRef.name is required for method workloadIdentity (no environment variable fallback: it identifies which ServiceAccount to federate, not a credential value)"))
		}

	default:
		return fmt.Errorf("unsupported azure auth method %q", cfg.Method)
	}

	return errors.Join(errs...)
}

// requireForMethod returns a descriptive error, naming both the config field and its
// environment variable fallback, when a value resolved to empty from both sources.
func requireForMethod(method, configField, envVar, resolved string) error {
	if resolved != "" {
		return nil
	}
	return fmt.Errorf("%s (config) or %s (environment variable) is required for method %s", configField, envVar, method)
}

// resolveClientSecret returns the client secret from cfg.ClientSecretRef if set, otherwise the
// AZURE_CLIENT_SECRET environment variable.
func resolveClientSecret(ctx context.Context, c client.Client, namespace string, cfg *commonv1alpha1.AzureAuth) (string, error) {
	if cfg.ClientSecretRef != nil {
		secret, err := getSecret(ctx, c, namespace, cfg.ClientSecretRef)
		if err != nil {
			return "", err
		}
		clientSecret, ok := secret.Data[commonv1alpha1.AzureClientSecretKey]
		if !ok {
			return "", fmt.Errorf("key %q not found in secret %s/%s", commonv1alpha1.AzureClientSecretKey, namespace, cfg.ClientSecretRef.Name)
		}
		return string(clientSecret), nil
	}
	if v := os.Getenv(envClientSecret); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("clientSecretRef (config) or %s (environment variable) is required for method clientSecret", envClientSecret)
}

// resolveClientCertificate returns certificate data and (optional) password from
// cfg.ClientCertificateRef if set, otherwise reads them from AZURE_CLIENT_CERTIFICATE_PATH (a
// file path on this process's own filesystem) and AZURE_CLIENT_CERTIFICATE_PASSWORD.
func resolveClientCertificate(ctx context.Context, c client.Client, namespace string, cfg *commonv1alpha1.AzureAuth) (certData, password []byte, err error) {
	if cfg.ClientCertificateRef != nil {
		secret, err := getSecret(ctx, c, namespace, cfg.ClientCertificateRef)
		if err != nil {
			return nil, nil, err
		}
		certData, ok := secret.Data[commonv1alpha1.AzureClientCertificateKey]
		if !ok {
			return nil, nil, fmt.Errorf("key %q not found in secret %s/%s", commonv1alpha1.AzureClientCertificateKey, namespace, cfg.ClientCertificateRef.Name)
		}
		// Absent password is fine: ParseCertificates accepts a nil/empty password for
		// certificates that aren't password-protected.
		return certData, secret.Data[commonv1alpha1.AzureClientCertificatePasswordKey], nil
	}

	path := os.Getenv(envClientCertificatePath)
	if path == "" {
		return nil, nil, fmt.Errorf("clientCertificateRef (config) or %s (environment variable) is required for method clientCertificate", envClientCertificatePath)
	}
	//nolint:gosec // G304: path is this process's own environment (the falco-operator
	// Deployment's, set by whoever configures the operator), not untrusted external input
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read certificate file %s (from %s): %w", path, envClientCertificatePath, err)
	}
	return data, []byte(os.Getenv(envClientCertificatePassword)), nil
}

// resolveString returns configValue if non-empty, otherwise the named environment variable
// (empty if unset). Config always wins when both are set.
func resolveString(configValue, envVar string) string {
	if configValue != "" {
		return configValue
	}
	return os.Getenv(envVar)
}

// resolveBool returns *configValue when configValue is non-nil (an explicit true or false in
// the CR), otherwise the named environment variable's truthiness ("1" or a case-insensitive
// "true"). A pointer, not a bare bool: a zero-value "false" CR field would otherwise be
// indistinguishable from "not set, check the environment.".
func resolveBool(configValue *bool, envVar string) bool {
	if configValue != nil {
		return *configValue
	}
	v := os.Getenv(envVar)
	return v == "1" || strings.EqualFold(v, "true")
}

// exchangeForRegistryToken exchanges an AAD access token for a registry-scoped refresh token
// via ACR's own OAuth2 exchange endpoint, documented at
// https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md -- the same ACR-owned endpoint
// regardless of which of the four methods produced cred. See the package doc comment for why
// this isn't assumed to be a registry-agnostic distribution-spec mechanism.
//
// httpClient is a parameter (rather than always retry.DefaultClient directly) purely so tests
// can point it at an httptest server instead of a real registry; CredentialFunc builds the
// production one via exchangeHTTPClient, honoring RegistryConfig.TLS.InsecureSkipVerify.
//
// plainHTTP mirrors RegistryConfig.PlainHTTP (the same field the OCI puller already honors for
// the blob pull itself, via ResolveRegistryOptions) -- without it this exchange always assumed
// HTTPS regardless of how the registry was actually configured.
func exchangeForRegistryToken(ctx context.Context, httpClient *http.Client, cred azcore.TokenCredential, registry string, plainHTTP bool) (auth.Credential, error) {
	aadToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{managementScope}})
	if err != nil {
		return auth.EmptyCredential, fmt.Errorf("get AAD access token: %w", err)
	}

	form := url.Values{
		"grant_type":   {"access_token"},
		"service":      {registry},
		"access_token": {aadToken.Token},
	}
	scheme := "https"
	if plainHTTP {
		scheme = "http"
	}
	exchangeURL := scheme + "://" + registry + "/oauth2/exchange"
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
		// Deliberately not including the response body: this error's text is likely to end up
		// in a Rulesfile/Plugin/Config resource's .status.conditions[].message, readable by
		// anyone with get/list on that resource -- a wider audience than whoever has log
		// access. A registry error response isn't guaranteed not to echo back request data
		// (in the worst case, form parameters from this very request), so surface only the
		// status code here; the response is still fully available to a debugger attaching to
		// this process, just not propagated into a resource anyone can read.
		return auth.EmptyCredential, fmt.Errorf("registry %s returned %d exchanging AAD token", registry, resp.StatusCode)
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

// clientCertificateOptions builds the azidentity options for the clientCertificate method,
// split out from resolveCredential so cfg.SendCertificateChain's wiring can be asserted
// directly in a test without needing to inspect azidentity's own credential internals.
func clientCertificateOptions(cfg *commonv1alpha1.AzureAuth) *azidentity.ClientCertificateCredentialOptions {
	return &azidentity.ClientCertificateCredentialOptions{
		SendCertificateChain: resolveBool(cfg.SendCertificateChain, envClientSendCertificateChain),
	}
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

// authorizeServiceAccountForWorkloadIdentity is the enforceable half of the workloadIdentity
// trust model: a Rulesfile/Plugin/Config resource naming a ServiceAccount isn't sufficient on
// its own to get a token minted for it -- that ServiceAccount must also carry
// azureClientIDAnnotation, set to exactly the clientID this resolution is for. Fetching it here
// (rather than trusting a bare name, the way mintServiceAccountToken's own TokenRequest call
// does) means an artifact resource can't silently ride on whatever other ServiceAccount in the
// same namespace already happens to be federated to some Azure identity -- setting this
// annotation is its own deliberate act, ordinarily by whoever administers ServiceAccounts in
// the namespace, not necessarily the same people who can create artifact resources.
//
// This is a namespace-local opt-in, not a full authorization system: anyone who can both create
// artifact resources *and* edit ServiceAccounts in the same namespace can self-authorize. It
// narrows the blast radius of the first capability alone; it doesn't replace RBAC on
// ServiceAccounts, and it's not a substitute for a validating webhook if that stronger guarantee
// is ever needed.
func authorizeServiceAccountForWorkloadIdentity(ctx context.Context, c client.Client, namespace, saName, clientID string) error {
	sa := &corev1.ServiceAccount{}
	if err := c.Get(ctx, client.ObjectKey{Name: saName, Namespace: namespace}, sa); err != nil {
		return fmt.Errorf("get serviceaccount %s/%s: %w", namespace, saName, err)
	}
	annotated, ok := sa.Annotations[azureClientIDAnnotation]
	if !ok {
		return fmt.Errorf("serviceaccount %s/%s is not opted in for Azure workload identity federation: it must carry the %q annotation, set to %q, before the operator will mint a token for it", namespace, saName, azureClientIDAnnotation, clientID)
	}
	if annotated != clientID {
		return fmt.Errorf("serviceaccount %s/%s's %q annotation is %q, which does not match this resource's clientId %q: refusing to mint a token for a federated identity this ServiceAccount was not opted in for", namespace, saName, azureClientIDAnnotation, annotated, clientID)
	}
	return nil
}
