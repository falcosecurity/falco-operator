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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// clearAzureEnv resets every AZURE_* variable this package reads to unset, via t.Setenv (so
// each caller's own restoration happens on its own test's cleanup). An ambient `az login`
// session or CI-injected credential on the machine running these tests would otherwise make
// "falls back to config" and "missing from both sources" tests flaky or silently wrong.
func clearAzureEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{envTenantID, envClientID, envClientSecret, envClientCertificatePath, envClientCertificatePassword, envClientSendCertificateChain} {
		t.Setenv(v, "")
	}
}

// workloadIdentitySA builds a ServiceAccount named "acr-refresher" (the name every workloadIdentity
// test in this file references) opted in for workloadIdentity federation as clientID, via
// azureClientIDAnnotation -- the shape authorizeServiceAccountForWorkloadIdentity requires before
// resolveCredential will mint a token for it.
func workloadIdentitySA(namespace, clientID string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "acr-refresher",
			Namespace:   namespace,
			Annotations: map[string]string{azureClientIDAnnotation: clientID},
		},
	}
}

// fakeTokenCredential is a minimal azcore.TokenCredential stand-in, avoiding any real
// AAD/network dependency for exchangeForRegistryToken's own tests.
type fakeTokenCredential struct {
	token string
	err   error
}

func (f fakeTokenCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// redirectingTransport rewrites every outbound request to target, regardless of the request's
// own scheme/host -- lets exchangeForRegistryToken's hardcoded "https://<registry>/..." URL be
// pointed at a local httptest.Server without needing a real TLS certificate for <registry>.
type redirectingTransport struct {
	target *url.URL
}

func (t redirectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

// roundTripFunc adapts a plain function to http.RoundTripper -- used where the test only needs
// to inspect the request (e.g. its scheme) rather than actually redirect it anywhere.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestExchangeForRegistryToken(t *testing.T) {
	t.Run("returns a RefreshToken credential on success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// assert, not require: this runs in the httptest server's own goroutine, where
			// require's FailNow doesn't actually stop the test (testifylint go-require).
			assert.NoError(t, r.ParseForm())
			assert.Equal(t, "access_token", r.FormValue("grant_type"))
			assert.Equal(t, "myregistry.azurecr.io", r.FormValue("service"))
			assert.Equal(t, "aad-token", r.FormValue("access_token"))
			assert.Equal(t, "/oauth2/exchange", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"refresh_token": "acr-refresh-token"}))
		}))
		defer server.Close()

		target, err := url.Parse(server.URL)
		require.NoError(t, err)
		httpClient := &http.Client{Transport: redirectingTransport{target: target}}

		cred, err := exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.azurecr.io", false)
		require.NoError(t, err)
		assert.Equal(t, "acr-refresh-token", cred.RefreshToken)
		assert.Empty(t, cred.Username)
		assert.Empty(t, cred.Password)
	})

	t.Run("returns an error when GetToken fails", func(t *testing.T) {
		httpClient := &http.Client{}
		_, err := exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{err: assert.AnError}, "myregistry.azurecr.io", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get AAD access token")
	})

	t.Run("returns an error on a non-200 response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("invalid_token"))
		}))
		defer server.Close()

		target, err := url.Parse(server.URL)
		require.NoError(t, err)
		httpClient := &http.Client{Transport: redirectingTransport{target: target}}

		_, err = exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.azurecr.io", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "returned 401")
	})

	t.Run("returns an error when the response has no refresh_token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}))
		defer server.Close()

		target, err := url.Parse(server.URL)
		require.NoError(t, err)
		httpClient := &http.Client{Transport: redirectingTransport{target: target}}

		_, err = exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.azurecr.io", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not return a refresh token")
	})

	t.Run("builds an http:// URL when plainHTTP is true", func(t *testing.T) {
		var gotScheme string
		roundTrip := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotScheme = req.URL.Scheme
			body := io.NopCloser(strings.NewReader(`{"refresh_token":"acr-refresh-token"}`))
			return &http.Response{StatusCode: http.StatusOK, Body: body, Header: http.Header{"Content-Type": {"application/json"}}}, nil
		})
		httpClient := &http.Client{Transport: roundTrip}

		_, err := exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.local:5000", true)
		require.NoError(t, err)
		assert.Equal(t, "http", gotScheme)
	})

	t.Run("builds an https:// URL when plainHTTP is false", func(t *testing.T) {
		var gotScheme string
		roundTrip := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotScheme = req.URL.Scheme
			body := io.NopCloser(strings.NewReader(`{"refresh_token":"acr-refresh-token"}`))
			return &http.Response{StatusCode: http.StatusOK, Body: body, Header: http.Header{"Content-Type": {"application/json"}}}, nil
		})
		httpClient := &http.Client{Transport: roundTrip}

		_, err := exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.azurecr.io", false)
		require.NoError(t, err)
		assert.Equal(t, "https", gotScheme)
	})

	t.Run("returns an error when the exchange request fails at the transport level", func(t *testing.T) {
		roundTrip := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return nil, assert.AnError
		})
		httpClient := &http.Client{Transport: roundTrip}

		_, err := exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.azurecr.io", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exchange AAD token with myregistry.azurecr.io")
	})

	t.Run("returns an error when the response body is not valid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not json"))
		}))
		defer server.Close()

		target, err := url.Parse(server.URL)
		require.NoError(t, err)
		httpClient := &http.Client{Transport: redirectingTransport{target: target}}

		_, err = exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.azurecr.io", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode registry token exchange response from myregistry.azurecr.io")
	})

	t.Run("a registry host with an explicit port is used unmodified for both the URL host and the service parameter", func(t *testing.T) {
		var gotHost, gotService string
		roundTrip := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotHost = req.URL.Host
			assert.NoError(t, req.ParseForm())
			gotService = req.FormValue("service")
			body := io.NopCloser(strings.NewReader(`{"refresh_token":"acr-refresh-token"}`))
			return &http.Response{StatusCode: http.StatusOK, Body: body, Header: http.Header{"Content-Type": {"application/json"}}}, nil
		})
		httpClient := &http.Client{Transport: roundTrip}

		_, err := exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.local:5000", true)
		require.NoError(t, err)
		assert.Equal(t, "myregistry.local:5000", gotHost)
		assert.Equal(t, "myregistry.local:5000", gotService)
	})
}

// TestExchangeForRegistryTokenWithORASAuthClient exercises exchangeForRegistryToken wired as an
// oras-go auth.CredentialFunc, driven by ORAS's own auth.Client -- not calling
// exchangeForRegistryToken directly the way the other tests in this file do. This is the actual
// integration boundary in question: does ORAS's own bearer-challenge handling correctly consume
// the auth.Credential{RefreshToken: ...} this package returns, exactly as
// oras-go/registry/remote/auth.Client.fetchOAuth2Token implements it (verified by reading that
// function directly, not assumed):
//
//  1. ORAS GETs the protected resource with no Authorization header.
//  2. The registry challenges with 401 + WWW-Authenticate: Bearer realm=...,service=....
//  3. ORAS calls the CredentialFunc (this package's exchangeForRegistryToken under the hood),
//     which itself calls the AAD exchange endpoint and returns a RefreshToken.
//  4. ORAS POSTs grant_type=refresh_token&refresh_token=<that value>&service=... to realm.
//  5. ORAS retries the original request with the resulting Authorization: Bearer <token>.
//
// Uses the httptest server's own real address as the "registry" throughout (rather than a fake
// hostname behind a rewriting transport, as the other tests in this file use) specifically so
// ORAS's own origin-matching safety check (comparing the challenged response's request URL
// against the originally requested URL, see auth.Client.Do / sameHTTPOrigin) sees a consistent
// origin at every step -- a rewriting transport would make that check see two different origins
// and reject the exchange before this test could prove anything.
func TestExchangeForRegistryTokenWithORASAuthClient(t *testing.T) {
	const (
		aadToken     = "aad-token"
		refreshToken = "acr-refresh-token-from-exchange"
		accessToken  = "final-bearer-token-from-oras-token-endpoint"
	)

	var exchangeCalled, tokenCalled, resourceAuthedCalled bool
	mux := http.NewServeMux()

	var registry string // set once the server is up; closed over by the handlers below

	mux.HandleFunc("/v2/test/manifest", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+accessToken {
			resourceAuthedCalled = true
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service=%q`, "http://"+registry+"/oauth2/token", registry))
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/oauth2/exchange", func(w http.ResponseWriter, r *http.Request) {
		exchangeCalled = true
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "access_token", r.FormValue("grant_type"))
		assert.Equal(t, aadToken, r.FormValue("access_token"))
		assert.Equal(t, registry, r.FormValue("service"))

		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"refresh_token": refreshToken}))
	})

	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalled = true
		assert.NoError(t, r.ParseForm())
		// This is ORAS's own request, built by auth.Client.fetchOAuth2Token -- proving it
		// picked up and correctly used the RefreshToken this package's exchange returned.
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, refreshToken, r.FormValue("refresh_token"))
		assert.Equal(t, registry, r.FormValue("service"))

		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken}))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	registry = strings.TrimPrefix(server.URL, "http://")

	authClient := &auth.Client{
		Client: http.DefaultClient,
		Credential: func(ctx context.Context, hostport string) (auth.Credential, error) {
			return exchangeForRegistryToken(ctx, http.DefaultClient, fakeTokenCredential{token: aadToken}, hostport, true)
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+registry+"/v2/test/manifest", http.NoBody)
	require.NoError(t, err)

	resp, err := authClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, exchangeCalled, "expected the AAD/ACR exchange endpoint to be called")
	assert.True(t, tokenCalled, "expected ORAS's own oauth2 token endpoint to be called with the refresh token")
	assert.True(t, resourceAuthedCalled, "expected the original resource to be retried with the resulting bearer token and succeed")
}

// selfSignedCertPEM generates a throwaway self-signed certificate + unencrypted RSA private
// key, PEM-encoded and concatenated -- the shape ParseCertificates (azidentity) expects for an
// unencrypted PEM input.
func selfSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	buf := make([]byte, 0, len(certPEM)+len(keyPEM))
	buf = append(buf, certPEM...)
	buf = append(buf, keyPEM...)
	return buf
}

func TestResolveCredential(t *testing.T) {
	const namespace = "falco"

	t.Run("clientSecret: builds a credential from the referenced secret", func(t *testing.T) {
		clearAzureEnv(t)
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app-secret", Namespace: namespace},
			Data:       map[string][]byte{commonv1alpha1.AzureClientSecretKey: []byte("s3cr3t")},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:          commonv1alpha1.AzureMethodClientSecret,
			TenantID:        "tenant",
			ClientID:        "client",
			ClientSecretRef: &commonv1alpha1.SecretRef{Name: "app-secret"},
		}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("clientSecret: builds a credential entirely from the environment when config is empty", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envTenantID, "tenant-from-env")
		t.Setenv(envClientID, "client-from-env")
		t.Setenv(envClientSecret, "secret-from-env")
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientSecret}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("clientSecret: errors when the secret is missing the key", func(t *testing.T) {
		clearAzureEnv(t)
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "app-secret", Namespace: namespace}}
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:          commonv1alpha1.AzureMethodClientSecret,
			TenantID:        "tenant",
			ClientID:        "client",
			ClientSecretRef: &commonv1alpha1.SecretRef{Name: "app-secret"},
		}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `key "clientSecret" not found`)
	})

	t.Run("clientSecret: errors when the secret does not exist", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:          commonv1alpha1.AzureMethodClientSecret,
			TenantID:        "tenant",
			ClientID:        "client",
			ClientSecretRef: &commonv1alpha1.SecretRef{Name: "missing"},
		}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get secret falco/missing")
	})

	t.Run("clientSecret: reports every missing field at once through the full resolution path", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientSecret}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenantId (config)")
		assert.Contains(t, err.Error(), "clientId (config)")
		assert.Contains(t, err.Error(), "clientSecretRef (config)")
	})

	t.Run("clientSecret: errors naming both sources when tenantId is missing from both", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:          commonv1alpha1.AzureMethodClientSecret,
			ClientID:        "client",
			ClientSecretRef: &commonv1alpha1.SecretRef{Name: "app-secret"},
		}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenantId (config) or AZURE_TENANT_ID (environment variable) is required for method clientSecret")
	})

	t.Run("clientSecret: errors naming both sources when clientSecret is missing from both", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientSecret, TenantID: "tenant", ClientID: "client"}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clientSecretRef (config) or AZURE_CLIENT_SECRET (environment variable) is required for method clientSecret")
	})

	t.Run("clientCertificate: builds a credential from a valid PEM certificate", func(t *testing.T) {
		clearAzureEnv(t)
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app-cert", Namespace: namespace},
			Data:       map[string][]byte{commonv1alpha1.AzureClientCertificateKey: selfSignedCertPEM(t)},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:               commonv1alpha1.AzureMethodClientCertificate,
			TenantID:             "tenant",
			ClientID:             "client",
			ClientCertificateRef: &commonv1alpha1.SecretRef{Name: "app-cert"},
		}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("clientCertificate: builds a credential entirely from the environment when config is empty", func(t *testing.T) {
		clearAzureEnv(t)
		certPath := filepath.Join(t.TempDir(), "client.pem")
		require.NoError(t, os.WriteFile(certPath, selfSignedCertPEM(t), 0o600))
		t.Setenv(envTenantID, "tenant-from-env")
		t.Setenv(envClientID, "client-from-env")
		t.Setenv(envClientCertificatePath, certPath)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientCertificate}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("clientCertificate: config wins even when the environment also points at a (nonexistent) file", func(t *testing.T) {
		clearAzureEnv(t)
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app-cert", Namespace: namespace},
			Data:       map[string][]byte{commonv1alpha1.AzureClientCertificateKey: selfSignedCertPEM(t)},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build()
		// If clientCertificateRef didn't take precedence, resolveClientCertificate would try to
		// read this nonexistent path and fail -- proving config, not the environment, was used.
		t.Setenv(envClientCertificatePath, filepath.Join(t.TempDir(), "does-not-exist.pem"))
		cfg := &commonv1alpha1.AzureAuth{
			Method:               commonv1alpha1.AzureMethodClientCertificate,
			TenantID:             "tenant",
			ClientID:             "client",
			ClientCertificateRef: &commonv1alpha1.SecretRef{Name: "app-cert"},
		}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("clientCertificate: sendCertificateChain does not break construction", func(t *testing.T) {
		clearAzureEnv(t)
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app-cert", Namespace: namespace},
			Data:       map[string][]byte{commonv1alpha1.AzureClientCertificateKey: selfSignedCertPEM(t)},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:               commonv1alpha1.AzureMethodClientCertificate,
			TenantID:             "tenant",
			ClientID:             "client",
			ClientCertificateRef: &commonv1alpha1.SecretRef{Name: "app-cert"},
			SendCertificateChain: new(true),
		}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("clientCertificate: errors on malformed certificate data", func(t *testing.T) {
		clearAzureEnv(t)
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app-cert", Namespace: namespace},
			Data:       map[string][]byte{commonv1alpha1.AzureClientCertificateKey: []byte("not a certificate")},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:               commonv1alpha1.AzureMethodClientCertificate,
			TenantID:             "tenant",
			ClientID:             "client",
			ClientCertificateRef: &commonv1alpha1.SecretRef{Name: "app-cert"},
		}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse client certificate")
	})

	t.Run("clientCertificate: errors naming both sources when neither is set", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientCertificate, TenantID: "tenant", ClientID: "client"}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clientCertificateRef (config) or AZURE_CLIENT_CERTIFICATE_PATH (environment variable) is required for method clientCertificate")
	})

	t.Run("clientCertificate: errors when the AZURE_CLIENT_CERTIFICATE_PATH file does not exist", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envClientCertificatePath, filepath.Join(t.TempDir(), "does-not-exist.pem"))
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodClientCertificate, TenantID: "tenant", ClientID: "client"}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read certificate file")
	})

	t.Run("managedIdentity: system-assigned (no clientId) does not error at construction", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodManagedIdentity}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("managedIdentity: user-assigned (clientId set) does not error at construction", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodManagedIdentity, ClientID: "user-assigned-client-id"}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("managedIdentity: user-assigned client ID also resolves from AZURE_CLIENT_ID", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envClientID, "client-from-env")
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodManagedIdentity}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("workloadIdentity: requires serviceAccountRef with no environment fallback", func(t *testing.T) {
		clearAzureEnv(t)
		// Set even though workloadIdentity doesn't need it for THIS assertion, to prove
		// serviceAccountRef's absence is what's rejected, not tenantId/clientId falling through.
		t.Setenv(envTenantID, "tenant-from-env")
		t.Setenv(envClientID, "client-from-env")
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodWorkloadIdentity}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serviceAccountRef.name is required")
		assert.Contains(t, err.Error(), "no environment variable fallback")
	})

	t.Run("workloadIdentity: a non-nil serviceAccountRef with an empty name is still rejected", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
			TenantID:          "tenant",
			ClientID:          "client",
			ServiceAccountRef: &corev1.LocalObjectReference{}, // non-nil, but Name == ""
		}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serviceAccountRef.name is required")
	})

	t.Run("workloadIdentity: does not error at construction with a valid config", func(t *testing.T) {
		clearAzureEnv(t)
		// Deliberately does not call cred.GetToken(): that would make a real network call to
		// AAD (via azidentity.NewClientAssertionCredential's internal token exchange), which
		// has no place in a unit test. mintServiceAccountToken's own request-shape/error
		// behavior is covered directly in token_test.go; the end-to-end path (assertion ->
		// AAD -> ACR) is covered by the kind/AKS verification in the PR description, not here.
		sa := workloadIdentitySA(namespace, "client")
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(sa).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
			TenantID:          "tenant",
			ClientID:          "client",
			ServiceAccountRef: &corev1.LocalObjectReference{Name: "acr-refresher"},
		}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("workloadIdentity: tenantId/clientId also resolve from the environment", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envTenantID, "tenant-from-env")
		t.Setenv(envClientID, "client-from-env")
		sa := workloadIdentitySA(namespace, "client-from-env")
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(sa).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
			ServiceAccountRef: &corev1.LocalObjectReference{Name: "acr-refresher"},
		}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("workloadIdentity: rejects a ServiceAccount not opted in (missing the annotation)", func(t *testing.T) {
		clearAzureEnv(t)
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "acr-refresher", Namespace: namespace}} // no azureClientIDAnnotation
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(sa).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
			TenantID:          "tenant",
			ClientID:          "client",
			ServiceAccountRef: &corev1.LocalObjectReference{Name: "acr-refresher"},
		}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not opted in for Azure workload identity federation")
		assert.Contains(t, err.Error(), azureClientIDAnnotation)
	})

	t.Run("workloadIdentity: rejects a ServiceAccount opted in for a different clientId", func(t *testing.T) {
		clearAzureEnv(t)
		sa := workloadIdentitySA(namespace, "some-other-client-id")
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(sa).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
			TenantID:          "tenant",
			ClientID:          "client",
			ServiceAccountRef: &corev1.LocalObjectReference{Name: "acr-refresher"},
		}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match this resource's clientId")
	})

	t.Run("workloadIdentity: rejects a nonexistent ServiceAccount", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
			TenantID:          "tenant",
			ClientID:          "client",
			ServiceAccountRef: &corev1.LocalObjectReference{Name: "does-not-exist"},
		}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get serviceaccount")
	})

	t.Run("workloadIdentity: a same-named ServiceAccount in a different namespace is never reachable", func(t *testing.T) {
		// Namespace binding: AzureAuth.ServiceAccountRef (corev1.LocalObjectReference) has no
		// namespace field at all -- there is no way for a CR to name a ServiceAccount outside
		// its own namespace. Proven behaviorally here, not just by the type's shape: an
		// identically-named ServiceAccount opted in (correctly annotated) in a *different*
		// namespace must never be the one resolveCredential resolves against when called with
		// this namespace -- only the one actually created in this namespace (deliberately
		// *not* created here) can ever be reached, so this must fail with a not-found error,
		// not succeed against the other namespace's ServiceAccount.
		clearAzureEnv(t)
		const otherNamespace = "not-falco"
		otherNamespaceSA := workloadIdentitySA(otherNamespace, "client")
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(otherNamespaceSA).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
			TenantID:          "tenant",
			ClientID:          "client",
			ServiceAccountRef: &corev1.LocalObjectReference{Name: "acr-refresher"},
		}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("get serviceaccount %s/acr-refresher", namespace))
	})

	t.Run("unsupported method", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{Method: "somethingElse"}

		_, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unsupported azure auth method "somethingElse"`)
	})
}

func TestResolveClientSecret(t *testing.T) {
	const namespace = "falco"

	t.Run("returns the secret value when clientSecretRef is set", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envClientSecret, "should-not-be-used")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app-secret", Namespace: namespace},
			Data:       map[string][]byte{commonv1alpha1.AzureClientSecretKey: []byte("from-secret")},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build()
		cfg := &commonv1alpha1.AzureAuth{ClientSecretRef: &commonv1alpha1.SecretRef{Name: "app-secret"}}

		got, err := resolveClientSecret(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.Equal(t, "from-secret", got)
	})

	t.Run("falls back to AZURE_CLIENT_SECRET when clientSecretRef is unset", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envClientSecret, "from-env")
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()

		got, err := resolveClientSecret(context.Background(), fakeClient, namespace, &commonv1alpha1.AzureAuth{})
		require.NoError(t, err)
		assert.Equal(t, "from-env", got)
	})

	t.Run("errors naming both sources when neither is set", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()

		_, err := resolveClientSecret(context.Background(), fakeClient, namespace, &commonv1alpha1.AzureAuth{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clientSecretRef (config) or AZURE_CLIENT_SECRET (environment variable)")
	})
}

func TestResolveClientCertificate(t *testing.T) {
	const namespace = "falco"

	t.Run("returns the secret's certificate and password when clientCertificateRef is set", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envClientCertificatePath, "/should/not/be/read")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app-cert", Namespace: namespace},
			Data: map[string][]byte{
				commonv1alpha1.AzureClientCertificateKey:         []byte("cert-from-secret"),
				commonv1alpha1.AzureClientCertificatePasswordKey: []byte("pw-from-secret"),
			},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build()
		cfg := &commonv1alpha1.AzureAuth{ClientCertificateRef: &commonv1alpha1.SecretRef{Name: "app-cert"}}

		certData, password, err := resolveClientCertificate(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.Equal(t, []byte("cert-from-secret"), certData)
		assert.Equal(t, []byte("pw-from-secret"), password)
	})

	t.Run("falls back to reading AZURE_CLIENT_CERTIFICATE_PATH when clientCertificateRef is unset", func(t *testing.T) {
		clearAzureEnv(t)
		certPath := filepath.Join(t.TempDir(), "client.pem")
		require.NoError(t, os.WriteFile(certPath, []byte("cert-from-file"), 0o600))
		t.Setenv(envClientCertificatePath, certPath)
		t.Setenv(envClientCertificatePassword, "pw-from-env")
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()

		certData, password, err := resolveClientCertificate(context.Background(), fakeClient, namespace, &commonv1alpha1.AzureAuth{})
		require.NoError(t, err)
		assert.Equal(t, []byte("cert-from-file"), certData)
		assert.Equal(t, []byte("pw-from-env"), password)
	})

	t.Run("errors naming both sources when neither is set", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()

		_, _, err := resolveClientCertificate(context.Background(), fakeClient, namespace, &commonv1alpha1.AzureAuth{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clientCertificateRef (config) or AZURE_CLIENT_CERTIFICATE_PATH (environment variable)")
	})

	t.Run("errors when the secret named by clientCertificateRef does not exist", func(t *testing.T) {
		clearAzureEnv(t)
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{ClientCertificateRef: &commonv1alpha1.SecretRef{Name: "missing"}}

		_, _, err := resolveClientCertificate(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get secret falco/missing")
	})

	t.Run("errors when the secret is missing the certificate key", func(t *testing.T) {
		clearAzureEnv(t)
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "app-cert", Namespace: namespace}}
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(secret).Build()
		cfg := &commonv1alpha1.AzureAuth{ClientCertificateRef: &commonv1alpha1.SecretRef{Name: "app-cert"}}

		_, _, err := resolveClientCertificate(context.Background(), fakeClient, namespace, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `key "certificate" not found`)
	})

	t.Run("errors when the file named by AZURE_CLIENT_CERTIFICATE_PATH does not exist", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envClientCertificatePath, filepath.Join(t.TempDir(), "does-not-exist.pem"))
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()

		_, _, err := resolveClientCertificate(context.Background(), fakeClient, namespace, &commonv1alpha1.AzureAuth{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read certificate file")
	})
}

func TestClientCertificateOptions(t *testing.T) {
	t.Run("threads an explicit true through", func(t *testing.T) {
		clearAzureEnv(t)
		opts := clientCertificateOptions(&commonv1alpha1.AzureAuth{SendCertificateChain: new(true)})
		require.NotNil(t, opts)
		assert.True(t, opts.SendCertificateChain)
	})

	t.Run("threads an explicit false through, ignoring a conflicting environment value", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envClientSendCertificateChain, "true")
		opts := clientCertificateOptions(&commonv1alpha1.AzureAuth{SendCertificateChain: new(false)})
		require.NotNil(t, opts)
		assert.False(t, opts.SendCertificateChain)
	})

	t.Run("falls back to the environment variable when unset", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envClientSendCertificateChain, "1")
		opts := clientCertificateOptions(&commonv1alpha1.AzureAuth{})
		require.NotNil(t, opts)
		assert.True(t, opts.SendCertificateChain)
	})

	t.Run("defaults to false when nothing is set anywhere", func(t *testing.T) {
		clearAzureEnv(t)
		opts := clientCertificateOptions(&commonv1alpha1.AzureAuth{})
		require.NotNil(t, opts)
		assert.False(t, opts.SendCertificateChain)
	})
}

func TestCredentialFunc(t *testing.T) {
	t.Run("errors when cfg is nil", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		_, err := CredentialFunc(fakeClient, "falco", nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "azure auth configuration is required")
	})

	t.Run("the returned CredentialFunc surfaces a resolveCredential error", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		credFunc, err := CredentialFunc(fakeClient, "falco", &commonv1alpha1.AzureAuth{Method: "bogus"}, nil)
		require.NoError(t, err)

		_, err = credFunc(context.Background(), "myregistry.azurecr.io")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolve azure credential")
	})
}

func TestExchangeHTTPClient(t *testing.T) {
	t.Run("returns retry.DefaultClient when registryOpts is nil", func(t *testing.T) {
		assert.Same(t, retry.DefaultClient, exchangeHTTPClient(nil))
	})

	t.Run("returns retry.DefaultClient when InsecureSkipVerify is false", func(t *testing.T) {
		assert.Same(t, retry.DefaultClient, exchangeHTTPClient(&puller.RegistryOptions{}))
	})

	t.Run("returns a client with InsecureSkipVerify set in its transport when requested", func(t *testing.T) {
		c := exchangeHTTPClient(&puller.RegistryOptions{InsecureSkipVerify: true})
		require.NotSame(t, retry.DefaultClient, c)

		rt, ok := c.Transport.(*retry.Transport)
		require.True(t, ok, "expected *retry.Transport, got %T", c.Transport)
		underlying, ok := rt.Base.(*http.Transport)
		require.True(t, ok, "expected the retry transport's base to be *http.Transport, got %T", rt.Base)
		require.NotNil(t, underlying.TLSClientConfig)
		assert.True(t, underlying.TLSClientConfig.InsecureSkipVerify)
	})
}

func TestResolveString(t *testing.T) {
	const envVar = "AZURE_TEST_RESOLVE_STRING"

	t.Run("returns config value when set, ignoring the environment", func(t *testing.T) {
		t.Setenv(envVar, "from-env")
		assert.Equal(t, "from-config", resolveString("from-config", envVar))
	})

	t.Run("falls back to the environment variable when config is empty", func(t *testing.T) {
		t.Setenv(envVar, "from-env")
		assert.Equal(t, "from-env", resolveString("", envVar))
	})

	t.Run("returns empty when neither is set", func(t *testing.T) {
		t.Setenv(envVar, "")
		assert.Empty(t, resolveString("", envVar))
	})
}

func TestResolveBool(t *testing.T) {
	const envVar = "AZURE_TEST_RESOLVE_BOOL"

	trueVal := true
	falseVal := false

	t.Run("an explicit true in config wins over a conflicting env value", func(t *testing.T) {
		t.Setenv(envVar, "false")
		assert.True(t, resolveBool(&trueVal, envVar))
	})

	t.Run("an explicit false in config wins over a conflicting env value", func(t *testing.T) {
		t.Setenv(envVar, "true")
		assert.False(t, resolveBool(&falseVal, envVar))
	})

	t.Run(`falls back to the environment variable "1"`, func(t *testing.T) {
		t.Setenv(envVar, "1")
		assert.True(t, resolveBool(nil, envVar))
	})

	t.Run(`falls back to the environment variable "true", case-insensitive`, func(t *testing.T) {
		t.Setenv(envVar, "TRUE")
		assert.True(t, resolveBool(nil, envVar))
	})

	t.Run("defaults to false when config is nil and the environment variable is unset", func(t *testing.T) {
		t.Setenv(envVar, "")
		assert.False(t, resolveBool(nil, envVar))
	})

	t.Run(`defaults to false for an unrecognized environment value`, func(t *testing.T) {
		t.Setenv(envVar, "yes")
		assert.False(t, resolveBool(nil, envVar))
	})
}

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
		assert.Contains(t, err.Error(), "serviceAccountRef.name is required for method workloadIdentity")
		assert.Contains(t, err.Error(), "no environment variable fallback")
	})

	t.Run("workloadIdentity: serviceAccountRef alone is still reported when tenantId/clientId are present", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: commonv1alpha1.AzureMethodWorkloadIdentity}

		err := validateMethod(cfg, "tenant", "client")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "tenantId (config)")
		assert.NotContains(t, err.Error(), "clientId (config)")
		assert.Contains(t, err.Error(), "serviceAccountRef.name is required")
	})

	t.Run("workloadIdentity: a non-nil serviceAccountRef with an empty name is still reported", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{
			Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
			ServiceAccountRef: &corev1.LocalObjectReference{},
		}

		err := validateMethod(cfg, "tenant", "client")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serviceAccountRef.name is required")
	})

	t.Run("unsupported method", func(t *testing.T) {
		cfg := &commonv1alpha1.AzureAuth{Method: "somethingElse"}

		err := validateMethod(cfg, "tenant", "client")
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unsupported azure auth method "somethingElse"`)
	})
}
