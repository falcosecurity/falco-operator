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
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
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

		cred, err := exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.azurecr.io")
		require.NoError(t, err)
		assert.Equal(t, "acr-refresh-token", cred.RefreshToken)
		assert.Empty(t, cred.Username)
		assert.Empty(t, cred.Password)
	})

	t.Run("returns an error when GetToken fails", func(t *testing.T) {
		httpClient := &http.Client{}
		_, err := exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{err: assert.AnError}, "myregistry.azurecr.io")
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

		_, err = exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.azurecr.io")
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

		_, err = exchangeForRegistryToken(context.Background(), httpClient, fakeTokenCredential{token: "aad-token"}, "myregistry.azurecr.io")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not return a refresh token")
	})
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
		assert.Contains(t, err.Error(), "serviceAccountRef is required")
		assert.Contains(t, err.Error(), "no environment variable fallback")
	})

	t.Run("workloadIdentity: does not error at construction with a valid config", func(t *testing.T) {
		clearAzureEnv(t)
		// Deliberately does not call cred.GetToken(): that would make a real network call to
		// AAD (via azidentity.NewClientAssertionCredential's internal token exchange), which
		// has no place in a unit test. mintServiceAccountToken's own request-shape/error
		// behavior is covered directly in token_test.go; the end-to-end path (assertion ->
		// AAD -> ACR) is covered by the kind/AKS verification in the PR description, not here.
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
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
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		cfg := &commonv1alpha1.AzureAuth{
			Method:            commonv1alpha1.AzureMethodWorkloadIdentity,
			ServiceAccountRef: &corev1.LocalObjectReference{Name: "acr-refresher"},
		}

		cred, err := resolveCredential(context.Background(), fakeClient, namespace, cfg)
		require.NoError(t, err)
		assert.NotNil(t, cred)
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
		_, err := CredentialFunc(fakeClient, "falco", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "azure auth configuration is required")
	})

	t.Run("the returned CredentialFunc surfaces a resolveCredential error", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()
		credFunc, err := CredentialFunc(fakeClient, "falco", &commonv1alpha1.AzureAuth{Method: "bogus"})
		require.NoError(t, err)

		_, err = credFunc(context.Background(), "myregistry.azurecr.io")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolve azure credential")
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
