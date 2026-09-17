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

package artifactserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactserver"
	"github.com/falcosecurity/falco-operator/internal/pkg/tlsutil"
)

// signSPIFFELeaf issues a client leaf certificate (signed by ca) carrying spiffeURI as its
// only URI SAN — the identity the Authorizer checks against known Falco instances.
func signSPIFFELeaf(t *testing.T, ca testCA, spiffeURI string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	u, err := url.Parse(spiffeURI)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "artifact-operator-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// TestServer_SPIFFEAuthorizer proves that a CA-signed client certificate is necessary but not
// sufficient: only a SPIFFE identity matching an actual, known Falco instance is accepted, even
// though every case here presents a certificate signed by the same trusted CA.
func TestServer_SPIFFEAuthorizer(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "test-root-ca")

	serverCertPEM, serverKeyPEM := signLeaf(t, ca, "artifact-server", []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth)
	serverCertFile := filepath.Join(dir, "tls.crt")
	serverKeyFile := filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(serverCertFile, serverCertPEM, 0o600))
	require.NoError(t, os.WriteFile(serverKeyFile, serverKeyPEM, 0o600))

	caFile := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caFile, ca.certPEM, 0o600))

	certWatcher, err := certwatcher.New(serverCertFile, serverKeyFile)
	require.NoError(t, err)
	caWatcher, err := tlsutil.NewCAWatcher(caFile)
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, instancev1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(&instancev1alpha1.Falco{
			ObjectMeta: metav1.ObjectMeta{Name: "known-falco", Namespace: "default"},
		}).
		Build()
	authorizer := artifactserver.NewAuthorizer(fakeClient, logr.Discard())

	cache := artifactcache.NewCache(t.TempDir())
	require.NoError(t, cache.Load())
	seedRulesfile(t, cache, "secure", []byte("secure content"))

	addr := reserveAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := artifactserver.New(cache,
		artifactserver.WithTLS(certWatcher),
		artifactserver.WithClientCAs(caWatcher),
		artifactserver.WithAuthorizer(authorizer))
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, addr) }()
	waitForListening(t, addr)

	targetURL := "https://" + addr + "/v1/artifacts/rulesfiles/default/secure"
	rootCAs := certPool(t, ca.certPEM)

	t.Run("known Falco identity is accepted", func(t *testing.T) {
		certPEM, keyPEM := signSPIFFELeaf(t, ca, "spiffe://cluster.local/ns/default/sa/known-falco")
		clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)

		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: rootCAs, Certificates: []tls.Certificate{clientCert},
		}}}
		resp, doErr := client.Get(targetURL) //nolint:noctx // test-only, short-lived
		require.NoError(t, doErr)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("unknown Falco identity is rejected despite a valid CA-signed cert", func(t *testing.T) {
		certPEM, keyPEM := signSPIFFELeaf(t, ca, "spiffe://cluster.local/ns/default/sa/unknown-falco")
		clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)

		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: rootCAs, Certificates: []tls.Certificate{clientCert},
		}}}
		resp, doErr := client.Get(targetURL) //nolint:noctx // test-only, short-lived
		if resp != nil {
			defer resp.Body.Close()
		}
		require.Error(t, doErr, "an unknown SPIFFE identity must be rejected at the TLS layer, not just CA-verified")
	})

	t.Run("cert with no SPIFFE URI SAN is rejected", func(t *testing.T) {
		clientCertPEM, clientKeyPEM := signLeaf(t, ca, "artifact-client", nil, x509.ExtKeyUsageClientAuth)
		clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		require.NoError(t, err)

		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: rootCAs, Certificates: []tls.Certificate{clientCert},
		}}}
		resp, doErr := client.Get(targetURL) //nolint:noctx // test-only, short-lived
		if resp != nil {
			defer resp.Body.Close()
		}
		require.Error(t, doErr)
	})

	t.Run("each request is restricted to the certificate namespace", func(t *testing.T) {
		const otherNamespace = "tenant-b"
		const artifactName = "scope-test"
		const pluginKind = "plugin"
		const rootDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		require.NoError(t, fakeClient.Create(ctx, &instancev1alpha1.Falco{
			ObjectMeta: metav1.ObjectMeta{Name: "other-falco", Namespace: otherNamespace},
		}))
		for _, namespace := range []string{"default", otherNamespace} {
			for _, kind := range []string{pluginKind, "rulesfile"} {
				goos, goarch, platform := "", "", ""
				if kind == pluginKind {
					goos, goarch, platform = "linux", "amd64", "linux-amd64"
				}
				path := artifactcache.BlobPath(cache.Dir(), kind, namespace+"/"+artifactName, rootDigest, goos, goarch)
				require.NoError(t, cache.Store(path, []byte(namespace+"/"+kind), 0o644))
				require.NoError(t, cache.Set(kind, namespace, artifactName, platform, path))
			}
		}

		certPEM, keyPEM := signSPIFFELeaf(t, ca, "spiffe://cluster.local/ns/default/sa/known-falco")
		clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)
		transport := &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: rootCAs, Certificates: []tls.Certificate{clientCert},
		}}
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}

		for _, kind := range []string{pluginKind, "rulesfile"} {
			t.Run(kind, func(t *testing.T) {
				for _, tc := range []struct {
					name, namespace, artifactName, query string
					headers                              map[string]string
					wantStatus                           int
				}{
					{name: "own namespace", namespace: "default", wantStatus: http.StatusOK},
					{name: "own pinned revision", namespace: "default", query: "&digest=" + rootDigest, wantStatus: http.StatusOK},
					{name: "other namespace", namespace: otherNamespace, wantStatus: http.StatusForbidden},
					{name: "other pinned revision", namespace: otherNamespace, query: "&digest=" + rootDigest, wantStatus: http.StatusForbidden},
					{name: "other namespace with range", namespace: otherNamespace, headers: map[string]string{"Range": "bytes=0-3"}, wantStatus: http.StatusForbidden},
					{name: "other namespace conditional read", namespace: otherNamespace, headers: map[string]string{"If-Modified-Since": time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)}, wantStatus: http.StatusForbidden},
					{name: "encoded other namespace", namespace: "%74enant-b", wantStatus: http.StatusForbidden},
					{name: "query cannot override namespace", namespace: otherNamespace, query: "&namespace=default", wantStatus: http.StatusForbidden},
					{name: "missing artifact in other namespace", namespace: otherNamespace, artifactName: "missing", wantStatus: http.StatusForbidden},
				} {
					t.Run(tc.name, func(t *testing.T) {
						name := tc.artifactName
						if name == "" {
							name = artifactName
						}
						requestURL := "https://" + addr + "/v1/artifacts/" + kind + "s/" + tc.namespace + "/" + name + "?os=linux&arch=amd64" + tc.query
						req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, http.NoBody)
						require.NoError(t, err)
						for name, value := range tc.headers {
							req.Header.Set(name, value)
						}
						resp, err := client.Do(req)
						require.NoError(t, err, "a transport failure is not an authorization decision")
						defer resp.Body.Close()
						body, err := io.ReadAll(resp.Body)
						require.NoError(t, err)
						assert.Equal(t, tc.wantStatus, resp.StatusCode)
						if tc.wantStatus == http.StatusOK {
							assert.Equal(t, "default/"+kind, string(body))
						} else {
							assert.NotContains(t, string(body), otherNamespace+"/"+kind)
							assert.Empty(t, resp.Header.Get(artifact.ArtifactDigestHeader))
							assert.Empty(t, resp.Header.Get("Content-Range"))
						}
					})
				}
			})
		}
	})

	cancel()
	select {
	case startErr := <-errCh:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestAuthorizer_AuthorizeRequest(t *testing.T) {
	identity, err := url.Parse("spiffe://cluster.local/ns/default/sa/known-falco")
	require.NoError(t, err)
	leaf := &x509.Certificate{URIs: []*url.URL{identity}}
	authorizer := artifactserver.NewAuthorizer(nil, logr.Discard())

	for _, tc := range []struct {
		name      string
		tls       *tls.ConnectionState
		namespace string
		wantError bool
	}{
		{name: "no TLS", namespace: "default", wantError: true},
		{name: "unverified certificate", tls: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, namespace: "default", wantError: true},
		{name: "empty verified chain", tls: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}, namespace: "default", wantError: true},
		{name: "missing identity", tls: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}, namespace: "default", wantError: true},
		{name: "same namespace", tls: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}, namespace: "default"},
		{name: "other namespace", tls: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}, namespace: "other", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{TLS: tc.tls}
			err := authorizer.AuthorizeRequest(req, tc.namespace)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
