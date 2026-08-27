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

	cancel()
	select {
	case startErr := <-errCh:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}
