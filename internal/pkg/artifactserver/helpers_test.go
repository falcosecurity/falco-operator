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

package artifactserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
)

func seedRulesfile(t *testing.T, cache *artifactcache.Cache, name string, content []byte) {
	t.Helper()
	const ns = "default"
	blobPath := artifactcache.BlobPath(cache.Dir(), string(artifact.KindRulesfile), ns+"/"+name, "sha256:deadbeef", "", "")
	require.NoError(t, cache.Store(blobPath, content, 0o644))
	require.NoError(t, cache.Set(string(artifact.KindRulesfile), ns, name, "", blobPath))
}

// reserveAddr opens a listener on an ephemeral loopback port, closes it immediately, and
// returns the address it was bound to, for handing to code that wants to bind it itself.
func reserveAddr(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// waitForListening blocks until addr accepts a bare TCP connection (regardless of whatever
// application-layer protocol, plaintext or TLS, is spoken on top), or fails the test.
func waitForListening(t *testing.T, addr string) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
	require.Eventually(t, func() bool {
		conn, dialErr := dialer.DialContext(context.Background(), "tcp", addr)
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 2*time.Second, 20*time.Millisecond, "server never started listening")
}

// --- mTLS test certificate helpers ---

// testCA is a self-signed CA certificate, along with the parsed cert and key needed to sign
// leaf certificates with it.
type testCA struct {
	certPEM []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, commonName string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return testCA{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert:    cert,
		key:     key,
	}
}

// signLeaf issues a leaf certificate signed by ca, returning cert+key PEM bytes. ipSANs is
// non-nil for a server cert (the IP the client dials); nil for a client cert (client-cert
// verification doesn't check hostname).
func signLeaf(t *testing.T, ca testCA, commonName string, ipSANs []net.IP, extKeyUsage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{extKeyUsage},
		IPAddresses:  ipSANs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func certPool(t *testing.T, certPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))
	return pool
}
