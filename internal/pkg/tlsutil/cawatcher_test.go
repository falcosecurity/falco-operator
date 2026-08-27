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

package tlsutil_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/tlsutil"
)

// generateTestCA returns a PEM-encoded self-signed CA certificate with the given common name,
// along with the parsed certificate itself (for verifying pool membership without relying on
// the deprecated CertPool.Subjects()).
func generateTestCA(t *testing.T, commonName string) (pemBytes []byte, cert *x509.Certificate) {
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

	cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert
}

// trusts reports whether pool currently trusts cert (used instead of the deprecated
// CertPool.Subjects() to check pool membership).
func trusts(cert *x509.Certificate, pool *x509.CertPool) bool {
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

func TestNewCAWatcher(t *testing.T) {
	tests := []struct {
		name            string
		writeFile       func(t *testing.T, path string)
		wantErrContains string
	}{
		{
			name: "valid PEM succeeds",
			writeFile: func(t *testing.T, path string) {
				pemBytes, _ := generateTestCA(t, "test-ca")
				require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
			},
		},
		{
			name:            "missing file errors",
			writeFile:       func(t *testing.T, path string) {},
			wantErrContains: "read CA file",
		},
		{
			name: "non-PEM garbage errors",
			writeFile: func(t *testing.T, path string) {
				require.NoError(t, os.WriteFile(path, []byte("not a pem file"), 0o600))
			},
			wantErrContains: "no valid certificates found",
		},
		{
			name: "empty file errors",
			writeFile: func(t *testing.T, path string) {
				require.NoError(t, os.WriteFile(path, []byte(""), 0o600))
			},
			wantErrContains: "no valid certificates found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ca.crt")
			tt.writeFile(t, path)

			w, err := tlsutil.NewCAWatcher(path)
			if tt.wantErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				assert.Nil(t, w)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, w)
			assert.NotNil(t, w.CertPool())
		})
	}
}

func TestCAWatcher_Start_ReloadsOnFileChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.crt")
	v1PEM, v1Cert := generateTestCA(t, "ca-v1")
	require.NoError(t, os.WriteFile(path, v1PEM, 0o600))

	w, err := tlsutil.NewCAWatcher(path)
	require.NoError(t, err)
	require.True(t, trusts(v1Cert, w.CertPool()), "initial pool must trust the v1 CA")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- w.Start(ctx) }()

	// Replace the CA file with a different cert, write-then-rename (as a Secret volume's
	// atomic symlink swap does), so the watcher's re-add-on-remove path gets exercised too.
	v2PEM, v2Cert := generateTestCA(t, "ca-v2")
	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, v2PEM, 0o600))
	require.NoError(t, os.Rename(tmp, path))

	require.Eventually(t, func() bool {
		return trusts(v2Cert, w.CertPool())
	}, 2*time.Second, 20*time.Millisecond, "CA pool was not reloaded after the file changed")
	assert.False(t, trusts(v1Cert, w.CertPool()), "old CA must no longer be trusted after reload")

	cancel()
	select {
	case startErr := <-errCh:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}
