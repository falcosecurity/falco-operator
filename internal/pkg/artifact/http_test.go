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

package artifact

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"

	"github.com/falcosecurity/falco-operator/internal/pkg/tlsutil"
)

func TestArtifactHTTPClient_Defaults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{name: "default download timeout", timeout: DefaultDownloadTimeout, want: 5 * time.Minute},
		{name: "custom download timeout", timeout: 2 * time.Minute, want: 2 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := NewHTTPClient(tc.timeout, nil, nil)
			t.Cleanup(client.CloseIdleConnections)
			assert.Equal(t, tc.want, client.Timeout)
			transport := client.Transport.(*http.Transport)
			assert.NotSame(t, http.DefaultTransport, transport)
			assert.NotNil(t, transport.DialContext)
			assert.Nil(t, transport.DialTLSContext)
			assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
		})
	}
}

func TestArtifactHTTPClient_DownloadTimeoutAndRetry(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, phase := range []string{"headers", "body"} {
			name := "HTTP/" + phase
			if secure {
				name = "TLS/" + phase
			}
			t.Run(name, func(t *testing.T) {
				started, disconnected := make(chan struct{}), make(chan struct{})
				var stalled atomic.Bool
				stalled.Store(true)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set(ArtifactDigestHeader, testFetchDigest)
					if r.URL.Path == "/v1/artifacts/rulesfiles/ns/slow" && stalled.Load() {
						if phase == "body" {
							_, _ = io.WriteString(w, "incomplete")
							w.(http.Flusher).Flush()
						}
						close(started)
						<-r.Context().Done()
						close(disconnected)
						return
					}
					_, _ = io.WriteString(w, "complete rules")
				}))
				if secure {
					server.StartTLS()
				} else {
					server.Start()
				}
				t.Cleanup(server.Close)
				var ca *tlsutil.CAWatcher
				if secure {
					ca = newArtifactTestCAWatcher(t, server.Certificate().Raw)
				}
				client := NewHTTPClient(500*time.Millisecond, nil, ca)
				t.Cleanup(client.CloseIdleConnections)
				fetcher := &Fetcher{HTTPClient: client, ServerURL: server.URL}
				// This watchdog is longer than the client deadline: it must not be what
				// releases FetchOCI if the production timeout is accidentally removed.
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				result, err := fetcher.FetchOCI(ctx, "ns", "slow", TypeRulesfile, testFetchDigest)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.NoError(t, ctx.Err(), "the client, not the test watchdog, must cancel the request")
				assert.Empty(t, result.Content, "partial response bytes must never be installable")
				select {
				case <-started:
				default:
					t.Fatal("the intended stalled response was never reached")
				}
				select {
				case <-disconnected:
				case <-ctx.Done():
					t.Fatal("server did not observe client cancellation")
				}
				result, err = fetcher.FetchOCI(ctx, "ns", "healthy", TypeRulesfile, testFetchDigest)
				require.NoError(t, err, "a later request must succeed with the same client")
				assert.Equal(t, "complete rules", string(result.Content))
				stalled.Store(false)
				result, err = fetcher.FetchOCI(ctx, "ns", "slow", TypeRulesfile, testFetchDigest)
				require.NoError(t, err, "the original artifact must recover without recreating the client")
				assert.Equal(t, "complete rules", string(result.Content))
			})
		}
	}
}

func TestArtifactHTTPClient_TLSHandshakeDeadline(t *testing.T) {
	for _, tc := range []struct {
		name             string
		handshakeTimeout time.Duration
		callerTimeout    time.Duration
		wantCallerErr    error
	}{
		{name: "transport deadline", handshakeTimeout: 100 * time.Millisecond, callerTimeout: 5 * time.Second},
		{name: "earlier caller deadline", handshakeTimeout: 5 * time.Second, callerTimeout: 100 * time.Millisecond, wantCallerErr: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Trigger the custom TLS path; the handshake stalls before certificates are read.
			client := NewHTTPClient(time.Minute, &certwatcher.CertWatcher{}, nil)
			t.Cleanup(client.CloseIdleConnections)
			transport := client.Transport.(*http.Transport)
			transport.TLSHandshakeTimeout = tc.handshakeTimeout
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() { _ = clientConn.Close() })
			t.Cleanup(func() { _ = serverConn.Close() })
			dialed := false
			transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return clientConn, nil
			}
			ctx, cancel := context.WithTimeout(t.Context(), tc.callerTimeout)
			defer cancel()
			conn, err := transport.DialTLSContext(ctx, "tcp", "example.test:443")
			assert.True(t, dialed, "custom TLS must reuse the transport's bounded TCP dialer")
			assert.Nil(t, conn)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.ErrorIs(t, ctx.Err(), tc.wantCallerErr, "the earlier deadline must cancel the handshake")
			_, err = serverConn.Read(make([]byte, 1))
			assert.ErrorIs(t, err, io.EOF, "failed handshake must close the underlying connection")
		})
	}
}

func TestArtifactHTTPClient_ClientCertificate(t *testing.T) {
	for _, tc := range []struct {
		name        string
		certificate bool
		wantErr     string
	}{
		{name: "watcher presents client certificate", certificate: true},
		{name: "missing client certificate is rejected", wantErr: "certificate required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Len(t, r.TLS.PeerCertificates, 1)
				_, _ = io.WriteString(w, "authenticated")
			}))
			// This test checks certificate presentation by the watcher; server-side trust and
			// identity authorization are covered by the artifactserver mTLS tests.
			server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
			server.StartTLS()
			t.Cleanup(server.Close)
			ca := newArtifactTestCAWatcher(t, server.Certificate().Raw)
			var watcher *certwatcher.CertWatcher
			if tc.certificate {
				dir := t.TempDir()
				certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
				key, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))
				require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600))
				watcher, err = certwatcher.New(certPath, keyPath)
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() { done <- watcher.Start(ctx) }()
				t.Cleanup(func() { cancel(); require.NoError(t, <-done) })
			}
			client := NewHTTPClient(time.Second, watcher, ca)
			t.Cleanup(client.CloseIdleConnections)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
			require.NoError(t, err)
			resp, err := client.Do(req)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			defer resp.Body.Close()
			content, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "authenticated", string(content))
		})
	}
}

func newArtifactTestCAWatcher(t *testing.T, certDER []byte) *tlsutil.CAWatcher {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600))
	watcher, err := tlsutil.NewCAWatcher(path)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- watcher.Start(ctx) }()
	t.Cleanup(func() { cancel(); require.NoError(t, <-done) })
	return watcher
}
