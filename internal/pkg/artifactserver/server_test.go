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
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactserver"
	"github.com/falcosecurity/falco-operator/internal/pkg/tlsutil"
)

func seedPlugin(t *testing.T, cache *artifactcache.Cache, ns, name, goos, goarch string, content []byte, perm fs.FileMode) {
	t.Helper()
	blobPath := artifactcache.BlobPath(cache.Dir(), "plugin", ns+"/"+name, "sha256:deadbeef", goos, goarch)
	require.NoError(t, artifactcache.Store(blobPath, content, perm))
	require.NoError(t, cache.Set("plugin", ns, name, goos+"-"+goarch, blobPath))
}

func seedRulesfile(t *testing.T, cache *artifactcache.Cache, name string, content []byte) {
	t.Helper()
	const ns = "default"
	blobPath := artifactcache.BlobPath(cache.Dir(), "rulesfile", ns+"/"+name, "sha256:deadbeef", "", "")
	require.NoError(t, artifactcache.Store(blobPath, content, 0o644))
	require.NoError(t, cache.Set("rulesfile", ns, name, "", blobPath))
}

// servePluginCase and serveRulesfileCase share this shape: seed the cache (or don't), issue one
// request against a fresh server, and check the response.
type serveCase struct {
	name string
	seed func(t *testing.T, cache *artifactcache.Cache) // nil means "leave the cache empty"

	method     string            // defaults to GET
	path       string            // appended to the httptest server's URL
	reqHeaders map[string]string // extra request headers, e.g. Range/If-Modified-Since

	wantStatus       int
	wantHeaders      map[string]string
	wantBodyContains string
	wantBodyEquals   string // when set, asserts exact body content instead of substring
}

func runServeCase(t *testing.T, tc *serveCase) {
	t.Helper()
	cache := artifactcache.NewCache(t.TempDir())
	require.NoError(t, cache.Load())
	if tc.seed != nil {
		tc.seed(t, cache)
	}

	ts := httptest.NewServer(artifactserver.New(cache).Handler())
	defer ts.Close()

	method := tc.method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(context.Background(), method, ts.URL+tc.path, http.NoBody)
	require.NoError(t, err)
	for key, val := range tc.reqHeaders {
		req.Header.Set(key, val)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, tc.wantStatus, resp.StatusCode)
	for key, want := range tc.wantHeaders {
		assert.Equal(t, want, resp.Header.Get(key), "header %q", key)
	}
	if tc.wantBodyContains != "" {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), tc.wantBodyContains)
	}
	if tc.wantBodyEquals != "" {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, tc.wantBodyEquals, string(body))
	}
}

func TestServer_ServePlugin(t *testing.T) {
	tests := []serveCase{
		{
			name: "returns the cached binary with its mode header",
			seed: func(t *testing.T, cache *artifactcache.Cache) {
				seedPlugin(t, cache, "default", "json", "linux", "amd64", []byte("binary-content"), 0o755)
			},
			path:       "/v1/artifacts/plugins/default/json?os=linux&arch=amd64",
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Content-Type":    "application/octet-stream",
				"X-Artifact-Mode": "493", // 0o755 in decimal
			},
			wantBodyContains: "binary-content",
		},
		{
			name: "defaults os/arch to the server's own runtime when the query is omitted",
			seed: func(t *testing.T, cache *artifactcache.Cache) {
				seedPlugin(t, cache, "default", "json", runtime.GOOS, runtime.GOARCH, []byte("binary-content"), 0o755)
			},
			path:       "/v1/artifacts/plugins/default/json",
			wantStatus: http.StatusOK,
		},
		{
			name:       "not yet cached returns 503 with a Retry-After hint",
			path:       "/v1/artifacts/plugins/default/missing?os=linux&arch=amd64",
			wantStatus: http.StatusServiceUnavailable,
			wantHeaders: map[string]string{
				"Retry-After": "10",
			},
		},
		{
			name: "indexed but missing from disk returns 503",
			seed: func(t *testing.T, cache *artifactcache.Cache) {
				blobPath := artifactcache.BlobPath(cache.Dir(), "plugin", "default/json", "sha256:deadbeef", "linux", "amd64")
				require.NoError(t, cache.Set("plugin", "default", "json", "linux-amd64", blobPath)) // no Store call
			},
			path:       "/v1/artifacts/plugins/default/json?os=linux&arch=amd64",
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "path missing the name segment returns 400",
			path:       "/v1/artifacts/plugins/onlyns",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "non-GET method returns 405",
			method:     http.MethodPost,
			path:       "/v1/artifacts/plugins/default/json",
			wantStatus: http.StatusMethodNotAllowed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { runServeCase(t, &tt) })
	}
}

func TestServer_ServeRulesfile(t *testing.T) {
	tests := []serveCase{
		{
			name: "returns the cached rulesfile with its mode header",
			seed: func(t *testing.T, cache *artifactcache.Cache) {
				seedRulesfile(t, cache, "myrules", []byte("rule content"))
			},
			path:       "/v1/artifacts/rulesfiles/default/myrules",
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"X-Artifact-Mode": "420", // 0o644 in decimal
			},
			wantBodyContains: "rule content",
		},
		{
			name:       "not yet cached returns 503",
			path:       "/v1/artifacts/rulesfiles/default/missing",
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "path missing the name segment returns 400",
			path:       "/v1/artifacts/rulesfiles/onlyns",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "non-GET method returns 405",
			method:     http.MethodPost,
			path:       "/v1/artifacts/rulesfiles/default/myrules",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name: "Range request returns partial content",
			seed: func(t *testing.T, cache *artifactcache.Cache) {
				seedRulesfile(t, cache, "myrules", []byte("rule content"))
			},
			path:           "/v1/artifacts/rulesfiles/default/myrules",
			reqHeaders:     map[string]string{"Range": "bytes=0-3"},
			wantStatus:     http.StatusPartialContent,
			wantBodyEquals: "rule",
		},
		{
			name: "If-Modified-Since in the future returns 304",
			seed: func(t *testing.T, cache *artifactcache.Cache) {
				seedRulesfile(t, cache, "myrules", []byte("rule content"))
			},
			path: "/v1/artifacts/rulesfiles/default/myrules",
			reqHeaders: map[string]string{
				"If-Modified-Since": time.Now().Add(time.Hour).UTC().Format(http.TimeFormat),
			},
			wantStatus: http.StatusNotModified,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { runServeCase(t, &tt) })
	}
}

// reserveAddr opens a listener on an ephemeral loopback port, closes it immediately, and
// returns the address it was bound to — for handing to code that wants to bind it itself.
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

// TestServer_Start_ListensAndShutsDown starts the server in a goroutine, waits for it to accept
// connections, then cancels the context and confirms Start returns.
func TestServer_Start_ListensAndShutsDown(t *testing.T) {
	cache := artifactcache.NewCache(t.TempDir())
	require.NoError(t, cache.Load())
	addr := reserveAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- artifactserver.New(cache).Start(ctx, addr) }()

	waitForListening(t, addr)

	cancel()

	select {
	case startErr := <-errCh:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

// recordingSink is a minimal, thread-safe logr.LogSink that records every Info call's
// accumulated name (from WithName) and key-values (from WithValues plus the call site),
// so a test can assert on what a request handler actually logged. mu is shared across every
// value returned by WithName/WithValues, since logr chains create new sink instances that
// must all serialize access to the same underlying records slice.
type recordingSink struct {
	mu      *sync.Mutex
	name    string
	values  []any
	records *[]loggedRecord
}

type loggedRecord struct {
	name          string
	msg           string
	keysAndValues []any
}

func newRecordingLogger() (logr.Logger, *[]loggedRecord) {
	records := &[]loggedRecord{}
	return logr.New(&recordingSink{mu: &sync.Mutex{}, records: records}), records
}

func (s *recordingSink) Init(logr.RuntimeInfo) {}
func (s *recordingSink) Enabled(int) bool      { return true }
func (s *recordingSink) Error(err error, msg string, keysAndValues ...any) {
	s.Info(0, msg, append(append([]any{}, keysAndValues...), "error", err)...)
}

func (s *recordingSink) Info(_ int, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := append(append([]any{}, s.values...), keysAndValues...)
	*s.records = append(*s.records, loggedRecord{name: s.name, msg: msg, keysAndValues: all})
}

func (s *recordingSink) WithValues(keysAndValues ...any) logr.LogSink {
	return &recordingSink{
		mu: s.mu, name: s.name,
		values:  append(append([]any{}, s.values...), keysAndValues...),
		records: s.records,
	}
}

func (s *recordingSink) WithName(name string) logr.LogSink {
	newName := name
	if s.name != "" {
		newName = s.name + "." + name
	}
	return &recordingSink{mu: s.mu, name: newName, values: s.values, records: s.records}
}

// valueFor searches a logr key-values slice for key and returns its value.
func valueFor(t *testing.T, keysAndValues []any, key string) any {
	t.Helper()
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		if keysAndValues[i] == key {
			return keysAndValues[i+1]
		}
	}
	t.Fatalf("key %q not found in %v", key, keysAndValues)
	return nil
}

// TestServer_Start_RequestLogsAreNamedAndCarryNodeHeader verifies that requests handled via a
// real Start call use the named logger (WithName("artifact-server")) and log the X-Node-Name
// header (set by artifact.Fetcher.FetchOCI).
func TestServer_Start_RequestLogsAreNamedAndCarryNodeHeader(t *testing.T) {
	cache := artifactcache.NewCache(t.TempDir())
	require.NoError(t, cache.Load())
	seedPlugin(t, cache, "default", "json", "linux", "amd64", []byte("bin"), 0o755)

	addr := reserveAddr(t)
	logger, records := newRecordingLogger()
	ctx, cancel := context.WithCancel(ctrllog.IntoContext(context.Background(), logger))

	errCh := make(chan error, 1)
	go func() { errCh <- artifactserver.New(cache).Start(ctx, addr) }()

	waitForListening(t, addr)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		fmt.Sprintf("http://%s/v1/artifacts/plugins/default/json?os=linux&arch=amd64", addr), http.NoBody)
	require.NoError(t, err)
	req.Header.Set(artifactserver.NodeNameHeader, "worker-7")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	cancel()
	select {
	case startErr := <-errCh:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	var found bool
	for _, rec := range *records {
		if rec.msg != "Artifact request received" {
			continue
		}
		found = true
		assert.Contains(t, rec.name, "artifact-server", "request logger must carry the name Start set")
		assert.Equal(t, "worker-7", valueFor(t, rec.keysAndValues, "node"))
	}
	assert.True(t, found, "expected an 'Artifact request received' log entry")
}

// TestServer_Start_AddressInUse is Start's one remaining failure mode: cache-dir creation
// moved to Cache.Load (covered by TestCache_Load_BlobsDirCannotBeCreated), so binding an
// already-occupied address is the only way left to make Start itself return an error.
func TestServer_Start_AddressInUse(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	cache := artifactcache.NewCache(t.TempDir())
	require.NoError(t, cache.Load())

	startErr := artifactserver.New(cache).Start(context.Background(), l.Addr().String())
	require.Error(t, startErr)
	assert.Contains(t, startErr.Error(), "artifact server")
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

// TestServer_Start_MTLS covers the full mTLS round trip: a client with no certificate is
// rejected at the handshake, a client with a CA-signed certificate succeeds, and — the CA
// hot-reload regression case — rotating the trusted CA on disk (as cert-manager renewing the
// CA Certificate would) is picked up by a *new* connection without restarting the server.
func TestServer_Start_MTLS(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "test-root-ca")

	serverCertPEM, serverKeyPEM := signLeaf(t, ca, "artifact-server", []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth)
	clientCertPEM, clientKeyPEM := signLeaf(t, ca, "artifact-client", nil, x509.ExtKeyUsageClientAuth)

	caFile := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caFile, ca.certPEM, 0o600))
	serverCertFile := filepath.Join(dir, "tls.crt")
	serverKeyFile := filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(serverCertFile, serverCertPEM, 0o600))
	require.NoError(t, os.WriteFile(serverKeyFile, serverKeyPEM, 0o600))

	certWatcher, err := certwatcher.New(serverCertFile, serverKeyFile)
	require.NoError(t, err)
	caWatcher, err := tlsutil.NewCAWatcher(caFile)
	require.NoError(t, err)

	cache := artifactcache.NewCache(t.TempDir())
	require.NoError(t, cache.Load())
	seedRulesfile(t, cache, "secure", []byte("secure content"))

	addr := reserveAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := artifactserver.New(cache, artifactserver.WithTLS(certWatcher), artifactserver.WithClientCAs(caWatcher))
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, addr) }()

	waitForListening(t, addr)

	url := "https://" + addr + "/v1/artifacts/rulesfiles/default/secure"
	rootCAs := certPool(t, ca.certPEM)

	t.Run("no client cert is rejected at handshake", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}}}
		resp, doErr := client.Get(url) //nolint:noctx // test-only, short-lived
		if resp != nil {
			defer resp.Body.Close()
		}
		require.Error(t, doErr)
	})

	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	require.NoError(t, err)

	t.Run("valid client cert succeeds", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: rootCAs, Certificates: []tls.Certificate{clientCert},
		}}}
		resp, doErr := client.Get(url) //nolint:noctx // test-only, short-lived
		require.NoError(t, doErr)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("CA hot-reload: a cert signed by a rotated CA is accepted without a restart", func(t *testing.T) {
		caCtx, caCancel := context.WithCancel(context.Background())
		defer caCancel()
		caErrCh := make(chan error, 1)
		// A short poll interval keeps this deterministic: an atomic rename-over-an-existing
		// path doesn't reliably fire an fsnotify event on every platform, so the test can't
		// depend on that alone within a short timeout.
		go func() { caErrCh <- caWatcher.WithWatchInterval(50 * time.Millisecond).Start(caCtx) }()

		newCA := newTestCA(t, "test-root-ca-v2")
		newClientCertPEM, newClientKeyPEM := signLeaf(t, newCA, "artifact-client-v2", nil, x509.ExtKeyUsageClientAuth)
		newClientCert, keyErr := tls.X509KeyPair(newClientCertPEM, newClientKeyPEM)
		require.NoError(t, keyErr)

		tmp := caFile + ".tmp"
		require.NoError(t, os.WriteFile(tmp, newCA.certPEM, 0o600))
		require.NoError(t, os.Rename(tmp, caFile))

		require.Eventually(t, func() bool {
			// The server's own certificate is unchanged (still signed by the original ca) —
			// only its ClientCAs trust pool is being rotated, so the test client keeps
			// trusting the server via the original rootCAs and only swaps its own client
			// certificate to one signed by the new CA.
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: rootCAs, Certificates: []tls.Certificate{newClientCert},
			}}}
			resp, getErr := client.Get(url) //nolint:noctx // test-only, short-lived
			if getErr != nil {
				return false
			}
			defer resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		}, 2*time.Second, 20*time.Millisecond, "server did not pick up the rotated CA")

		caCancel()
	})

	cancel()
	select {
	case startErr := <-errCh:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

// TestServer_Start_ClientCAsWithoutTLS_ReturnsConfigError guards against silently serving
// plaintext when mTLS was requested but no server certificate was configured to go with it.
func TestServer_Start_ClientCAsWithoutTLS_ReturnsConfigError(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "test-ca")
	caFile := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caFile, ca.certPEM, 0o600))

	caWatcher, err := tlsutil.NewCAWatcher(caFile)
	require.NoError(t, err)

	cache := artifactcache.NewCache(t.TempDir())
	require.NoError(t, cache.Load())

	srv := artifactserver.New(cache, artifactserver.WithClientCAs(caWatcher))
	startErr := srv.Start(context.Background(), reserveAddr(t))
	require.Error(t, startErr)
	assert.Contains(t, startErr.Error(), "client CAs configured without a TLS certificate watcher")
}
