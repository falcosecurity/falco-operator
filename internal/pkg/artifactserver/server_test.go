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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/tlsutil"
)

func seedPlugin(t *testing.T, cache *artifactcache.Cache, ns, name, goos, goarch string, content []byte) {
	t.Helper()
	blobPath := artifactcache.BlobPath(cache.Dir(), string(artifact.KindPlugin), ns+"/"+name, "sha256:deadbeef", goos, goarch)
	require.NoError(t, cache.Store(blobPath, content, 0o755))
	require.NoError(t, cache.Set(string(artifact.KindPlugin), ns, name, goos+"-"+goarch, blobPath))
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

	ts := httptest.NewServer(New(cache).Handler())
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
				seedPlugin(t, cache, "default", "json", "linux", "amd64", []byte("binary-content"))
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
				seedPlugin(t, cache, "default", "json", runtime.GOOS, runtime.GOARCH, []byte("binary-content"))
			},
			path:       "/v1/artifacts/plugins/default/json",
			wantStatus: http.StatusOK,
		},
		{
			name: "a binary cached for another OS is not served",
			seed: func(t *testing.T, cache *artifactcache.Cache) {
				seedPlugin(t, cache, "default", "json", "darwin", "amd64", []byte("other-os-binary"))
			},
			path:           "/v1/artifacts/plugins/default/json?os=linux&arch=amd64",
			wantStatus:     http.StatusServiceUnavailable,
			wantHeaders:    map[string]string{"Retry-After": "10"},
			wantBodyEquals: "artifact not yet available; retry shortly\n",
		},
		{
			name: "a binary cached for another architecture is not served",
			seed: func(t *testing.T, cache *artifactcache.Cache) {
				seedPlugin(t, cache, "default", "json", "linux", "arm64", []byte("other-architecture-binary"))
			},
			path:           "/v1/artifacts/plugins/default/json?os=linux&arch=amd64",
			wantStatus:     http.StatusServiceUnavailable,
			wantHeaders:    map[string]string{"Retry-After": "10"},
			wantBodyEquals: "artifact not yet available; retry shortly\n",
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
				blobPath := artifactcache.BlobPath(cache.Dir(), string(artifact.KindPlugin), "default/json", "sha256:deadbeef", "linux", "amd64")
				require.NoError(t, cache.Set(string(artifact.KindPlugin), "default", "json", "linux-amd64", blobPath)) // no Store call
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

// TestServer_Start_ListensAndShutsDown starts the server in a goroutine, waits for it to accept
// connections, then cancels the context and confirms Start returns.
func TestServer_Start_ListensAndShutsDown(t *testing.T) {
	cache := artifactcache.NewCache(t.TempDir())
	require.NoError(t, cache.Load())
	addr := reserveAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- New(cache).Start(ctx, addr) }()

	waitForListening(t, addr)

	cancel()

	select {
	case startErr := <-errCh:
		require.NoError(t, startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestServer_Start_PodRouting(t *testing.T) {
	const servingValue = "true"
	for _, bindFailure := range []bool{false, true} {
		name := "publishes after bind and withdraws on shutdown"
		if bindFailure {
			name = "bind failure never publishes the Pod"
		}
		t.Run(name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "operator", Name: "current", UID: "current-uid",
				Labels: map[string]string{"app": "operator", ServingLabel: servingValue},
			}}
			service := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "artifacts"},
				Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "operator", ServingLabel: servingValue}},
			}
			cl := fake.NewClientBuilder().WithObjects(pod, service).Build()
			cache := artifactcache.NewCache(t.TempDir())
			require.NoError(t, cache.Load())
			seedPlugin(t, cache, "tenant", "routing-plugin", "linux", "amd64", []byte("cached-plugin"))
			srv := New(cache, WithPodRouting(cl, &corev1.ObjectReference{
				Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID,
			}, service.Name, true))
			require.NoError(t, srv.ResetRouting(t.Context()))
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
			assert.NotContains(t, pod.Labels, ServingLabel, "restart must clear stale routing before manager startup")

			addr := reserveAddr(t)
			if bindFailure {
				listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
				require.NoError(t, err)
				defer listener.Close()
				require.Error(t, srv.Start(t.Context(), listener.Addr().String()))
				require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
				assert.NotContains(t, pod.Labels, ServingLabel)
				return
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- srv.Start(ctx, addr) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(2 * time.Second):
					t.Error("server did not stop")
				}
				require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(pod), pod))
				assert.NotContains(t, pod.Labels, ServingLabel)
			})
			require.Eventually(t, func() bool {
				return cl.Get(ctx, client.ObjectKeyFromObject(pod), pod) == nil && pod.Labels[ServingLabel] == servingValue
			}, 2*time.Second, 10*time.Millisecond)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				fmt.Sprintf("http://%s/v1/artifacts/plugins/tenant/routing-plugin?os=linux&arch=amd64", addr), http.NoBody)
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "cached-plugin", string(body))

			// Repair a late publication by the former leader without restarting either server.
			previous := pod.DeepCopy()
			previous.Name, previous.UID, previous.ResourceVersion = "previous", "previous-uid", ""
			require.NoError(t, cl.Create(ctx, previous))
			delete(pod.Labels, ServingLabel)
			require.NoError(t, cl.Update(ctx, pod))
			require.Eventually(t, func() bool {
				return cl.Get(ctx, client.ObjectKeyFromObject(pod), pod) == nil &&
					cl.Get(ctx, client.ObjectKeyFromObject(previous), previous) == nil &&
					pod.Labels[ServingLabel] == servingValue && previous.Labels[ServingLabel] == ""
			}, 7*time.Second, 20*time.Millisecond)
		})
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

func (s *recordingSink) Enabled(int) bool { return true }

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
	seedPlugin(t, cache, "default", "json", "linux", "amd64", []byte("bin"))

	addr := reserveAddr(t)
	logger, records := newRecordingLogger()
	ctx, cancel := context.WithCancel(ctrllog.IntoContext(context.Background(), logger))

	errCh := make(chan error, 1)
	go func() { errCh <- New(cache).Start(ctx, addr) }()

	waitForListening(t, addr)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		fmt.Sprintf("http://%s/v1/artifacts/plugins/default/json?os=linux&arch=amd64", addr), http.NoBody)
	require.NoError(t, err)
	req.Header.Set(artifact.NodeNameHeader, "worker-7")
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

// TestServer_Start_AddressInUse verifies that an occupied port fails startup.
func TestServer_Start_AddressInUse(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	cache := artifactcache.NewCache(t.TempDir())
	require.NoError(t, cache.Load())

	startErr := New(cache).Start(context.Background(), l.Addr().String())
	require.Error(t, startErr)
	assert.Contains(t, startErr.Error(), "artifact server")
}

// TestServer_Start_MTLS covers the full mTLS round trip: a client with no certificate is
// rejected at the handshake, a client with a CA-signed certificate succeeds, and the CA
// hot-reload regression case (rotating the trusted CA on disk, as cert-manager renewing the
// CA Certificate would) is picked up by a *new* connection without restarting the server.
func TestServer_Start_MTLS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint16
	}{
		{name: "TLS 1.2", version: tls.VersionTLS12},
		{name: "TLS 1.3", version: tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
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

			srv := New(cache, WithTLS(certWatcher), WithClientCAs(caWatcher))
			errCh := make(chan error, 1)
			go func() { errCh <- srv.Start(ctx, addr) }()

			waitForListening(t, addr)

			url := "https://" + addr + "/v1/artifacts/rulesfiles/default/secure"
			rootCAs := certPool(t, ca.certPEM)

			t.Run("no client cert is rejected at handshake", func(t *testing.T) {
				httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tc.version, MaxVersion: tc.version}}}
				resp, doErr := httpClient.Get(url) //nolint:noctx // test-only, short-lived
				if resp != nil {
					defer resp.Body.Close()
				}
				require.Error(t, doErr)
			})

			clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
			require.NoError(t, err)

			t.Run("valid client cert succeeds", func(t *testing.T) {
				httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
					RootCAs: rootCAs, Certificates: []tls.Certificate{clientCert},
					MinVersion: tc.version, MaxVersion: tc.version,
				}}}
				resp, doErr := httpClient.Get(url) //nolint:noctx // test-only, short-lived
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

				t.Run("CA renewal with the same key preserves existing server and client certificates", func(t *testing.T) {
					renewed := *ca.cert
					renewed.SerialNumber = new(big.Int).Add(ca.cert.SerialNumber, big.NewInt(1))
					renewed.NotAfter = ca.cert.NotAfter.Add(time.Hour)
					der, renewErr := x509.CreateCertificate(rand.Reader, &renewed, &renewed, &ca.key.PublicKey, ca.key)
					require.NoError(t, renewErr)
					renewedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
					renewedPool := certPool(t, renewedPEM)
					require.False(t, rootCAs.Equal(renewedPool), "the CA certificate must actually change")

					tmp := caFile + ".tmp"
					require.NoError(t, os.WriteFile(tmp, renewedPEM, 0o600))
					require.NoError(t, os.Rename(tmp, caFile))
					require.Eventually(t, func() bool {
						return caWatcher.CertPool().Equal(renewedPool)
					}, 2*time.Second, 20*time.Millisecond, "server did not load the renewed CA")

					// Both peers trust only the renewed CA, but still present their original leaf certificates.
					transport := &http.Transport{
						TLSClientConfig:   &tls.Config{RootCAs: renewedPool, Certificates: []tls.Certificate{clientCert}, MinVersion: tc.version, MaxVersion: tc.version},
						DisableKeepAlives: true,
					}
					t.Cleanup(transport.CloseIdleConnections)
					httpClient := &http.Client{Transport: transport, Timeout: 2 * time.Second}
					req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
					require.NoError(t, reqErr)
					resp, getErr := httpClient.Do(req)
					require.NoError(t, getErr)
					defer resp.Body.Close()
					assert.Equal(t, http.StatusOK, resp.StatusCode)
					body, readErr := io.ReadAll(resp.Body)
					require.NoError(t, readErr)
					assert.Equal(t, "secure content", string(body))
				})

				newCA := newTestCA(t, "test-root-ca-v2")
				newClientCertPEM, newClientKeyPEM := signLeaf(t, newCA, "artifact-client-v2", nil, x509.ExtKeyUsageClientAuth)
				newClientCert, keyErr := tls.X509KeyPair(newClientCertPEM, newClientKeyPEM)
				require.NoError(t, keyErr)

				tmp := caFile + ".tmp"
				require.NoError(t, os.WriteFile(tmp, newCA.certPEM, 0o600))
				require.NoError(t, os.Rename(tmp, caFile))

				require.Eventually(t, func() bool {
					// The server's own certificate is unchanged (still signed by the original ca);
					// only its ClientCAs trust pool is being rotated, so the test client keeps
					// trusting the server via the original rootCAs and only swaps its own client
					// certificate to one signed by the new CA.
					httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
						RootCAs: rootCAs, Certificates: []tls.Certificate{newClientCert},
						MinVersion: tc.version, MaxVersion: tc.version,
					}}}
					resp, getErr := httpClient.Get(url) //nolint:noctx // test-only, short-lived
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
		})
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

	srv := New(cache, WithClientCAs(caWatcher))
	startErr := srv.Start(context.Background(), reserveAddr(t))
	require.Error(t, startErr)
	assert.Contains(t, startErr.Error(), "client CAs configured without a TLS certificate watcher")
}

func TestServer_ServeRequestedDigest(t *testing.T) {
	const amd64Arch = "amd64"
	const arm64Arch = "arm64"
	const expectedDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const otherDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	for _, variant := range []struct{ artifactType, goos, goarch, platform, path string }{
		{string(artifact.KindPlugin), "linux", amd64Arch, "linux-amd64", "/v1/artifacts/plugins/ns/name?os=linux&arch=amd64"},
		{string(artifact.KindPlugin), "linux", arm64Arch, "linux-arm64", "/v1/artifacts/plugins/ns/name?os=linux&arch=arm64"},
		{string(artifact.KindRulesfile), "", "", "", "/v1/artifacts/rulesfiles/ns/name?"},
	} {
		t.Run(variant.artifactType+"/"+variant.platform, func(t *testing.T) {
			cache := artifactcache.NewCache(t.TempDir())
			require.NoError(t, cache.Load())
			blob := artifactcache.BlobPath(cache.Dir(), variant.artifactType, "repo:tag", expectedDigest, variant.goos, variant.goarch)
			content := "bytes for " + variant.artifactType + "/" + variant.platform
			require.NoError(t, cache.Store(blob, []byte(content), 0o644))
			require.NoError(t, cache.Set(variant.artifactType, "ns", "name", variant.platform, blob))
			// A plugin index digest is shared across platforms, but the extracted binaries are not.
			if variant.artifactType == string(artifact.KindPlugin) {
				otherArch := arm64Arch
				if variant.goarch == arm64Arch {
					otherArch = amd64Arch
				}
				otherPath := artifactcache.BlobPath(cache.Dir(), string(artifact.KindPlugin), "repo:tag", expectedDigest, "linux", otherArch)
				require.NoError(t, cache.Store(otherPath, []byte("wrong architecture"), 0o755))
				require.NoError(t, cache.Set(string(artifact.KindPlugin), "ns", "name", "linux-"+otherArch, otherPath))
			}
			handler := New(cache).Handler()
			for _, tc := range []struct {
				name, query string
				status      int
				confirmed   bool
			}{
				{"expected revision", "&digest=" + expectedDigest, http.StatusOK, true},
				{"different revision", "&digest=" + otherDigest, http.StatusServiceUnavailable, false},
				{"empty digest", "&digest=", http.StatusBadRequest, false},
				{"malformed digest", "&digest=sha256:invalid", http.StatusBadRequest, false},
				{"duplicate digest", "&digest=" + expectedDigest + "&digest=" + otherDigest, http.StatusBadRequest, false},
				{"legacy client", "", http.StatusOK, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, variant.path+tc.query, http.NoBody)
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					require.Equal(t, tc.status, response.Code)
					if tc.status == http.StatusOK {
						require.Equal(t, content, response.Body.String())
					} else {
						require.NotContains(t, response.Body.String(), content)
					}
					if tc.confirmed {
						require.Equal(t, expectedDigest, response.Header().Get(artifact.ArtifactDigestHeader))
					} else {
						require.Empty(t, response.Header().Get(artifact.ArtifactDigestHeader))
					}
					if tc.status == http.StatusServiceUnavailable {
						require.Equal(t, "10", response.Header().Get("Retry-After"))
					}
				})
			}
		})
	}
}

// TestServer_httpServer_DefaultTimeouts asserts the constructed http.Server carries the
// baseline hardening timeouts unconditionally.
func TestServer_httpServer_DefaultTimeouts(t *testing.T) {
	s := &Server{}
	srv := s.httpServer(":0", func(net.Listener) context.Context { return context.Background() })

	assert.Equal(t, DefaultReadHeaderTimeout, srv.ReadHeaderTimeout)
	assert.Equal(t, DefaultReadTimeout, srv.ReadTimeout)
	assert.Equal(t, DefaultWriteTimeout, srv.WriteTimeout)
	assert.Equal(t, DefaultIdleTimeout, srv.IdleTimeout)
	assert.Equal(t, DefaultMaxHeaderBytes, srv.MaxHeaderBytes)
}

func routingPod(name, namespace, installation string, serving bool) *corev1.Pod {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: namespace, UID: types.UID(namespace + "/" + name),
		Labels: map[string]string{"app": installation, "unrelated": "preserve"},
	}}
	if serving {
		pod.Labels[ServingLabel] = servingValue
	}
	return pod
}

func routingService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "artifacts"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "operator", ServingLabel: servingValue}},
	}
}

func routingReference(pod *corev1.Pod) corev1.ObjectReference {
	return corev1.ObjectReference{Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
}

func TestPodRouting_Reconcile(t *testing.T) {
	for _, exclusive := range []bool{true, false} {
		name := "without leader election"
		if exclusive {
			name = "with leader election"
		}
		t.Run(name, func(t *testing.T) {
			own := routingPod("current", "operator", "operator", false)
			previous := routingPod("previous", "operator", "operator", true)
			previous.Labels["pod-template-hash"] = "old-replicaset"
			own.Labels["pod-template-hash"] = "new-replicaset"
			otherRelease := routingPod("other-release", "operator", "another-installation", true)
			otherNamespace := routingPod("other-namespace", "elsewhere", "operator", true)
			service := routingService()
			patches := 0
			cl := fake.NewClientBuilder().WithObjects(own, previous, otherRelease, otherNamespace, service).
				WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						patches++
						return cl.Patch(ctx, obj, patch, opts...)
					},
				}).Build()
			r := &podRouting{client: cl, pod: routingReference(own), service: service.Name, exclusive: exclusive}
			require.NoError(t, r.reconcile(t.Context()))
			for _, pod := range []*corev1.Pod{own, previous, otherRelease, otherNamespace} {
				require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
				assert.Equal(t, "preserve", pod.Labels["unrelated"])
				if pod.Name == previous.Name && exclusive {
					assert.NotContains(t, pod.Labels, ServingLabel)
				} else {
					assert.Equal(t, servingValue, pod.Labels[ServingLabel])
				}
			}
			before := patches
			require.NoError(t, r.reconcile(t.Context()))
			assert.Equal(t, before, patches, "steady state must not patch Pods")
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(service), service))
			assert.Equal(t, routingService().Spec.Selector, service.Spec.Selector)

			if exclusive {
				// A former leader's delayed publish can arrive after the first cleanup.
				previous.Labels[ServingLabel] = servingValue
				require.NoError(t, cl.Update(t.Context(), previous))
				require.NoError(t, r.reconcile(t.Context()))
				require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(previous), previous))
				assert.NotContains(t, previous.Labels, ServingLabel)
			}
		})
	}
}

func TestServer_ResetRouting(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		name := "same Pod after container restart"
		if replaced {
			name = "replacement Pod must not be modified"
		}
		t.Run(name, func(t *testing.T) {
			pod := routingPod("current", "operator", "operator", true)
			ref := routingReference(pod)
			if replaced {
				pod.UID = "new-uid"
			}
			cl := fake.NewClientBuilder().WithObjects(pod).Build()
			s := New(nil, WithPodRouting(cl, &ref, "artifacts", true))
			err := s.ResetRouting(t.Context())
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
			if replaced {
				require.ErrorContains(t, err, "has been replaced")
				assert.Equal(t, servingValue, pod.Labels[ServingLabel])
			} else {
				require.NoError(t, err)
				assert.NotContains(t, pod.Labels, ServingLabel)
			}
			assert.Equal(t, "preserve", pod.Labels["unrelated"])
		})
	}
	require.NoError(t, New(nil).ResetRouting(t.Context()))
	s := New(nil, WithPodRouting(nil, nil, "", true))
	require.ErrorContains(t, s.ResetRouting(t.Context()), "requires a client")
}

func TestPodRouting_InvalidService(t *testing.T) {
	for name, selector := range map[string]map[string]string{
		"missing serving selector":      {"app": "operator"},
		"missing installation selector": {ServingLabel: servingValue},
		"own Pod outside selector":      {"app": "different", ServingLabel: servingValue},
	} {
		t.Run(name, func(t *testing.T) {
			pod := routingPod("current", "operator", "operator", false)
			service := routingService()
			service.Spec.Selector = selector
			foreign := routingPod("foreign", "operator", "different", true)
			cl := fake.NewClientBuilder().WithObjects(pod, foreign, service).Build()
			r := &podRouting{client: cl, pod: routingReference(pod), service: service.Name, exclusive: true}
			require.Error(t, r.reconcile(t.Context()))
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
			assert.NotContains(t, pod.Labels, ServingLabel)
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(foreign), foreign))
			assert.Equal(t, servingValue, foreign.Labels[ServingLabel], "invalid routing must not disable another installation")
		})
	}
}

func TestPodRouting_APIFailureAndRecovery(t *testing.T) {
	for _, operation := range []string{"list", "withdraw", "publish"} {
		t.Run(operation, func(t *testing.T) {
			pod := routingPod("current", "operator", "operator", false)
			previous := routingPod("previous", "operator", "operator", true)
			failure := errors.New("API unavailable")
			cl := fake.NewClientBuilder().WithObjects(pod, previous, routingService()).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if operation == "list" && failure != nil {
							return failure
						}
						return cl.List(ctx, list, opts...)
					},
					Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						if failure != nil && ((operation == "withdraw" && obj.GetName() == previous.Name) ||
							(operation == "publish" && obj.GetName() == pod.Name)) {
							return failure
						}
						return cl.Patch(ctx, obj, patch, opts...)
					},
				}).Build()
			r := &podRouting{client: cl, pod: routingReference(pod), service: "artifacts", exclusive: true}
			require.ErrorIs(t, r.reconcile(t.Context()), failure)
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
			assert.NotContains(t, pod.Labels, ServingLabel)
			failure = nil
			require.NoError(t, r.reconcile(t.Context()))
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
			assert.Equal(t, servingValue, pod.Labels[ServingLabel])
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(previous), previous))
			assert.NotContains(t, previous.Labels, ServingLabel)
		})
	}
}

func TestPodRouting_ConflictPreservesConcurrentLabels(t *testing.T) {
	pod := routingPod("current", "operator", "operator", false)
	attempts := 0
	cl := fake.NewClientBuilder().WithObjects(pod, routingService()).WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			attempts++
			if attempts == 1 {
				var current corev1.Pod
				require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(obj), &current))
				current.Labels["concurrent"] = "preserve"
				require.NoError(t, cl.Update(ctx, &current))
				return k8serrors.NewConflict(schema.GroupResource{Resource: "pods"}, pod.Name, errors.New("concurrent edit"))
			}
			return cl.Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	r := &podRouting{client: cl, pod: routingReference(pod), service: "artifacts", exclusive: true}
	require.NoError(t, r.reconcile(t.Context()))
	assert.Equal(t, 2, attempts)
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
	assert.Equal(t, servingValue, pod.Labels[ServingLabel])
	assert.Equal(t, "preserve", pod.Labels["concurrent"])
}

func TestPodRouting_CancellationDuringAPIRead(t *testing.T) {
	pod := routingPod("current", "operator", "operator", false)
	reading := make(chan struct{})
	cl := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
			close(reading)
			<-ctx.Done()
			return ctx.Err()
		},
	}).Build()
	r := &podRouting{client: cl, pod: routingReference(pod), service: "artifacts", exclusive: true}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.run(ctx)
	}()
	select {
	case <-reading:
	case <-time.After(routingInterval + 2*time.Second):
		t.Fatal("routing did not start its API read")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("routing did not stop after its API read was canceled")
	}
}

func TestPodRouting_CopiesPodIdentity(t *testing.T) {
	pod := routingPod("current", "operator", "operator", false)
	ref := routingReference(pod)
	cl := fake.NewClientBuilder().WithObjects(pod).Build()
	s := New(nil, WithPodRouting(cl, &ref, "artifacts", true))
	ref.Name, ref.UID = "replacement", "replacement-uid"
	assert.Equal(t, routingReference(pod), s.routing.pod)
}

// TestServer_MetricLabelsAreTheLowercaseKind pins the type label the request metrics carry: dashboards and alerts
// select on "plugin" and "rulesfile", which the handler derives from the kind.
func TestServer_MetricLabelsAreTheLowercaseKind(t *testing.T) {
	handler := New(artifactcache.NewCache(t.TempDir())).Handler()
	rejected := func(label string) float64 {
		m := &dto.Metric{}
		require.NoError(t, requestsTotal.WithLabelValues(label, strconv.Itoa(http.StatusMethodNotAllowed)).Write(m))
		return m.GetCounter().GetValue()
	}
	for path, label := range map[string]string{
		"/v1/artifacts/plugins/ns/name":    "plugin",
		"/v1/artifacts/rulesfiles/ns/name": "rulesfile",
	} {
		t.Run(label, func(t *testing.T) {
			before := rejected(label)

			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, http.NoBody))

			assert.InDelta(t, before+1, rejected(label), 0)
		})
	}
}
