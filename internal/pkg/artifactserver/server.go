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

// Package artifactserver provides the HTTP artifact cache server embedded in the
// falco-operator. It serves pre-extracted OCI artifact binaries that have been pulled
// and cached by the instance-level aggregator controllers.
//
// The server itself never contacts the OCI registry; it only reads from the local
// blob cache written by the Plugin and Rulesfile aggregator controllers.
package artifactserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/tlsutil"
)

// Default timeouts and limits applied unconditionally to the underlying http.Server.
const (
	// DefaultReadHeaderTimeout bounds how long a client may take sending request headers.
	DefaultReadHeaderTimeout = 5 * time.Second
	// DefaultReadTimeout bounds how long reading the entire request may take. Requests here
	// are small GETs with no body.
	DefaultReadTimeout = 15 * time.Second
	// DefaultWriteTimeout bounds how long writing the response may take, covering streaming
	// of artifact blobs up to tens of MB.
	DefaultWriteTimeout = 5 * time.Minute
	// DefaultIdleTimeout bounds how long an idle keep-alive connection is kept open.
	DefaultIdleTimeout = 2 * time.Minute
	// DefaultMaxHeaderBytes caps the total size of request headers, below Go's 1MiB default.
	DefaultMaxHeaderBytes = 32 * 1024
)

// Server is the artifact HTTP cache server embedded in the falco-operator.
// It serves binaries that the aggregator controllers have already pulled and cached,
// looked up through the same in-memory Cache the aggregator controllers write to.
type Server struct {
	cache       *artifactcache.Cache
	certWatcher *certwatcher.CertWatcher // nil = plain HTTP, the default; no behavior change
	clientCAs   *tlsutil.CAWatcher       // nil = no client-cert requirement
	authorizer  *Authorizer              // nil = no additional check beyond CA chain verification
	maxInflight int                      // 0 = unlimited
}

// Option configures optional Server behavior.
type Option func(*Server)

// WithTLS configures the server's own TLS identity via a hot-reloadable cert+key watcher.
// The caller is responsible for also registering cw with the manager (mgr.Add) so its
// reload loop actually runs.
func WithTLS(cw *certwatcher.CertWatcher) Option {
	return func(s *Server) { s.certWatcher = cw }
}

// WithClientCAs enables mTLS: the server requires and verifies a client certificate against
// caw's current trust pool, re-read on every new connection. Only takes effect together with
// WithTLS; Start returns a configuration error if client CAs are set without a cert watcher.
// The caller is responsible for also registering caw with the manager (mgr.Add).
func WithClientCAs(caw *tlsutil.CAWatcher) Option {
	return func(s *Server) { s.clientCAs = caw }
}

// WithAuthorizer adds an application-level check after standard mTLS chain verification: a's
// VerifyConnection runs for every connection, including resumed ones, rejecting a client
// certificate that is CA-signed but does not correspond to a known Falco instance. Only takes
// effect together with WithClientCAs.
func WithAuthorizer(a *Authorizer) Option {
	return func(s *Server) { s.authorizer = a }
}

// WithMaxConcurrentRequests limits how many blob transfers may be in flight simultaneously.
// When the limit is reached the server returns 503 with a jittered Retry-After header so
// clients spread their retries. Zero (the default) disables the limit.
func WithMaxConcurrentRequests(n int) Option {
	return func(s *Server) { s.maxInflight = n }
}

// New creates a Server that serves cached binaries indexed by cache. cache.Load must
// already have been called.
func New(cache *artifactcache.Cache, opts ...Option) *Server {
	s := &Server{cache: cache}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// httpServer builds the http.Server used by Start, with baseline timeout hardening applied
// unconditionally.
func (s *Server) httpServer(addr string, baseCtx func(net.Listener) context.Context) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		BaseContext:       baseCtx,
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       DefaultReadTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		IdleTimeout:       DefaultIdleTimeout,
		MaxHeaderBytes:    DefaultMaxHeaderBytes,
	}
}

// Start binds to addr and serves requests until ctx is canceled.
func (s *Server) Start(ctx context.Context, addr string) error {
	if s.clientCAs != nil && s.certWatcher == nil {
		return fmt.Errorf("artifact server: client CAs configured without a TLS certificate watcher")
	}

	logger := log.FromContext(ctx).WithName("artifact-server")
	// BaseContext returns a context carrying the named logger. Request handlers obtain their
	// logger from r.Context(), which descends from BaseContext's return value, not from
	// Start's own ctx variable.
	baseCtx := log.IntoContext(ctx, logger)

	srv := s.httpServer(addr, func(net.Listener) context.Context { return baseCtx })

	var tlsConfig *tls.Config
	if s.certWatcher != nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.certWatcher.GetCertificate}
				if s.clientCAs != nil {
					cfg.ClientCAs = s.clientCAs.CertPool()
					cfg.ClientAuth = tls.RequireAndVerifyClientCert
					if s.authorizer != nil {
						cfg.VerifyConnection = s.authorizer.VerifyConnection
					}
				}
				return cfg, nil
			},
		}
		srv.TLSConfig = tlsConfig
	}

	go func() { //nolint:gosec // shutdown watcher outlives ctx by design; it must wait for ctx.Done() before acting
		<-ctx.Done()
		_ = srv.Shutdown(context.Background()) //nolint:contextcheck // ctx is Done; Shutdown needs a live context to drain requests
	}()

	logger.Info("Artifact server listening", "addr", addr, "tls", tlsConfig != nil, "mtls", s.clientCAs != nil,
		"spiffeAuthz", s.authorizer != nil)
	var err error
	if tlsConfig != nil {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("artifact server: %w", err)
	}
	return nil
}

// limitConcurrency wraps next with a semaphore-based concurrency limit when maxInflight > 0.
// Excess requests receive a 503 with a jittered Retry-After so simultaneous retries spread out.
func (s *Server) limitConcurrency(next http.Handler) http.Handler {
	if s.maxInflight <= 0 {
		return next
	}
	sem := make(chan struct{}, s.maxInflight)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)
		default:
			delay := int(wait.Jitter(10*time.Second, 0.5).Seconds())
			w.Header().Set("Retry-After", strconv.Itoa(delay))
			http.Error(w, "server busy, retry shortly", http.StatusServiceUnavailable)
		}
	})
}

// Handler returns the HTTP request multiplexer. Exported for testing.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/artifacts/plugins/", s.servePlugin)
	mux.HandleFunc("/v1/artifacts/rulesfiles/", s.serveRulesfile)
	return s.limitConcurrency(mux)
}

// servePlugin handles GET /v1/artifacts/plugins/{namespace}/{name}?os=linux&arch=amd64
// The binary must already be cached by the Plugin aggregator controller.
func (s *Server) servePlugin(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		requestsTotal.WithLabelValues("plugin", strconv.Itoa(http.StatusMethodNotAllowed)).Inc()
		return
	}

	ns, name, ok := parsePath(r.URL.Path, "/v1/artifacts/plugins/")
	if !ok {
		http.Error(w, "path must be /v1/artifacts/plugins/{namespace}/{name}", http.StatusBadRequest)
		requestsTotal.WithLabelValues("plugin", strconv.Itoa(http.StatusBadRequest)).Inc()
		return
	}

	goos := queryDefault(r, "os", runtime.GOOS)
	goarch := queryDefault(r, "arch", runtime.GOARCH)

	ctx := r.Context()
	logger := log.FromContext(ctx).WithValues(
		"artifact", ns+"/"+name,
		"type", "plugin",
		"os", goos,
		"arch", goarch,
		"caller", r.RemoteAddr,
		"node", r.Header.Get(artifact.NodeNameHeader),
	)
	logger.V(1).Info("Artifact request received")

	platformKey := goos + "-" + goarch
	blobPath, ok := s.cache.Lookup("plugin", ns, name, platformKey)
	if !ok {
		cacheLookupsTotal.WithLabelValues("plugin", "miss").Inc()
		logger.Info("Plugin not yet cached; waiting for aggregator reconcile")
		w.Header().Set("Retry-After", "10")
		http.Error(w, "artifact not yet available; retry shortly", http.StatusServiceUnavailable)
		requestsTotal.WithLabelValues("plugin", strconv.Itoa(http.StatusServiceUnavailable)).Inc()
		requestDuration.WithLabelValues("plugin").Observe(time.Since(start).Seconds())
		return
	}
	cacheLookupsTotal.WithLabelValues("plugin", "hit").Inc()

	logger.V(1).Info("Serving plugin blob", "blob", blobPath)
	status := serveBlob(w, r, blobPath)
	requestsTotal.WithLabelValues("plugin", strconv.Itoa(status)).Inc()
	requestDuration.WithLabelValues("plugin").Observe(time.Since(start).Seconds())
}

// serveRulesfile handles GET /v1/artifacts/rulesfiles/{namespace}/{name}
// Rulesfiles are platform-agnostic; the binary must already be cached by the Rulesfile
// aggregator controller.
func (s *Server) serveRulesfile(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		requestsTotal.WithLabelValues("rulesfile", strconv.Itoa(http.StatusMethodNotAllowed)).Inc()
		return
	}

	ns, name, ok := parsePath(r.URL.Path, "/v1/artifacts/rulesfiles/")
	if !ok {
		http.Error(w, "path must be /v1/artifacts/rulesfiles/{namespace}/{name}", http.StatusBadRequest)
		requestsTotal.WithLabelValues("rulesfile", strconv.Itoa(http.StatusBadRequest)).Inc()
		return
	}

	ctx := r.Context()
	logger := log.FromContext(ctx).WithValues(
		"artifact", ns+"/"+name,
		"type", "rulesfile",
		"caller", r.RemoteAddr,
		"node", r.Header.Get(artifact.NodeNameHeader),
	)
	logger.V(1).Info("Artifact request received")

	blobPath, ok := s.cache.Lookup("rulesfile", ns, name, "")
	if !ok {
		cacheLookupsTotal.WithLabelValues("rulesfile", "miss").Inc()
		logger.Info("Rulesfile not yet cached; waiting for aggregator reconcile")
		w.Header().Set("Retry-After", "10")
		http.Error(w, "artifact not yet available; retry shortly", http.StatusServiceUnavailable)
		requestsTotal.WithLabelValues("rulesfile", strconv.Itoa(http.StatusServiceUnavailable)).Inc()
		requestDuration.WithLabelValues("rulesfile").Observe(time.Since(start).Seconds())
		return
	}
	cacheLookupsTotal.WithLabelValues("rulesfile", "hit").Inc()

	logger.V(1).Info("Serving rulesfile blob", "blob", blobPath)
	status := serveBlob(w, r, blobPath)
	requestsTotal.WithLabelValues("rulesfile", strconv.Itoa(status)).Inc()
	requestDuration.WithLabelValues("rulesfile").Observe(time.Since(start).Seconds())
}

// statusCapturingWriter wraps an http.ResponseWriter and records the status code written,
// since http.ServeContent does not return one.
type statusCapturingWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCapturingWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// serveBlob streams the cached blob at blobPath to w via http.ServeContent, which adds Range
// and If-Modified-Since/If-Range support. Blobs are content-addressed and immutable once
// written, so a Range read never races a concurrent write. The original file mode is sent in
// the X-Artifact-Mode header for the artifact-operator to apply when writing the file. Returns
// the status code that was ultimately written, for metrics.
func serveBlob(w http.ResponseWriter, r *http.Request, blobPath string) int {
	perm := artifactcache.ReadPerm(blobPath)

	f, err := os.Open(blobPath) //nolint:gosec // blobPath is derived from artifactcache.BlobPath(), not raw external input
	if err != nil {
		http.Error(w, "cached blob unavailable; retry shortly", http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "cached blob unavailable; retry shortly", http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Artifact-Mode", strconv.FormatUint(uint64(perm), 10))

	sw := &statusCapturingWriter{ResponseWriter: w, status: http.StatusOK}
	http.ServeContent(sw, r, filepath.Base(blobPath), stat.ModTime(), f)
	return sw.status
}

// parsePath splits a URL path of the form {prefix}{namespace}/{name} into namespace and name.
func parsePath(urlPath, prefix string) (namespace, name string, ok bool) {
	tail := strings.TrimPrefix(urlPath, prefix)
	parts := strings.SplitN(tail, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func queryDefault(r *http.Request, key, def string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	return def
}
