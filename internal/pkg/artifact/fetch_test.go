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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetcher_FetchOCI(t *testing.T) {
	tests := []struct {
		name            string
		artifactType    Type
		nodeName        string
		handler         http.HandlerFunc
		wantErrContains string
		wantContent     string
		wantPerm        int
		wantNodeHeader  string // "" means: assert the header is absent entirely
	}{
		{
			name:         "plugin request includes os/arch query and node header",
			artifactType: TypePlugin,
			nodeName:     "node-1",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "linux", r.URL.Query().Get("os"))
				assert.Equal(t, "amd64", r.URL.Query().Get("arch"))
				w.Header().Set("X-Artifact-Mode", "493") // 0o755
				_, _ = w.Write([]byte("binary-content"))
			},
			wantContent:    "binary-content",
			wantPerm:       0o755,
			wantNodeHeader: "node-1",
		},
		{
			name:         "rulesfile request has no os/arch query",
			artifactType: TypeRulesfile,
			nodeName:     "node-2",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.URL.Query().Get("os"))
				assert.Empty(t, r.URL.Query().Get("arch"))
				w.Header().Set("X-Artifact-Mode", "420") // 0o644
				_, _ = w.Write([]byte("rule content"))
			},
			wantContent:    "rule content",
			wantPerm:       0o644,
			wantNodeHeader: "node-2",
		},
		{
			name:         "empty NodeName omits the header entirely",
			artifactType: TypeRulesfile,
			nodeName:     "",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("x"))
			},
			wantContent:    "x",
			wantPerm:       0o755, // no X-Artifact-Mode header set by this handler → default
			wantNodeHeader: "",
		},
		{
			name:         "missing X-Artifact-Mode header defaults to 0o755",
			artifactType: TypeRulesfile,
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("x"))
			},
			wantContent: "x",
			wantPerm:    0o755,
		},
		{
			name:         "unparseable X-Artifact-Mode header defaults to 0o755",
			artifactType: TypeRulesfile,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Artifact-Mode", "not-a-number")
				_, _ = w.Write([]byte("x"))
			},
			wantContent: "x",
			wantPerm:    0o755,
		},
		{
			// RetryableError.Error() forwards the wrapped error's message regardless of retryability.
			name:         "non-200 status returns an error",
			artifactType: TypeRulesfile,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wantErrContains: "returned 503",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nodeHeaderSeen string
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nodeHeaderSeen = r.Header.Get(NodeNameHeader)
				tt.handler(w, r)
			}))
			srv.Start()
			defer srv.Close()

			f := &Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client(), NodeName: tt.nodeName}
			result, err := f.FetchOCI(context.Background(), "ns", "name", tt.artifactType)

			if tt.wantErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantContent, string(result.Content))
			assert.Equal(t, tt.wantPerm, int(result.Perm))
			h := sha256.Sum256([]byte(tt.wantContent))
			assert.Equal(t, hex.EncodeToString(h[:]), result.ContentHash)

			if tt.wantNodeHeader == "" {
				assert.Empty(t, nodeHeaderSeen, "NodeNameHeader must be omitted when NodeName is empty")
			} else {
				assert.Equal(t, tt.wantNodeHeader, nodeHeaderSeen)
			}
		})
	}
}

func TestFetcher_FetchOCI_UnsupportedType(t *testing.T) {
	f := &Fetcher{ServerURL: "http://example.invalid", HTTPClient: http.DefaultClient}
	_, err := f.FetchOCI(context.Background(), "ns", "name", TypeConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support type")
}

func TestFetcher_FetchOCI_RequestError(t *testing.T) {
	// A ServerURL containing a raw control character makes http.NewRequestWithContext fail to build the request.
	// The resulting error is permanent, not retryable.
	f := &Fetcher{ServerURL: "http://\x7f", HTTPClient: http.DefaultClient}
	_, err := f.FetchOCI(context.Background(), "ns", "name", TypeRulesfile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build artifact server request")
	var retryErr *RetryableError
	assert.NotErrorAs(t, err, &retryErr, "a build-request failure must not be retryable")
}

func TestFetcher_FetchOCI_ClientDoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // closed before use: any request against it fails at the transport level

	f := &Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.FetchOCI(context.Background(), "ns", "name", TypeRulesfile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "artifact server request for ns/name")
	// A transport-level failure is retryable; this test only checks the error message text.
}

// errBodyTransport returns a 200 response whose body always errors on read.
type errBodyTransport struct{}

func (errBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(iotest.ErrReader(errors.New("body read error"))),
		Header:     make(http.Header),
	}, nil
}

func TestFetcher_FetchOCI_BodyReadError(t *testing.T) {
	// A body-read failure is permanent and not retryable.
	f := &Fetcher{ServerURL: "http://example.invalid", HTTPClient: &http.Client{Transport: errBodyTransport{}}}
	_, err := f.FetchOCI(context.Background(), "ns", "name", TypeRulesfile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read artifact server response body")
	var retryErr *RetryableError
	assert.NotErrorAs(t, err, &retryErr, "a body-read failure must not be retryable")
}

// TestFetcher_FetchOCI_Retryable asserts FetchOCI makes exactly one attempt (never blocking
// on a retry loop), and that transient failures come back as *RetryableError (with RetryAfter
// populated from the server's header when present) while permanent failures don't.
func TestFetcher_FetchOCI_Retryable(t *testing.T) {
	t.Run("503 with Retry-After header", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		f := &Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client()}
		_, err := f.FetchOCI(context.Background(), "ns", "name", TypeRulesfile)
		require.Error(t, err)

		var retryErr *RetryableError
		require.ErrorAs(t, err, &retryErr)
		assert.Equal(t, 5*time.Second, retryErr.RetryAfter)
		assert.EqualValues(t, 1, calls.Load(), "FetchOCI must make exactly one attempt")
	})

	t.Run("503 without Retry-After header", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		f := &Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client()}
		_, err := f.FetchOCI(context.Background(), "ns", "name", TypeRulesfile)
		require.Error(t, err)

		var retryErr *RetryableError
		require.ErrorAs(t, err, &retryErr)
		assert.Zero(t, retryErr.RetryAfter)
	})

	t.Run("transport error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close() // closed before use: any request against it fails at the transport level

		f := &Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client()}
		_, err := f.FetchOCI(context.Background(), "ns", "name", TypeRulesfile)
		require.Error(t, err)

		var retryErr *RetryableError
		require.ErrorAs(t, err, &retryErr)
		assert.Zero(t, retryErr.RetryAfter)
	})

	t.Run("permanent 400 is not retryable", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer srv.Close()

		f := &Fetcher{ServerURL: srv.URL, HTTPClient: srv.Client()}
		_, err := f.FetchOCI(context.Background(), "ns", "name", TypeRulesfile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "returned 400")

		var retryErr *RetryableError
		assert.NotErrorAs(t, err, &retryErr)
		assert.EqualValues(t, 1, calls.Load())
	})
}

func TestRequeueDelay(t *testing.T) {
	t.Run("non-retryable error", func(t *testing.T) {
		_, ok := RequeueDelay(errors.New("permanent failure"))
		assert.False(t, ok)
	})

	t.Run("RetryableError with a server-advertised RetryAfter", func(t *testing.T) {
		base := 7 * time.Second
		delay, ok := RequeueDelay(&RetryableError{Err: errors.New("x"), RetryAfter: base})
		require.True(t, ok)
		// wait.Jitter(base, 0.3) returns a value in [base, 1.3*base).
		assert.GreaterOrEqual(t, delay, base)
		assert.Less(t, delay, base+base*3/10+time.Millisecond)
	})

	t.Run("RetryableError with no RetryAfter falls back to a jittered default", func(t *testing.T) {
		delay, ok := RequeueDelay(&RetryableError{Err: errors.New("x")})
		require.True(t, ok)
		// wait.Jitter(DefaultRetryDelay, 0.5) returns a value in [DefaultRetryDelay,
		// 1.5*DefaultRetryDelay).
		assert.GreaterOrEqual(t, delay, DefaultRetryDelay)
		assert.Less(t, delay, DefaultRetryDelay+DefaultRetryDelay/2)
	})
}
