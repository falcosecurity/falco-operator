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

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

func TestNewClientBearerIsolation(t *testing.T) {
	var tokenRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenRequests.Add(1)
			username, password, ok := r.BasicAuth()
			if !ok || username != "reader" || password != "test-password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"test-reader-token"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-reader-token" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="http://%s/token",service="test-registry"`, r.Host))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "http://")
	credential := auth.StaticCredential(host, auth.Credential{Username: "reader", Password: "test-password"})
	authorized := NewClient(WithCredentialFunc(credential))
	anonymous := NewClient()
	for _, tc := range []struct {
		name          string
		client        *auth.Client
		credentials   auth.CredentialFunc
		unauthorized  bool
		tokenRequests int32
	}{
		{name: "authorized client obtains a token", client: authorized, tokenRequests: 1},
		{name: "authorized client reuses its token", client: authorized, tokenRequests: 1},
		{name: "existing anonymous client authenticates independently", client: anonymous, unauthorized: true, tokenRequests: 2},
		{name: "new anonymous client authenticates independently", unauthorized: true, tokenRequests: 3},
		{
			name: "wrong credentials authenticate independently", unauthorized: true, tokenRequests: 4,
			credentials: auth.StaticCredential(host, auth.Credential{Username: "reader", Password: "wrong-password"}),
		},
		{name: "failed callers leave the authorized token intact", client: authorized, tokenRequests: 4},
		{name: "new authorized client obtains its own token", credentials: credential, tokenRequests: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.client
			if client == nil {
				client = NewClient(WithCredentialFunc(tc.credentials))
			}
			status, err := requestStatus(t.Context(), client, server.URL)
			if tc.unauthorized {
				var unauthorized *errcode.ErrorResponse
				require.ErrorAs(t, err, &unauthorized, "another client must authenticate independently")
				assert.Equal(t, http.StatusUnauthorized, unauthorized.StatusCode)
			} else {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, status)
			}
			assert.Equal(t, tc.tokenRequests, tokenRequests.Load())
		})
	}
}

func TestNewClientTransportIsolation(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	before := NewClient()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	t.Cleanup(transport.CloseIdleConnections)
	insecure := NewClient(WithTransport(transport))
	tests := []struct {
		name     string
		client   *auth.Client
		insecure bool
		parallel bool
	}{
		{name: "default client created before custom transport", client: before},
		{name: "default client created after custom transport"},
		{name: "client with custom transport", client: insecure, insecure: true},
		{name: "concurrent custom client 1", insecure: true, parallel: true},
		{name: "concurrent default client 1", parallel: true},
		{name: "concurrent custom client 2", insecure: true, parallel: true},
		{name: "concurrent default client 2", parallel: true},
		{name: "concurrent custom client 3", insecure: true, parallel: true},
		{name: "concurrent default client 3", parallel: true},
		{name: "concurrent custom client 4", insecure: true, parallel: true},
		{name: "concurrent default client 4", parallel: true},
		{name: "concurrent custom client 5", insecure: true, parallel: true},
		{name: "concurrent default client 5", parallel: true},
		{name: "concurrent custom client 6", insecure: true, parallel: true},
		{name: "concurrent default client 6", parallel: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.parallel {
				t.Parallel()
			}
			client := tc.client
			if client == nil {
				client = NewClient()
				if tc.insecure {
					client = NewClient(WithTransport(transport))
				}
			}
			status, err := requestStatus(t.Context(), client, server.URL)
			if tc.insecure {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, status)
			} else {
				var authorityErr x509.UnknownAuthorityError
				assert.ErrorAs(t, err, &authorityErr)
			}
		})
	}
}

func TestNewClientRetriesAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{name: "service unavailable", status: http.StatusServiceUnavailable},
		{name: "rate limited", status: http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, defaultClientID, r.UserAgent())
				if requests.Add(1) == 1 {
					w.WriteHeader(tc.status)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(server.Close)
			client := NewClient()
			status, err := requestStatus(t.Context(), client, server.URL)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, status)
			assert.EqualValues(t, 2, requests.Load(), "a transient registry error must still be retried")

			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			_, err = requestStatus(ctx, client, server.URL)
			assert.ErrorIs(t, err, context.Canceled)
			assert.EqualValues(t, 2, requests.Load(), "a canceled request must not reach the registry")
		})
	}
}

func requestStatus(ctx context.Context, client *auth.Client, url string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// ORAS retries bodyless GETs; http.NoBody is non-nil without a GetBody callback.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gocritic // Preserve ORAS's retry path.
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, err
}
