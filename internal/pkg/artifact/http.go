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
	"net"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/certwatcher"

	"github.com/falcosecurity/falco-operator/internal/pkg/tlsutil"
)

// DefaultDownloadTimeout bounds one complete download from the central artifact server.
const DefaultDownloadTimeout = 5 * time.Minute

// NewHTTPClient creates the client used to download from the central artifact server.
// Optional certificate and CA watchers are read on each new TLS connection.
func NewHTTPClient(timeout time.Duration, clientCert *certwatcher.CertWatcher, ca *tlsutil.CAWatcher) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if clientCert != nil || ca != nil {
		// http.Transport.TLSClientConfig is a single static *tls.Config shared across
		// connections; there is no client-side hook to re-read the trust pool or client cert
		// per connection. DialTLSContext instead builds a fresh tls.Config from the watchers'
		// current state on every new TCP connection, so a cert/CA reload takes effect the next
		// time a keep-alive connection is re-established.
		transport.DialTLSContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			conn, err := transport.DialContext(dialCtx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				host = addr
			}
			tlsConfig := &tls.Config{ServerName: host}
			if ca != nil {
				tlsConfig.RootCAs = ca.CertPool()
			}
			if clientCert != nil {
				tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return clientCert.GetCertificate(nil)
				}
			}
			// Custom TLS dialing bypasses the transport's handshake timeout, and its
			// context can outlive the request. Bound the handshake independently.
			handshakeCtx, cancel := context.WithTimeout(dialCtx, transport.TLSHandshakeTimeout)
			defer cancel()
			tlsConn := tls.Client(conn, tlsConfig)
			if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		}
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}
