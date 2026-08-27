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
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// verifyConnectionTimeout bounds the client-identity lookup performed by VerifyConnection.
// tls.Config.VerifyConnection carries no context or deadline of its own.
const verifyConnectionTimeout = 5 * time.Second

// Authorizer checks that a client's SPIFFE URI SAN corresponds to a Falco instance that
// actually exists. Chain verification alone cannot distinguish one instance's identity from
// another, since every per-instance certificate is signed by the same CA.
type Authorizer struct {
	reader client.Reader // cache-backed; the manager's own client
	logger logr.Logger
}

// NewAuthorizer returns an Authorizer backed by reader, expected to be the manager's
// cache-backed client. logger records rejections distinctly from other TLS handshake failures.
func NewAuthorizer(reader client.Reader, logger logr.Logger) *Authorizer {
	return &Authorizer{reader: reader, logger: logger.WithName("artifact-server-authz")}
}

// VerifyConnection implements tls.Config.VerifyConnection, which runs for every connection,
// including resumed ones, after chain verification has already succeeded. cs.PeerCertificates
// is therefore guaranteed non-empty when this runs during a real handshake.
func (a *Authorizer) VerifyConnection(cs tls.ConnectionState) error { //nolint:gocritic // must match tls.Config.VerifyConnection's exact signature
	if len(cs.PeerCertificates) == 0 {
		return errors.New("artifact server: no verified client certificate chain")
	}

	leaf := cs.PeerCertificates[0]
	namespace, name, err := parseSPIFFEURI(leaf.URIs)
	if err != nil {
		a.logger.Info("Rejecting client: certificate has no valid SPIFFE URI SAN", "error", err.Error())
		return fmt.Errorf("artifact server: client certificate missing a valid SPIFFE URI SAN: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), verifyConnectionTimeout)
	defer cancel()

	var falco instancev1alpha1.Falco
	if err := a.reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &falco); err != nil {
		a.logger.Info("Rejecting client: SPIFFE identity does not match a known Falco instance",
			"namespace", namespace, "name", name, "error", err.Error())
		return fmt.Errorf("artifact server: client identity %s/%s does not correspond to a known Falco instance: %w",
			namespace, name, err)
	}

	return nil
}

// parseSPIFFEURI extracts namespace/name from the first SPIFFE URI SAN matching
// spiffe://<trust-domain>/ns/<namespace>/sa/<name>. The trust domain is not checked.
func parseSPIFFEURI(uris []*url.URL) (namespace, name string, err error) {
	for _, u := range uris {
		if u == nil || u.Scheme != "spiffe" {
			continue
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) == 4 && parts[0] == "ns" && parts[2] == "sa" && parts[1] != "" && parts[3] != "" {
			return parts[1], parts[3], nil
		}
	}
	return "", "", fmt.Errorf("no URI SAN matching spiffe://<trust-domain>/ns/<namespace>/sa/<name>")
}
