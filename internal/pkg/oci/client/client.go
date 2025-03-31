// Copyright (C) 2025 The Falco Authors
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
	"net/http"

	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const defaultClientID = "falco-artifact-operator"

// Option represents a client option function.
type Option func(*auth.Client)

// NewClient creates a new ORAS client with the provided options.
func NewClient(opts ...Option) *auth.Client {
	client := &auth.Client{
		Client: retry.DefaultClient,
		Header: http.Header{
			"User-Agent": {defaultClientID},
		},
		Cache:    auth.DefaultCache,
		ClientID: defaultClientID,
	}

	// Apply all provided options
	for _, opt := range opts {
		opt(client)
	}

	return client
}

// WithClientID configures the client with a custom client ID for OAuth2.
func WithClientID(clientID string) Option {
	return func(c *auth.Client) {
		c.ClientID = clientID
	}
}

// WithForceOAuth2 configures the client to always attempt OAuth2 authentication.
func WithForceOAuth2(force bool) Option {
	return func(c *auth.Client) {
		c.ForceAttemptOAuth2 = force
	}
}

// WithCredentialFunc configures the client with a custom credential function.
func WithCredentialFunc(credFunc auth.CredentialFunc) Option {
	return func(c *auth.Client) {
		c.Credential = credFunc
	}
}

// WithTransport configures the client with a custom HTTP transport.
func WithTransport(transport http.RoundTripper) Option {
	return func(c *auth.Client) {
		c.Client.Transport = transport
	}
}
