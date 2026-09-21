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

package puller

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote/retry"
)

func TestTransportFor(t *testing.T) {
	t.Run("returns nil for nil options", func(t *testing.T) {
		assert.Nil(t, TransportFor(nil))
	})

	t.Run("returns nil when InsecureSkipVerify is false", func(t *testing.T) {
		assert.Nil(t, TransportFor(&RegistryOptions{}))
	})

	t.Run("returns nil when only PlainHTTP is set", func(t *testing.T) {
		assert.Nil(t, TransportFor(&RegistryOptions{PlainHTTP: true}))
	})

	t.Run("returns a retry-wrapped transport with InsecureSkipVerify set when requested", func(t *testing.T) {
		rt := TransportFor(&RegistryOptions{InsecureSkipVerify: true})
		require.NotNil(t, rt)

		retryTransport, ok := rt.(*retry.Transport)
		require.True(t, ok, "expected *retry.Transport, got %T", rt)
		base, ok := retryTransport.Base.(*http.Transport)
		require.True(t, ok, "expected the retry transport's base to be *http.Transport, got %T", retryTransport.Base)
		require.NotNil(t, base.TLSClientConfig)
		assert.True(t, base.TLSClientConfig.InsecureSkipVerify)
	})
}
