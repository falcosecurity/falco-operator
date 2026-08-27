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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
