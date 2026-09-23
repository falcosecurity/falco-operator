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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArtifactServiceURL(t *testing.T) {
	for _, tc := range []struct {
		name, domain, want string
		secure             bool
	}{
		{name: "plain", domain: "cluster.local", want: "http://custom-service.operator-system.svc.cluster.local:8082"},
		{name: "TLS", domain: "cluster.local", secure: true, want: "https://custom-service.operator-system.svc.cluster.local:8082"},
		{name: "custom plain", domain: "cluster.example", want: "http://custom-service.operator-system.svc.cluster.example:8082"},
		{name: "custom TLS", domain: "cluster.example", secure: true, want: "https://custom-service.operator-system.svc.cluster.example:8082"},
	} {
		for _, address := range []string{":8082", "0.0.0.0:8082", "127.0.0.1:8082", "[::]:8082", "[::1]:8082"} {
			t.Run(tc.name+"/"+address, func(t *testing.T) {
				got, err := artifactServiceURL("operator-system", "custom-service", tc.domain, address, tc.secure)
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			})
		}
	}
	for _, address := range []string{"8082", "0.0.0.0", "::1:8082", "[::1"} {
		t.Run("invalid/"+address, func(t *testing.T) {
			got, err := artifactServiceURL("operator-system", "custom-service", "cluster.local", address, false)
			require.Error(t, err)
			assert.Empty(t, got)
		})
	}
	for _, domain := range []string{"", " ", ".cluster.local", "cluster/local", "cluster..local"} {
		t.Run("invalid domain/"+domain, func(t *testing.T) {
			got, err := artifactServiceURL("operator-system", "custom-service", domain, ":8082", true)
			require.Error(t, err)
			assert.Empty(t, got)
		})
	}
}
