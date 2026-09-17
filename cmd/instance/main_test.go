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
		name, want string
		secure     bool
	}{
		{name: "plain", want: "http://custom-service.operator-system.svc.cluster.local:8082"},
		{name: "TLS", secure: true, want: "https://custom-service.operator-system.svc.cluster.local:8082"},
	} {
		for _, address := range []string{":8082", "0.0.0.0:8082", "127.0.0.1:8082", "[::]:8082", "[::1]:8082"} {
			t.Run(tc.name+"/"+address, func(t *testing.T) {
				got, err := artifactServiceURL("operator-system", "custom-service", address, tc.secure)
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			})
		}
	}
	for _, address := range []string{"8082", "0.0.0.0", "::1:8082", "[::1"} {
		t.Run("invalid/"+address, func(t *testing.T) {
			got, err := artifactServiceURL("operator-system", "custom-service", address, false)
			require.Error(t, err)
			assert.Empty(t, got)
		})
	}
}
