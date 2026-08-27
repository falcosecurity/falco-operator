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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// createTestScheme creates a runtime scheme with corev1 types registered.
func createTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	return scheme
}

func TestNewManager(t *testing.T) {
	t.Run("creates manager with namespace", func(t *testing.T) {
		scheme := createTestScheme(t)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		manager := NewManager(fakeClient, "test-namespace")
		require.NotNil(t, manager)
		assert.Equal(t, "test-namespace", manager.namespace)
		assert.NotNil(t, manager.client)
		assert.NotNil(t, manager.ociPuller)
	})

	t.Run("WithOCIPuller sets custom puller", func(t *testing.T) {
		scheme := createTestScheme(t)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		mockPuller := &puller.MockOCIPuller{}
		manager := NewManagerWithOptions(fakeClient, "ns", WithOCIPuller(mockPuller))
		require.NotNil(t, manager)
		assert.Equal(t, mockPuller, manager.ociPuller)
	})
}
