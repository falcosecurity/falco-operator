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

package falco

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"

	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

func getArtifactClientCertificate(t *testing.T, ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	t.Helper()
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"})
	err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, cert)
	return cert, err
}

func TestEnsureArtifactClientCertificate(t *testing.T) {
	ctx := context.Background()

	t.Run("mTLS disabled is a no-op", func(t *testing.T) {
		falco := createFalco(t, ctx, builders.NewFalco().WithName("test-cert-disabled").WithNamespace(testutil.TestNamespace).Build())
		reconciler := newTestReconciler()
		require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))

		_, err := getArtifactClientCertificate(t, ctx, falco.Namespace, artifactClientCertSecretName(falco))
		assert.True(t, errors.IsNotFound(err), "no Certificate should be created when mTLS is disabled")
	})

	t.Run("mTLS enabled creates a Certificate with SPIFFE SAN and owner reference", func(t *testing.T) {
		falco := createFalco(t, ctx, builders.NewFalco().WithName("test-cert-enabled").WithNamespace(testutil.TestNamespace).Build())
		reconciler := NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100),
			WithArtifactMTLS("my-cluster-issuer", "my-falco-operator-artifact-ca-bundle", 0, 0))

		require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))

		wantName := artifactClientCertSecretName(falco)
		cert, err := getArtifactClientCertificate(t, ctx, falco.Namespace, wantName)
		require.NoError(t, err)

		secretName, _, _ := unstructured.NestedString(cert.Object, "spec", "secretName")
		assert.Equal(t, wantName, secretName)

		issuerName, _, _ := unstructured.NestedString(cert.Object, "spec", "issuerRef", "name")
		assert.Equal(t, "my-cluster-issuer", issuerName)
		issuerKind, _, _ := unstructured.NestedString(cert.Object, "spec", "issuerRef", "kind")
		assert.Equal(t, "ClusterIssuer", issuerKind)

		uris, _, _ := unstructured.NestedStringSlice(cert.Object, "spec", "uris")
		require.Len(t, uris, 1)
		assert.Equal(t, fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s", falco.Namespace, falco.Name), uris[0])

		duration, _, _ := unstructured.NestedString(cert.Object, "spec", "duration")
		assert.Equal(t, DefaultArtifactClientCertDuration.String(), duration)
		renewBefore, _, _ := unstructured.NestedString(cert.Object, "spec", "renewBefore")
		assert.Equal(t, DefaultArtifactClientCertRenewBefore.String(), renewBefore)

		ownerRefs := cert.GetOwnerReferences()
		require.Len(t, ownerRefs, 1)
		assert.Equal(t, falco.Name, ownerRefs[0].Name)
		assert.Equal(t, "Falco", ownerRefs[0].Kind)
		require.NotNil(t, ownerRefs[0].Controller)
		assert.True(t, *ownerRefs[0].Controller)
	})

	t.Run("second call is idempotent", func(t *testing.T) {
		falco := createFalco(t, ctx, builders.NewFalco().WithName("test-cert-idempotent").WithNamespace(testutil.TestNamespace).Build())
		reconciler := NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100),
			WithArtifactMTLS("my-cluster-issuer", "my-falco-operator-artifact-ca-bundle", 0, 0))

		require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))
		require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))
	})

	t.Run("custom duration and renewBefore are honored", func(t *testing.T) {
		falco := createFalco(t, ctx, builders.NewFalco().WithName("test-cert-custom-duration").WithNamespace(testutil.TestNamespace).Build())
		reconciler := NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100),
			WithArtifactMTLS("my-cluster-issuer", "my-falco-operator-artifact-ca-bundle", 48*time.Hour, 12*time.Hour))

		require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))

		cert, err := getArtifactClientCertificate(t, ctx, falco.Namespace, artifactClientCertSecretName(falco))
		require.NoError(t, err)

		duration, _, _ := unstructured.NestedString(cert.Object, "spec", "duration")
		assert.Equal(t, "48h0m0s", duration)
		renewBefore, _, _ := unstructured.NestedString(cert.Object, "spec", "renewBefore")
		assert.Equal(t, "12h0m0s", renewBefore)
	})
}
