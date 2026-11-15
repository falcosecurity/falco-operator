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

package azure

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func createTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, authenticationv1.AddToScheme(scheme))
	return scheme
}

// tokenSubResourceName is the "token" SubResourceCreate name mintServiceAccountToken's own
// TokenRequest call targets -- named once here so the two interceptors below that filter on it
// don't repeat the literal.
const tokenSubResourceName = "token"

func TestMintServiceAccountToken(t *testing.T) {
	const namespace = "falco"
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "acr-refresher", Namespace: namespace}}

	t.Run("returns the token from a successful TokenRequest", func(t *testing.T) {
		// The controller-runtime fake client (pinned version, go.mod) natively simulates
		// SubResource("token").Create for a ServiceAccount that exists, returning a fixed
		// "fake-token" -- confirmed by direct experiment before writing this test, not
		// assumed. No interceptor needed for this path.
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(sa).Build()

		token, err := mintServiceAccountToken(context.Background(), fakeClient, namespace, "acr-refresher", "api://AzureADTokenExchange")
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("wraps the underlying error when the ServiceAccount does not exist", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(createTestScheme(t)).Build()

		_, err := mintServiceAccountToken(context.Background(), fakeClient, namespace, "missing", "api://AzureADTokenExchange")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mint token for serviceaccount falco/missing")
	})

	t.Run("propagates the requested audience and surfaces an empty token as an error", func(t *testing.T) {
		// Exercises the request path via an interceptor rather than the fake client's default
		// stub, to assert the audience is actually threaded through, and that
		// mintServiceAccountToken itself guards against an empty Status.Token (e.g. a
		// misbehaving or future fake/test double that "succeeds" without setting one) rather
		// than silently returning "".
		var gotAudiences []string
		fakeClient := fake.NewClientBuilder().
			WithScheme(createTestScheme(t)).
			WithObjects(sa).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourceCreate: func(_ context.Context, _ client.Client, subResourceName string, _ client.Object, subResource client.Object, _ ...client.SubResourceCreateOption) error {
					if subResourceName != tokenSubResourceName {
						return nil
					}
					tr := subResource.(*authenticationv1.TokenRequest) //nolint:forcetypeassert // fake test double, shape is controlled by this test
					gotAudiences = tr.Spec.Audiences
					return nil // Status.Token deliberately left empty
				},
			}).
			Build()

		token, err := mintServiceAccountToken(context.Background(), fakeClient, namespace, "acr-refresher", "api://AzureADTokenExchange")
		require.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "empty token")
		assert.Equal(t, []string{"api://AzureADTokenExchange"}, gotAudiences)
	})

	t.Run("requests exactly the audience, expiration, and target the caller supplied -- nothing else", func(t *testing.T) {
		// The full TokenRequest shape, captured via interceptor rather than asserted against
		// the fake client's own (opaque) default behavior: the audience, a 600-second
		// (tokenTTL) expiration, and a ServiceAccount name/namespace matching exactly what the
		// caller passed in -- no other namespace or name can reach this call, since
		// mintServiceAccountToken takes namespace and name as plain string parameters supplied
		// by its own callers (see resolveCredential), not sourced from anything on the
		// TokenRequest object itself that a user-controlled value could redirect.
		var gotObjKey client.ObjectKey
		var gotExpirationSeconds *int64
		fakeClient := fake.NewClientBuilder().
			WithScheme(createTestScheme(t)).
			WithObjects(sa).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourceCreate: func(_ context.Context, _ client.Client, subResourceName string, obj client.Object, subResource client.Object, _ ...client.SubResourceCreateOption) error {
					if subResourceName != tokenSubResourceName {
						return nil
					}
					gotObjKey = client.ObjectKeyFromObject(obj)
					tr := subResource.(*authenticationv1.TokenRequest) //nolint:forcetypeassert // fake test double, shape is controlled by this test
					gotExpirationSeconds = tr.Spec.ExpirationSeconds
					tr.Status.Token = "fake-token"
					return nil
				},
			}).
			Build()

		_, err := mintServiceAccountToken(context.Background(), fakeClient, namespace, "acr-refresher", "api://AzureADTokenExchange")
		require.NoError(t, err)
		assert.Equal(t, client.ObjectKey{Namespace: namespace, Name: "acr-refresher"}, gotObjKey)
		require.NotNil(t, gotExpirationSeconds)
		assert.Equal(t, int64(600), *gotExpirationSeconds)
	})
}
