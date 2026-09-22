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
	"fmt"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// tokenTTL is how long a minted ServiceAccount token is requested to be valid for. Short-lived
// by design: mintServiceAccountToken is called fresh on every workloadIdentity credential
// resolution rather than caching across a token's full lifetime, so this only bounds the
// blast radius of a token that leaks in transit or in a log line, not how often minting happens.
const tokenTTL = 10 * time.Minute

// mintServiceAccountToken requests a short-lived, audience-scoped token for the named
// ServiceAccount via the TokenRequest API (the "serviceaccounts/token" subresource, stable
// since Kubernetes 1.20), using this process's own RBAC rather than relying on any ambient,
// pod-level identity injection (contrast with azidentity's own NewWorkloadIdentityCredential,
// which reads a static token file tied to one pod's one identity). This is what lets a single
// falco-operator process mint tokens -- and therefore resolve distinct federated identities --
// for many different ServiceAccounts, one per AzureAuth that uses workloadIdentity, rather than
// being limited to whichever one identity its own pod happens to carry.
//
//nolint:unparam // audience is always workloadIdentityAudience today; kept generic for a future AWS/GCP provider's own audience
func mintServiceAccountToken(ctx context.Context, c client.Client, namespace, name, audience string) (string, error) {
	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: new(int64(tokenTTL.Seconds())),
		},
	}
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	if err := c.SubResource("token").Create(ctx, sa, tr); err != nil {
		return "", fmt.Errorf("mint token for serviceaccount %s/%s (audience %s): %w", namespace, name, audience, err)
	}
	if tr.Status.Token == "" {
		return "", fmt.Errorf("token request for serviceaccount %s/%s returned an empty token", namespace, name)
	}
	return tr.Status.Token, nil
}
