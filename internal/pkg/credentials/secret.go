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

package credentials

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/v2/registry/remote/auth"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func credentialFuncFromCredentials(creds auth.Credential) auth.CredentialFunc {
	return func(ctx context.Context, hostport string) (auth.Credential, error) {
		return creds, nil
	}
}

// GetCredentialsFromSecret retrieves credentials from the Kubernetes secret
// referenced by the AuthSecretRef and returns an ORAS credential.
func GetCredentialsFromSecret(ctx context.Context, k8sClient client.Client, namespace string, authSecretRef *commonv1alpha1.SecretRef) (auth.CredentialFunc, error) {
	var creds = auth.EmptyCredential

	if authSecretRef == nil {
		return credentialFuncFromCredentials(creds), nil
	}

	// Fetch the secret
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      authSecretRef.Name,
		Namespace: namespace,
	}

	if err := k8sClient.Get(ctx, secretNamespacedName, secret); err != nil {
		return nil, fmt.Errorf("failed to get pull secret %s: %w", authSecretRef.Name, err)
	}

	// Extract username and password using standard kubernetes.io/basic-auth keys.
	username, ok := secret.Data[commonv1alpha1.SecretUsernameKey]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret %s", commonv1alpha1.SecretUsernameKey, authSecretRef.Name)
	}

	password, ok := secret.Data[commonv1alpha1.SecretPasswordKey]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret %s", commonv1alpha1.SecretPasswordKey, authSecretRef.Name)
	}

	return credentialFuncFromCredentials(auth.Credential{
		Username: string(username),
		Password: string(password),
	}), nil
}
