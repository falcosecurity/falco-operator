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
	"oras.land/oras-go/v2/registry/remote/auth"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func anonymousCredential(_ context.Context, _ string) (auth.Credential, error) {
	return auth.EmptyCredential, nil
}

// FromSecret derives an ORAS credential function from a Secret.
// A nil secret yields anonymous credentials.
func FromSecret(registry string, secret *corev1.Secret) (auth.CredentialFunc, error) {
	if secret == nil {
		return anonymousCredential, nil
	}
	if registry == "" {
		return nil, fmt.Errorf("registry host is required when using pull credentials")
	}

	creds, err := CredentialsFromSecret(secret)
	if err != nil {
		return nil, err
	}
	return auth.StaticCredential(registry, creds), nil
}

// CredentialsFromSecret extracts registry credentials from a Kubernetes Secret.
func CredentialsFromSecret(secret *corev1.Secret) (auth.Credential, error) {
	username, ok := secret.Data[commonv1alpha1.SecretUsernameKey]
	if !ok {
		return auth.Credential{}, fmt.Errorf("key %q not found in secret %s", commonv1alpha1.SecretUsernameKey, secret.Name)
	}

	password, ok := secret.Data[commonv1alpha1.SecretPasswordKey]
	if !ok {
		return auth.Credential{}, fmt.Errorf("key %q not found in secret %s", commonv1alpha1.SecretPasswordKey, secret.Name)
	}

	return auth.Credential{
		Username: string(username),
		Password: string(password),
	}, nil
}
