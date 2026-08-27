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
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

func (am *Manager) fetchOCIAuthSecret(ctx context.Context, ref *commonv1alpha1.SecretRef) (*corev1.Secret, error) {
	if ref == nil {
		return nil, nil
	}

	secret := &corev1.Secret{}
	key := client.ObjectKey{Name: ref.Name, Namespace: am.namespace}
	if err := am.client.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("failed to get pull secret %s: %w", ref.Name, err)
	}
	return secret, nil
}

func isExpectedOCIArtifactType(expected Type, actual puller.ArtifactType) bool {
	switch expected {
	case TypeRulesfile:
		return actual == puller.Rulesfile
	case TypePlugin:
		return actual == puller.Plugin
	default:
		return false
	}
}
