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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

// generateApplyConfiguration builds the desired Deployment/DaemonSet for falco. When
// artifactClientCertSecretName is non-empty, the artifact-operator sidecar's pod spec gains the
// matching per-instance mTLS Secret + CA bundle ConfigMap volume mounts + env vars (see
// resources.WithArtifactClientCertOverlay); empty means mTLS is disabled for this instance.
func generateApplyConfiguration(
	falco *instancev1alpha1.Falco, resourceType, artifactClientCertSecretName, artifactCABundleConfigMapName string,
) (*unstructured.Unstructured, error) {
	baseResource, err := resources.GenerateWorkload(resourceType, &falco.ObjectMeta, resources.FalcoDefaults)
	if err != nil {
		return nil, err
	}

	opts := resources.GenerateOverlayOptions(falco)
	if artifactClientCertSecretName != "" {
		opts = append(opts, resources.WithArtifactClientCertOverlay(artifactClientCertSecretName, artifactCABundleConfigMapName))
	}

	userOverlay, err := resources.GenerateUserOverlay(resourceType, falco.Name, resources.FalcoDefaults, opts...)
	if err != nil {
		return nil, err
	}

	return instance.MergeApplyConfiguration(resourceType, baseResource, userOverlay)
}
