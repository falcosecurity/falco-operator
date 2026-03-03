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

package instance

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

// ResolveVersion determines the version to use for an instance controller.
// Resolution priority (highest wins):
//  1. PodTemplateSpec container image tag (if the main container is present).
//  2. spec.version from the CR.
//  3. Default version from the instance defaults.
func ResolveVersion(obj client.Object, defs *resources.InstanceDefaults) string {
	var version *string
	var podTemplateSpec *corev1.PodTemplateSpec

	switch o := obj.(type) {
	case *instancev1alpha1.Falco:
		version = o.Spec.Version
		podTemplateSpec = o.Spec.PodTemplateSpec
	case *instancev1alpha1.Component:
		version = o.Spec.Component.Version
		podTemplateSpec = o.Spec.PodTemplateSpec
	}

	if podTemplateSpec != nil {
		for i := range podTemplateSpec.Spec.Containers {
			if podTemplateSpec.Spec.Containers[i].Name == defs.ContainerName {
				if v := image.VersionFromImage(podTemplateSpec.Spec.Containers[i].Image); v != "" {
					return v
				}
				break
			}
		}
	}

	if version != nil && *version != "" {
		return *version
	}

	return defs.ImageTag
}
