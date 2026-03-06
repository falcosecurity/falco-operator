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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func generateService(falco *instancev1alpha1.Falco) runtime.Object {
	return builders.NewService().
		WithName(falco.Name).
		WithNamespace(falco.Namespace).
		WithLabels(falco.Labels).
		WithType(corev1.ServiceTypeClusterIP).
		WithSelector(map[string]string{
			"app.kubernetes.io/name":     falco.Name,
			"app.kubernetes.io/instance": falco.Name,
		}).
		AddPort(&corev1.ServicePort{
			Name:       "web",
			Protocol:   corev1.ProtocolTCP,
			Port:       8765,
			TargetPort: intstr.FromInt32(8765),
		}).
		Build()
}

func (r *Reconciler) ensureService(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		generateService,
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false},
	)
}
