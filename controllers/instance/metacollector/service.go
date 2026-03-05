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

package metacollector

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func generateService(mc *instancev1alpha1.Metacollector) runtime.Object {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      mc.Name,
			Namespace: mc.Namespace,
			Labels:    mc.Labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics",
					Protocol:   corev1.ProtocolTCP,
					Port:       8080,
					TargetPort: intstr.FromInt32(8080),
				},
				{
					Name:       "health-probe",
					Protocol:   corev1.ProtocolTCP,
					Port:       8081,
					TargetPort: intstr.FromInt32(8081),
				},
				{
					Name:       "broker-grpc",
					Protocol:   corev1.ProtocolTCP,
					Port:       45000,
					TargetPort: intstr.FromInt32(45000),
				},
			},
			Selector: map[string]string{
				"app.kubernetes.io/name":     mc.Name,
				"app.kubernetes.io/instance": mc.Name,
			},
		},
	}
}

func (r *Reconciler) ensureService(ctx context.Context, mc *instancev1alpha1.Metacollector) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, mc, fieldManager,
		generateService,
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false},
	)
}
