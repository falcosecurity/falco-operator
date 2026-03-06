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

package builders

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestNewService_TypeMeta(t *testing.T) {
	svc := NewService().Build()
	assert.Equal(t, "Service", svc.Kind)
	assert.Equal(t, "v1", svc.APIVersion)
}

func TestServiceBuilder(t *testing.T) {
	labels := map[string]string{"app": "test"}
	selector := map[string]string{"app.kubernetes.io/name": "test"}

	svc := NewService().
		WithName("my-svc").
		WithNamespace("ns").
		WithLabels(labels).
		WithType(corev1.ServiceTypeClusterIP).
		WithSelector(selector).
		Build()

	assert.Equal(t, "my-svc", svc.Name)
	assert.Equal(t, "ns", svc.Namespace)
	assert.Equal(t, labels, svc.Labels)
	assert.Equal(t, corev1.ServiceTypeClusterIP, svc.Spec.Type)
	assert.Equal(t, selector, svc.Spec.Selector)
}

func TestServiceBuilder_AddPort(t *testing.T) {
	svc := NewService().
		AddPort(&corev1.ServicePort{
			Name:       "http",
			Protocol:   corev1.ProtocolTCP,
			Port:       8080,
			TargetPort: intstr.FromInt32(8080),
		}).
		AddPort(&corev1.ServicePort{
			Name:       "grpc",
			Protocol:   corev1.ProtocolTCP,
			Port:       9090,
			TargetPort: intstr.FromInt32(9090),
		}).
		Build()

	require.Len(t, svc.Spec.Ports, 2)
	assert.Equal(t, "http", svc.Spec.Ports[0].Name)
	assert.Equal(t, int32(8080), svc.Spec.Ports[0].Port)
	assert.Equal(t, "grpc", svc.Spec.Ports[1].Name)
	assert.Equal(t, int32(9090), svc.Spec.Ports[1].Port)
}
