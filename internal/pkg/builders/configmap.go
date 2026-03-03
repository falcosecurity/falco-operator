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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConfigMapBuilder provides a fluent API for constructing corev1.ConfigMap objects.
type ConfigMapBuilder struct {
	cm *corev1.ConfigMap
}

// NewConfigMap creates a ConfigMapBuilder with TypeMeta pre-populated.
func NewConfigMap() *ConfigMapBuilder {
	return &ConfigMapBuilder{
		cm: &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
		},
	}
}

// WithName sets the name.
func (b *ConfigMapBuilder) WithName(name string) *ConfigMapBuilder {
	b.cm.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *ConfigMapBuilder) WithNamespace(namespace string) *ConfigMapBuilder {
	b.cm.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *ConfigMapBuilder) WithLabels(labels map[string]string) *ConfigMapBuilder {
	b.cm.Labels = labels
	return b
}

// WithFinalizers sets the finalizers.
func (b *ConfigMapBuilder) WithFinalizers(finalizers []string) *ConfigMapBuilder {
	b.cm.Finalizers = finalizers
	return b
}

// WithDeletionTimestamp sets the deletion timestamp.
func (b *ConfigMapBuilder) WithDeletionTimestamp(ts *metav1.Time) *ConfigMapBuilder {
	b.cm.DeletionTimestamp = ts
	return b
}

// WithData sets the data map.
func (b *ConfigMapBuilder) WithData(data map[string]string) *ConfigMapBuilder {
	b.cm.Data = data
	return b
}

// Build returns the constructed ConfigMap object.
func (b *ConfigMapBuilder) Build() *corev1.ConfigMap {
	return b.cm
}
