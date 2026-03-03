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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// ConfigBuilder provides a fluent API for constructing artifactv1alpha1.Config objects.
type ConfigBuilder struct {
	config *artifactv1alpha1.Config
}

// NewConfig creates a ConfigBuilder with no defaults.
func NewConfig() *ConfigBuilder {
	return &ConfigBuilder{
		config: &artifactv1alpha1.Config{},
	}
}

// WithName sets the name.
func (b *ConfigBuilder) WithName(name string) *ConfigBuilder {
	b.config.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *ConfigBuilder) WithNamespace(namespace string) *ConfigBuilder {
	b.config.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *ConfigBuilder) WithLabels(labels map[string]string) *ConfigBuilder {
	b.config.Labels = labels
	return b
}

// WithFinalizers sets the finalizers.
func (b *ConfigBuilder) WithFinalizers(finalizers []string) *ConfigBuilder {
	b.config.Finalizers = finalizers
	return b
}

// WithDeletionTimestamp sets the deletion timestamp.
func (b *ConfigBuilder) WithDeletionTimestamp(ts *metav1.Time) *ConfigBuilder {
	b.config.DeletionTimestamp = ts
	return b
}

// WithGeneration sets the generation.
func (b *ConfigBuilder) WithGeneration(gen int64) *ConfigBuilder {
	b.config.Generation = gen
	return b
}

// WithConfig sets the inline config JSON.
func (b *ConfigBuilder) WithConfig(cfg *apiextensionsv1.JSON) *ConfigBuilder {
	b.config.Spec.Config = cfg
	return b
}

// WithConfigMapRef sets the ConfigMap reference.
func (b *ConfigBuilder) WithConfigMapRef(ref *commonv1alpha1.ConfigMapRef) *ConfigBuilder {
	b.config.Spec.ConfigMapRef = ref
	return b
}

// WithPriority sets the priority.
func (b *ConfigBuilder) WithPriority(priority int32) *ConfigBuilder {
	b.config.Spec.Priority = priority
	return b
}

// WithSelector sets the label selector.
func (b *ConfigBuilder) WithSelector(selector *metav1.LabelSelector) *ConfigBuilder {
	b.config.Spec.Selector = selector
	return b
}

// Build returns the constructed Config object.
func (b *ConfigBuilder) Build() *artifactv1alpha1.Config {
	return b.config
}
