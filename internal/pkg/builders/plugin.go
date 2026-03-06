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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// PluginBuilder provides a fluent API for constructing artifactv1alpha1.Plugin objects.
type PluginBuilder struct {
	plugin *artifactv1alpha1.Plugin
}

// NewPlugin creates a PluginBuilder with no defaults.
func NewPlugin() *PluginBuilder {
	return &PluginBuilder{
		plugin: &artifactv1alpha1.Plugin{},
	}
}

// WithName sets the name.
func (b *PluginBuilder) WithName(name string) *PluginBuilder {
	b.plugin.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *PluginBuilder) WithNamespace(namespace string) *PluginBuilder {
	b.plugin.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *PluginBuilder) WithLabels(labels map[string]string) *PluginBuilder {
	b.plugin.Labels = labels
	return b
}

// WithFinalizers sets the finalizers.
func (b *PluginBuilder) WithFinalizers(finalizers []string) *PluginBuilder {
	b.plugin.Finalizers = finalizers
	return b
}

// WithDeletionTimestamp sets the deletion timestamp.
func (b *PluginBuilder) WithDeletionTimestamp(ts *metav1.Time) *PluginBuilder {
	b.plugin.DeletionTimestamp = ts
	return b
}

// WithGeneration sets the generation.
func (b *PluginBuilder) WithGeneration(gen int64) *PluginBuilder {
	b.plugin.Generation = gen
	return b
}

// WithOCIArtifact sets the OCI artifact.
func (b *PluginBuilder) WithOCIArtifact(artifact commonv1alpha1.OCIArtifact) *PluginBuilder {
	b.plugin.Spec.OCIArtifact = &artifact
	return b
}

// WithPluginConfig sets the plugin configuration.
func (b *PluginBuilder) WithPluginConfig(cfg *artifactv1alpha1.PluginConfig) *PluginBuilder {
	b.plugin.Spec.Config = cfg
	return b
}

// WithSelector sets the label selector.
func (b *PluginBuilder) WithSelector(selector *metav1.LabelSelector) *PluginBuilder {
	b.plugin.Spec.Selector = selector
	return b
}

// Build returns the constructed Plugin object.
func (b *PluginBuilder) Build() *artifactv1alpha1.Plugin {
	return b.plugin
}
