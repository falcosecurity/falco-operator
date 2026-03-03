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

// RulesfileBuilder provides a fluent API for constructing artifactv1alpha1.Rulesfile objects.
type RulesfileBuilder struct {
	rulesfile *artifactv1alpha1.Rulesfile
}

// NewRulesfile creates a RulesfileBuilder with no defaults.
func NewRulesfile() *RulesfileBuilder {
	return &RulesfileBuilder{
		rulesfile: &artifactv1alpha1.Rulesfile{},
	}
}

// WithName sets the name.
func (b *RulesfileBuilder) WithName(name string) *RulesfileBuilder {
	b.rulesfile.Name = name
	return b
}

// WithNamespace sets the namespace.
func (b *RulesfileBuilder) WithNamespace(namespace string) *RulesfileBuilder {
	b.rulesfile.Namespace = namespace
	return b
}

// WithLabels sets the labels.
func (b *RulesfileBuilder) WithLabels(labels map[string]string) *RulesfileBuilder {
	b.rulesfile.Labels = labels
	return b
}

// WithFinalizers sets the finalizers.
func (b *RulesfileBuilder) WithFinalizers(finalizers []string) *RulesfileBuilder {
	b.rulesfile.Finalizers = finalizers
	return b
}

// WithDeletionTimestamp sets the deletion timestamp.
func (b *RulesfileBuilder) WithDeletionTimestamp(ts *metav1.Time) *RulesfileBuilder {
	b.rulesfile.DeletionTimestamp = ts
	return b
}

// WithGeneration sets the generation.
func (b *RulesfileBuilder) WithGeneration(gen int64) *RulesfileBuilder {
	b.rulesfile.Generation = gen
	return b
}

// WithOCIArtifact sets the OCI artifact.
func (b *RulesfileBuilder) WithOCIArtifact(artifact commonv1alpha1.OCIArtifact) *RulesfileBuilder {
	b.rulesfile.Spec.OCIArtifact = &artifact
	return b
}

// WithInlineRules sets the inline rules content.
func (b *RulesfileBuilder) WithInlineRules(rules *apiextensionsv1.JSON) *RulesfileBuilder {
	b.rulesfile.Spec.InlineRules = rules
	return b
}

// WithConfigMapRef sets the ConfigMap reference.
func (b *RulesfileBuilder) WithConfigMapRef(ref *commonv1alpha1.ConfigMapRef) *RulesfileBuilder {
	b.rulesfile.Spec.ConfigMapRef = ref
	return b
}

// WithPriority sets the priority.
func (b *RulesfileBuilder) WithPriority(priority int32) *RulesfileBuilder {
	b.rulesfile.Spec.Priority = priority
	return b
}

// WithSelector sets the label selector.
func (b *RulesfileBuilder) WithSelector(selector *metav1.LabelSelector) *RulesfileBuilder {
	b.rulesfile.Spec.Selector = selector
	return b
}

// Build returns the constructed Rulesfile object.
func (b *RulesfileBuilder) Build() *artifactv1alpha1.Rulesfile {
	return b.rulesfile
}
