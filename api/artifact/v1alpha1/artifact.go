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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// Artifact is what the operator reads the same way from every artifact kind: Rulesfile, Plugin and Config. Code
// shared by the three kinds reads an artifact through it.
// +kubebuilder:object:generate=false
type Artifact interface {
	metav1.Object
	runtime.Object

	// GetArtifactKind returns the kind of the artifact.
	GetArtifactKind() ArtifactKind
	// GetSelector returns the selector of the nodes the artifact is installed on. Nil selects every node.
	GetSelector() *metav1.LabelSelector
	// GetOCIArtifact returns the OCI source of the artifact, nil when it has none. A Config never has one.
	GetOCIArtifact() *commonv1alpha1.OCIArtifact
	// GetStatusConditions returns the conditions of the artifact's status, to read and to set.
	GetStatusConditions() *[]metav1.Condition
	// GetStatusObservedGeneration returns the generation of the artifact the instance operator has processed, to
	// read and to set.
	GetStatusObservedGeneration() *int64
	// GetArtifactMeta returns the metadata the instance operator publishes for the nodes, nil when there is none. A
	// Config never has any.
	GetArtifactMeta() *commonv1alpha1.ArtifactMeta
	// GetArtifactMetaSourcesHash returns the hash of the sources the metadata was computed from, empty when the
	// kind does not record one.
	GetArtifactMetaSourcesHash() string
}

var (
	_ Artifact = &Rulesfile{}
	_ Artifact = &Plugin{}
	_ Artifact = &Config{}
)

// GetArtifactKind returns KindRulesfile.
func (*Rulesfile) GetArtifactKind() ArtifactKind { return KindRulesfile }

// GetSelector returns the selector of the nodes the Rulesfile is installed on.
func (r *Rulesfile) GetSelector() *metav1.LabelSelector { return r.Spec.Selector }

// GetOCIArtifact returns the OCI source of the Rulesfile, nil when it has none.
func (r *Rulesfile) GetOCIArtifact() *commonv1alpha1.OCIArtifact { return r.Spec.OCIArtifact }

// GetStatusConditions returns the conditions of the Rulesfile's status.
func (r *Rulesfile) GetStatusConditions() *[]metav1.Condition { return &r.Status.Conditions }

// GetStatusObservedGeneration returns the generation of the Rulesfile the instance operator has processed.
func (r *Rulesfile) GetStatusObservedGeneration() *int64 { return &r.Status.ObservedGeneration }

// GetArtifactMeta returns the metadata of the Rulesfile.
func (r *Rulesfile) GetArtifactMeta() *commonv1alpha1.ArtifactMeta { return r.Status.ArtifactMeta }

// GetArtifactMetaSourcesHash returns the hash of the sources the Rulesfile's metadata was computed from.
func (r *Rulesfile) GetArtifactMetaSourcesHash() string { return r.Status.ArtifactMetaSourcesHash }

// GetArtifactKind returns KindPlugin.
func (*Plugin) GetArtifactKind() ArtifactKind { return KindPlugin }

// GetSelector returns the selector of the nodes the Plugin is installed on.
func (p *Plugin) GetSelector() *metav1.LabelSelector { return p.Spec.Selector }

// GetOCIArtifact returns the OCI source of the Plugin, nil when it has none.
func (p *Plugin) GetOCIArtifact() *commonv1alpha1.OCIArtifact { return p.Spec.OCIArtifact }

// GetStatusConditions returns the conditions of the Plugin's status.
func (p *Plugin) GetStatusConditions() *[]metav1.Condition { return &p.Status.Conditions }

// GetStatusObservedGeneration returns the generation of the Plugin the instance operator has processed.
func (p *Plugin) GetStatusObservedGeneration() *int64 { return &p.Status.ObservedGeneration }

// GetArtifactMeta returns the metadata of the Plugin.
func (p *Plugin) GetArtifactMeta() *commonv1alpha1.ArtifactMeta { return p.Status.ArtifactMeta }

// GetArtifactMetaSourcesHash returns "": a Plugin's metadata has a single source, its OCI artifact.
func (*Plugin) GetArtifactMetaSourcesHash() string { return "" }

// GetArtifactKind returns KindConfig.
func (*Config) GetArtifactKind() ArtifactKind { return KindConfig }

// GetSelector returns the selector of the nodes the Config is installed on.
func (c *Config) GetSelector() *metav1.LabelSelector { return c.Spec.Selector }

// GetOCIArtifact returns nil: a Config has no OCI source.
func (*Config) GetOCIArtifact() *commonv1alpha1.OCIArtifact { return nil }

// GetStatusConditions returns the conditions of the Config's status.
func (c *Config) GetStatusConditions() *[]metav1.Condition { return &c.Status.Conditions }

// GetStatusObservedGeneration returns the generation of the Config the instance operator has processed.
func (c *Config) GetStatusObservedGeneration() *int64 { return &c.Status.ObservedGeneration }

// GetArtifactMeta returns nil: a Config declares no requirements.
func (*Config) GetArtifactMeta() *commonv1alpha1.ArtifactMeta { return nil }

// GetArtifactMetaSourcesHash returns "": a Config has no metadata.
func (*Config) GetArtifactMetaSourcesHash() string { return "" }
