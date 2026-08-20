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

package index

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

const (
	// ConfigMapOnRulesfile is the index field name for Rulesfile resources indexed by their ConfigMapRef.
	ConfigMapOnRulesfile = "ConfigMapOnRulesfile"
	// SecretOnRulesfile is the index field name for Rulesfile resources indexed by their SecretRef.
	SecretOnRulesfile = "SecretOnRulesfile"
	// PluginOnRulesfile is the index field name for Rulesfile resources indexed by the plugin names
	// declared in Status.ArtifactMeta.Dependencies (primary and alternatives).
	PluginOnRulesfile = "PluginOnRulesfile"
)

// RulesfileByConfigMapRef indexes Rulesfile resources by their .spec.configMapRef.name.
var RulesfileByConfigMapRef = IndexByConfigMapRef(
	func(rf *artifactv1alpha1.Rulesfile) *commonv1alpha1.ConfigMapRef {
		return rf.Spec.ConfigMapRef
	},
)

// RulesfileBySecretRef indexes Rulesfile resources by their .spec.ociArtifact.registry.auth.secretRef.name.
var RulesfileBySecretRef = IndexBySecretRef(
	func(rf *artifactv1alpha1.Rulesfile) *commonv1alpha1.SecretRef {
		if rf.Spec.OCIArtifact == nil || rf.Spec.OCIArtifact.Registry == nil ||
			rf.Spec.OCIArtifact.Registry.Auth == nil {
			return nil
		}
		return rf.Spec.OCIArtifact.Registry.Auth.SecretRef
	},
)

// RulesfileByPluginDependency indexes Rulesfile resources by the plugin names declared in
// Status.ArtifactMeta.Dependencies, including all alternatives. Returns nil when ArtifactMeta
// is not yet populated (status not written by the instance operator).
var RulesfileByPluginDependency client.IndexerFunc = func(obj client.Object) []string {
	rf, ok := obj.(*artifactv1alpha1.Rulesfile)
	if !ok || rf.Status.ArtifactMeta == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var names []string
	addName := func(name string) {
		if _, exists := seen[name]; !exists {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	for _, dep := range rf.Status.ArtifactMeta.Dependencies {
		addName(dep.Name)
		for _, alt := range dep.Alternatives {
			addName(alt.Name)
		}
	}
	return names
}

// RulesfileIndexes holds all field indexes for Rulesfile resources.
var RulesfileIndexes = []Entry{
	{
		Object:         &artifactv1alpha1.Rulesfile{},
		Field:          ConfigMapOnRulesfile,
		ExtractValueFn: RulesfileByConfigMapRef,
	},
	{
		Object:         &artifactv1alpha1.Rulesfile{},
		Field:          SecretOnRulesfile,
		ExtractValueFn: RulesfileBySecretRef,
	},
	{
		Object:         &artifactv1alpha1.Rulesfile{},
		Field:          PluginOnRulesfile,
		ExtractValueFn: RulesfileByPluginDependency,
	},
}
