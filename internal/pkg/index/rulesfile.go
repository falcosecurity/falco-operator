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
	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

const (
	// ConfigMapOnRulesfile is the index field name for Rulesfile resources indexed by their ConfigMapRef.
	ConfigMapOnRulesfile = "ConfigMapOnRulesfile"
	// SecretOnRulesfile is the index field name for Rulesfile resources indexed by their SecretRef.
	SecretOnRulesfile = "SecretOnRulesfile"
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
}
