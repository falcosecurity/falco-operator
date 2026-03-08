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

// SecretOnPlugin is the index field name for Plugin resources indexed by their SecretRef.
const SecretOnPlugin = "SecretOnPlugin"

// PluginBySecretRef indexes Plugin resources by their .spec.ociArtifact.registry.auth.secretRef.name.
var PluginBySecretRef = IndexBySecretRef(
	func(pl *artifactv1alpha1.Plugin) *commonv1alpha1.SecretRef {
		if pl.Spec.OCIArtifact == nil || pl.Spec.OCIArtifact.Registry == nil ||
			pl.Spec.OCIArtifact.Registry.Auth == nil {
			return nil
		}
		return pl.Spec.OCIArtifact.Registry.Auth.SecretRef
	},
)

// PluginIndexes holds all field indexes for Plugin resources.
var PluginIndexes = []Entry{
	{
		Object:         &artifactv1alpha1.Plugin{},
		Field:          SecretOnPlugin,
		ExtractValueFn: PluginBySecretRef,
	},
}
