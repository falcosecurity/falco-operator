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

// ConfigMapOnConfig is the index field name for Config resources indexed by their ConfigMapRef.
const ConfigMapOnConfig = "ConfigMapOnConfig"

// ConfigByConfigMapRef indexes Config resources by their .spec.configMapRef.name.
var ConfigByConfigMapRef = IndexByConfigMapRef(
	func(c *artifactv1alpha1.Config) *commonv1alpha1.ConfigMapRef {
		return c.Spec.ConfigMapRef
	},
)

// ConfigIndexes holds all field indexes for Config resources.
var ConfigIndexes = []Entry{
	{
		Object:         &artifactv1alpha1.Config{},
		Field:          ConfigMapOnConfig,
		ExtractValueFn: ConfigByConfigMapRef,
	},
}
