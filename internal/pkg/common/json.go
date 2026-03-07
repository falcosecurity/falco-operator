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

package common

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// JSONRawToYAML converts an apiextensionsv1.JSON field to a YAML string pointer.
// Returns nil if the field is nil or contains no data.
func JSONRawToYAML(raw *apiextensionsv1.JSON) (*string, error) {
	if raw == nil || len(raw.Raw) == 0 {
		return nil, nil
	}
	b, err := yaml.JSONToYAML(raw.Raw)
	if err != nil {
		return nil, err
	}
	s := string(b)
	return &s, nil
}
