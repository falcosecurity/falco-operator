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

package compat

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

func TestSemverAtLeast(t *testing.T) {
	tests := []struct {
		name      string
		available string
		required  string
		want      bool
		wantErr   bool
	}{
		{name: "equal versions", available: "0.62.0", required: "0.62.0", want: true},
		{name: "available major higher", available: "1.0.0", required: "0.9.9", want: true},
		{name: "available minor higher", available: "0.63.0", required: "0.62.9", want: true},
		{name: "available patch higher", available: "0.62.1", required: "0.62.0", want: true},
		{name: "available major lower", available: "0.61.0", required: "0.62.0", want: false},
		{name: "available minor lower", available: "0.62.0", required: "0.63.0", want: false},
		{name: "available patch lower", available: "0.62.0", required: "0.62.1", want: false},
		{name: "short available padded with zeros", available: "62", required: "15", want: true},
		{name: "short required padded with zeros", available: "0.62.0", required: "0", want: true},
		{name: "short versions equal", available: "62", required: "62", want: true},
		{name: "invalid available part returns error", available: "x.62.0", required: "0.62.0", wantErr: true},
		{name: "invalid required part returns error", available: "0.62.0", required: "0.x.0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SemverAtLeast(tt.available, tt.required)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSemverMajorCompatible(t *testing.T) {
	tests := []struct {
		name      string
		available string
		required  string
		want      bool
		wantErr   bool
	}{
		{name: "same major same version", available: "2.0.0", required: "2.0.0", want: true},
		{name: "same major available minor higher", available: "2.1.0", required: "2.0.0", want: true},
		{name: "same major available patch higher", available: "2.0.1", required: "2.0.0", want: true},
		{name: "same major available lower minor", available: "2.0.0", required: "2.1.0", want: false},
		{name: "available major higher incompatible", available: "3.12.0", required: "2.0.0", want: false},
		{name: "available major lower incompatible", available: "1.9.9", required: "2.0.0", want: false},
		{name: "zero major same", available: "0.5.0", required: "0.5.0", want: true},
		{name: "zero major available higher patch", available: "0.5.1", required: "0.5.0", want: true},
		{name: "zero major available lower", available: "0.4.9", required: "0.5.0", want: false},
		{name: "invalid available returns error", available: "x.0.0", required: "2.0.0", wantErr: true},
		{name: "invalid required returns error", available: "2.0.0", required: "x.0.0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SemverMajorCompatible(tt.available, tt.required)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseRulesRequirements(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		wantEng      string
		wantEngIsInt bool
		wantPlugins  []RulesPluginRequirement
		wantErr      bool
	}{
		{
			name: "nil data returns empty requirements",
			data: nil,
		},
		{
			name: "empty data returns empty requirements",
			data: []byte{},
		},
		{
			name: "rules with no requirement directives",
			data: []byte("- rule: test\n  desc: d\n  condition: always_true\n  output: o\n  priority: WARNING\n"),
		},
		{
			name:    "engine version as semver string",
			data:    []byte("- required_engine_version: 0.57.0\n"),
			wantEng: "0.57.0",
		},
		{
			name:         "engine version as bare integer",
			data:         []byte("- required_engine_version: 26\n"),
			wantEng:      "26",
			wantEngIsInt: true,
		},
		{
			// yaml.v3 decodes a bare float (e.g. 1.5) as float64, which falls through
			// to the default case and is formatted via fmt.Sprintf("%v", v).
			name:    "engine version as float falls through to default formatter",
			data:    []byte("- required_engine_version: 1.5\n"),
			wantEng: "1.5",
		},
		{
			name: "plugin without alternatives",
			data: []byte("- required_plugin_versions:\n    - name: container\n      version: 0.4.0\n"),
			wantPlugins: []RulesPluginRequirement{
				{Name: "container", Version: "0.4.0"},
			},
		},
		{
			name: "plugin with alternatives",
			data: []byte("- required_plugin_versions:\n    - name: container\n      version: 0.4.0\n      alternatives:\n        - name: k8smeta\n          version: 0.1.0\n"),
			wantPlugins: []RulesPluginRequirement{
				{
					Name:    "container",
					Version: "0.4.0",
					Alternatives: []puller.Dependency{
						{Name: "k8smeta", Version: "0.1.0"},
					},
				},
			},
		},
		{
			name:    "mixed engine version and plugin with alternatives",
			data:    []byte("- required_engine_version: 0.57.0\n- required_plugin_versions:\n    - name: container\n      version: 0.4.0\n      alternatives:\n        - name: k8smeta\n          version: 0.1.0\n- rule: foo\n  desc: d\n  condition: always_true\n  output: o\n  priority: WARNING\n"),
			wantEng: "0.57.0",
			wantPlugins: []RulesPluginRequirement{
				{
					Name:    "container",
					Version: "0.4.0",
					Alternatives: []puller.Dependency{
						{Name: "k8smeta", Version: "0.1.0"},
					},
				},
			},
		},
		{
			name:    "invalid YAML returns error",
			data:    []byte("key: [unclosed"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRulesRequirements(tt.data)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tt.wantEng, got.EngineVersion)
			assert.Equal(t, tt.wantEngIsInt, got.EngineVersionIsInt)
			assert.Equal(t, tt.wantPlugins, got.PluginVersions)
		})
	}
}
