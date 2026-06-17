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

package instance

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		key     string
		want    bool
	}{
		{name: "exact match", pattern: "argocd.argoproj.io/instance", key: "argocd.argoproj.io/instance", want: true},
		{name: "exact mismatch", pattern: "argocd.argoproj.io/instance", key: "argocd.argoproj.io/secret-type", want: false},
		{name: "trailing wildcard matches suffix", pattern: "kustomize.toolkit.fluxcd.io/*", key: "kustomize.toolkit.fluxcd.io/name", want: true},
		{name: "trailing wildcard crosses slash", pattern: "kustomize.toolkit.fluxcd.io/*", key: "kustomize.toolkit.fluxcd.io/namespace", want: true},
		{name: "trailing wildcard matches empty", pattern: "prefix/*", key: "prefix/", want: true},
		{name: "wildcard does not match different prefix", pattern: "kustomize.toolkit.fluxcd.io/*", key: "argocd.argoproj.io/instance", want: false},
		{name: "leading wildcard", pattern: "*/instance", key: "argocd.argoproj.io/instance", want: true},
		{name: "leading wildcard crosses slash", pattern: "*instance", key: "app.kubernetes.io/instance", want: true},
		{name: "middle wildcard", pattern: "app.*.io/name", key: "app.kubernetes.io/name", want: true},
		{name: "multiple wildcards", pattern: "*.fluxcd.io/*", key: "kustomize.toolkit.fluxcd.io/name", want: true},
		{name: "bare wildcard matches anything", pattern: "*", key: "any/label-key", want: true},
		{name: "bare wildcard matches empty", pattern: "*", key: "", want: true},
		{name: "no wildcard empty mismatch", pattern: "x", key: "", want: false},
		{name: "literal mismatch with wildcard present", pattern: "a*c", key: "axd", want: false},
		{name: "wildcard greedy backtrack", pattern: "a*c", key: "abcbc", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchGlob(tt.pattern, tt.key))
		})
	}
}

func TestNewLabelFilter(t *testing.T) {
	tests := []struct {
		name        string
		patterns    []string
		wantEnabled bool
	}{
		{name: "nil patterns", patterns: nil, wantEnabled: false},
		{name: "empty slice", patterns: []string{}, wantEnabled: false},
		{name: "only blanks", patterns: []string{"", "   "}, wantEnabled: false},
		{name: "blanks are trimmed away", patterns: []string{" argocd.argoproj.io/instance ", ""}, wantEnabled: true},
		{name: "valid patterns", patterns: []string{"argocd.argoproj.io/instance"}, wantEnabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewLabelFilter(tt.patterns)
			assert.Equal(t, tt.wantEnabled, f.Enabled())
		})
	}
}

func TestLabelFilterMatches(t *testing.T) {
	f := NewLabelFilter([]string{"argocd.argoproj.io/instance", "kustomize.toolkit.fluxcd.io/*"})

	assert.True(t, f.Matches("argocd.argoproj.io/instance"))
	assert.True(t, f.Matches("kustomize.toolkit.fluxcd.io/name"))
	assert.False(t, f.Matches("app.kubernetes.io/name"))
	assert.False(t, NewLabelFilter(nil).Matches("anything"))
}

func TestLabelFilterApply(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		labels   map[string]string
		want     map[string]string
	}{
		{
			name:     "disabled filter returns input unchanged",
			patterns: nil,
			labels:   map[string]string{"argocd.argoproj.io/instance": "falco", "app": "falco"},
			want:     map[string]string{"argocd.argoproj.io/instance": "falco", "app": "falco"},
		},
		{
			name:     "nil labels returned as-is",
			patterns: []string{"argocd.argoproj.io/instance"},
			labels:   nil,
			want:     nil,
		},
		{
			name:     "removes matching tracking label, keeps the rest",
			patterns: []string{"argocd.argoproj.io/instance"},
			labels:   map[string]string{"argocd.argoproj.io/instance": "falco", "app.kubernetes.io/name": "falco"},
			want:     map[string]string{"app.kubernetes.io/name": "falco"},
		},
		{
			name:     "wildcard removes flux labels",
			patterns: []string{"kustomize.toolkit.fluxcd.io/*"},
			labels: map[string]string{
				"kustomize.toolkit.fluxcd.io/name":      "falco",
				"kustomize.toolkit.fluxcd.io/namespace": "falco-system",
				"team":                                  "secops",
			},
			want: map[string]string{"team": "secops"},
		},
		{
			name:     "nothing matches returns equivalent map",
			patterns: []string{"argocd.argoproj.io/instance"},
			labels:   map[string]string{"app.kubernetes.io/name": "falco"},
			want:     map[string]string{"app.kubernetes.io/name": "falco"},
		},
		{
			name:     "removing every label returns nil",
			patterns: []string{"*"},
			labels:   map[string]string{"a": "1", "b": "2"},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewLabelFilter(tt.patterns).Apply(tt.labels)
			assert.Equal(t, tt.want, got)
		})
	}
}
