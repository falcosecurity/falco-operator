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

import "strings"

// LabelFilter excludes label keys matching any of its glob patterns from being
// propagated onto operator-generated resources. A pattern supports the '*'
// wildcard, which matches any sequence of characters (including '/'); every
// other character is matched literally. The zero value excludes nothing.
type LabelFilter struct {
	patterns []string
}

// NewLabelFilter builds a LabelFilter from the given glob patterns. Empty or
// whitespace-only patterns are ignored.
func NewLabelFilter(patterns []string) LabelFilter {
	cleaned := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if p = strings.TrimSpace(p); p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return LabelFilter{patterns: cleaned}
}

// Enabled reports whether the filter has any pattern configured.
func (f LabelFilter) Enabled() bool {
	return len(f.patterns) > 0
}

// Matches reports whether the given label key matches any configured pattern.
func (f LabelFilter) Matches(key string) bool {
	for _, p := range f.patterns {
		if matchGlob(p, key) {
			return true
		}
	}
	return false
}

// Apply returns a copy of labels with every key matching the filter removed.
// The input is returned unchanged when the filter is disabled or labels is
// empty. It returns nil when filtering removes every entry.
func (f LabelFilter) Apply(labels map[string]string) map[string]string {
	if !f.Enabled() || len(labels) == 0 {
		return labels
	}

	filtered := make(map[string]string, len(labels))
	for k, v := range labels {
		if !f.Matches(k) {
			filtered[k] = v
		}
	}

	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

// matchGlob reports whether s matches pattern, where '*' matches any sequence of
// characters (including '/') and every other character is matched literally.
func matchGlob(pattern, s string) bool {
	// Fast path: a pattern without a wildcard is an exact match.
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}

	var (
		px, sx         int
		starPx, starSx = -1, -1
	)
	for sx < len(s) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			// Record the wildcard position and assume it matches nothing yet.
			starPx, starSx = px, sx
			px++
		case px < len(pattern) && pattern[px] == s[sx]:
			px++
			sx++
		case starPx != -1:
			// Backtrack: let the last wildcard consume one more character.
			px = starPx + 1
			starSx++
			sx = starSx
		default:
			return false
		}
	}

	// Trailing wildcards in the pattern match the empty string.
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
