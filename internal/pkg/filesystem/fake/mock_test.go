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

package fake

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMockFileSystem_Glob_MatchesOnlyPatternInSameDirectory(t *testing.T) {
	m := NewMockFileSystem()
	m.Files["/rules.d/50-01-my-rules-oci.yaml"] = []byte("x")
	m.Files["/rules.d/50-02-other-inline.yaml"] = []byte("x")
	m.Files["/rules.d/notes.txt"] = []byte("x")
	m.Files["/rules.d/sub/50-03-nested-oci.yaml"] = []byte("x")

	matches, err := m.Glob("/rules.d/*.yaml")
	require.NoError(t, err)

	sort.Strings(matches)
	require.Equal(t, []string{
		"/rules.d/50-01-my-rules-oci.yaml",
		"/rules.d/50-02-other-inline.yaml",
	}, matches)
}
