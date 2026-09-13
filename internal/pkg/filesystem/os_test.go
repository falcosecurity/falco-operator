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

package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOS_Glob_MatchesOnlyPatternInSameDirectory(t *testing.T) {
	dir := t.TempDir()

	matching := filepath.Join(dir, "50-01-my-rules-oci.yaml")
	require.NoError(t, os.WriteFile(matching, []byte("x"), 0o644))

	nonMatching := filepath.Join(dir, "notes.txt")
	require.NoError(t, os.WriteFile(nonMatching, []byte("x"), 0o644))

	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))
	inSub := filepath.Join(sub, "50-02-nested-oci.yaml")
	require.NoError(t, os.WriteFile(inSub, []byte("x"), 0o644))

	fsys := NewOSFileSystem()
	matches, err := fsys.Glob(filepath.Join(dir, "*.yaml"))
	require.NoError(t, err)
	require.Equal(t, []string{matching}, matches)
}
