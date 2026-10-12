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

package artifact

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"
)

// mustArtifactPath is ArtifactPath for a test that has no business handling an error: every
// combination used here is registered, so a failure means the registration changed.
func mustArtifactPath(t *testing.T, dirs ArtifactDirs, name string, artifactPriority int32,
	medium Medium, kind Kind) string {
	t.Helper()
	path, err := ArtifactPath(dirs, name, artifactPriority, medium, kind)
	require.NoError(t, err)
	return path
}

// mustPermFor is PermFor for a registered type.
func mustPermFor(t *testing.T, kind Kind) fs.FileMode {
	t.Helper()
	perm, err := PermFor(kind)
	require.NoError(t, err)
	return perm
}
