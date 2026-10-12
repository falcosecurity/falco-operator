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

package testutil

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// MustArtifactPath is artifact.ArtifactPath for a test that has no business handling an error: every
// combination used in tests is registered, so a failure means the registration changed.
func MustArtifactPath(t *testing.T, dirs artifact.ArtifactDirs, name string, artifactPriority int32,
	medium artifact.Medium, kind artifact.Kind) string {
	t.Helper()
	path, err := artifact.ArtifactPath(dirs, name, artifactPriority, medium, kind)
	require.NoError(t, err)
	return path
}

// MustPermFor is artifact.PermFor for a registered kind.
func MustPermFor(t *testing.T, kind artifact.Kind) fs.FileMode {
	t.Helper()
	perm, err := artifact.PermFor(kind)
	require.NoError(t, err)
	return perm
}
