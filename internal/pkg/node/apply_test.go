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

package node

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestNode_Remove_WithdrawsTheArtifactsStatus(t *testing.T) {
	m, published := newStatusManager(t)
	key := installConfig(t, m, statusTestNamespace, "cfg")
	m.PublishStatus(artifact.KindConfig, artifactObj("cfg"), &artifactv1alpha1.NodeArtifactStatus{Conditions: statusConditions()})
	require.Eventually(t, func() bool { return len(published()) == 1 }, 2*time.Second, 5*time.Millisecond)

	require.NoError(t, removeArtifact(t.Context(), m, key))

	require.Eventually(t, func() bool { return len(published()) == 0 }, 2*time.Second, 5*time.Millisecond,
		"once every file of an artifact is gone its status entry is withdrawn")
}

func TestNode_RemovePassesThroughToUnderlyingStore(t *testing.T) {
	m := newTestNode()
	key := installConfig(t, m, testutil.TestNamespace, "myfile")
	file := m.FindInstalled(key, artifact.MediumInline)
	require.NotNil(t, file)

	err := removeArtifact(context.Background(), m, key)
	require.NoError(t, err)

	ok, err := m.Verify(context.Background(), file)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestNode_Remove_RemovesEveryInstalledMedium(t *testing.T) {
	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil), configMapFor(testutil.TestNamespace, "myfile-cm", "log_level: info\n"))
	config := inlineConfig(testutil.TestNamespace, "myfile", 50, configData)
	config.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: "myfile-cm"}
	require.NoError(t, apply(t, m, config))
	key := artifact.RefOf(artifact.KindConfig, config)
	files := []*artifact.File{m.FindInstalled(key, artifact.MediumInline), m.FindInstalled(key, artifact.MediumConfigMap)}
	require.NotContains(t, files, (*artifact.File)(nil))

	require.NoError(t, removeArtifact(context.Background(), m, key))
	for _, removedFile := range files {
		intact, err := m.Verify(context.Background(), removedFile)
		require.NoError(t, err)
		assert.False(t, intact)
	}

	assert.Empty(t, m.GetInstalled(key))
}
