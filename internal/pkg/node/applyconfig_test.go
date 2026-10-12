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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestNode_ApplyConfig_PartialPriorityMoveTracksInstalledFileAndRetries(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		oldPriority, newPriority int32
	}{
		{name: "higher priority", oldPriority: 50, newPriority: 20},
		{name: "lower priority", oldPriority: 20, newPriority: 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			dirs := artifact.DefaultArtifactDirs()
			m := newTestNodeOver(&artifact.LocalStore{FS: fs, Dirs: dirs}, compatfake.NewMockVersionsFetcher(nil))
			const oldData, updatedData = `{"log_level":"info"}`, `{"log_level":"debug"}`
			oldContent, updatedContent := inlineFile(t, oldData), inlineFile(t, updatedData)
			key := artifact.Ref{Kind: artifact.KindConfig, Name: "myfile"}
			require.NoError(t, apply(t, m, inlineConfig("ns", key.Name, tc.oldPriority, oldData)))
			original := m.FindInstalled(key, artifact.MediumInline)
			require.NotNil(t, original)
			newPath := testutil.MustArtifactPath(t, dirs, key.Name, tc.newPriority, artifact.MediumInline, artifact.KindConfig)
			replaceErr := errors.New("cannot replace moved config")
			fs.RenameErrFor = map[string]error{artifact.StagingPath(newPath): replaceErr}

			err := apply(t, m, inlineConfig("ns", key.Name, tc.newPriority, updatedData))

			// The file moved to its new priority, but the new content could not replace it: the node records
			// the file where it now is, with the content it still has.
			require.ErrorIs(t, err, replaceErr)
			relocated := m.FindInstalled(key, artifact.MediumInline)
			require.NotNil(t, relocated)
			assert.Equal(t, newPath, relocated.Path)
			assert.Equal(t, tc.newPriority, relocated.Priority)
			assert.Equal(t, testutil.SHA256Hex(oldContent), relocated.ContentHash)
			assert.Equal(t, oldContent, fs.Files[newPath])
			assert.NotContains(t, fs.Files, original.Path)
			assert.NotContains(t, fs.Files, artifact.StagingPath(newPath))
			intact, err := m.Verify(ctx, relocated)
			require.NoError(t, err)
			assert.True(t, intact)

			delete(fs.RenameErrFor, artifact.StagingPath(newPath))
			require.NoError(t, apply(t, m, inlineConfig("ns", key.Name, tc.newPriority, updatedData)))

			installed := m.FindInstalled(key, artifact.MediumInline)
			require.NotNil(t, installed)
			assert.Equal(t, newPath, installed.Path)
			assert.Equal(t, tc.newPriority, installed.Priority)
			assert.Equal(t, testutil.SHA256Hex(updatedContent), installed.ContentHash)
			assert.Equal(t, updatedContent, fs.Files[newPath])
			assert.NotContains(t, fs.Files, original.Path)
			assert.NotContains(t, fs.Files, artifact.StagingPath(newPath))
			intact, err = m.Verify(ctx, installed)
			require.NoError(t, err)
			assert.True(t, intact)

			writes := len(fs.WriteCalls)
			require.NoError(t, apply(t, m, inlineConfig("ns", key.Name, tc.newPriority, updatedData)))
			assert.Len(t, fs.WriteCalls, writes, "an unchanged Config is not written again")
		})
	}
}

func TestNode_ApplyConfig_WritesAFileThatVerifies(t *testing.T) {
	m := newTestNode()

	key := installConfig(t, m, testutil.TestNamespace, "myfile")

	file := m.FindInstalled(key, artifact.MediumInline)
	require.NotNil(t, file)
	ok, err := m.Verify(t.Context(), file)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestNode_ApplyConfig_OnlyWritesConfig(t *testing.T) {
	for _, tc := range []struct {
		medium artifact.Medium
		config *artifactv1alpha1.Config
	}{
		{medium: artifact.MediumInline, config: inlineConfig("ns", "artifact", 50, configData)},
		{medium: artifact.MediumConfigMap, config: configMapConfig("ns", "artifact", 50, "artifact-cm")},
	} {
		t.Run(string(tc.medium), func(t *testing.T) {
			store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
			m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil), configMapFor("ns", "artifact-cm", "log_level: info\n"))
			key := artifact.RefOf(artifact.KindConfig, tc.config)

			require.NoError(t, apply(t, m, tc.config))

			file := m.FindInstalled(key, tc.medium)
			require.NotNil(t, file)
			assert.Equal(t, testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), key.Name, 50, tc.medium, artifact.KindConfig), file.Path)
			for _, kind := range []artifact.Kind{artifact.KindRulesfile, artifact.KindPlugin} {
				assert.Empty(t, m.GetInstalled(artifact.Ref{Kind: kind, Name: key.Name}))
			}
			for _, kind := range []artifact.Kind{artifact.KindRulesfile, artifact.KindPlugin} {
				disk, err := m.ScanAll(t.Context(), kind)
				require.NoError(t, err)
				assert.Empty(t, disk)
			}
		})
	}
}

func TestNode_ApplyConfig_ProtectsSharedPluginConfigPath(t *testing.T) {
	const configMapData = "log_level: debug\n"
	for _, tc := range []struct {
		name    string
		config  *artifactv1alpha1.Config
		want    []byte
		wantErr bool
	}{
		{name: "reserved path", config: inlineConfig("ns", "plugins-config", 99, configData), wantErr: true},
		{name: "different priority", config: inlineConfig("ns", "plugins-config", 50, configData), want: inlineFile(t, configData)},
		{name: "configmap medium", config: configMapConfig("ns", "plugins-config", 99, "cm"), want: []byte(configMapData)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil), configMapFor("ns", "cm", configMapData))
			_, shared, err := m.AddPluginConfig(ctx, testPlugin("container"))
			require.NoError(t, err)
			before, err := store.Read(ctx, shared.Path)
			require.NoError(t, err)
			writes := len(fs.WriteCalls)

			err = apply(t, m, tc.config)

			installed := m.GetInstalled(artifact.RefOf(artifact.KindConfig, tc.config))
			if tc.wantErr {
				require.Error(t, err)
				assert.Empty(t, installed)
				assert.Len(t, fs.WriteCalls, writes)
			} else {
				require.NoError(t, err)
				require.Len(t, installed, 1)
				assert.NotEqual(t, shared.Path, installed[0].Path)
				assert.Equal(t, tc.want, fs.Files[installed[0].Path])
			}
			intact, err := m.Verify(ctx, shared)
			require.NoError(t, err)
			assert.True(t, intact)
			after, err := store.Read(ctx, shared.Path)
			require.NoError(t, err)
			assert.Equal(t, before, after)
		})
	}
}

func TestNode_ApplyConfig_SecondIdenticalApplyWritesNothing(t *testing.T) {
	fs := fsfake.NewMockFileSystem()
	m := newTestNodeOver(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}, compatfake.NewMockVersionsFetcher(nil))
	installConfig(t, m, testutil.TestNamespace, "myfile")
	writes := len(fs.WriteCalls)

	// Nothing tells the node what it holds but its own record, which is what recognizes the second
	// apply as a no-op.
	installConfig(t, m, testutil.TestNamespace, "myfile")

	assert.Len(t, fs.WriteCalls, writes)
}

// A source withdrawn from the spec whose file cannot be removed keeps its condition, False, until the
// removal succeeds: dropping it would let the aggregate status hide the file still on the node. The
// replacement source is not written while the withdrawn one is still there.
func TestNode_ApplyConfig_AWithdrawnSourceThatCannotBeRemovedStaysReported(t *testing.T) {
	const configMapName = "config"
	inline := inlineConfig(testutil.TestNamespace, "myfile", 50, configData)
	fromConfigMap := configMapConfig(testutil.TestNamespace, "myfile", 50, configMapName)
	for _, tc := range []struct {
		name                 string
		before, after        *artifactv1alpha1.Config
		withdrawn, remaining commonv1alpha1.ConditionType
		remainingMedium      artifact.Medium
	}{
		{"inline withdrawn", inline, fromConfigMap,
			commonv1alpha1.ConditionInlineArtifactProgrammed, commonv1alpha1.ConditionConfigMapArtifactProgrammed, artifact.MediumConfigMap},
		{"configmap withdrawn", fromConfigMap, inline,
			commonv1alpha1.ConditionConfigMapArtifactProgrammed, commonv1alpha1.ConditionInlineArtifactProgrammed, artifact.MediumInline},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := fsfake.NewMockFileSystem()
			n := newTestNodeOver(&artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()},
				compatfake.NewMockVersionsFetcher(nil), configMapFor(testutil.TestNamespace, configMapName, `log_level: debug`))
			key := artifact.Ref{Kind: artifact.KindConfig, Name: "myfile"}
			status := &artifactv1alpha1.NodeArtifactStatus{}
			require.NoError(t, n.ApplyArtifact(t.Context(), tc.before, status))
			withdrawnMedium := artifact.MediumInline
			if tc.remainingMedium == artifact.MediumInline {
				withdrawnMedium = artifact.MediumConfigMap
			}
			installed := n.FindInstalled(key, withdrawnMedium)
			require.NotNil(t, installed)
			previous := *installed
			previousContent := fs.Files[previous.Path]
			next := testutil.MustArtifactPath(t, artifact.DefaultArtifactDirs(), key.Name, 50, tc.remainingMedium, artifact.KindConfig)

			removeErr := errors.New("injected removal failure")
			fs.RemoveErr = removeErr
			for range 2 {
				err := n.ApplyArtifact(t.Context(), tc.after, status)

				require.ErrorIs(t, err, removeErr)
				condition := apimeta.FindStatusCondition(status.Conditions, tc.withdrawn.String())
				require.NotNil(t, condition, "%+v", status.Conditions)
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				assert.Equal(t, artifact.ReasonArtifactRemoveFailed, condition.Reason)
				assert.Contains(t, condition.Message, removeErr.Error())
				assert.Equal(t, previousContent, fs.Files[previous.Path])
				assert.NotContains(t, fs.Files, next)
			}

			fs.RemoveErr = nil
			require.NoError(t, n.ApplyArtifact(t.Context(), tc.after, status))

			assert.Nil(t, apimeta.FindStatusCondition(status.Conditions, tc.withdrawn.String()))
			assert.True(t, apimeta.IsStatusConditionTrue(status.Conditions, tc.remaining.String()), "%+v", status.Conditions)
			assert.NotContains(t, fs.Files, previous.Path)
			assert.Contains(t, fs.Files, next)
		})
	}
}
