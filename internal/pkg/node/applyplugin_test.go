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
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestNode_ApplyPlugin_ProtectsInstalledOwnership(t *testing.T) {
	const (
		configCollision = "config name collision"
		recreatedOwner  = "recreated owner"
		blockedRename   = "blocked rename"
	)
	for _, scenario := range []string{configCollision, recreatedOwner, blockedRename} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			fs := fsfake.NewMockFileSystem()
			store := &artifact.LocalStore{FS: fs, Dirs: artifact.DefaultArtifactDirs()}
			m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil))
			plugin := testPlugin("plugin-cr")
			plugin.Namespace, plugin.UID = "ns", "original-uid"
			plugin.Spec.Config = &artifactv1alpha1.PluginConfig{Name: "container"}
			require.NoError(t, apply(t, m, withBinary(plugin, "installed binary")))
			binary := m.FindInstalled(artifact.RefOf(artifact.KindPlugin, plugin), artifact.MediumOCI)
			require.NotNil(t, binary)
			config := pluginsConfigFileOf(m)
			require.NotNil(t, config)
			candidate := plugin.DeepCopy()
			switch scenario {
			case configCollision:
				candidate.Name, candidate.UID = "another-cr", "another-uid"
			case recreatedOwner:
				candidate.UID = "replacement-uid"
				candidate.Spec.Config.Name = "replacement-name"
			case blockedRename:
				candidate.Spec.Config.Name = "renamed"
				m.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcherWithPlugins(map[string]string{"container": "1.0.0"}).Result)
				installTestRulesfile(t, m, artifact.Ref{Kind: artifact.KindRulesfile, Name: "rules"},
					[]commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "1.0.0"}})
			}
			before, err := store.Read(ctx, config.Path)
			require.NoError(t, err)
			writes := len(fs.WriteCalls)

			err = apply(t, m, withBinary(candidate, "candidate binary"))

			require.Error(t, err)
			if scenario == blockedRename {
				var blocked *BlockedError
				require.ErrorAs(t, err, &blocked)
			}
			if scenario != recreatedOwner && scenario != blockedRename {
				assert.Nil(t, m.FindInstalled(artifact.RefOf(artifact.KindPlugin, candidate), artifact.MediumOCI))
			}
			_, _, err = m.AddPluginConfig(ctx, candidate)
			require.Error(t, err, "the aggregate must reject the same ownership conflict")
			if scenario != blockedRename {
				require.NoError(t, m.RemovePluginConfig(ctx, candidate), "a different owner cannot remove the installed entry")
			}
			assert.Len(t, fs.WriteCalls, writes, "rejected ownership must not write a binary or config")
			after, err := store.Read(ctx, config.Path)
			require.NoError(t, err)
			assert.Equal(t, before, after)
			for _, file := range []*artifact.File{binary, config} {
				intact, verifyErr := m.Verify(ctx, file)
				require.NoError(t, verifyErr)
				assert.True(t, intact, "installed bytes must survive the rejected update")
			}
			if scenario == configCollision {
				require.NoError(t, m.RemovePluginConfig(ctx, plugin))
				require.NoError(t, apply(t, m, withBinary(candidate, "candidate binary")),
					"an explicitly removed config name is not reserved forever")
			}
		})
	}
}

func TestNode_ReportPluginCompatibility_CompareError(t *testing.T) {
	tests := []struct {
		name        string
		meta        *commonv1alpha1.ArtifactMeta
		falcoCaps   map[string]string
		wantMessage string
	}{
		{
			name: "uncomparable capability version",
			meta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{{Name: "engine_version_semver", Version: "0.57.0"}},
			},
			falcoCaps:   map[string]string{"engine_version_semver": "not-a-version"},
			wantMessage: "Unable to compare engine_version_semver versions",
		},
		{
			name: "uncomparable plugin dependency version",
			meta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
			},
			falcoCaps:   map[string]string{"container": "not-a-version"},
			wantMessage: "Unable to compare plugin versions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := newJudgeTestNode(t, false)
			n.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.falcoCaps).Result)
			plugin := testPlugin("plugin-cr")
			plugin.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{Repository: "repo/plugin", Tag: "latest"},
			}
			plugin.Status.ArtifactMeta = tt.meta
			status := &artifactv1alpha1.NodeArtifactStatus{}

			skip, err := n.reportPluginCompatibility(t.Context(), plugin, status)

			require.Error(t, err)
			assert.False(t, skip, "a compare fault is retried, not treated as a blocked install")
			cond := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
			require.NotNil(t, cond)
			assert.Equal(t, metav1.ConditionUnknown, cond.Status)
			assert.Equal(t, artifact.ReasonDependenciesUnknown, cond.Reason)
			assert.Contains(t, cond.Message, tt.wantMessage)
		})
	}
}

// A node that enforces requirements does not install an artifact whose metadata declares none: it cannot tell
// whether Falco provides what the artifact needs. An update of something already installed is rejected, and
// says so.
func TestReportCompatibility_EnforcingRefusesMetadataThatDeclaresNoRequirements(t *testing.T) {
	silent := &commonv1alpha1.ArtifactMeta{Digest: "sha256:abc"}
	report := map[string]func(*Node, *artifactv1alpha1.NodeArtifactStatus) (artifact.Ref, func() (bool, error)){
		"Plugin": func(n *Node, status *artifactv1alpha1.NodeArtifactStatus) (artifact.Ref, func() (bool, error)) {
			plugin := withBinary(testPlugin("pl"), "binary")
			plugin.Status.ArtifactMeta = silent
			return artifact.RefOf(artifact.KindPlugin, plugin), func() (bool, error) {
				return n.reportPluginCompatibility(t.Context(), plugin, status)
			}
		},
		"Rulesfile": func(n *Node, status *artifactv1alpha1.NodeArtifactStatus) (artifact.Ref, func() (bool, error)) {
			rulesfile := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName},
				Spec:       artifactv1alpha1.RulesfileSpec{OCIArtifact: &commonv1alpha1.OCIArtifact{}},
			}
			return artifact.RefOf(artifact.KindRulesfile, rulesfile), func() (bool, error) {
				sources := &artifact.RulesfileSources{OCIArtifact: rulesfile.Spec.OCIArtifact}
				return n.reportRulesfileCompatibility(t.Context(), rulesfile, status, sources, silent)
			}
		},
	}
	for kind, prepare := range report {
		for _, installed := range []bool{false, true} {
			t.Run(kind+", already installed: "+strconv.FormatBool(installed), func(t *testing.T) {
				n := newJudgeTestNode(t, true)
				status := &artifactv1alpha1.NodeArtifactStatus{}
				key, run := prepare(n, status)
				wantReason, wantMessage := artifact.ReasonDependenciesUnknown, artifact.MessageRequirementsUndeclared
				if installed {
					n.SeedInstalled(key, []artifactv1alpha1.InstalledArtifact{{Path: "/installed", Medium: string(artifact.MediumOCI)}})
					wantReason = artifact.ReasonDependenciesNotSatisfiedUpdateRejected
					wantMessage += artifact.MessageSuffixUpdateRejected
				}

				blocked, err := run()

				require.NoError(t, err)
				assert.True(t, blocked)
				cond := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
				require.NotNil(t, cond)
				assert.Equal(t, metav1.ConditionUnknown, cond.Status)
				assert.Equal(t, wantReason, cond.Reason)
				assert.Equal(t, wantMessage, cond.Message)
			})
		}
	}
}

// pluginWithInitConfigFrom is an installable Plugin whose init config is read from the ConfigMap named configMap.
func pluginWithInitConfigFrom(name, configMap string) *artifactv1alpha1.Plugin {
	plugin := testPlugin(name)
	plugin.Namespace, plugin.UID = testutil.TestNamespace, types.UID(name+"-uid")
	plugin.Spec.Config = &artifactv1alpha1.PluginConfig{ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: configMap}}
	return withBinary(plugin, "binary")
}

// initConfigMap is the ConfigMap a Plugin's spec.config.configMapRef names, holding data under the init config key.
func initConfigMap(name, data string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: name},
		Data:       map[string]string{commonv1alpha1.ConfigMapPluginInitConfigKey: data},
	}
}

func TestNode_ApplyPlugin_InitConfigFromConfigMap(t *testing.T) {
	ctx := t.Context()
	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	configMap := initConfigMap("container-init", "label_max_len: 100\nengines:\n  containerd:\n    enabled: true\n")
	m := newTestNodeOver(store, compatfake.NewMockVersionsFetcher(nil), configMap)
	plugin := pluginWithInitConfigFrom("container", configMap.Name)
	status := &artifactv1alpha1.NodeArtifactStatus{}

	require.NoError(t, m.ApplyArtifact(ctx, plugin, status))

	testutil.RequireCondition(t, status.Conditions, commonv1alpha1.ConditionResolvedRefs.String(),
		metav1.ConditionTrue, artifact.ReasonReferenceResolved)
	testutil.RequireCondition(t, status.Conditions, commonv1alpha1.ConditionConfigProgrammed.String(),
		metav1.ConditionTrue, artifact.ReasonConfigProgrammed)
	entry := findPluginConfig(m.pluginsConfig.Configs, "container")
	require.NotNil(t, entry)
	require.NotNil(t, entry.InitConfig)
	assert.JSONEq(t, `{"label_max_len":100,"engines":{"containerd":{"enabled":true}}}`, string(entry.InitConfig.Raw))
	data, err := store.Read(ctx, pluginsConfigFileOf(m).Path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "init_config:")
	assert.Contains(t, string(data), "label_max_len: 100")
	require.NotNil(t, plugin.Spec.Config.ConfigMapRef, "the caller's Plugin must not be changed")
	assert.Nil(t, plugin.Spec.Config.InitConfig, "the caller's Plugin must not be changed")

	// The ConfigMap changes: the next apply writes its new content.
	configMap.Data[commonv1alpha1.ConfigMapPluginInitConfigKey] = "label_max_len: 200\n"
	require.NoError(t, m.cl.Update(ctx, configMap))
	require.NoError(t, m.ApplyArtifact(ctx, plugin, status))
	entry = findPluginConfig(m.pluginsConfig.Configs, "container")
	require.NotNil(t, entry)
	require.NotNil(t, entry.InitConfig)
	assert.JSONEq(t, `{"label_max_len":200}`, string(entry.InitConfig.Raw))

	// The key is emptied: the entry no longer carries an init config.
	configMap.Data[commonv1alpha1.ConfigMapPluginInitConfigKey] = ""
	require.NoError(t, m.cl.Update(ctx, configMap))
	require.NoError(t, m.ApplyArtifact(ctx, plugin, status))
	entry = findPluginConfig(m.pluginsConfig.Configs, "container")
	require.NotNil(t, entry)
	assert.Nil(t, entry.InitConfig)
}

func TestNode_ApplyPlugin_InitConfigFromConfigMapFailures(t *testing.T) {
	tests := []struct {
		name      string
		configMap *corev1.ConfigMap
		// inline, when set, is also the Plugin's spec.config.initConfig.
		inline *apiextensionsv1.JSON
		// wantResolvedRefs is the ResolvedRefs status the apply leaves.
		wantResolvedRefs metav1.ConditionStatus
		// wantConfigProgrammedMessage, when set, is a part of the message of ConfigProgrammed=False.
		wantConfigProgrammedMessage string
	}{
		{
			name:             "missing ConfigMap",
			wantResolvedRefs: metav1.ConditionFalse,
		},
		{
			name: "ConfigMap without the init config key",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: testutil.TestNamespace, Name: "container-init"},
				Data:       map[string]string{commonv1alpha1.ConfigMapConfigKey: "label_max_len: 100\n"},
			},
			wantResolvedRefs:            metav1.ConditionTrue,
			wantConfigProgrammedMessage: `missing expected key "initConfig.yaml"`,
		},
		{
			name:                        "init config that is not YAML",
			configMap:                   initConfigMap("container-init", "label_max_len: [100\n"),
			wantResolvedRefs:            metav1.ConditionTrue,
			wantConfigProgrammedMessage: `parse key "initConfig.yaml"`,
		},
		{
			name:                        "init config set inline as well",
			configMap:                   initConfigMap("container-init", "label_max_len: 100\n"),
			inline:                      &apiextensionsv1.JSON{Raw: []byte(`{"label_max_len":200}`)},
			wantResolvedRefs:            metav1.ConditionTrue,
			wantConfigProgrammedMessage: "spec.config.initConfig and spec.config.configMapRef are mutually exclusive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if tt.configMap != nil {
				objs = append(objs, tt.configMap)
			}
			m := newTestNodeOver(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()},
				compatfake.NewMockVersionsFetcher(nil), objs...)
			status := &artifactv1alpha1.NodeArtifactStatus{}
			plugin := pluginWithInitConfigFrom("container", "container-init")
			plugin.Spec.Config.InitConfig = tt.inline

			err := m.ApplyArtifact(t.Context(), plugin, status)

			require.Error(t, err)
			resolvedRefs := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionResolvedRefs.String())
			require.NotNil(t, resolvedRefs)
			assert.Equal(t, tt.wantResolvedRefs, resolvedRefs.Status)
			if tt.wantConfigProgrammedMessage != "" {
				configProgrammed := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionConfigProgrammed.String())
				require.NotNil(t, configProgrammed)
				assert.Equal(t, metav1.ConditionFalse, configProgrammed.Status)
				assert.Equal(t, artifact.ReasonConfigProgramFailed, configProgrammed.Reason)
				assert.Contains(t, configProgrammed.Message, tt.wantConfigProgrammedMessage)
			}
			assert.Nil(t, findPluginConfig(m.pluginsConfig.Configs, "container"),
				"no entry is written without the init config the Plugin asks for")
		})
	}
}
