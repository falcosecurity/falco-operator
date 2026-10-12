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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestRulesfileHandler_ReportCompatibility(t *testing.T) {
	engineReq := func(name, version string) commonv1alpha1.ArtifactMetaRequirement {
		return commonv1alpha1.ArtifactMetaRequirement{Name: name, Version: version}
	}
	pluginDep := func(name, version string, alts ...commonv1alpha1.ArtifactMetaDependencyVariant) commonv1alpha1.ArtifactMetaDependency {
		return commonv1alpha1.ArtifactMetaDependency{Name: name, Version: version, Alternatives: alts}
	}
	altDep := func(name, version string) commonv1alpha1.ArtifactMetaDependencyVariant {
		return commonv1alpha1.ArtifactMetaDependencyVariant{Name: name, Version: version}
	}

	tests := []struct {
		name                string
		rf                  *artifactv1alpha1.Rulesfile
		artifactMeta        *commonv1alpha1.ArtifactMeta
		falcoCaps           map[string]string
		falcoErr            error
		enforceRequirements bool
		preInstalled        bool
		presetConditions    []metav1.Condition
		wantSkip            bool
		wantErr             bool
		wantConditions      []testutil.ConditionExpect
		wantMessageContains []string
	}{
		{
			name: "no source configured removes DependenciesSatisfied condition",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			presetConditions: []metav1.Condition{
				common.NewDependenciesSatisfiedCondition(metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, 0),
			},
			wantConditions: nil,
		},
		{
			name: "source configured with nil ArtifactMeta in non-strict mode proceeds",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionUnknown, Reason: artifact.ReasonArtifactMetaNotReady},
			},
		},
		{
			name: "source configured with nil ArtifactMeta in strict mode blocks",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionUnknown, Reason: artifact.ReasonArtifactMetaNotReady},
			},
		},
		{
			name: "ArtifactMeta with no requirements sets DependenciesSatisfied True",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "engine requirement not found in Falco versions",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoCaps:           map[string]string{},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "engine requirement version too low",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "engine requirement satisfied sets DependenciesSatisfied True",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")}},
			falcoCaps:    map[string]string{"engine_version_semver": "0.57.0"},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "integer engine version requirement satisfied via engine_version capability",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version", "15")}},
			falcoCaps:    map[string]string{"engine_version": "62", "engine_version_semver": "0.62.0"},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "integer engine version requirement not satisfied",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta:        &commonv1alpha1.ArtifactMeta{Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version", "100")}},
			falcoCaps:           map[string]string{"engine_version": "62", "engine_version_semver": "0.62.0"},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "plugin dependency not satisfied no alternatives",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta:        &commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{pluginDep("container", "0.4.0")}},
			falcoCaps:           map[string]string{},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "plugin dependency satisfied sets DependenciesSatisfied True",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{Dependencies: []commonv1alpha1.ArtifactMetaDependency{pluginDep("container", "0.4.0")}},
			falcoCaps:    map[string]string{"container": "0.4.0"},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "plugin alternative satisfied sets DependenciesSatisfied True",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{pluginDep("container", "0.4.0", altDep("k8smeta", "0.1.0"))},
			},
			falcoCaps: map[string]string{"k8smeta": "0.1.0"},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonDependenciesSatisfied},
			},
		},
		{
			name: "plugin alternatives all unsatisfied sets DependenciesSatisfied False",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{pluginDep("container", "0.4.0", altDep("k8smeta", "0.1.0"))},
			},
			falcoCaps:           map[string]string{},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "Falco versions not yet observed non-strict installs anyway",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")}},
			falcoErr:     fmt.Errorf("connection refused"),
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse,
					Reason: artifact.ReasonDependenciesNotSatisfiedInstalledAnyway,
				},
			},
		},
		{
			name: "Falco versions not yet observed strict blocks without returning an error",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoErr:            fmt.Errorf("connection refused"),
			enforceRequirements: true,
			wantSkip:            true,
			wantErr:             false,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
		},
		{
			name: "multiple plugin deps all unsatisfied reports all in condition message",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{
					pluginDep("container", "0.4.0"),
					pluginDep("k8saudit", "0.7.0"),
				},
			},
			falcoCaps:           map[string]string{},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
			wantMessageContains: []string{"container >= 0.4.0", "k8saudit >= 0.7.0"},
		},
		{
			name: "multiple plugin deps partially satisfied reports only unsatisfied",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{
					pluginDep("container", "0.4.0"),
					pluginDep("k8saudit", "0.7.0"),
				},
			},
			falcoCaps:           map[string]string{"container": "0.5.0"},
			enforceRequirements: true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfied},
			},
			wantMessageContains: []string{"k8saudit >= 0.7.0"},
		},
		{
			name: "advise mode installs despite unsatisfied engine requirement",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			enforceRequirements: false,
			wantSkip:            false,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfiedInstalledAnyway,
				},
			},
			wantMessageContains: []string{"installed anyway"},
		},
		{
			name: "enforce mode rejects update but keeps previously installed rulesfile",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec: artifactv1alpha1.RulesfileSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
				},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoCaps:           map[string]string{"engine_version_semver": "0.50.0"},
			enforceRequirements: true,
			preInstalled:        true,
			wantSkip:            true,
			wantConditions: []testutil.ConditionExpect{
				{
					Type:   commonv1alpha1.ConditionDependenciesSatisfied.String(),
					Status: metav1.ConditionFalse, Reason: artifact.ReasonDependenciesNotSatisfiedUpdateRejected,
				},
			},
			wantMessageContains: []string{"keeping the previously installed version"},
		},
		{
			name: "uncomparable capability version sets DependenciesSatisfied Unknown and returns error",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Requirements: []commonv1alpha1.ArtifactMetaRequirement{engineReq("engine_version_semver", "0.57.0")},
			},
			falcoCaps: map[string]string{"engine_version_semver": "not-a-version"},
			wantErr:   true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionUnknown, Reason: artifact.ReasonDependenciesUnknown},
			},
			wantMessageContains: []string{"Unable to compare engine_version_semver versions"},
		},
		{
			name: "uncomparable plugin dependency version sets DependenciesSatisfied Unknown and returns error",
			rf: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Name: judgeTestRulesfileName, Namespace: testutil.TestNamespace},
				Spec:       artifactv1alpha1.RulesfileSpec{InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)}},
			},
			artifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{pluginDep("container", "0.4.0")},
			},
			falcoCaps: map[string]string{"container": "not-a-version"},
			wantErr:   true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionDependenciesSatisfied.String(), Status: metav1.ConditionUnknown, Reason: artifact.ReasonDependenciesUnknown},
			},
			wantMessageContains: []string{"Unable to compare plugin versions"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := newJudgeTestNode(t, tt.enforceRequirements)
			if tt.falcoErr == nil && tt.falcoCaps != nil {
				n.OnFalcoVersionsObserved(compatfake.NewMockVersionsFetcher(tt.falcoCaps).Result)
			}

			tt.rf.Status.ArtifactMeta = tt.artifactMeta
			status := &artifactv1alpha1.NodeArtifactStatus{}
			if len(tt.presetConditions) > 0 {
				status.Conditions = tt.presetConditions
			}
			if tt.preInstalled {
				n.SeedInstalled(artifact.Ref{Kind: artifact.KindRulesfile, Name: tt.rf.Name},
					[]artifactv1alpha1.InstalledArtifact{
						{Path: "/etc/falco/rules.d/test.yaml", Medium: string(artifact.MediumOCI)},
					})
			}

			sources := &artifact.RulesfileSources{
				OCIArtifact: tt.rf.Spec.OCIArtifact,
				InlineRules: tt.rf.Spec.InlineRules,
			}

			skip, err := n.reportRulesfileCompatibility(t.Context(), tt.rf, status, sources, tt.artifactMeta)

			assert.Equal(t, tt.wantSkip, skip)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			testutil.RequireConditions(t, status.Conditions, tt.wantConditions)
			for _, substr := range tt.wantMessageContains {
				cond := apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
				require.NotNil(t, cond)
				assert.Contains(t, cond.Message, substr)
			}
		})
	}
}
