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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// failingOCIFetcher serves inline and ConfigMap sources as the test fetcher does, but fails every OCI
// fetch. A Rulesfile's sources are handled in the order oci, inline, configmap, so it makes the first
// source fail while the later ones are still in play.
type failingOCIFetcher struct {
	artifact.ArtifactFetcher
}

func (failingOCIFetcher) FetchOCI(context.Context, string, string, artifact.Kind, string) (artifact.FetchResult, error) {
	return artifact.FetchResult{}, errors.New("registry unreachable")
}

// TestApplySources_DoesNotReportSourcesItNeverReached pins that a source the apply never got to is not
// reported as programmed. Sources are applied in order and the apply stops at the first failure, so a
// condition set for a later source would claim a file that is not on disk, and the parent aggregates it.
func TestApplySources_DoesNotReportSourcesItNeverReached(t *testing.T) {
	n := newTestNode()
	n.fetcher = failingOCIFetcher{ArtifactFetcher: n.fetcher}

	rf := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "two-sources", Namespace: testutil.TestNamespace, UID: "two-sources-uid"},
		Spec: artifactv1alpha1.RulesfileSpec{
			Priority:    50,
			OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "latest"}},
			InlineRules: &apiextensionsv1.JSON{Raw: []byte(testInlineRulesJSON)},
		},
		Status: artifactv1alpha1.RulesfileStatus{
			ArtifactMeta: &commonv1alpha1.ArtifactMeta{Digest: "deadbeef"},
		},
	}

	status := &artifactv1alpha1.NodeArtifactStatus{}
	require.Error(t, n.ApplyArtifact(t.Context(), rf, status), "the OCI source must fail")

	assert.Nil(t, apimeta.FindStatusCondition(status.Conditions, commonv1alpha1.ConditionInlineArtifactProgrammed.String()),
		"the inline source was never applied, so nothing is reported about it")
	assert.Empty(t, status.InstalledArtifacts, "nothing was installed")
}

// An apply that drops the artifact's only file, as a switch from one source to another does before it fetches
// the new one, keeps the artifact's status entry: withdrawn, it could be published as gone while the artifact is
// being installed. Removing the artifact is what withdraws it.
func TestApplySources_DroppingTheLastSourceKeepsTheStatusEntry(t *testing.T) {
	artifactNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{Name: statusTestNode, Namespace: statusTestNamespace},
		Spec:       artifactv1alpha1.ArtifactNodeSpec{NodeName: statusTestNode},
	}
	n := installOnDisk(t, "cfg", artifactNode)
	key := installedKey("cfg")
	require.True(t, n.status.Has(key.Kind, key.Name))

	_, removed, err := n.removeIfInstalled(t.Context(), key, artifact.MediumInline)

	require.NoError(t, err)
	require.True(t, removed)
	assert.True(t, n.status.Has(key.Kind, key.Name), "the apply is still installing the artifact")

	require.NoError(t, n.Remove(t.Context(), key))
	assert.False(t, n.status.Has(key.Kind, key.Name))
}

// A source withdrawn from the spec keeps its condition until the apply has actually got to removing its file: the
// apply stops at the first failure, and the file of a source it never reached may still be on disk.
func TestStoreFailuresRecord_AWithdrawnSourceKeepsItsConditionUntilItIsReached(t *testing.T) {
	inline := commonv1alpha1.ConditionInlineArtifactProgrammed.String()
	conditions := []metav1.Condition{sourceConditions[artifact.MediumInline].newCondition(
		metav1.ConditionTrue, artifact.ReasonInlineArtifactProgrammed, "installed", 1)}
	rf := &artifactv1alpha1.Rulesfile{}
	withdrawn := map[artifact.Medium]bool{}

	rulesfileStoreFailures.record(recorderFor{node: newTestNode()}, rf, &conditions, 2, withdrawn, nil, artifact.MediumOCI)
	assert.NotNil(t, apimeta.FindStatusCondition(conditions, inline), "never reached: the file may still be there")

	reached := map[artifact.Medium]artifact.StoreAction{artifact.MediumInline: artifact.StoreActionRemoved}
	rulesfileStoreFailures.record(recorderFor{node: newTestNode()}, rf, &conditions, 2, withdrawn, reached, "")
	assert.Nil(t, apimeta.FindStatusCondition(conditions, inline), "removed: the condition goes with the file")
}

// The kinds are a registry, but installing one is a flow of its own that ApplyArtifact picks by type. A kind
// added to the registry and not to ApplyArtifact would be assigned to nodes that refuse to install it.
func TestApplyArtifact_HasAFlowForEveryRegisteredKind(t *testing.T) {
	objects := map[artifact.Kind]artifactv1alpha1.Artifact{
		artifact.KindRulesfile: &artifactv1alpha1.Rulesfile{},
		artifact.KindPlugin:    &artifactv1alpha1.Plugin{},
		artifact.KindConfig:    &artifactv1alpha1.Config{},
	}
	for _, info := range artifact.Kinds() {
		obj := objects[info.Kind]
		require.NotNil(t, obj, "kind %s is registered: give it an object here and a flow in ApplyArtifact", info.Kind)
		obj.SetName("registered")
		obj.SetNamespace(testutil.TestNamespace)

		err := newTestNode().ApplyArtifact(t.Context(), obj, &artifactv1alpha1.NodeArtifactStatus{})

		if err != nil {
			assert.NotContains(t, err.Error(), "does not install", "kind %s", info.Kind)
		}
	}
}
