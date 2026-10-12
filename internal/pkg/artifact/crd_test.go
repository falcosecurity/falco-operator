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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
)

// The ArtifactNode CRD's limits and enums are written as literals in kubebuilder markers, and the code that fills
// the lists works from Go constants and registries. Each sidecar writes its whole status list in one patch, so a
// list longer than the schema allows, or a value its enum does not know, gets that patch rejected on every node.
func TestArtifactNodeCRD_MatchesTheRegistries(t *testing.T) {
	data, err := os.ReadFile("../../../chart/falco-operator/crds/artifact.falcosecurity.dev_artifactnodes.yaml")
	require.NoError(t, err)
	crd := &apiextensionsv1.CustomResourceDefinition{}
	require.NoError(t, yaml.Unmarshal(data, crd))
	require.Len(t, crd.Spec.Versions, 1)
	root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties
	enum := func(prop *apiextensionsv1.JSONSchemaProps) (values []string) {
		for _, v := range prop.Enum {
			var s string
			require.NoError(t, yaml.Unmarshal(v.Raw, &s))
			values = append(values, s)
		}
		return values
	}
	kindNames, mediumNames := make([]string, 0, len(kinds)), make([]string, 0, len(sources))
	for i := range kinds {
		kindNames = append(kindNames, string(kinds[i].Kind))
	}
	for i := range sources {
		mediumNames = append(mediumNames, string(sources[i].Medium))
	}

	assigned := root["spec"].Properties["artifacts"]
	reported := root["status"].Properties["artifacts"]
	installed := reported.Items.Schema.Properties["installedArtifacts"]
	assignedKind, reportedKind := assigned.Items.Schema.Properties["kind"], reported.Items.Schema.Properties["kind"]
	medium := installed.Items.Schema.Properties["medium"]

	assert.EqualValues(t, artifactv1alpha1.MaxNodeArtifacts, *assigned.MaxItems, "spec.artifacts")
	assert.EqualValues(t, artifactv1alpha1.MaxNodeArtifacts, *reported.MaxItems, "status.artifacts")
	assert.EqualValues(t, len(sources), *installed.MaxItems, "an artifact has at most one file per medium")
	assert.ElementsMatch(t, kindNames, enum(&assignedKind), "spec.artifacts[].kind")
	assert.ElementsMatch(t, kindNames, enum(&reportedKind), "status.artifacts[].kind")
	assert.ElementsMatch(t, mediumNames, enum(&medium), "installedArtifacts[].medium")
}
