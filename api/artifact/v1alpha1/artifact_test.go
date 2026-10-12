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

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// Each kind answers from its own spec and status, and the accessors of the status point into it.
func TestArtifactAccessors(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
	oci := &commonv1alpha1.OCIArtifact{}
	meta := &commonv1alpha1.ArtifactMeta{Digest: "sha256:x"}
	for _, tc := range []struct {
		artifact   Artifact
		kind       ArtifactKind
		oci        *commonv1alpha1.OCIArtifact
		meta       *commonv1alpha1.ArtifactMeta
		sourceHash string
	}{
		{
			artifact: &Rulesfile{
				Spec:   RulesfileSpec{Selector: selector, OCIArtifact: oci},
				Status: RulesfileStatus{ArtifactMeta: meta, ArtifactMetaSourcesHash: "h"},
			},
			kind: KindRulesfile, oci: oci, meta: meta, sourceHash: "h",
		},
		{
			artifact: &Plugin{Spec: PluginSpec{Selector: selector, OCIArtifact: oci}, Status: PluginStatus{ArtifactMeta: meta}},
			kind:     KindPlugin, oci: oci, meta: meta,
		},
		{
			artifact: &Config{Spec: ConfigSpec{Selector: selector}},
			kind:     KindConfig,
		},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			a := tc.artifact

			assert.Equal(t, tc.kind, a.GetArtifactKind())
			assert.Same(t, selector, a.GetSelector())
			assert.Same(t, tc.oci, a.GetOCIArtifact())
			assert.Same(t, tc.meta, a.GetArtifactMeta())
			assert.Equal(t, tc.sourceHash, a.GetArtifactMetaSourcesHash())

			*a.GetStatusObservedGeneration() = 7
			*a.GetStatusConditions() = []metav1.Condition{{Type: "Programmed"}}
			assert.Equal(t, int64(7), *a.GetStatusObservedGeneration(), "the observed generation is set in place")
			assert.Len(t, *a.GetStatusConditions(), 1, "the conditions are set in place")
		})
	}
}
