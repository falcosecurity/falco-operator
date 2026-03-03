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

package builders

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func TestNewRulesfile_Empty(t *testing.T) {
	r := NewRulesfile().Build()
	assert.Empty(t, r.Name)
	assert.Empty(t, r.Namespace)
	assert.Nil(t, r.Spec.OCIArtifact)
	assert.Nil(t, r.Spec.InlineRules)
	assert.Nil(t, r.Spec.ConfigMapRef)
	assert.Zero(t, r.Spec.Priority)
	assert.Nil(t, r.Spec.Selector)
}

func TestRulesfileBuilder(t *testing.T) {
	labels := map[string]string{"app": "falco"}
	now := metav1.Now()
	ociArtifact := commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{
			Repository: "falcosecurity/rules/falco-rules",
			Tag:        "3.0.0",
		},
	}
	cmRef := &commonv1alpha1.ConfigMapRef{Name: "my-rules-cm"}
	selector := &metav1.LabelSelector{
		MatchLabels: map[string]string{"node": "worker"},
	}

	r := NewRulesfile().
		WithName("my-rulesfile").
		WithNamespace("ns").
		WithLabels(labels).
		WithFinalizers([]string{"rulesfile.falcosecurity.dev/finalizer"}).
		WithDeletionTimestamp(&now).
		WithGeneration(7).
		WithOCIArtifact(ociArtifact).
		WithInlineRules(&apiextensionsv1.JSON{Raw: []byte(`"- rule: test\n  desc: test rule\n"`)}).
		WithConfigMapRef(cmRef).
		WithPriority(90).
		WithSelector(selector).
		Build()

	assert.Equal(t, "my-rulesfile", r.Name)
	assert.Equal(t, "ns", r.Namespace)
	assert.Equal(t, labels, r.Labels)
	assert.Equal(t, []string{"rulesfile.falcosecurity.dev/finalizer"}, r.Finalizers)
	assert.Equal(t, &now, r.DeletionTimestamp)
	assert.Equal(t, int64(7), r.Generation)
	require.NotNil(t, r.Spec.OCIArtifact)
	assert.Equal(t, "falcosecurity/rules/falco-rules", r.Spec.OCIArtifact.Image.Repository)
	assert.Equal(t, "3.0.0", r.Spec.OCIArtifact.Image.Tag)
	require.NotNil(t, r.Spec.InlineRules)
	assert.Contains(t, string(r.Spec.InlineRules.Raw), "test rule")
	require.NotNil(t, r.Spec.ConfigMapRef)
	assert.Equal(t, "my-rules-cm", r.Spec.ConfigMapRef.Name)
	assert.Equal(t, int32(90), r.Spec.Priority)
	require.NotNil(t, r.Spec.Selector)
	assert.Equal(t, selector, r.Spec.Selector)
}
