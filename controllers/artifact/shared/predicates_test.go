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

package shared_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/shared"
)

// The aggregate the instance operator writes back to an artifact as its nodes report does not wake the nodes;
// what they act on does.
func TestParentChanged(t *testing.T) {
	base := func() *artifactv1alpha1.Rulesfile {
		return &artifactv1alpha1.Rulesfile{
			ObjectMeta: metav1.ObjectMeta{Name: "rf", Namespace: "ns", Generation: 2},
			Status: artifactv1alpha1.RulesfileStatus{
				ObservedGeneration: 2,
				ArtifactMeta:       &commonv1alpha1.ArtifactMeta{Digest: "sha256:a"},
			},
		}
	}
	now := metav1.Now()
	for name, tc := range map[string]struct {
		change func(*artifactv1alpha1.Rulesfile)
		want   bool
	}{
		"the aggregated conditions change": {func(rf *artifactv1alpha1.Rulesfile) {
			rf.Status.Conditions = []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue}}
		}, false},
		"nothing changes":                {func(*artifactv1alpha1.Rulesfile) {}, false},
		"a new generation":               {func(rf *artifactv1alpha1.Rulesfile) { rf.Generation = 3 }, true},
		"the deletion starts":            {func(rf *artifactv1alpha1.Rulesfile) { rf.DeletionTimestamp = &now }, true},
		"the observed generation moves":  {func(rf *artifactv1alpha1.Rulesfile) { rf.Status.ObservedGeneration = 1 }, true},
		"the artifact metadata changes":  {func(rf *artifactv1alpha1.Rulesfile) { rf.Status.ArtifactMeta.Digest = "sha256:b" }, true},
		"the metadata's sources changed": {func(rf *artifactv1alpha1.Rulesfile) { rf.Status.ArtifactMetaSourcesHash = "h" }, true},
	} {
		t.Run(name, func(t *testing.T) {
			updated := base()
			tc.change(updated)

			got := shared.ParentChanged().Update(event.UpdateEvent{ObjectOld: base(), ObjectNew: updated})

			assert.Equal(t, tc.want, got)
		})
	}
	assert.True(t, shared.ParentChanged().Create(event.CreateEvent{Object: base()}), "a creation is always accepted")
}
