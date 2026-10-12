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

package index_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

func TestPodByNodeName(t *testing.T) {
	scheduled := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: testNamespace}, Spec: corev1.PodSpec{NodeName: "n1"}}
	assert.Equal(t, []string{"n1"}, index.PodByNodeName(scheduled))

	unscheduled := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: testNamespace}}
	assert.Nil(t, index.PodByNodeName(unscheduled), "a pod without a node is on no node")

	assert.Nil(t, index.PodByNodeName(&artifactv1alpha1.Plugin{}), "another type is not a pod")
}

func TestInstanceOperator(t *testing.T) {
	expected := append(append([]index.Entry{}, index.All...), index.PodIndexes...)
	require.Len(t, index.InstanceOperator, len(expected),
		"the instance operator registers every artifact index, plus the pod index that only it needs")
	for i, entry := range index.InstanceOperator {
		assert.Equal(t, expected[i].Field, entry.Field, "entry %d", i)
		assert.IsType(t, expected[i].Object, entry.Object, "entry %d", i)
		assert.NotNil(t, entry.ExtractValueFn, "entry %d", i)
	}
	assert.Len(t, index.All, len(expected)-len(index.PodIndexes), "the sidecar's list must not grow a pod index")
}
