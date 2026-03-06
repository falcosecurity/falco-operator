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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewConfigMap_TypeMeta(t *testing.T) {
	cm := NewConfigMap().Build()
	assert.Equal(t, "ConfigMap", cm.Kind)
	assert.Equal(t, "v1", cm.APIVersion)
}

func TestConfigMapBuilder(t *testing.T) {
	labels := map[string]string{"app": "test"}
	data := map[string]string{"config.yaml": "key: value"}

	now := metav1.Now()
	cm := NewConfigMap().
		WithName("my-cm").
		WithNamespace("ns").
		WithLabels(labels).
		WithFinalizers([]string{"test-finalizer"}).
		WithDeletionTimestamp(&now).
		WithData(data).
		Build()

	assert.Equal(t, "my-cm", cm.Name)
	assert.Equal(t, "ns", cm.Namespace)
	assert.Equal(t, labels, cm.Labels)
	assert.Equal(t, []string{"test-finalizer"}, cm.Finalizers)
	assert.Equal(t, &now, cm.DeletionTimestamp)
	assert.Equal(t, data, cm.Data)
}
