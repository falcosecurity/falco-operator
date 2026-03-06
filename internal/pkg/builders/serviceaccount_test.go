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
)

func TestNewServiceAccount_TypeMeta(t *testing.T) {
	sa := NewServiceAccount().Build()
	assert.Equal(t, "ServiceAccount", sa.Kind)
	assert.Equal(t, "v1", sa.APIVersion)
}

func TestServiceAccountBuilder(t *testing.T) {
	labels := map[string]string{"app": "test"}

	sa := NewServiceAccount().
		WithName("my-sa").
		WithNamespace("ns").
		WithLabels(labels).
		Build()

	assert.Equal(t, "my-sa", sa.Name)
	assert.Equal(t, "ns", sa.Namespace)
	assert.Equal(t, labels, sa.Labels)
}
