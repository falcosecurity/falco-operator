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

package controllerhelper_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func TestArtifactNodeLabels(t *testing.T) {
	assert.Equal(t, map[string]string{controllerhelper.LabelArtifactNode: "node-1"},
		controllerhelper.ArtifactNodeLabels("node-1"))
}

func TestArtifactNodeLabels_LongNodeNamesRemainValidAndDistinct(t *testing.T) {
	a := controllerhelper.ArtifactNodeLabels(strings.Repeat("a", 253))[controllerhelper.LabelArtifactNode]
	b := controllerhelper.ArtifactNodeLabels(strings.Repeat("a", 252) + "b")[controllerhelper.LabelArtifactNode]

	assert.Empty(t, validation.IsValidLabelValue(a), "a hashed value must be a valid label value")
	assert.Empty(t, validation.IsValidLabelValue(b))
	assert.NotEqual(t, a, b)
	assert.Equal(t, a, controllerhelper.ArtifactNodeLabels(strings.Repeat("a", 253))[controllerhelper.LabelArtifactNode],
		"the label must be stable: sidecars select their object by it")
}
