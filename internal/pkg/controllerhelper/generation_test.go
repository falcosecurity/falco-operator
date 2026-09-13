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
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func TestWaitForObservedGeneration_MismatchReturnsTrue(t *testing.T) {
	wait := controllerhelper.WaitForObservedGeneration(logr.Discard(), 1, 2)
	assert.True(t, wait, "observedGeneration behind generation must defer")
}

func TestWaitForObservedGeneration_MatchReturnsFalse(t *testing.T) {
	wait := controllerhelper.WaitForObservedGeneration(logr.Discard(), 3, 3)
	assert.False(t, wait, "observedGeneration caught up to generation must proceed")
}
