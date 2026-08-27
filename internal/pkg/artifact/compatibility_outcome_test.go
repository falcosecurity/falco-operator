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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDependenciesNotSatisfiedOutcome(t *testing.T) {
	const baseMsg = "requires foo >= 1.0.0 but Falco reports 0.9.0"

	tests := []struct {
		name                string
		enforceRequirements bool
		alreadyInstalled    bool
		wantSkip            bool
		wantReason          string
		wantMessage         string
	}{
		{
			name:                "advise mode installs anyway with nothing previously installed",
			enforceRequirements: false,
			alreadyInstalled:    false,
			wantSkip:            false,
			wantReason:          ReasonDependenciesNotSatisfiedInstalledAnyway,
			wantMessage:         baseMsg + MessageSuffixInstalledAnyway,
		},
		{
			name:                "advise mode installs anyway even with something already installed",
			enforceRequirements: false,
			alreadyInstalled:    true,
			wantSkip:            false,
			wantReason:          ReasonDependenciesNotSatisfiedInstalledAnyway,
			wantMessage:         baseMsg + MessageSuffixInstalledAnyway,
		},
		{
			name:                "enforce mode blocks a fresh install with nothing previously installed",
			enforceRequirements: true,
			alreadyInstalled:    false,
			wantSkip:            true,
			wantReason:          ReasonDependenciesNotSatisfied,
			wantMessage:         baseMsg,
		},
		{
			name:                "enforce mode rejects an update but keeps the previous install",
			enforceRequirements: true,
			alreadyInstalled:    true,
			wantSkip:            true,
			wantReason:          ReasonDependenciesNotSatisfiedUpdateRejected,
			wantMessage:         baseMsg + MessageSuffixUpdateRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skip, reason, message := DependenciesNotSatisfiedOutcome(tt.enforceRequirements, tt.alreadyInstalled, baseMsg)
			assert.Equal(t, tt.wantSkip, skip)
			assert.Equal(t, tt.wantReason, reason)
			assert.Equal(t, tt.wantMessage, message)
		})
	}
}
