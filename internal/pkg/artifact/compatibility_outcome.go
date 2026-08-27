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

// DependenciesNotSatisfiedOutcome decides whether a compatibility-check failure blocks installation, and
// picks the Reason/message for the DependenciesSatisfied condition, based on the enforcement mode and
// whether an artifact is already installed. baseMsg is the per-requirement failure message; a
// mode-specific suffix is appended to it unmodified. A bad update must never regress a working security
// control, so an already-installed artifact is never removed by a failed update:
//
//   - enforceRequirements=false: never blocks; the artifact is installed anyway.
//   - enforceRequirements=true, alreadyInstalled=false: blocks (nothing installed yet).
//   - enforceRequirements=true, alreadyInstalled=true: blocks the update and keeps the installed
//     artifact active.
func DependenciesNotSatisfiedOutcome(enforceRequirements, alreadyInstalled bool, baseMsg string) (skip bool, reason, message string) {
	switch {
	case !enforceRequirements:
		return false, ReasonDependenciesNotSatisfiedInstalledAnyway, baseMsg + MessageSuffixInstalledAnyway
	case alreadyInstalled:
		return true, ReasonDependenciesNotSatisfiedUpdateRejected, baseMsg + MessageSuffixUpdateRejected
	default:
		return true, ReasonDependenciesNotSatisfied, baseMsg
	}
}
