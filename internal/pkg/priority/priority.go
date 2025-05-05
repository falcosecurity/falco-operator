// Copyright (C) 2025 The Falco Authors
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

package priority

import (
	"fmt"
)

const (
	// MaxPriority is the maximum value for the priority annotation.
	MaxPriority = 99
	// MinPriority is the minimum value for the priority annotation.
	MinPriority = 0
	// DefaultPriority is the default priority value used when the priority annotation is not present in the artifact.
	DefaultPriority = 50
	// OCISubPriority is the sub-priority value for OCI-based artifacts.
	OCISubPriority = 1
	// CMSubPriority is the sub-priority value for ConfigMap-based artifacts.
	CMSubPriority = 2
	// InLineRulesSubPriority is the sub-priority value for raw YAML-based artifacts.
	InLineRulesSubPriority = 3
)

// NameFromPriority generates a name by combining the priority and original name.
func NameFromPriority(priority int32, originalName string) string {
	return fmt.Sprintf("%0*d-%s", 2, priority, originalName)
}

// NameFromPriorityAndSubPriority generates a name by combining the priority, sub-priority, and original name.
// It takes priority, subPriority and originalName as inputs and returns a string formatted as "priority-subPriority-originalName".
func NameFromPriorityAndSubPriority(priority, subPriority int32, originalName string) string {
	return fmt.Sprintf("%0*d-%0*d-%s", 2, priority, 2, subPriority, originalName)
}
