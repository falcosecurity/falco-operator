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

package falco

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/alacuku/falco-operator/api/common/v1alpha1"
)

// findCondition searches for a condition of the specified type in the given slice of conditions.
// It returns a pointer to the condition if found, otherwise it returns nil.
func findCondition(conditions []metav1.Condition, conditionType commonv1alpha1.ConditionType) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == string(conditionType) {
			return &conditions[i]
		}
	}
	return nil
}

// updateConditions updates the given slice of conditions with the new conditions provided.
// If a condition of the same type already exists, it updates the existing condition.
// If the status of the condition has not changed, it retains the original LastTransitionTime.
func updateConditions(conditions []metav1.Condition, newConditions ...metav1.Condition) []metav1.Condition {
	ret := make([]metav1.Condition, 0, len(conditions))

	for _, nc := range newConditions {
		c := findCondition(conditions, commonv1alpha1.ConditionType(nc.Type))
		if c == nil {
			ret = append(ret, nc)
			continue
		}

		if nc.Status == c.Status {
			nc.LastTransitionTime = c.LastTransitionTime
		}
		ret = append(ret, nc)
	}

	return ret
}
