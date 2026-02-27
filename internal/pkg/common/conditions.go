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

package common

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// NewCondition creates a new metav1.Condition with the given parameters.
func NewCondition(
	conditionType commonv1alpha1.ConditionType,
	status metav1.ConditionStatus,
	reason, message string,
	generation int64,
) metav1.Condition {
	return metav1.Condition{
		Type:               string(conditionType),
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	}
}

// NewReconciledCondition creates a ConditionReconciled condition.
func NewReconciledCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionReconciled, status, reason, message, generation)
}

// NewResolvedRefCondition creates a ConditionResolvedRef condition.
func NewResolvedRefCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionResolvedRef, status, reason, message, generation)
}

// NewAvailableCondition creates a ConditionAvailable condition.
func NewAvailableCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionAvailable, status, reason, message, generation)
}

// NewOCIArtifactCondition creates a ConditionOCIArtifact condition.
func NewOCIArtifactCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionOCIArtifact, status, reason, message, generation)
}

// NewInlineContentCondition creates a ConditionInlineContent condition.
func NewInlineContentCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionInlineContent, status, reason, message, generation)
}
