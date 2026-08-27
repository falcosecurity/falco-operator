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
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// msgNoConditionsToGateOn is the Programmed message used when there are no
// non-Programmed conditions to gate on.
const msgNoConditionsToGateOn = "no conditions to gate on"

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

// NewResolvedRefsCondition creates a ConditionResolvedRef condition.
func NewResolvedRefsCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionResolvedRefs, status, reason, message, generation)
}

// NewAvailableCondition creates a ConditionAvailable condition.
func NewAvailableCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionAvailable, status, reason, message, generation)
}

// NewProgrammedCondition creates a ConditionProgrammed condition.
func NewProgrammedCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionProgrammed, status, reason, message, generation)
}

// ComputeProgrammedCondition derives the gateway Programmed condition from every other
// condition currently in conditions: True only when all of them (except any skip excludes)
// are also True. skip is consulted per condition type — pass nil to gate on everything — and
// lets callers make a specific condition (e.g. DependenciesSatisfied in advise mode)
// advisory-only rather than blocking.
//
// On failure the message names the specific blocking condition and its own message (e.g.
// "blocked by ConfigProgrammed (False): unable to fetch ConfigMap").
//
// Shared by every per-node reconciler (Plugin, Rulesfile, Config): each writes conditions for
// its own sources, then converges on this single Programmed gate the same way.
func ComputeProgrammedCondition(
	conditions []metav1.Condition,
	skip func(condType string) bool,
	trueReason, trueMessage, falseReason string,
	generation int64,
) metav1.Condition {
	n := 0
	var blocking *metav1.Condition
	for i := range conditions {
		cond := &conditions[i]
		if cond.Type == commonv1alpha1.ConditionProgrammed.String() || (skip != nil && skip(cond.Type)) {
			continue
		}
		n++
		if cond.Status != metav1.ConditionTrue && blocking == nil {
			blocking = cond
		}
	}
	if n > 0 && blocking == nil {
		return NewProgrammedCondition(metav1.ConditionTrue, trueReason, trueMessage, generation)
	}
	msg := msgNoConditionsToGateOn
	if blocking != nil {
		msg = fmt.Sprintf("blocked by %s (%s): %s", blocking.Type, blocking.Status, blocking.Message)
	}
	return NewProgrammedCondition(metav1.ConditionFalse, falseReason, msg, generation)
}

// NewDependenciesSatisfiedCondition creates a ConditionDependenciesSatisfied condition.
func NewDependenciesSatisfiedCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionDependenciesSatisfied, status, reason, message, generation)
}

// NewOCIArtifactProgrammedCondition creates a ConditionOCIArtifactProgrammed condition.
func NewOCIArtifactProgrammedCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionOCIArtifactProgrammed, status, reason, message, generation)
}

// NewInlineArtifactProgrammedCondition creates a ConditionInlineArtifactProgrammed condition.
func NewInlineArtifactProgrammedCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionInlineArtifactProgrammed, status, reason, message, generation)
}

// NewConfigMapArtifactProgrammedCondition creates a ConditionConfigMapArtifactProgrammed condition.
func NewConfigMapArtifactProgrammedCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionConfigMapArtifactProgrammed, status, reason, message, generation)
}

// NewConfigProgrammedCondition creates a ConditionConfigProgrammed condition.
func NewConfigProgrammedCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionConfigProgrammed, status, reason, message, generation)
}

// NewDeletionBlockedCondition creates a ConditionDeletionBlocked condition.
func NewDeletionBlockedCondition(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return NewCondition(commonv1alpha1.ConditionDeletionBlocked, status, reason, message, generation)
}
