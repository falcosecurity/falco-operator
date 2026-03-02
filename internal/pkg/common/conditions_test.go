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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func TestNewCondition(t *testing.T) {
	condition := NewCondition(
		commonv1alpha1.ConditionReconciled,
		metav1.ConditionTrue,
		"Reconciled",
		"test message",
		42,
	)

	if condition.Type != string(commonv1alpha1.ConditionReconciled) {
		t.Errorf("NewCondition().Type = %v, want %v", condition.Type, commonv1alpha1.ConditionReconciled)
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("NewCondition().Status = %v, want %v", condition.Status, metav1.ConditionTrue)
	}
	if condition.Reason != "Reconciled" {
		t.Errorf("NewCondition().Reason = %v, want %v", condition.Reason, "Reconciled")
	}
	if condition.Message != "test message" {
		t.Errorf("NewCondition().Message = %v, want %v", condition.Message, "test message")
	}
	if condition.ObservedGeneration != 42 {
		t.Errorf("NewCondition().ObservedGeneration = %v, want %v", condition.ObservedGeneration, 42)
	}
	if !condition.LastTransitionTime.IsZero() {
		t.Errorf("NewCondition().LastTransitionTime = %v, want zero (set by apimeta.SetStatusCondition)",
			condition.LastTransitionTime)
	}
}

func TestNewReconciledCondition(t *testing.T) {
	condition := NewReconciledCondition(metav1.ConditionTrue, "Reconciled", "success", 1)

	if condition.Type != string(commonv1alpha1.ConditionReconciled) {
		t.Errorf("NewReconciledCondition().Type = %v, want %v",
			condition.Type, string(commonv1alpha1.ConditionReconciled))
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("NewReconciledCondition().Status = %v, want %v", condition.Status, metav1.ConditionTrue)
	}
}

func TestNewResolvedRefsCondition(t *testing.T) {
	condition := NewResolvedRefsCondition(metav1.ConditionFalse, "ReferenceResolutionFailed", "not found", 2)

	if condition.Type != string(commonv1alpha1.ConditionResolvedRefs) {
		t.Errorf("NewResolvedRefsCondition().Type = %v, want %v",
			condition.Type, string(commonv1alpha1.ConditionResolvedRefs))
	}
	if condition.Status != metav1.ConditionFalse {
		t.Errorf("NewResolvedRefsCondition().Status = %v, want %v", condition.Status, metav1.ConditionFalse)
	}
	if condition.Reason != "ReferenceResolutionFailed" {
		t.Errorf("NewResolvedRefsCondition().Reason = %v, want %v",
			condition.Reason, "ReferenceResolutionFailed")
	}
}

func TestNewAvailableCondition(t *testing.T) {
	condition := NewAvailableCondition(metav1.ConditionTrue, "Available", "ready", 3)

	if condition.Type != string(commonv1alpha1.ConditionAvailable) {
		t.Errorf("NewAvailableCondition().Type = %v, want %v",
			condition.Type, string(commonv1alpha1.ConditionAvailable))
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("NewAvailableCondition().Status = %v, want %v", condition.Status, metav1.ConditionTrue)
	}
	if condition.Reason != "Available" {
		t.Errorf("NewAvailableCondition().Reason = %v, want %v",
			condition.Reason, "Available")
	}
}

func TestNewProgrammedCondition(t *testing.T) {
	condition := NewProgrammedCondition(metav1.ConditionFalse, "ProgramFailed", "disk full", 4)

	if condition.Type != string(commonv1alpha1.ConditionProgrammed) {
		t.Errorf("NewProgrammedCondition().Type = %v, want %v",
			condition.Type, string(commonv1alpha1.ConditionProgrammed))
	}
	if condition.Status != metav1.ConditionFalse {
		t.Errorf("NewProgrammedCondition().Status = %v, want %v", condition.Status, metav1.ConditionFalse)
	}
	if condition.Reason != "ProgramFailed" {
		t.Errorf("NewProgrammedCondition().Reason = %v, want %v",
			condition.Reason, "ProgramFailed")
	}
}
