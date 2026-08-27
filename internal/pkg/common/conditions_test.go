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

func TestNewDependenciesSatisfiedCondition(t *testing.T) {
	condition := NewDependenciesSatisfiedCondition(metav1.ConditionTrue, "DependenciesSatisfied", "ok", 1)
	if condition.Type != string(commonv1alpha1.ConditionDependenciesSatisfied) {
		t.Errorf("NewDependenciesSatisfiedCondition().Type = %v, want %v",
			condition.Type, string(commonv1alpha1.ConditionDependenciesSatisfied))
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("NewDependenciesSatisfiedCondition().Status = %v, want %v", condition.Status, metav1.ConditionTrue)
	}
}

func TestNewOCIArtifactProgrammedCondition(t *testing.T) {
	condition := NewOCIArtifactProgrammedCondition(metav1.ConditionTrue, "OCIArtifactProgrammed", "ok", 1)
	if condition.Type != string(commonv1alpha1.ConditionOCIArtifactProgrammed) {
		t.Errorf("NewOCIArtifactProgrammedCondition().Type = %v, want %v",
			condition.Type, string(commonv1alpha1.ConditionOCIArtifactProgrammed))
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("NewOCIArtifactProgrammedCondition().Status = %v, want %v", condition.Status, metav1.ConditionTrue)
	}
}

func TestNewInlineArtifactProgrammedCondition(t *testing.T) {
	condition := NewInlineArtifactProgrammedCondition(metav1.ConditionFalse, "InlineArtifactProgramFailed", "bad yaml", 1)
	if condition.Type != string(commonv1alpha1.ConditionInlineArtifactProgrammed) {
		t.Errorf("NewInlineArtifactProgrammedCondition().Type = %v, want %v",
			condition.Type, string(commonv1alpha1.ConditionInlineArtifactProgrammed))
	}
	if condition.Status != metav1.ConditionFalse {
		t.Errorf("NewInlineArtifactProgrammedCondition().Status = %v, want %v", condition.Status, metav1.ConditionFalse)
	}
}

func TestNewConfigMapArtifactProgrammedCondition(t *testing.T) {
	condition := NewConfigMapArtifactProgrammedCondition(metav1.ConditionTrue, "ConfigMapArtifactProgrammed", "ok", 1)
	if condition.Type != string(commonv1alpha1.ConditionConfigMapArtifactProgrammed) {
		t.Errorf("NewConfigMapArtifactProgrammedCondition().Type = %v, want %v",
			condition.Type, string(commonv1alpha1.ConditionConfigMapArtifactProgrammed))
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("NewConfigMapArtifactProgrammedCondition().Status = %v, want %v", condition.Status, metav1.ConditionTrue)
	}
}

func TestNewConfigProgrammedCondition(t *testing.T) {
	condition := NewConfigProgrammedCondition(metav1.ConditionTrue, "ConfigProgrammed", "ok", 1)
	if condition.Type != string(commonv1alpha1.ConditionConfigProgrammed) {
		t.Errorf("NewConfigProgrammedCondition().Type = %v, want %v",
			condition.Type, string(commonv1alpha1.ConditionConfigProgrammed))
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("NewConfigProgrammedCondition().Status = %v, want %v", condition.Status, metav1.ConditionTrue)
	}
}

func TestComputeProgrammedCondition(t *testing.T) {
	gen := int64(7)

	t.Run("all true -> Programmed True", func(t *testing.T) {
		conditions := []metav1.Condition{
			{Type: "A", Status: metav1.ConditionTrue},
			{Type: "B", Status: metav1.ConditionTrue},
		}
		got := ComputeProgrammedCondition(conditions, nil, "TrueReason", "TrueMsg", "FalseReason", gen)
		if got.Status != metav1.ConditionTrue || got.Reason != "TrueReason" || got.Message != "TrueMsg" {
			t.Errorf("got %+v, want Status=True Reason=TrueReason Message=TrueMsg", got)
		}
		if got.ObservedGeneration != gen {
			t.Errorf("got ObservedGeneration=%d, want %d", got.ObservedGeneration, gen)
		}
	})

	t.Run("one condition false -> Programmed False naming the blocker", func(t *testing.T) {
		conditions := []metav1.Condition{
			{Type: "A", Status: metav1.ConditionTrue},
			{Type: "B", Status: metav1.ConditionFalse, Message: "disk full"},
		}
		got := ComputeProgrammedCondition(conditions, nil, "TrueReason", "TrueMsg", "FalseReason", gen)
		if got.Status != metav1.ConditionFalse || got.Reason != "FalseReason" {
			t.Errorf("got %+v, want Status=False Reason=FalseReason", got)
		}
		want := "blocked by B (False): disk full"
		if got.Message != want {
			t.Errorf("got Message=%q, want %q", got.Message, want)
		}
	})

	t.Run("first blocking condition wins when several are not True", func(t *testing.T) {
		conditions := []metav1.Condition{
			{Type: "A", Status: metav1.ConditionFalse, Message: "first failure"},
			{Type: "B", Status: metav1.ConditionUnknown, Message: "second failure"},
		}
		got := ComputeProgrammedCondition(conditions, nil, "TrueReason", "TrueMsg", "FalseReason", gen)
		want := "blocked by A (False): first failure"
		if got.Message != want {
			t.Errorf("got Message=%q, want %q", got.Message, want)
		}
	})

	t.Run("skip excludes a condition type from the gate even when False", func(t *testing.T) {
		conditions := []metav1.Condition{
			{Type: "A", Status: metav1.ConditionTrue},
			{Type: "DependenciesSatisfied", Status: metav1.ConditionFalse, Message: "advisory only"},
		}
		skip := func(condType string) bool { return condType == "DependenciesSatisfied" }
		got := ComputeProgrammedCondition(conditions, skip, "TrueReason", "TrueMsg", "FalseReason", gen)
		if got.Status != metav1.ConditionTrue {
			t.Errorf("got Status=%v, want True (DependenciesSatisfied should be skipped)", got.Status)
		}
	})

	t.Run("existing Programmed condition in the input is always excluded from the gate", func(t *testing.T) {
		conditions := []metav1.Condition{
			{Type: string(commonv1alpha1.ConditionProgrammed), Status: metav1.ConditionFalse},
		}
		got := ComputeProgrammedCondition(conditions, nil, "TrueReason", "TrueMsg", "FalseReason", gen)
		// The only input condition is Programmed and it's excluded, so n stays 0 and the
		// result is False with the msgNoConditionsToGateOn message.
		if got.Status != metav1.ConditionFalse || got.Message != msgNoConditionsToGateOn {
			t.Errorf("got %+v, want Status=False Message=%q", got, msgNoConditionsToGateOn)
		}
	})

	t.Run("empty conditions -> False, no conditions to gate on", func(t *testing.T) {
		got := ComputeProgrammedCondition(nil, nil, "TrueReason", "TrueMsg", "FalseReason", gen)
		if got.Status != metav1.ConditionFalse || got.Message != msgNoConditionsToGateOn {
			t.Errorf("got %+v, want Status=False Message=%q", got, msgNoConditionsToGateOn)
		}
	})
}
