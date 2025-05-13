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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func TestFindCondition(t *testing.T) {
	now := metav1.Now()
	tests := []struct {
		name          string
		conditions    []metav1.Condition
		conditionType commonv1alpha1.ConditionType
		wantCondition *metav1.Condition
	}{
		{
			name: "condition found",
			conditions: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionTrue,
					LastTransitionTime: now,
					Reason:             "TestReason",
					Message:            "Test message",
				},
			},
			conditionType: commonv1alpha1.ConditionAvailable,
			wantCondition: &metav1.Condition{
				Type:               string(commonv1alpha1.ConditionAvailable),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: now,
				Reason:             "TestReason",
				Message:            "Test message",
			},
		},
		{
			name: "condition not found",
			conditions: []metav1.Condition{
				{
					Type:   string(commonv1alpha1.ConditionAvailable),
					Status: metav1.ConditionTrue,
				},
			},
			conditionType: commonv1alpha1.ConditionReconciled,
			wantCondition: nil,
		},
		{
			name:          "empty conditions",
			conditions:    []metav1.Condition{},
			conditionType: commonv1alpha1.ConditionAvailable,
			wantCondition: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findCondition(tt.conditions, tt.conditionType)
			if (got == nil) != (tt.wantCondition == nil) {
				t.Errorf("findCondition() got = %v, want %v", got, tt.wantCondition)
				return
			}
			if got != nil && *got != *tt.wantCondition {
				t.Errorf("findCondition() = %v, want %v", got, tt.wantCondition)
			}
		})
	}
}

func TestUpdateConditions(t *testing.T) {
	oldTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	newTime := metav1.NewTime(time.Now())

	tests := []struct {
		name          string
		conditions    []metav1.Condition
		newConditions []metav1.Condition
		want          []metav1.Condition
	}{
		{
			name: "update existing condition with same status but different message",
			conditions: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionTrue,
					LastTransitionTime: oldTime,
					Reason:             "OldReason",
					Message:            "Old message",
				},
			},
			newConditions: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionTrue,
					LastTransitionTime: newTime,
					Reason:             "NewReason",
					Message:            "New message",
				},
			},
			want: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionTrue,
					LastTransitionTime: oldTime,
					Reason:             "NewReason",
					Message:            "New message",
				},
			},
		},
		{
			name: "update existing condition with different status and message",
			conditions: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionTrue,
					LastTransitionTime: oldTime,
					Reason:             "OldReason",
					Message:            "Old message",
				},
			},
			newConditions: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionFalse,
					LastTransitionTime: newTime,
					Reason:             "NewReason",
					Message:            "New message",
				},
			},
			want: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionFalse,
					LastTransitionTime: newTime,
					Reason:             "NewReason",
					Message:            "New message",
				},
			},
		},
		{
			name: "add multiple new conditions",
			conditions: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionTrue,
					LastTransitionTime: oldTime,
					Reason:             "ExistingReason",
					Message:            "Existing message",
				},
			},
			newConditions: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionReconciled),
					Status:             metav1.ConditionFalse,
					LastTransitionTime: newTime,
					Reason:             "NewReason1",
					Message:            "New message 1",
				},
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionTrue,
					LastTransitionTime: newTime,
					Reason:             "UpdatedReason",
					Message:            "Updated message",
				},
			},
			want: []metav1.Condition{
				{
					Type:               string(commonv1alpha1.ConditionReconciled),
					Status:             metav1.ConditionFalse,
					LastTransitionTime: newTime,
					Reason:             "NewReason1",
					Message:            "New message 1",
				},
				{
					Type:               string(commonv1alpha1.ConditionAvailable),
					Status:             metav1.ConditionTrue,
					LastTransitionTime: oldTime, // Should keep old time as status hasn't changed
					Reason:             "UpdatedReason",
					Message:            "Updated message",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := updateConditions(tt.conditions, tt.newConditions...)
			if len(got) != len(tt.want) {
				t.Errorf("updateConditions() got len = %v, want len = %v", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i].Type != tt.want[i].Type {
					t.Errorf("updateConditions()[%d] Type = %v, want %v", i, got[i].Type, tt.want[i].Type)
				}
				if got[i].Status != tt.want[i].Status {
					t.Errorf("updateConditions()[%d] Status = %v, want %v", i, got[i].Status, tt.want[i].Status)
				}
				if got[i].LastTransitionTime != tt.want[i].LastTransitionTime {
					t.Errorf("updateConditions()[%d] LastTransitionTime = %v, want %v", i, got[i].LastTransitionTime, tt.want[i].LastTransitionTime)
				}
				if got[i].Reason != tt.want[i].Reason {
					t.Errorf("updateConditions()[%d] Reason = %v, want %v", i, got[i].Reason, tt.want[i].Reason)
				}
				if got[i].Message != tt.want[i].Message {
					t.Errorf("updateConditions()[%d] Message = %v, want %v", i, got[i].Message, tt.want[i].Message)
				}
			}
		})
	}
}
