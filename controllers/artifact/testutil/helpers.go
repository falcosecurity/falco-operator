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

package testutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
)

const (
	// Namespace is the default namespace used for test resources.
	Namespace = "test-ns"
	// NodeName is the default node name used in tests.
	NodeName = "test-node"
)

// ConditionExpect describes an expected condition for declarative assertions.
type ConditionExpect struct {
	Type   string
	Status metav1.ConditionStatus
	Reason string
}

// Scheme creates a runtime.Scheme with the artifact and core API types registered.
func Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	require.NoError(t, corev1.AddToScheme(s))
	return s
}

// Request creates a ctrl.Request for the given resource name in Namespace.
func Request(name string) ctrl.Request {
	return ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: Namespace,
		},
	}
}

// RequireCondition finds a condition by type and asserts its status and reason.
func RequireCondition(t *testing.T, conditions []metav1.Condition, condType string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	for _, c := range conditions {
		if c.Type == condType {
			assert.Equal(t, status, c.Status, "condition %s status", condType)
			assert.Equal(t, reason, c.Reason, "condition %s reason", condType)
			return
		}
	}
	t.Errorf("condition %s not found", condType)
}

// RequireConditions asserts that the given conditions match all expectations (count + each entry).
func RequireConditions(t *testing.T, actual []metav1.Condition, expected []ConditionExpect) {
	t.Helper()
	require.Len(t, actual, len(expected))
	for _, exp := range expected {
		RequireCondition(t, actual, exp.Type, exp.Status, exp.Reason)
	}
}

// BoolPtr returns a pointer to the given bool value, useful for optional table fields.
func BoolPtr(b bool) *bool {
	return &b
}
