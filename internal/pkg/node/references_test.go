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

package node

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func referencingRulesfile() *artifactv1alpha1.Rulesfile {
	return &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: "default"}}
}

func TestResolveReferences_NoReferenceRemovesCondition(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).Build()
	conditions := []metav1.Condition{
		common.NewResolvedRefsCondition(metav1.ConditionTrue, artifact.ReasonReferenceResolved, "", 1),
	}

	err := resolveReferences(t.Context(), cl, events.NewFakeRecorder(10), referencingRulesfile(), &conditions, nil)

	require.NoError(t, err)
	assert.Nil(t, apimeta.FindStatusCondition(conditions, commonv1alpha1.ConditionResolvedRefs.String()))
}

func TestResolveReferences_ExistingConfigMapSetsTrue(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "my-cm", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(cm).Build()
	var conditions []metav1.Condition

	err := resolveReferences(t.Context(), cl, events.NewFakeRecorder(10), referencingRulesfile(), &conditions,
		&commonv1alpha1.ConfigMapRef{Name: "my-cm"})

	require.NoError(t, err)
	cond := apimeta.FindStatusCondition(conditions, commonv1alpha1.ConditionResolvedRefs.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, artifact.ReasonReferenceResolved, cond.Reason)
}

func TestResolveReferences_MissingConfigMapSetsFalseAndReturnsError(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).Build()
	var conditions []metav1.Condition

	err := resolveReferences(t.Context(), cl, events.NewFakeRecorder(10), referencingRulesfile(), &conditions,
		&commonv1alpha1.ConfigMapRef{Name: "missing-cm"})

	require.Error(t, err)
	cond := apimeta.FindStatusCondition(conditions, commonv1alpha1.ConditionResolvedRefs.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
	assert.Equal(t, artifact.ReasonReferenceResolutionFailed, cond.Reason)
	assert.Contains(t, cond.Message, "missing-cm")
}

// The Normal Event marks the references becoming resolved. Every node reconciles the same artifact, so recording it
// on each reconcile would have every node write Events about it for as long as it stays resolved.
func TestResolveReferences_RecordsResolvedOnlyWhenItBecomesSo(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "my-cm", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(cm).Build()
	rulesfile := referencingRulesfile()
	recorder := events.NewFakeRecorder(10)
	var conditions []metav1.Condition
	resolve := func(name string) {
		_ = resolveReferences(t.Context(), cl, recorder, rulesfile, &conditions, &commonv1alpha1.ConfigMapRef{Name: name})
	}
	resolved := func() int {
		n := 0
		for {
			select {
			case e := <-recorder.Events:
				if strings.Contains(e, artifact.ReasonReferenceResolved) {
					n++
				}
			default:
				return n
			}
		}
	}

	resolve("my-cm")
	assert.Equal(t, 1, resolved(), "resolved for the first time")
	resolve("my-cm")
	resolve("my-cm")
	assert.Equal(t, 0, resolved(), "still resolved: nothing new to say")
	resolve("missing")
	resolve("my-cm")
	assert.Equal(t, 1, resolved(), "resolved again after a failure")
}

func TestAwaitObservedGeneration(t *testing.T) {
	n := &Node{}

	assert.True(t, n.awaitObservedGeneration(t.Context(), 1, 2), "observedGeneration behind generation must defer")
	assert.False(t, n.awaitObservedGeneration(t.Context(), 3, 3), "observedGeneration caught up to generation must proceed")
}
