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

package controllerhelper_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func testPluginForReferenceTest() *artifactv1alpha1.Plugin {
	return &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
}

func TestResolveReferences_NoChecksRemovesCondition(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newArtifactScheme(t)).Build()
	plugin := testPluginForReferenceTest()
	conditions := []metav1.Condition{
		common.NewResolvedRefsCondition(metav1.ConditionTrue, artifact.ReasonReferenceResolved, "", 1),
	}

	err := controllerhelper.ResolveReferences(context.Background(), cl, events.NewFakeRecorder(10), plugin, &conditions)

	require.NoError(t, err)
	assert.Nil(t, apimeta.FindStatusCondition(conditions, commonv1alpha1.ConditionResolvedRefs.String()))
}

func TestResolveReferences_AllSucceedSetsTrue(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "my-cm", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(newArtifactScheme(t)).WithObjects(cm).Build()
	plugin := testPluginForReferenceTest()
	var conditions []metav1.Condition

	err := controllerhelper.ResolveReferences(context.Background(), cl, events.NewFakeRecorder(10), plugin, &conditions,
		controllerhelper.ConfigMapReferenceCheck("default", "my-cm"))

	require.NoError(t, err)
	cond := apimeta.FindStatusCondition(conditions, commonv1alpha1.ConditionResolvedRefs.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, artifact.ReasonReferenceResolved, cond.Reason)
}

func TestResolveReferences_FailingCheckSetsFalseAndReturnsError(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newArtifactScheme(t)).Build()
	plugin := testPluginForReferenceTest()
	var conditions []metav1.Condition

	err := controllerhelper.ResolveReferences(context.Background(), cl, events.NewFakeRecorder(10), plugin, &conditions,
		controllerhelper.ConfigMapReferenceCheck("default", "missing-cm"))

	require.Error(t, err)
	cond := apimeta.FindStatusCondition(conditions, commonv1alpha1.ConditionResolvedRefs.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
	assert.Equal(t, artifact.ReasonReferenceResolutionFailed, cond.Reason)
	assert.Contains(t, cond.Message, "missing-cm")
}

func TestResolveReferences_StopsAtFirstFailure(t *testing.T) {
	secretGets := 0
	cl := fake.NewClientBuilder().WithScheme(newArtifactScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				secretGets++
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()
	plugin := testPluginForReferenceTest()
	var conditions []metav1.Condition

	err := controllerhelper.ResolveReferences(context.Background(), cl, events.NewFakeRecorder(10), plugin, &conditions,
		controllerhelper.ConfigMapReferenceCheck("default", "missing-cm"),
		controllerhelper.SecretReferenceCheck("default", "some-secret"))

	require.Error(t, err)
	assert.Zero(t, secretGets, "the second check must not run once the first has already failed")
	cond := apimeta.FindStatusCondition(conditions, commonv1alpha1.ConditionResolvedRefs.String())
	require.NotNil(t, cond)
	assert.Contains(t, cond.Message, "missing-cm")
}
