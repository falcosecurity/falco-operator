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

package metacollector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func TestGenerateClusterRoleBinding(t *testing.T) {
	mc := &instancev1alpha1.Metacollector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mc",
			Namespace: "default",
			Labels:    map[string]string{"app": "metacollector"},
		},
	}

	result := generateClusterRoleBinding(mc)
	require.NotNil(t, result)

	crb := result.(*rbacv1.ClusterRoleBinding)
	assert.Equal(t, "test-mc--default", crb.Name)
	assert.Equal(t, "ClusterRoleBinding", crb.Kind)
	assert.Equal(t, "rbac.authorization.k8s.io/v1", crb.APIVersion)
	assert.Equal(t, map[string]string{"app": "metacollector"}, crb.Labels)

	require.Len(t, crb.Subjects, 1)
	assert.Equal(t, "ServiceAccount", crb.Subjects[0].Kind)
	assert.Equal(t, "test-mc", crb.Subjects[0].Name)
	assert.Equal(t, "default", crb.Subjects[0].Namespace)

	assert.Equal(t, "ClusterRole", crb.RoleRef.Kind)
	assert.Equal(t, "test-mc--default", crb.RoleRef.Name)
}

func TestEnsureClusterRoleBinding(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)
	mc := newMetacollector(withName("test-mc"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mc).Build()
	r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

	require.NoError(t, r.ensureClusterRoleBinding(context.Background(), mc))

	crb := &rbacv1.ClusterRoleBinding{}
	expectedName := instance.GenerateUniqueName(mc.Name, mc.Namespace)
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: expectedName}, crb))
	assert.Equal(t, expectedName, crb.Name)
	assert.Equal(t, expectedName, crb.RoleRef.Name)
	require.Len(t, crb.Subjects, 1)
	assert.Equal(t, mc.Name, crb.Subjects[0].Name)
	assert.Equal(t, mc.Namespace, crb.Subjects[0].Namespace)
}
