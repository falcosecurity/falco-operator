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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
)

func TestGenerateServiceAccount(t *testing.T) {
	tests := []struct {
		name       string
		mc         *instancev1alpha1.Metacollector
		wantName   string
		wantLabels map[string]string
	}{
		{
			name: "basic ServiceAccount creation",
			mc: &instancev1alpha1.Metacollector{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-mc",
					Namespace: "default",
					Labels:    map[string]string{"app": "metacollector"},
				},
			},
			wantName:   "test-mc",
			wantLabels: map[string]string{"app": "metacollector"},
		},
		{
			name: "ServiceAccount with nil labels",
			mc: &instancev1alpha1.Metacollector{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-mc",
					Namespace: "default",
				},
			},
			wantName: "test-mc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateServiceAccount(tt.mc)
			require.NotNil(t, result)

			sa := result.(*corev1.ServiceAccount)
			assert.Equal(t, tt.wantName, sa.Name)
			assert.Equal(t, "ServiceAccount", sa.Kind)
			assert.Equal(t, "v1", sa.APIVersion)
			assert.Equal(t, tt.wantLabels, sa.Labels)
		})
	}
}

func TestEnsureServiceAccount(t *testing.T) {
	scheme := testutil.Scheme(t, instancev1alpha1.AddToScheme)

	tests := []struct {
		name         string
		mc           *instancev1alpha1.Metacollector
		existingObjs []client.Object
		wantLabels   map[string]string
		wantAnnots   map[string]string
	}{
		{
			name: "creates with correct name and namespace",
			mc:   newMetacollector(withName("test-mc")),
		},
		{
			name: "preserves existing annotations during update",
			mc:   newMetacollector(withName("test-mc")),
			existingObjs: []client.Object{
				&corev1.ServiceAccount{
					TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-mc", Namespace: testutil.TestNamespace, Annotations: map[string]string{"existing": "annotation"}},
				},
			},
			wantAnnots: map[string]string{"existing": "annotation"},
		},
		{
			name: "applies new labels on existing ServiceAccount",
			mc:   newMetacollector(withName("test-mc"), withLabels(map[string]string{"new": "label"})),
			existingObjs: []client.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{Name: "test-mc", Namespace: testutil.TestNamespace, Labels: map[string]string{"old": "label"}},
				},
			},
			wantLabels: map[string]string{"new": "label"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tt.mc}, tt.existingObjs...)
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := NewReconciler(cl, scheme, events.NewFakeRecorder(10))

			err := r.ensureServiceAccount(context.Background(), tt.mc)
			require.NoError(t, err)

			sa := &corev1.ServiceAccount{}
			require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(tt.mc), sa))
			assert.Equal(t, tt.mc.Name, sa.Name)
			assert.Equal(t, tt.mc.Namespace, sa.Namespace)
			for k, v := range tt.wantLabels {
				assert.Equal(t, v, sa.Labels[k], "label %s", k)
			}
			for k, v := range tt.wantAnnots {
				assert.Equal(t, v, sa.Annotations[k], "annotation %s", k)
			}
		})
	}
}
