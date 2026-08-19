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
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

// These tests run against a real API server (envtest) to prove the merge-patch contract of
// ReconcileInUseFinalizer: removal of finalizers left by another manager, and no-op reconciles
// not bumping resourceVersion. Neither is faithfully reproduced by the fake client.
var k8sClient client.Client

func TestMain(m *testing.M) {
	cl, stop, err := testutil.StartEnvtest()
	if err != nil {
		ctrllog.Log.Error(err, "Failed to start envtest")
		os.Exit(1)
	}
	k8sClient = cl
	code := m.Run()
	stop()
	os.Exit(code)
}

// createFinalizerCM creates a ConfigMap carrying finalizers through a plain create,
// so the finalizer elements are owned by an update manager. This is exactly how finalizers
// left behind by old operator versions (or kubectl) look on a real object.
func createFinalizerCM(t *testing.T, ctx context.Context, name string, finalizers ...string) *corev1.ConfigMap {
	t.Helper()
	cm := &corev1.ConfigMap{}
	cm.Name = name
	cm.Namespace = "default"
	cm.Finalizers = finalizers
	require.NoError(t, k8sClient.Create(ctx, cm))
	t.Cleanup(func() { testutil.CleanupObject(t, ctx, k8sClient, cm) })
	return cm
}

func TestReconcileInUseFinalizer_Removals(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		initial        []string
		isReferenced   bool
		wantFinalizers []string
	}{
		{
			name:           "isReferenced=false, in-use finalizer present -> removed",
			initial:        []string{testFinalizer},
			isReferenced:   false,
			wantFinalizers: nil,
		},
		{
			name: "strips all legacy per-node finalizers, keeps foreign and in-use",
			initial: []string{
				testLegacyRulesfileFinalizer, testFinalizer,
				testLegacyPluginFinalizer, testForeignFinalizer, testLegacyConfigFinalizer,
			},
			isReferenced:   true,
			wantFinalizers: []string{testFinalizer, testForeignFinalizer},
		},
		{
			name:           "strips legacy finalizer and adds in-use in one reconcile",
			initial:        []string{testLegacyPluginFinalizer},
			isReferenced:   true,
			wantFinalizers: []string{testFinalizer},
		},
		{
			name:           "strips the last (legacy) finalizer, list left empty",
			initial:        []string{testLegacyConfigFinalizer},
			isReferenced:   false,
			wantFinalizers: nil,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := createFinalizerCM(t, ctx, fmt.Sprintf("ssa-finalizer-%d", i), tt.initial...)

			require.NoError(t, controllerhelper.ReconcileInUseFinalizer(
				ctx, k8sClient, cm, testFinalizer, tt.isReferenced))

			got := &corev1.ConfigMap{}
			require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(cm), got))
			assert.ElementsMatch(t, tt.wantFinalizers, got.Finalizers)

			// A second call must be a no-op: the state already matches the desired state.
			require.NoError(t, controllerhelper.ReconcileInUseFinalizer(
				ctx, k8sClient, cm, testFinalizer, tt.isReferenced))
			rv := got.ResourceVersion
			require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(cm), got))
			assert.Equal(t, rv, got.ResourceVersion, "second reconcile must not write")
		})
	}
}
