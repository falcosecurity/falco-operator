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
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

const (
	testFinalizerInUse = "test.example.com/in-use"
	testFinalizer      = "test.example.com/finalizer"

	testFieldManager = "test-field-manager"
)

func newFinalizerScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	return s
}

func newFinalizerCM(finalizers ...string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "my-cm",
			Namespace:  "default",
			Finalizers: finalizers,
		},
	}
}

func newConfigMap(finalizers ...string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cm",
			Namespace:  "default",
			Finalizers: finalizers,
		},
	}
}

func TestEnsureFinalizer(t *testing.T) {
	tests := []struct {
		name       string
		obj        *corev1.ConfigMap
		patchErr   error
		wantAdded  bool
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:      "finalizer already present returns false without patching",
			obj:       newConfigMap(testFinalizer),
			wantAdded: false,
			wantErr:   false,
		},
		{
			name:      "finalizer not present is added successfully",
			obj:       newConfigMap(),
			wantAdded: true,
			wantErr:   false,
		},
		{
			name:       "patch returns conflict error",
			obj:        newConfigMap(),
			patchErr:   k8serrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "cm", fmt.Errorf("conflict")),
			wantAdded:  false,
			wantErr:    true,
			wantErrMsg: "conflict",
		},
		{
			name:       "patch returns non-conflict error",
			obj:        newConfigMap(),
			patchErr:   fmt.Errorf("server unavailable"),
			wantAdded:  false,
			wantErr:    true,
			wantErrMsg: "server unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFinalizerScheme(t)
			builder := fake.NewClientBuilder().WithScheme(s).WithObjects(tt.obj)
			if tt.patchErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						return tt.patchErr
					},
				})
			}
			cl := builder.Build()

			added, err := controllerhelper.EnsureFinalizer(context.Background(), cl, testFinalizer, tt.obj)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantAdded, added)

			if tt.wantAdded {
				// Verify the finalizer was actually persisted.
				got := &corev1.ConfigMap{}
				require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(tt.obj), got))
				assert.True(t, controllerutil.ContainsFinalizer(got, testFinalizer))
			}
		})
	}
}

func TestEnsureInUseFinalizer(t *testing.T) {
	tests := []struct {
		name           string
		initialCM      *corev1.ConfigMap
		isReferenced   bool
		setupFn        func(t *testing.T, cl client.Client, s *runtime.Scheme)
		interceptApply func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error
		wantErr        bool
		wantFinalizer  bool
	}{
		{
			name:          "isReferenced=true, no finalizer -> adds finalizer",
			initialCM:     newFinalizerCM(),
			isReferenced:  true,
			wantFinalizer: true,
		},
		{
			name:          "isReferenced=true, finalizer already present -> no-op, returns nil",
			initialCM:     newFinalizerCM(testFinalizer),
			isReferenced:  true,
			wantFinalizer: true,
		},
		{
			// The finalizer must have been added via SSA (by the same field manager)
			// for SSA to be able to remove it. setupFn establishes that ownership first.
			name:      "isReferenced=false, finalizer present -> removes finalizer",
			initialCM: newFinalizerCM(),
			setupFn: func(t *testing.T, cl client.Client, s *runtime.Scheme) {
				t.Helper()
				cm := &corev1.ConfigMap{}
				require.NoError(t, cl.Get(context.Background(),
					types.NamespacedName{Name: "my-cm", Namespace: "default"}, cm))
				require.NoError(t, controllerhelper.EnsureInUseFinalizer(
					context.Background(), cl, s, testFinalizer, testFieldManager, cm, true))
			},
			isReferenced:  false,
			wantFinalizer: false,
		},
		{
			name:          "isReferenced=false, no finalizer -> no-op, returns nil",
			initialCM:     newFinalizerCM(),
			isReferenced:  false,
			wantFinalizer: false,
		},
		{
			name:      "apply error propagates",
			initialCM: newFinalizerCM(),
			interceptApply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				return fmt.Errorf("server unavailable")
			},
			isReferenced: true,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFinalizerScheme(t)
			builder := fake.NewClientBuilder().WithScheme(s).WithObjects(tt.initialCM)
			if tt.interceptApply != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Apply: tt.interceptApply,
				})
			}
			cl := builder.Build()

			if tt.setupFn != nil {
				tt.setupFn(t, cl, s)
			}

			// Fetch a live copy so controllerutil.ContainsFinalizer works correctly.
			fetched := &corev1.ConfigMap{}
			require.NoError(t, cl.Get(context.Background(),
				types.NamespacedName{Name: tt.initialCM.Name, Namespace: tt.initialCM.Namespace}, fetched))

			err := controllerhelper.EnsureInUseFinalizer(
				context.Background(), cl, s, testFinalizer, testFieldManager, fetched, tt.isReferenced)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Re-fetch to verify the server state when a patch was expected.
			result := &corev1.ConfigMap{}
			require.NoError(t, cl.Get(context.Background(),
				types.NamespacedName{Name: tt.initialCM.Name, Namespace: tt.initialCM.Namespace}, result))

			hasFinalizer := slices.Contains(result.Finalizers, testFinalizer)
			assert.Equal(t, tt.wantFinalizer, hasFinalizer)
		})
	}
}
