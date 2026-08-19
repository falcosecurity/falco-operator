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
		interceptPatch func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error
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
			name:      "isReferenced=false, finalizer present -> removes finalizer",
			initialCM: newFinalizerCM(),
			setupFn: func(t *testing.T, cl client.Client, s *runtime.Scheme) {
				t.Helper()
				cm := &corev1.ConfigMap{}
				require.NoError(t, cl.Get(context.Background(),
					types.NamespacedName{Name: "my-cm", Namespace: "default"}, cm))
				require.NoError(t, controllerhelper.EnsureInUseFinalizer(
					context.Background(), cl, testFinalizer, cm, true))
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
			name:      "patch error propagates",
			initialCM: newFinalizerCM(),
			interceptPatch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
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
			if tt.interceptPatch != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Patch: tt.interceptPatch,
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
				context.Background(), cl, testFinalizer, fetched, tt.isReferenced)

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

func TestEnsureInUseFinalizer_GetNotFound(t *testing.T) {
	s := newFinalizerScheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).Build() // object never created

	err := controllerhelper.EnsureInUseFinalizer(
		context.Background(), cl, testFinalizer, newFinalizerCM(), true)
	require.NoError(t, err, "object already gone is treated as nothing to do, not an error")
}

func TestEnsureInUseFinalizer_GetOtherError(t *testing.T) {
	s := newFinalizerScheme(t)
	cm := newFinalizerCM()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return fmt.Errorf("api server unavailable")
			},
		}).
		Build()

	err := controllerhelper.EnsureInUseFinalizer(context.Background(), cl, testFinalizer, cm, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api server unavailable")
}

func TestEnsureInUseFinalizer_PatchNotFoundOrConflictSwallowed(t *testing.T) {
	for _, mkErr := range []struct {
		name string
		err  error
	}{
		{"NotFound", k8serrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, "my-cm")},
		{"Conflict", k8serrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "my-cm", fmt.Errorf("conflict"))},
	} {
		t.Run(mkErr.name, func(t *testing.T) {
			s := newFinalizerScheme(t)
			cm := newFinalizerCM()
			cl := fake.NewClientBuilder().
				WithScheme(s).
				WithObjects(cm).
				WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
						return mkErr.err
					},
				}).
				Build()

			err := controllerhelper.EnsureInUseFinalizer(context.Background(), cl, testFinalizer, cm, true)
			require.NoError(t, err, "%s on Patch must be swallowed, not propagated", mkErr.name)
		})
	}
}

const (
	testLegacyRulesfileFinalizer = "rulesfile.artifact.falcosecurity.dev/finalizer-node-1"
	testLegacyPluginFinalizer    = "plugin.artifact.falcosecurity.dev/finalizer-node-2"
	testLegacyConfigFinalizer    = "config.artifact.falcosecurity.dev/finalizer-node-3"
	testForeignFinalizer         = "other.example.com/keep-me"
)

func TestReconcileInUseFinalizer(t *testing.T) {
	// NOTE: the SSA path (pure additions) and the no-op guard are also verified against a
	// real API server in finalizer_envtest_test.go, since the fake client does not fully
	// implement SSA ownership semantics for metadata.finalizers.
	tests := []struct {
		name           string
		initialCM      *corev1.ConfigMap
		isReferenced   bool
		interceptPatch func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error
		wantErr        bool
		wantFinalizers []string
	}{
		{
			name:           "isReferenced=true, no finalizer -> adds finalizer",
			initialCM:      newFinalizerCM(),
			isReferenced:   true,
			wantFinalizers: []string{testFinalizer},
		},
		{
			name:           "isReferenced=true, finalizer already present -> no-op, returns nil",
			initialCM:      newFinalizerCM(testFinalizer),
			isReferenced:   true,
			wantFinalizers: []string{testFinalizer},
		},
		{
			name:           "isReferenced=false, finalizer present -> removes finalizer, list left empty",
			initialCM:      newFinalizerCM(testFinalizer),
			isReferenced:   false,
			wantFinalizers: nil,
		},
		{
			name:           "isReferenced=false, no finalizer -> no-op, returns nil",
			initialCM:      newFinalizerCM(),
			isReferenced:   false,
			wantFinalizers: nil,
		},
		{
			name: "strips all legacy per-node finalizers, keeps foreign and in-use",
			initialCM: newFinalizerCM(
				testLegacyRulesfileFinalizer, testFinalizer,
				testLegacyPluginFinalizer, testForeignFinalizer, testLegacyConfigFinalizer),
			isReferenced:   true,
			wantFinalizers: []string{testForeignFinalizer, testFinalizer},
		},
		{
			name:           "strips legacy finalizer and adds in-use in one reconcile",
			initialCM:      newFinalizerCM(testLegacyPluginFinalizer),
			isReferenced:   true,
			wantFinalizers: []string{testFinalizer},
		},
		{
			name:           "strips the last (legacy) finalizer, list left empty",
			initialCM:      newFinalizerCM(testLegacyConfigFinalizer),
			isReferenced:   false,
			wantFinalizers: nil,
		},
		{
			// Removal takes the MergeFrom path (c.Patch), so the Patch interceptor fires.
			name:      "patch error propagates on removal",
			initialCM: newFinalizerCM(testFinalizer),
			interceptPatch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return fmt.Errorf("server unavailable")
			},
			isReferenced: false,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFinalizerScheme(t)
			builder := fake.NewClientBuilder().WithScheme(s).WithObjects(tt.initialCM)
			if tt.interceptPatch != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Patch: tt.interceptPatch,
				})
			}
			cl := builder.Build()

			err := controllerhelper.ReconcileInUseFinalizer(
				context.Background(), cl, tt.initialCM, testFinalizer, tt.isReferenced)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			result := &corev1.ConfigMap{}
			require.NoError(t, cl.Get(context.Background(),
				types.NamespacedName{Name: tt.initialCM.Name, Namespace: tt.initialCM.Namespace}, result))
			assert.Equal(t, tt.wantFinalizers, result.Finalizers)
		})
	}
}

func TestReconcileInUseFinalizer_NoOpGuardSkipsApply(t *testing.T) {
	s := newFinalizerScheme(t)
	cm := newFinalizerCM(testFinalizer, testForeignFinalizer)
	patchCalls := 0
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				patchCalls++
				return c.Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	err := controllerhelper.ReconcileInUseFinalizer(
		context.Background(), cl, cm, testFinalizer, true)
	require.NoError(t, err)
	assert.Equal(t, 0, patchCalls, "no API call expected when finalizer state already matches")
}

func TestReconcileInUseFinalizer_GetNotFound(t *testing.T) {
	s := newFinalizerScheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).Build() // object never created

	err := controllerhelper.ReconcileInUseFinalizer(
		context.Background(), cl, newFinalizerCM(), testFinalizer, true)
	require.NoError(t, err, "object already gone is treated as nothing to do, not an error")
}

func TestReconcileInUseFinalizer_GetOtherError(t *testing.T) {
	s := newFinalizerScheme(t)
	cm := newFinalizerCM()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cm).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return fmt.Errorf("api server unavailable")
			},
		}).
		Build()

	err := controllerhelper.ReconcileInUseFinalizer(
		context.Background(), cl, cm, testFinalizer, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api server unavailable")
}

func TestReconcileInUseFinalizer_ApplyNotFoundOrConflictSwallowed(t *testing.T) {
	for _, mkErr := range []struct {
		name string
		err  error
	}{
		{"NotFound", k8serrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, "my-cm")},
		{"Conflict", k8serrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "my-cm", fmt.Errorf("conflict"))},
	} {
		t.Run(mkErr.name, func(t *testing.T) {
			s := newFinalizerScheme(t)
			cm := newFinalizerCM()
			cl := fake.NewClientBuilder().
				WithScheme(s).
				WithObjects(cm).
				WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
						return mkErr.err
					},
				}).
				Build()

			err := controllerhelper.ReconcileInUseFinalizer(
				context.Background(), cl, cm, testFinalizer, true)
			require.NoError(t, err, "%s on patch must be swallowed, not propagated", mkErr.name)
		})
	}
}
