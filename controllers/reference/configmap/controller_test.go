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

package configmap

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

func newScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	return s
}

func newCM(name string, finalizers ...string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  "default",
			Finalizers: finalizers,
		},
	}
}

func TestConfigMapReconciler_Reconcile(t *testing.T) {
	s := newScheme(t)
	ctx := context.Background()

	tests := []struct {
		name                 string
		objects              []client.Object
		intercept            interceptor.Funcs
		setup                func(cl client.Client)
		request              ctrl.Request
		wantErr              string
		wantFinalizer        string
		finalizerShouldExist bool
	}{
		{
			name:    "ConfigMap not found",
			objects: nil,
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "missing"}},
		},
		{
			name:    "List error for Rulesfile",
			objects: []client.Object{newCM("cm1")},
			intercept: interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*artifactv1alpha1.RulesfileList); ok {
						return errors.New("rulesfile list error")
					}
					return nil
				},
			},
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "cm1"}},
			wantErr: "rulesfile list error",
		},
		{
			name:    "List error for Config",
			objects: []client.Object{newCM("cm2")},
			intercept: interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*artifactv1alpha1.ConfigList); ok {
						return errors.New("config list error")
					}
					return nil
				},
			},
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "cm2"}},
			wantErr: "config list error",
		},
		{
			name: "Referenced, not deleting, adds finalizer",
			objects: []client.Object{newCM("cm3"), &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf1"},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "cm3"},
				},
			}},
			request:              ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "cm3"}},
			wantFinalizer:        common.ConfigmapInUseFinalizer,
			finalizerShouldExist: true,
		},
		{
			name: "Not referenced, removes finalizer",
			objects: []client.Object{newCM("cm4"), &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf-cm4"},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "cm4"},
				},
			}},
			setup: func(cl client.Client) {
				// Remove the Rulesfile so cm4 is no longer referenced.
				rf := &artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf-cm4"},
					Spec: artifactv1alpha1.RulesfileSpec{
						ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "cm4"},
					},
				}
				_ = cl.Delete(ctx, rf)
			},
			request:              ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "cm4"}},
			wantFinalizer:        common.ConfigmapInUseFinalizer,
			finalizerShouldExist: false,
		},
		{
			name: "Referenced, deleting, blocks deletion",
			objects: []client.Object{func() *corev1.ConfigMap {
				cm := newCM("cm5", common.ConfigmapInUseFinalizer)
				cm.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Time}
				return cm
			}(), &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf2"},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "cm5"},
				},
			}},
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "cm5"}},
		},
		{
			name: "Apply error propagates",
			objects: []client.Object{newCM("cm6"), &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf3"},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "cm6"},
				},
			}},
			intercept: interceptor.Funcs{
				Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
					return errors.New("apply failed")
				},
			},
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "cm6"}},
			wantErr: "apply failed",
		},
		{
			name:    "Get error (not NotFound)",
			objects: nil,
			intercept: interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					return errors.New("generic get error")
				},
			},
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "cm-error"}},
			wantErr: "generic get error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(s)
			if tt.objects != nil {
				builder = builder.WithObjects(tt.objects...)
			}
			for _, e := range index.All {
				builder = builder.WithIndex(e.Object, e.Field, e.ExtractValueFn)
			}
			if tt.intercept.Get != nil || tt.intercept.List != nil || tt.intercept.Apply != nil || tt.intercept.Delete != nil {
				builder = builder.WithInterceptorFuncs(tt.intercept)
			}
			cl := builder.Build()
			if tt.setup != nil {
				tt.setup(cl)
			}
			r := NewConfigMapReconciler(cl, s)
			res, err := r.Reconcile(ctx, tt.request)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, ctrl.Result{}, res)
				if tt.wantFinalizer != "" {
					cmOut := &corev1.ConfigMap{}
					require.NoError(t, cl.Get(ctx, types.NamespacedName{Namespace: tt.request.Namespace, Name: tt.request.Name}, cmOut))
					if tt.finalizerShouldExist {
						assert.Contains(t, cmOut.Finalizers, tt.wantFinalizer)
					} else {
						assert.NotContains(t, cmOut.Finalizers, tt.wantFinalizer)
					}
				}
			}
		})
	}
}

func TestConfigMapReconciler_isReferenced(t *testing.T) {
	s := newScheme(t)
	ctx := t.Context()
	cm := newCM("cmX")

	tests := []struct {
		name      string
		objects   []client.Object
		listError func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error
		want      bool
		wantErr   string
	}{
		{
			name:    "no references",
			objects: []client.Object{cm},
			want:    false,
		},
		{
			name: "rulesfile reference",
			objects: []client.Object{cm, &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rfX"},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "cmX"},
				},
			}},
			want: true,
		},
		{
			name: "config reference",
			objects: []client.Object{cm, &artifactv1alpha1.Config{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cfgX"},
				Spec: artifactv1alpha1.ConfigSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "cmX"},
				},
			}},
			want: true,
		},
		{
			name:    "rulesfile list error",
			objects: []client.Object{cm},
			listError: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.RulesfileList); ok {
					return errors.New("rulesfile list error")
				}
				return nil
			},
			wantErr: "rulesfile list error",
		},
		{
			name:    "config list error",
			objects: []client.Object{cm},
			listError: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.ConfigList); ok {
					return errors.New("config list error")
				}
				return nil
			},
			wantErr: "config list error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(s).WithObjects(tt.objects...)
			for _, e := range index.All {
				builder = builder.WithIndex(e.Object, e.Field, e.ExtractValueFn)
			}
			if tt.listError != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					List: tt.listError,
				})
			}
			cl := builder.Build()
			r := NewConfigMapReconciler(cl, s)
			ref, err := r.isReferenced(ctx, cm)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, ref)
			}
		})
	}
}

func TestConfigMapReconciler_findConfigMapsForRulesfile(t *testing.T) {
	s := newScheme(t)
	r := NewConfigMapReconciler(nil, s)

	tests := []struct {
		name string
		obj  client.Object
		want []ctrl.Request
	}{
		{
			name: "not a Rulesfile",
			obj:  newCM("cmX"),
			want: nil,
		},
		{
			name: "nil ConfigMapRef",
			obj: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rfX"},
				Spec:       artifactv1alpha1.RulesfileSpec{},
			},
			want: nil,
		},
		{
			name: "valid ConfigMapRef",
			obj: &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rfY"},
				Spec: artifactv1alpha1.RulesfileSpec{
					ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "cmY"},
				},
			},
			want: []ctrl.Request{
				{NamespacedName: client.ObjectKey{Namespace: "default", Name: "cmY"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.findConfigMapsForRulesfile(context.Background(), tt.obj)
			assert.Equal(t, tt.want, got)
		})
	}
}
