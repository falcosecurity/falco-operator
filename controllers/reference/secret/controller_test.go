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

package secret

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
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	return s
}

func newSecret(name string, finalizers ...string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  "default",
			Finalizers: finalizers,
		},
	}
}

// ociWithSecret builds a minimal OCIArtifact that references the given Secret name.
func ociWithSecret(secretName string) *commonv1alpha1.OCIArtifact {
	return &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{Repository: "test/repo"},
		Registry: &commonv1alpha1.RegistryConfig{
			Auth: &commonv1alpha1.RegistryAuth{
				SecretRef: &commonv1alpha1.SecretRef{Name: secretName},
			},
		},
	}
}

func TestSecretReconciler_Reconcile(t *testing.T) {
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
			name:    "Secret not found",
			objects: nil,
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "missing"}},
		},
		{
			name:    "List error for Rulesfile",
			objects: []client.Object{newSecret("sec1")},
			intercept: interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*artifactv1alpha1.RulesfileList); ok {
						return errors.New("rulesfile list error")
					}
					return nil
				},
			},
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "sec1"}},
			wantErr: "rulesfile list error",
		},
		{
			name:    "List error for Plugin",
			objects: []client.Object{newSecret("sec2")},
			intercept: interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*artifactv1alpha1.PluginList); ok {
						return errors.New("plugin list error")
					}
					return nil
				},
			},
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "sec2"}},
			wantErr: "plugin list error",
		},
		{
			name: "Referenced via Rulesfile, not deleting, adds finalizer",
			objects: []client.Object{newSecret("sec3"), &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf1"},
				Spec:       artifactv1alpha1.RulesfileSpec{OCIArtifact: ociWithSecret("sec3")},
			}},
			request:              ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "sec3"}},
			wantFinalizer:        common.SecretInUseFinalizer,
			finalizerShouldExist: true,
		},
		{
			name: "Referenced via Plugin, not deleting, adds finalizer",
			objects: []client.Object{newSecret("sec4"), &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pl1"},
				Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: ociWithSecret("sec4")},
			}},
			request:              ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "sec4"}},
			wantFinalizer:        common.SecretInUseFinalizer,
			finalizerShouldExist: true,
		},
		{
			name: "Not referenced, removes finalizer",
			objects: []client.Object{newSecret("sec5"), &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf-sec5"},
				Spec:       artifactv1alpha1.RulesfileSpec{OCIArtifact: ociWithSecret("sec5")},
			}},
			setup: func(cl client.Client) {
				rf := &artifactv1alpha1.Rulesfile{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf-sec5"},
				}
				_ = cl.Delete(ctx, rf)
			},
			request:              ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "sec5"}},
			wantFinalizer:        common.SecretInUseFinalizer,
			finalizerShouldExist: false,
		},
		{
			name: "Referenced, deleting, blocks deletion",
			objects: []client.Object{func() *corev1.Secret {
				sec := newSecret("sec6", common.SecretInUseFinalizer)
				sec.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Time}
				return sec
			}(), &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf2"},
				Spec:       artifactv1alpha1.RulesfileSpec{OCIArtifact: ociWithSecret("sec6")},
			}},
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "sec6"}},
		},
		{
			name: "Apply error propagates",
			objects: []client.Object{newSecret("sec7"), &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rf3"},
				Spec:       artifactv1alpha1.RulesfileSpec{OCIArtifact: ociWithSecret("sec7")},
			}},
			intercept: interceptor.Funcs{
				Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
					return errors.New("apply failed")
				},
			},
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "sec7"}},
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
			request: ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "sec-error"}},
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
			r := NewSecretReconciler(cl, s)
			res, err := r.Reconcile(ctx, tt.request)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, ctrl.Result{}, res)
				if tt.wantFinalizer != "" {
					secOut := &corev1.Secret{}
					require.NoError(t, cl.Get(ctx, types.NamespacedName{Namespace: tt.request.Namespace, Name: tt.request.Name}, secOut))
					if tt.finalizerShouldExist {
						assert.Contains(t, secOut.Finalizers, tt.wantFinalizer)
					} else {
						assert.NotContains(t, secOut.Finalizers, tt.wantFinalizer)
					}
				}
			}
		})
	}
}

func TestSecretReconciler_isReferenced(t *testing.T) {
	s := newScheme(t)
	ctx := t.Context()
	sec := newSecret("secX")

	tests := []struct {
		name      string
		objects   []client.Object
		listError func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error
		want      bool
		wantErr   string
	}{
		{
			name:    "no references",
			objects: []client.Object{sec},
			want:    false,
		},
		{
			name: "rulesfile reference",
			objects: []client.Object{sec, &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rfX"},
				Spec:       artifactv1alpha1.RulesfileSpec{OCIArtifact: ociWithSecret("secX")},
			}},
			want: true,
		},
		{
			name: "plugin reference",
			objects: []client.Object{sec, &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "plX"},
				Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: ociWithSecret("secX")},
			}},
			want: true,
		},
		{
			name:    "rulesfile list error",
			objects: []client.Object{sec},
			listError: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.RulesfileList); ok {
					return errors.New("rulesfile list error")
				}
				return nil
			},
			wantErr: "rulesfile list error",
		},
		{
			name:    "plugin list error",
			objects: []client.Object{sec},
			listError: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.PluginList); ok {
					return errors.New("plugin list error")
				}
				return nil
			},
			wantErr: "plugin list error",
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
			r := NewSecretReconciler(cl, s)
			ref, err := r.isReferenced(ctx, sec)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, ref)
			}
		})
	}
}

func TestSecretReconciler_findSecretsFor(t *testing.T) {
	s := newScheme(t)
	r := NewSecretReconciler(nil, s)

	type findCase struct {
		name string
		obj  client.Object
		want []ctrl.Request
	}

	mappers := []struct {
		name  string
		fn    func(context.Context, client.Object) []ctrl.Request
		cases []findCase
	}{
		{
			name: "Rulesfile",
			fn:   r.findSecretsForRulesfile,
			cases: []findCase{
				{name: "not a Rulesfile", obj: newSecret("secX"), want: nil},
				{
					name: "nil OCIArtifact",
					obj:  &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rfX"}},
					want: nil,
				},
				{
					name: "nil Registry",
					obj: &artifactv1alpha1.Rulesfile{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rfX"},
						Spec: artifactv1alpha1.RulesfileSpec{
							OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "test/repo"}},
						},
					},
					want: nil,
				},
				{
					name: "nil Auth",
					obj: &artifactv1alpha1.Rulesfile{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rfX"},
						Spec: artifactv1alpha1.RulesfileSpec{
							OCIArtifact: &commonv1alpha1.OCIArtifact{
								Image:    commonv1alpha1.ImageSpec{Repository: "test/repo"},
								Registry: &commonv1alpha1.RegistryConfig{},
							},
						},
					},
					want: nil,
				},
				{
					name: "nil SecretRef",
					obj: &artifactv1alpha1.Rulesfile{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rfX"},
						Spec: artifactv1alpha1.RulesfileSpec{
							OCIArtifact: &commonv1alpha1.OCIArtifact{
								Image:    commonv1alpha1.ImageSpec{Repository: "test/repo"},
								Registry: &commonv1alpha1.RegistryConfig{Auth: &commonv1alpha1.RegistryAuth{}},
							},
						},
					},
					want: nil,
				},
				{
					name: "valid SecretRef",
					obj: &artifactv1alpha1.Rulesfile{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rfY"},
						Spec:       artifactv1alpha1.RulesfileSpec{OCIArtifact: ociWithSecret("secY")},
					},
					want: []ctrl.Request{{NamespacedName: client.ObjectKey{Namespace: "default", Name: "secY"}}},
				},
			},
		},
		{
			name: "Plugin",
			fn:   r.findSecretsForPlugin,
			cases: []findCase{
				{name: "not a Plugin", obj: newSecret("secX"), want: nil},
				{
					name: "nil OCIArtifact",
					obj:  &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "plX"}},
					want: nil,
				},
				{
					name: "nil Registry",
					obj: &artifactv1alpha1.Plugin{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "plX"},
						Spec: artifactv1alpha1.PluginSpec{
							OCIArtifact: &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "test/repo"}},
						},
					},
					want: nil,
				},
				{
					name: "nil Auth",
					obj: &artifactv1alpha1.Plugin{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "plX"},
						Spec: artifactv1alpha1.PluginSpec{
							OCIArtifact: &commonv1alpha1.OCIArtifact{
								Image:    commonv1alpha1.ImageSpec{Repository: "test/repo"},
								Registry: &commonv1alpha1.RegistryConfig{},
							},
						},
					},
					want: nil,
				},
				{
					name: "nil SecretRef",
					obj: &artifactv1alpha1.Plugin{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "plX"},
						Spec: artifactv1alpha1.PluginSpec{
							OCIArtifact: &commonv1alpha1.OCIArtifact{
								Image:    commonv1alpha1.ImageSpec{Repository: "test/repo"},
								Registry: &commonv1alpha1.RegistryConfig{Auth: &commonv1alpha1.RegistryAuth{}},
							},
						},
					},
					want: nil,
				},
				{
					name: "valid SecretRef",
					obj: &artifactv1alpha1.Plugin{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "plY"},
						Spec:       artifactv1alpha1.PluginSpec{OCIArtifact: ociWithSecret("secY")},
					},
					want: []ctrl.Request{{NamespacedName: client.ObjectKey{Namespace: "default", Name: "secY"}}},
				},
			},
		},
	}

	for _, m := range mappers {
		t.Run(m.name, func(t *testing.T) {
			for _, tt := range m.cases {
				t.Run(tt.name, func(t *testing.T) {
					assert.Equal(t, tt.want, m.fn(context.Background(), tt.obj))
				})
			}
		})
	}
}
