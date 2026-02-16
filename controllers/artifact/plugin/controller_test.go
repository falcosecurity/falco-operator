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

package plugin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

const (
	testNamespace  = "test-ns"
	testNodeName   = "test-node"
	testPluginName = "test-plugin"
)

// testScheme creates a runtime.Scheme with the required types registered.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	require.NoError(t, corev1.AddToScheme(s))
	return s
}

// newTestReconciler creates a PluginReconciler backed by a fake client and mock dependencies.
func newTestReconciler(t *testing.T, objs ...client.Object) (*PluginReconciler, client.Client) {
	t.Helper()
	s := testScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		Build()

	mockFS := filesystem.NewMockFileSystem()
	am := artifact.NewManagerWithOptions(fakeClient, testNamespace,
		artifact.WithFS(mockFS),
		artifact.WithOCIPuller(&puller.MockOCIPuller{}),
	)

	return &PluginReconciler{
		Client:          fakeClient,
		Scheme:          s,
		finalizer:       testFinalizerName(),
		artifactManager: am,
		PluginsConfig:   &PluginsConfig{},
		nodeName:        testNodeName,
		crToConfigName:  make(map[string]string),
	}, fakeClient
}

// testFinalizerName returns the finalizer name used by the test reconciler.
func testFinalizerName() string {
	return common.FormatFinalizerName(pluginFinalizerPrefix, testNodeName)
}

// defaultLibraryPath returns the expected library path for a plugin with the given CR name.
func defaultLibraryPath(name string) string {
	return artifact.Path(name, priority.DefaultPriority, artifact.MediumOCI, artifact.TypePlugin)
}

// testRequest creates a ctrl.Request for the given plugin name in testNamespace.
func testRequest(name string) ctrl.Request {
	return ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: testNamespace,
		},
	}
}

// --- Reconciler constructor ---

func TestNewPluginReconciler(t *testing.T) {
	s := testScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(s).Build()

	r := NewPluginReconciler(fakeClient, s, "my-node", "my-namespace")

	require.NotNil(t, r)
	assert.Equal(t, "my-node", r.nodeName)
	assert.Equal(t, common.FormatFinalizerName(pluginFinalizerPrefix, "my-node"), r.finalizer)
	assert.NotNil(t, r.PluginsConfig)
	assert.NotNil(t, r.crToConfigName)
	assert.NotNil(t, r.artifactManager)
}

// --- Reconcile integration tests ---

func TestReconcile(t *testing.T) {
	tests := []struct {
		name    string
		objects []client.Object
		setup   func(t *testing.T, r *PluginReconciler, cl client.Client)
		req     ctrl.Request
		wantErr bool
		verify  func(t *testing.T, r *PluginReconciler, cl client.Client)
	}{
		{
			name:    "plugin not found returns no error",
			objects: nil,
			req:     testRequest("nonexistent"),
		},
		{
			name: "first reconcile sets finalizer and returns early",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testPluginName,
						Namespace: testNamespace,
					},
				},
			},
			req: testRequest(testPluginName),
			verify: func(t *testing.T, r *PluginReconciler, cl client.Client) {
				plugin := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, plugin))
				assert.True(t, controllerutil.ContainsFinalizer(plugin, testFinalizerName()))
				// Returned early after setting finalizer, so config should be empty.
				assert.True(t, r.PluginsConfig.isEmpty())
			},
		},
		{
			name: "happy path with finalizer already set writes config",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testNamespace,
						Finalizers: []string{testFinalizerName()},
					},
				},
			},
			req: testRequest(testPluginName),
			verify: func(t *testing.T, r *PluginReconciler, cl client.Client) {
				require.Len(t, r.PluginsConfig.Configs, 1)
				assert.Equal(t, testPluginName, r.PluginsConfig.Configs[0].Name)
				assert.Equal(t, []string{testPluginName}, r.PluginsConfig.LoadPlugins)
				assert.Equal(t, testPluginName, r.crToConfigName[testPluginName])
			},
		},
		{
			name: "happy path with plugin config",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "container",
						Namespace:  testNamespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.PluginSpec{
						Config: &artifactv1alpha1.PluginConfig{
							InitConfig: &apiextensionsv1.JSON{
								Raw: []byte(`{"engines":{"containerd":{"enabled":true}}}`),
							},
						},
					},
				},
			},
			req: testRequest("container"),
			verify: func(t *testing.T, r *PluginReconciler, cl client.Client) {
				require.Len(t, r.PluginsConfig.Configs, 1)
				assert.Equal(t, "container", r.PluginsConfig.Configs[0].Name)
				require.NotNil(t, r.PluginsConfig.Configs[0].InitConfig)
			},
		},
		{
			name: "deletion with finalizer cleans up",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testNamespace,
						Finalizers: []string{testFinalizerName()},
					},
				},
			},
			setup: func(t *testing.T, r *PluginReconciler, cl client.Client) {
				r.PluginsConfig = &PluginsConfig{
					Configs:     []PluginConfig{{Name: testPluginName, LibraryPath: defaultLibraryPath(testPluginName)}},
					LoadPlugins: []string{testPluginName},
				}
				r.crToConfigName[testPluginName] = testPluginName
				// Trigger deletion via the fake client (sets DeletionTimestamp due to finalizer).
				plugin := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, plugin))
				require.NoError(t, cl.Delete(context.Background(), plugin))
			},
			req: testRequest(testPluginName),
			verify: func(t *testing.T, r *PluginReconciler, cl client.Client) {
				assert.True(t, r.PluginsConfig.isEmpty())
				assert.Empty(t, r.crToConfigName)
			},
		},
		{
			name: "deletion without our finalizer is no-op",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testNamespace,
						Finalizers: []string{"some-other-finalizer"},
					},
				},
			},
			setup: func(t *testing.T, r *PluginReconciler, cl client.Client) {
				plugin := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, plugin))
				require.NoError(t, cl.Delete(context.Background(), plugin))
			},
			req: testRequest(testPluginName),
		},
		{
			name: "selector matches node proceeds normally",
			objects: []client.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   testNodeName,
						Labels: map[string]string{"role": "worker"},
					},
				},
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testNamespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.PluginSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "worker"},
						},
					},
				},
			},
			req: testRequest(testPluginName),
			verify: func(t *testing.T, r *PluginReconciler, cl client.Client) {
				require.Len(t, r.PluginsConfig.Configs, 1)
				assert.Equal(t, testPluginName, r.PluginsConfig.Configs[0].Name)
			},
		},
		{
			name: "selector does not match node removes local resources",
			objects: []client.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   testNodeName,
						Labels: map[string]string{"role": "worker"},
					},
				},
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testNamespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.PluginSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "gpu"},
						},
					},
				},
			},
			req: testRequest(testPluginName),
			verify: func(t *testing.T, r *PluginReconciler, cl client.Client) {
				// Selector didn't match, so no config should be written.
				assert.True(t, r.PluginsConfig.isEmpty())
				// Finalizer should have been removed by RemoveLocalResources.
				plugin := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, plugin))
				assert.False(t, controllerutil.ContainsFinalizer(plugin, testFinalizerName()))
			},
		},
		{
			name: "node not found with selector returns error",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testPluginName,
						Namespace: testNamespace,
					},
					Spec: artifactv1alpha1.PluginSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "worker"},
						},
					},
				},
			},
			req:     testRequest(testPluginName),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)
			if tt.setup != nil {
				tt.setup(t, r, cl)
			}

			result, err := r.Reconcile(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, ctrl.Result{}, result)
			}
			if tt.verify != nil {
				tt.verify(t, r, cl)
			}
		})
	}
}

// --- handleDeletion ---

func TestHandleDeletion(t *testing.T) {
	tests := []struct {
		name    string
		objects []client.Object
		setup   func(t *testing.T, r *PluginReconciler, cl client.Client) *artifactv1alpha1.Plugin
		wantOK  bool
		wantErr bool
		verify  func(t *testing.T, r *PluginReconciler)
	}{
		{
			name: "not marked for deletion returns false",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testNamespace,
						Finalizers: []string{testFinalizerName()},
					},
				},
			},
			setup: func(t *testing.T, r *PluginReconciler, cl client.Client) *artifactv1alpha1.Plugin {
				plugin := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, plugin))
				return plugin
			},
			wantOK: false,
		},
		{
			name: "marked for deletion with finalizer cleans up",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testNamespace,
						Finalizers: []string{testFinalizerName()},
					},
				},
			},
			setup: func(t *testing.T, r *PluginReconciler, cl client.Client) *artifactv1alpha1.Plugin {
				r.PluginsConfig = &PluginsConfig{
					Configs:     []PluginConfig{{Name: testPluginName, LibraryPath: defaultLibraryPath(testPluginName)}},
					LoadPlugins: []string{testPluginName},
				}
				r.crToConfigName[testPluginName] = testPluginName
				// Delete to set DeletionTimestamp, then re-fetch.
				plugin := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, plugin))
				require.NoError(t, cl.Delete(context.Background(), plugin))
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, plugin))
				return plugin
			},
			wantOK: true,
			verify: func(t *testing.T, r *PluginReconciler) {
				assert.True(t, r.PluginsConfig.isEmpty())
				assert.Empty(t, r.crToConfigName)
			},
		},
		{
			name: "marked for deletion without our finalizer skips cleanup",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testNamespace,
						Finalizers: []string{"some-other-finalizer"},
					},
				},
			},
			setup: func(t *testing.T, r *PluginReconciler, cl client.Client) *artifactv1alpha1.Plugin {
				plugin := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, plugin))
				require.NoError(t, cl.Delete(context.Background(), plugin))
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, plugin))
				return plugin
			},
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)
			plugin := tt.setup(t, r, cl)

			ok, err := r.handleDeletion(context.Background(), plugin)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantOK, ok)
			if tt.verify != nil {
				tt.verify(t, r)
			}
		})
	}
}

// --- ensureFinalizers ---

func TestEnsureFinalizers(t *testing.T) {
	tests := []struct {
		name       string
		finalizers []string
		wantOK     bool
		wantErr    bool
	}{
		{
			name:   "adds finalizer when not present",
			wantOK: true,
		},
		{
			name:       "no-op when finalizer already present",
			finalizers: []string{testFinalizerName()},
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testPluginName,
					Namespace:  testNamespace,
					Finalizers: tt.finalizers,
				},
			}
			r, cl := newTestReconciler(t, plugin)

			// Fetch to get ResourceVersion from the fake client.
			fetched := &artifactv1alpha1.Plugin{}
			require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, fetched))

			ok, err := r.ensureFinalizers(context.Background(), fetched)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantOK, ok)

			if tt.wantOK {
				updated := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testNamespace}, updated))
				assert.True(t, controllerutil.ContainsFinalizer(updated, testFinalizerName()))
			}
		})
	}
}

// --- ensurePlugin ---

func TestEnsurePlugin(t *testing.T) {
	tests := []struct {
		name    string
		plugin  *artifactv1alpha1.Plugin
		wantErr bool
	}{
		{
			name: "nil OCI artifact succeeds",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testNamespace},
			},
		},
		{
			name: "nil OCI artifact spec is also fine",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testNamespace},
				Spec:       artifactv1alpha1.PluginSpec{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			err := r.ensurePlugin(context.Background(), tt.plugin)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- ensurePluginConfig ---

func TestEnsurePluginConfig(t *testing.T) {
	tests := []struct {
		name           string
		plugin         *artifactv1alpha1.Plugin
		crToConfigName map[string]string
		initialConfig  *PluginsConfig
		wantErr        bool
		verify         func(t *testing.T, r *PluginReconciler)
	}{
		{
			name: "writes config for basic plugin",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json", Namespace: testNamespace},
			},
			crToConfigName: make(map[string]string),
			initialConfig:  &PluginsConfig{},
			verify: func(t *testing.T, r *PluginReconciler) {
				require.Len(t, r.PluginsConfig.Configs, 1)
				assert.Equal(t, "json", r.PluginsConfig.Configs[0].Name)
				assert.Equal(t, "json", r.crToConfigName["json"])
			},
		},
		{
			name: "writes config with initConfig",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: testNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						InitConfig: &apiextensionsv1.JSON{
							Raw: []byte(`{"engines":{"containerd":{"enabled":true}}}`),
						},
					},
				},
			},
			crToConfigName: make(map[string]string),
			initialConfig:  &PluginsConfig{},
			verify: func(t *testing.T, r *PluginReconciler) {
				require.Len(t, r.PluginsConfig.Configs, 1)
				require.NotNil(t, r.PluginsConfig.Configs[0].InitConfig)
			},
		},
		{
			name: "removes stale entry on config name change",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: testNamespace},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name: "new-name",
					},
				},
			},
			crToConfigName: map[string]string{"my-plugin": "old-name"},
			initialConfig: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "old-name", LibraryPath: defaultLibraryPath("my-plugin")},
				},
				LoadPlugins: []string{"old-name"},
			},
			verify: func(t *testing.T, r *PluginReconciler) {
				require.Len(t, r.PluginsConfig.Configs, 1)
				assert.Equal(t, "new-name", r.PluginsConfig.Configs[0].Name)
				assert.Equal(t, "new-name", r.crToConfigName["my-plugin"])
			},
		},
		{
			name: "same config name does not remove entry",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json", Namespace: testNamespace},
			},
			crToConfigName: map[string]string{"json": "json"},
			initialConfig: &PluginsConfig{
				Configs:     []PluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
				LoadPlugins: []string{"json"},
			},
			verify: func(t *testing.T, r *PluginReconciler) {
				require.Len(t, r.PluginsConfig.Configs, 1)
				assert.Equal(t, "json", r.PluginsConfig.Configs[0].Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			r.crToConfigName = tt.crToConfigName
			r.PluginsConfig = tt.initialConfig

			err := r.ensurePluginConfig(context.Background(), tt.plugin)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.verify != nil {
				tt.verify(t, r)
			}
		})
	}
}

// --- removePluginConfig ---

func TestRemovePluginConfig(t *testing.T) {
	tests := []struct {
		name          string
		plugin        *artifactv1alpha1.Plugin
		initialConfig *PluginsConfig
		wantErr       bool
		wantEmpty     bool
	}{
		{
			name:   "empty after removal removes file",
			plugin: &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}},
			initialConfig: &PluginsConfig{
				Configs:     []PluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
				LoadPlugins: []string{"json"},
			},
			wantEmpty: true,
		},
		{
			name:   "not empty after removal writes updated config",
			plugin: &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}},
			initialConfig: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
					{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")},
				},
				LoadPlugins: []string{"json", "k8saudit"},
			},
			wantEmpty: false,
		},
		{
			name:   "already empty config is a no-op removal",
			plugin: &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "nonexistent"}},
			initialConfig: &PluginsConfig{
				Configs:     []PluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
				LoadPlugins: []string{"json"},
			},
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t)
			r.PluginsConfig = tt.initialConfig

			err := r.removePluginConfig(context.Background(), tt.plugin)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantEmpty, r.PluginsConfig.isEmpty())
		})
	}
}

// --- PluginsConfig.addConfig ---

func TestPluginsConfig_AddConfig(t *testing.T) {
	tests := []struct {
		name            string
		initial         *PluginsConfig
		plugin          *artifactv1alpha1.Plugin
		expectedConfigs []PluginConfig
		expectedLoad    []string
	}{
		{
			name:    "add plugin with no spec.config",
			initial: &PluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name:    "add plugin with spec.config.name override",
			initial: &PluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name: "json",
					},
				},
			},
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("my-json-plugin")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name:    "add plugin with full spec.config",
			initial: &PluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name:        "json",
						LibraryPath: "/custom/path/json.so",
						InitConfig: &apiextensionsv1.JSON{
							Raw: []byte(`{"sssURL": "https://example.com"}`),
						},
						OpenParams: "some-params",
					},
				},
			},
			expectedConfigs: []PluginConfig{
				{
					Name:        "json",
					LibraryPath: "/custom/path/json.so",
					InitConfig:  &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://example.com"}`)}},
					OpenParams:  "some-params",
				},
			},
			expectedLoad: []string{"json"},
		},
		{
			name:    "skip identical config (no duplicate)",
			initial: &PluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			// We'll call addConfig twice to verify idempotency.
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "update existing config when initConfig changes",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{
						Name:        "json",
						LibraryPath: defaultLibraryPath("json"),
						InitConfig:  &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://initial.example.com"}`)}},
					},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://updated.example.com"}`)},
					},
				},
			},
			expectedConfigs: []PluginConfig{
				{
					Name:        "json",
					LibraryPath: defaultLibraryPath("json"),
					InitConfig:  &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://updated.example.com"}`)}},
				},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "update existing config when openParams changes",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{
						Name:        "json",
						LibraryPath: defaultLibraryPath("json"),
						OpenParams:  "old-params",
					},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						OpenParams: "new-params",
					},
				},
			},
			expectedConfigs: []PluginConfig{
				{
					Name:        "json",
					LibraryPath: defaultLibraryPath("json"),
					OpenParams:  "new-params",
				},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "add second plugin preserves existing",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "k8saudit"},
			},
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
				{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")},
			},
			expectedLoad: []string{"json", "k8saudit"},
		},
		{
			name: "loadPlugins uses config.Name not CR name",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "existing", LibraryPath: defaultLibraryPath("existing")},
				},
				LoadPlugins: []string{"existing"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-json-cr"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name: "json",
					},
				},
			},
			expectedConfigs: []PluginConfig{
				{Name: "existing", LibraryPath: defaultLibraryPath("existing")},
				{Name: "json", LibraryPath: defaultLibraryPath("my-json-cr")},
			},
			expectedLoad: []string{"existing", "json"},
		},
		{
			name:    "empty initConfig raw bytes are ignored",
			initial: &PluginsConfig{},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						InitConfig: &apiextensionsv1.JSON{Raw: []byte{}},
					},
				},
			},
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
			},
			expectedLoad: []string{"json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := tt.initial

			if tt.name == "skip identical config (no duplicate)" {
				// Call addConfig twice to verify idempotency.
				pc.addConfig(tt.plugin)
			}
			pc.addConfig(tt.plugin)

			assert.Equal(t, tt.expectedConfigs, pc.Configs)
			assert.Equal(t, tt.expectedLoad, pc.LoadPlugins)
		})
	}
}

// --- PluginsConfig.removeConfig ---

func TestPluginsConfig_RemoveConfig(t *testing.T) {
	tests := []struct {
		name            string
		initial         *PluginsConfig
		plugin          *artifactv1alpha1.Plugin
		expectedConfigs []PluginConfig
		expectedLoad    []string
		expectedEmpty   bool
	}{
		{
			name: "remove plugin by CR name",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			expectedConfigs: []PluginConfig{},
			expectedLoad:    []string{},
			expectedEmpty:   true,
		},
		{
			name: "remove plugin when spec.config.name differs from CR name",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("my-json-plugin")},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name: "json",
					},
				},
			},
			expectedConfigs: []PluginConfig{},
			expectedLoad:    []string{},
			expectedEmpty:   true,
		},
		{
			name: "remove non-existent plugin is a no-op",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
				},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "nonexistent"},
			},
			expectedConfigs: []PluginConfig{
				{Name: "json", LibraryPath: defaultLibraryPath("json")},
			},
			expectedLoad:  []string{"json"},
			expectedEmpty: false,
		},
		{
			name: "remove one plugin preserves others",
			initial: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: defaultLibraryPath("json")},
					{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")},
				},
				LoadPlugins: []string{"json", "k8saudit"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
			expectedConfigs: []PluginConfig{
				{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")},
			},
			expectedLoad:  []string{"k8saudit"},
			expectedEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := tt.initial
			pc.removeConfig(tt.plugin)

			assert.Equal(t, tt.expectedConfigs, pc.Configs)
			assert.Equal(t, tt.expectedLoad, pc.LoadPlugins)
			assert.Equal(t, tt.expectedEmpty, pc.isEmpty())
		})
	}
}

// --- Round-trip add/remove tests ---

func TestPluginsConfig_AddThenRemove_RoundTrip(t *testing.T) {
	t.Run("add and remove with mismatched names cleans up fully", func(t *testing.T) {
		pc := &PluginsConfig{}

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					Name: "json",
				},
			},
		}

		pc.addConfig(plugin)
		assert.Len(t, pc.Configs, 1)
		assert.Equal(t, "json", pc.Configs[0].Name)
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		pc.removeConfig(plugin)
		assert.Empty(t, pc.Configs)
		assert.Empty(t, pc.LoadPlugins)
		assert.True(t, pc.isEmpty())
	})

	t.Run("changing spec.config.name removes stale entry via reconciler tracking", func(t *testing.T) {
		pc := &PluginsConfig{}
		crToConfigName := make(map[string]string)

		// Initial: CR "my-plugin" with spec.config.name = "json".
		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					Name: "json",
				},
			},
		}
		crToConfigName[plugin.Name] = resolveConfigName(plugin)
		pc.addConfig(plugin)
		require.Len(t, pc.Configs, 1)
		assert.Equal(t, "json", pc.Configs[0].Name)
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		// User changes spec.config.name from "json" to "json-v2".
		pluginRenamed := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					Name: "json-v2",
				},
			},
		}

		// Reconciler detects name change and removes stale entry before addConfig.
		newName := resolveConfigName(pluginRenamed)
		if oldName, ok := crToConfigName[pluginRenamed.Name]; ok && oldName != newName {
			pc.removeByName(oldName)
		}
		crToConfigName[pluginRenamed.Name] = newName
		pc.addConfig(pluginRenamed)

		// The old "json" entry must be gone, only "json-v2" should remain.
		require.Len(t, pc.Configs, 1)
		assert.Equal(t, "json-v2", pc.Configs[0].Name)
		assert.Equal(t, []string{"json-v2"}, pc.LoadPlugins)

		// Deletion should clean up fully.
		pc.removeConfig(pluginRenamed)
		delete(crToConfigName, pluginRenamed.Name)
		assert.True(t, pc.isEmpty())
	})

	t.Run("add, update, then remove", func(t *testing.T) {
		pc := &PluginsConfig{}

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "json"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://initial.example.com"}`)},
				},
			},
		}

		// Add initial config.
		pc.addConfig(plugin)
		var initialConfig map[string]interface{}
		require.NoError(t, json.Unmarshal(pc.Configs[0].InitConfig.Raw, &initialConfig))
		assert.Equal(t, "https://initial.example.com", initialConfig["sssURL"])

		// Update initConfig.
		pluginUpdated := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "json"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{
					InitConfig: &apiextensionsv1.JSON{Raw: []byte(`{"sssURL": "https://updated.example.com"}`)},
				},
			},
		}
		pc.addConfig(pluginUpdated)
		require.Len(t, pc.Configs, 1)
		var updatedConfig map[string]interface{}
		require.NoError(t, json.Unmarshal(pc.Configs[0].InitConfig.Raw, &updatedConfig))
		assert.Equal(t, "https://updated.example.com", updatedConfig["sssURL"])
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		// Remove.
		pc.removeConfig(pluginUpdated)
		assert.True(t, pc.isEmpty())
	})
}

// --- toString ---

func TestPluginsConfig_ToString(t *testing.T) {
	tests := []struct {
		name        string
		pc          *PluginsConfig
		contains    []string
		notContains []string
	}{
		{
			name: "serializes to yaml",
			pc: &PluginsConfig{
				Configs: []PluginConfig{
					{Name: "json", LibraryPath: "/usr/share/falco/plugins/json.so"},
				},
				LoadPlugins: []string{"json"},
			},
			contains: []string{
				"name: json",
				"library_path: /usr/share/falco/plugins/json.so",
				"load_plugins:",
				"- json",
			},
		},
		{
			name:     "empty config serializes without load_plugins",
			pc:       &PluginsConfig{},
			contains: []string{"plugins: []"},
		},
		{
			name: "nested init_config serializes as nested yaml (issue #214)",
			pc: &PluginsConfig{
				Configs: []PluginConfig{
					{
						Name:        "container",
						LibraryPath: "/usr/share/falco/plugins/container.so",
						InitConfig: &InitConfig{
							JSON: &apiextensionsv1.JSON{
								Raw: []byte(`{"hooks":["create"],"label_max_len":"100","engines":{"containerd":{"enabled":true}}}`),
							},
						},
					},
				},
				LoadPlugins: []string{"container"},
			},
			contains: []string{
				"init_config:",
				"hooks:",
				"- create",
				"label_max_len:",
				"engines:",
				"containerd:",
				"enabled: true",
			},
			notContains: []string{
				"raw:",
				"Raw:",
			},
		},
		{
			name: "config with open_params serializes correctly",
			pc: &PluginsConfig{
				Configs: []PluginConfig{
					{
						Name:        "k8saudit",
						LibraryPath: "/usr/share/falco/plugins/k8saudit.so",
						OpenParams:  "http://:9765/k8s-audit",
					},
				},
				LoadPlugins: []string{"k8saudit"},
			},
			contains: []string{
				"open_params: http://:9765/k8s-audit",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.pc.toString()
			require.NoError(t, err)
			for _, s := range tt.contains {
				assert.Contains(t, result, s)
			}
			for _, s := range tt.notContains {
				assert.NotContains(t, result, s)
			}
		})
	}
}

// --- isEmpty ---

func TestPluginsConfig_IsEmpty(t *testing.T) {
	assert.True(t, (&PluginsConfig{}).isEmpty())
	assert.False(t, (&PluginsConfig{Configs: []PluginConfig{{Name: "json"}}}).isEmpty())
	assert.False(t, (&PluginsConfig{LoadPlugins: []string{"json"}}).isEmpty())
}

// --- isSame ---

func TestPluginConfig_IsSame(t *testing.T) {
	tests := []struct {
		name     string
		a        PluginConfig
		b        PluginConfig
		expected bool
	}{
		{
			name:     "identical configs",
			a:        PluginConfig{LibraryPath: "/a.so", OpenParams: "p", InitConfig: &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"k": "v"}`)}}},
			b:        PluginConfig{LibraryPath: "/a.so", OpenParams: "p", InitConfig: &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"k": "v"}`)}}},
			expected: true,
		},
		{
			name:     "different library path",
			a:        PluginConfig{LibraryPath: "/a.so"},
			b:        PluginConfig{LibraryPath: "/b.so"},
			expected: false,
		},
		{
			name:     "different open params",
			a:        PluginConfig{LibraryPath: "/a.so", OpenParams: "p1"},
			b:        PluginConfig{LibraryPath: "/a.so", OpenParams: "p2"},
			expected: false,
		},
		{
			name:     "different init config",
			a:        PluginConfig{LibraryPath: "/a.so", InitConfig: &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"k": "v1"}`)}}},
			b:        PluginConfig{LibraryPath: "/a.so", InitConfig: &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"k": "v2"}`)}}},
			expected: false,
		},
		{
			name:     "name difference is ignored by isSame",
			a:        PluginConfig{Name: "a", LibraryPath: "/a.so"},
			b:        PluginConfig{Name: "b", LibraryPath: "/a.so"},
			expected: true,
		},
		{
			name:     "both nil init config",
			a:        PluginConfig{LibraryPath: "/a.so"},
			b:        PluginConfig{LibraryPath: "/a.so"},
			expected: true,
		},
		{
			name:     "one nil one non-nil init config",
			a:        PluginConfig{LibraryPath: "/a.so", InitConfig: &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{}`)}}},
			b:        PluginConfig{LibraryPath: "/a.so"},
			expected: false,
		},
		{
			name:     "reversed nil vs non-nil init config",
			a:        PluginConfig{LibraryPath: "/a.so"},
			b:        PluginConfig{LibraryPath: "/a.so", InitConfig: &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{}`)}}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.a.isSame(&tt.b))
		})
	}
}

// --- MarshalYAML ---

func TestInitConfig_MarshalYAML(t *testing.T) {
	tests := []struct {
		name    string
		ic      *InitConfig
		wantNil bool
		wantErr bool
	}{
		{
			name:    "nil InitConfig returns nil",
			ic:      nil,
			wantNil: true,
		},
		{
			name:    "nil JSON returns nil",
			ic:      &InitConfig{JSON: nil},
			wantNil: true,
		},
		{
			name:    "empty raw bytes returns nil",
			ic:      &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte{}}},
			wantNil: true,
		},
		{
			name: "valid JSON returns parsed data",
			ic:   &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{"key":"value"}`)}},
		},
		{
			name:    "invalid JSON returns error",
			ic:      &InitConfig{JSON: &apiextensionsv1.JSON{Raw: []byte(`{invalid`)}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.ic.MarshalYAML()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

// --- resolveConfigName ---

func TestResolveConfigName(t *testing.T) {
	tests := []struct {
		name     string
		plugin   *artifactv1alpha1.Plugin
		expected string
	}{
		{
			name: "uses CR name when config is nil",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			},
			expected: "my-plugin",
		},
		{
			name: "uses CR name when config name is empty",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{},
				},
			},
			expected: "my-plugin",
		},
		{
			name: "uses config name when set",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						Name: "custom-name",
					},
				},
			},
			expected: "custom-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolveConfigName(tt.plugin))
		})
	}
}
