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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

const testPluginName = "test-plugin"

func testFinalizerName() string {
	return common.FormatFinalizerName(pluginFinalizerPrefix, testutil.NodeName)
}

func defaultLibraryPath(name string) string {
	return artifact.Path(name, priority.DefaultPriority, artifact.MediumOCI, artifact.TypePlugin)
}

func findPluginConfig(configs []PluginConfig, name string) *PluginConfig {
	for i := range configs {
		if configs[i].Name == name {
			return &configs[i]
		}
	}
	return nil
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*PluginReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		Build()

	mockFS := filesystem.NewMockFileSystem()
	am := artifact.NewManagerWithOptions(cl, testutil.Namespace,
		artifact.WithFS(mockFS),
		artifact.WithOCIPuller(&puller.MockOCIPuller{}),
	)

	return &PluginReconciler{
		Client:          cl,
		Scheme:          s,
		recorder:        events.NewFakeRecorder(100),
		finalizer:       testFinalizerName(),
		artifactManager: am,
		PluginsConfig:   &PluginsConfig{},
		nodeName:        testutil.NodeName,
		crToConfigName:  make(map[string]string),
	}, cl
}

func TestNewPluginReconciler(t *testing.T) {
	s := testutil.Scheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	r := NewPluginReconciler(cl, s, events.NewFakeRecorder(10), "my-node", "my-namespace")

	require.NotNil(t, r)
	assert.Equal(t, "my-node", r.nodeName)
	assert.Equal(t, common.FormatFinalizerName(pluginFinalizerPrefix, "my-node"), r.finalizer)
	assert.NotNil(t, r.PluginsConfig)
	assert.NotNil(t, r.crToConfigName)
	assert.NotNil(t, r.artifactManager)
}

func TestReconcile(t *testing.T) {
	tests := []struct {
		name            string
		objects         []client.Object
		req             ctrl.Request
		triggerDeletion bool
		pullErr         error
		preConfig       *PluginsConfig
		preCRTracking   map[string]string
		wantErr         bool
		wantFinalizer   *bool
		wantConfigEmpty *bool
		wantConditions  []testutil.ConditionExpect
	}{
		{
			name: "plugin not found returns no error",
			req:  testutil.Request("nonexistent"),
		},
		{
			name: "first reconcile sets finalizer and returns early",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testPluginName,
						Namespace: testutil.Namespace,
					},
				},
			},
			req:             testutil.Request(testPluginName),
			wantFinalizer:   testutil.BoolPtr(true),
			wantConfigEmpty: testutil.BoolPtr(true),
		},
		{
			name: "happy path with finalizer already set writes config",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
				},
			},
			req:             testutil.Request(testPluginName),
			wantConfigEmpty: testutil.BoolPtr(false),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "happy path with plugin config",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "container",
						Namespace:  testutil.Namespace,
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
			req:             testutil.Request("container"),
			wantConfigEmpty: testutil.BoolPtr(false),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "deletion with finalizer cleans up",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
				},
			},
			triggerDeletion: true,
			preConfig: &PluginsConfig{
				Configs:     []PluginConfig{{Name: testPluginName, LibraryPath: defaultLibraryPath(testPluginName)}},
				LoadPlugins: []string{testPluginName},
			},
			preCRTracking:   map[string]string{testPluginName: testPluginName},
			req:             testutil.Request(testPluginName),
			wantConfigEmpty: testutil.BoolPtr(true),
		},
		{
			name: "deletion without our finalizer is no-op",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{"some-other-finalizer"},
					},
				},
			},
			req:             testutil.Request(testPluginName),
			triggerDeletion: true,
		},
		{
			name: "selector matches node proceeds normally",
			objects: []client.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   testutil.NodeName,
						Labels: map[string]string{"role": "worker"},
					},
				},
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.PluginSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "worker"},
						},
					},
				},
			},
			req:             testutil.Request(testPluginName),
			wantConfigEmpty: testutil.BoolPtr(false),
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonProgrammed},
			},
		},
		{
			name: "selector does not match node removes local resources",
			objects: []client.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   testutil.NodeName,
						Labels: map[string]string{"role": "worker"},
					},
				},
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.PluginSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "gpu"},
						},
					},
				},
			},
			req:             testutil.Request(testPluginName),
			wantConfigEmpty: testutil.BoolPtr(true),
			wantFinalizer:   testutil.BoolPtr(false),
		},
		{
			name: "node not found with selector returns error",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testPluginName,
						Namespace: testutil.Namespace,
					},
					Spec: artifactv1alpha1.PluginSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"role": "worker"},
						},
					},
				},
			},
			req:     testutil.Request(testPluginName),
			wantErr: true,
		},
		{
			name: "OCI store failure sets error conditions on status",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Reference: "ghcr.io/falcosecurity/plugins/test:latest",
						},
					},
				},
			},
			req:     testutil.Request(testPluginName),
			pullErr: fmt.Errorf("network error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactStoreFailed},
			},
		},
		{
			name: "references resolved but OCI pull fails sets ResolvedRefs true and Programmed false",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-pull-secret",
						Namespace: testutil.Namespace,
					},
				},
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
					Spec: artifactv1alpha1.PluginSpec{
						OCIArtifact: &commonv1alpha1.OCIArtifact{
							Reference: "ghcr.io/falcosecurity/plugins/test:latest",
							PullSecret: &commonv1alpha1.OCIPullSecret{
								SecretName: "my-pull-secret",
							},
						},
					},
				},
			},
			req:     testutil.Request(testPluginName),
			pullErr: fmt.Errorf("network error"),
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonOCIArtifactStoreFailed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			if tt.pullErr != nil {
				mockFS := filesystem.NewMockFileSystem()
				r.artifactManager = artifact.NewManagerWithOptions(cl, testutil.Namespace,
					artifact.WithFS(mockFS),
					artifact.WithOCIPuller(&puller.MockOCIPuller{PullErr: tt.pullErr}),
				)
			}

			if tt.preConfig != nil {
				r.PluginsConfig = tt.preConfig
			}
			if tt.preCRTracking != nil {
				r.crToConfigName = tt.preCRTracking
			}

			if tt.triggerDeletion {
				obj := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), tt.req.NamespacedName, obj))
				require.NoError(t, cl.Delete(context.Background(), obj))
			}

			result, err := r.Reconcile(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, ctrl.Result{}, result)
			}

			if tt.wantFinalizer != nil {
				obj := &artifactv1alpha1.Plugin{}
				if err := cl.Get(context.Background(), tt.req.NamespacedName, obj); err == nil {
					assert.Equal(t, *tt.wantFinalizer, controllerutil.ContainsFinalizer(obj, testFinalizerName()))
				}
			}

			if tt.wantConfigEmpty != nil {
				assert.Equal(t, *tt.wantConfigEmpty, r.PluginsConfig.isEmpty())
			}

			if len(tt.wantConditions) > 0 {
				obj := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), tt.req.NamespacedName, obj))
				testutil.RequireConditions(t, obj.Status.Conditions, tt.wantConditions)
			}
		})
	}
}

func TestHandleDeletion(t *testing.T) {
	tests := []struct {
		name                string
		objects             []client.Object
		triggerDeletion     bool
		preConfig           *PluginsConfig
		preCRTracking       map[string]string
		wantOK              bool
		wantConfigEmpty     *bool
		wantCRTrackingEmpty *bool
	}{
		{
			name: "not marked for deletion returns false",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
				},
			},
			wantOK: false,
		},
		{
			name: "marked for deletion with finalizer cleans up",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{testFinalizerName()},
					},
				},
			},
			triggerDeletion: true,
			preConfig: &PluginsConfig{
				Configs:     []PluginConfig{{Name: testPluginName, LibraryPath: defaultLibraryPath(testPluginName)}},
				LoadPlugins: []string{testPluginName},
			},
			preCRTracking:       map[string]string{testPluginName: testPluginName},
			wantOK:              true,
			wantConfigEmpty:     testutil.BoolPtr(true),
			wantCRTrackingEmpty: testutil.BoolPtr(true),
		},
		{
			name: "marked for deletion without our finalizer skips cleanup",
			objects: []client.Object{
				&artifactv1alpha1.Plugin{
					ObjectMeta: metav1.ObjectMeta{
						Name:       testPluginName,
						Namespace:  testutil.Namespace,
						Finalizers: []string{"some-other-finalizer"},
					},
				},
			},
			triggerDeletion: true,
			wantOK:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t, tt.objects...)

			if tt.preConfig != nil {
				r.PluginsConfig = tt.preConfig
			}
			if tt.preCRTracking != nil {
				r.crToConfigName = tt.preCRTracking
			}

			plugin := &artifactv1alpha1.Plugin{}
			require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testutil.Namespace}, plugin))

			if tt.triggerDeletion {
				require.NoError(t, cl.Delete(context.Background(), plugin))
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testutil.Namespace}, plugin))
			}

			ok, err := r.handleDeletion(context.Background(), plugin)

			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)

			if tt.wantConfigEmpty != nil {
				assert.Equal(t, *tt.wantConfigEmpty, r.PluginsConfig.isEmpty())
			}
			if tt.wantCRTrackingEmpty != nil {
				if *tt.wantCRTrackingEmpty {
					assert.Empty(t, r.crToConfigName)
				}
			}
		})
	}
}

func TestEnsureFinalizers(t *testing.T) {
	tests := []struct {
		name       string
		finalizers []string
		wantOK     bool
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
					Namespace:  testutil.Namespace,
					Finalizers: tt.finalizers,
				},
			}
			r, cl := newTestReconciler(t, plugin)

			fetched := &artifactv1alpha1.Plugin{}
			require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testutil.Namespace}, fetched))

			ok, err := r.ensureFinalizers(context.Background(), fetched)

			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)

			if tt.wantOK {
				updated := &artifactv1alpha1.Plugin{}
				require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testutil.Namespace}, updated))
				assert.True(t, controllerutil.ContainsFinalizer(updated, testFinalizerName()))
			}
		})
	}
}

func TestEnsurePlugin(t *testing.T) {
	tests := []struct {
		name    string
		plugin  *artifactv1alpha1.Plugin
		wantErr bool
	}{
		{
			name: "nil OCI artifact succeeds",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.Namespace},
			},
		},
		{
			name: "nil OCI artifact spec is also fine",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.Namespace},
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

func TestEnsurePluginConfig(t *testing.T) {
	tests := []struct {
		name              string
		plugin            *artifactv1alpha1.Plugin
		crToConfigName    map[string]string
		initialConfig     *PluginsConfig
		writeErr          error
		wantErr           bool
		wantConfigCount   int
		wantConfigName    string
		wantHasInitConfig bool
		wantCRTrackKey    string
		wantCRTrackValue  string
		wantConditions    []testutil.ConditionExpect
	}{
		{
			name: "writes config for basic plugin",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json", Namespace: testutil.Namespace},
			},
			crToConfigName:   make(map[string]string),
			initialConfig:    &PluginsConfig{},
			wantConfigCount:  1,
			wantConfigName:   "json",
			wantCRTrackKey:   "json",
			wantCRTrackValue: "json",
		},
		{
			name: "writes config with initConfig",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{
						InitConfig: &apiextensionsv1.JSON{
							Raw: []byte(`{"engines":{"containerd":{"enabled":true}}}`),
						},
					},
				},
			},
			crToConfigName:    make(map[string]string),
			initialConfig:     &PluginsConfig{},
			wantConfigCount:   1,
			wantHasInitConfig: true,
		},
		{
			name: "removes stale entry on config name change",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-plugin", Namespace: testutil.Namespace},
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
			wantConfigCount:  1,
			wantConfigName:   "new-name",
			wantCRTrackKey:   "my-plugin",
			wantCRTrackValue: "new-name",
		},
		{
			name: "same config name does not remove entry",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json", Namespace: testutil.Namespace},
			},
			crToConfigName: map[string]string{"json": "json"},
			initialConfig: &PluginsConfig{
				Configs:     []PluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
				LoadPlugins: []string{"json"},
			},
			wantConfigCount: 1,
			wantConfigName:  "json",
		},
		{
			name: "store inline yaml fails sets error conditions",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testPluginName,
					Namespace:  testutil.Namespace,
					Finalizers: []string{testFinalizerName()},
				},
			},
			crToConfigName: make(map[string]string),
			initialConfig:  &PluginsConfig{},
			writeErr:       fmt.Errorf("disk full"),
			wantErr:        true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonInlinePluginConfigStoreFailed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cl := newTestReconciler(t)
			r.crToConfigName = tt.crToConfigName
			r.PluginsConfig = tt.initialConfig

			if tt.writeErr != nil {
				mockFS := filesystem.NewMockFileSystem()
				mockFS.WriteErr = tt.writeErr
				r.artifactManager = artifact.NewManagerWithOptions(cl, testutil.Namespace,
					artifact.WithFS(mockFS),
					artifact.WithOCIPuller(&puller.MockOCIPuller{}),
				)
			}

			err := r.ensurePluginConfig(context.Background(), tt.plugin)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantConfigCount > 0 {
				require.Len(t, r.PluginsConfig.Configs, tt.wantConfigCount)
			}
			if tt.wantConfigName != "" {
				found := findPluginConfig(r.PluginsConfig.Configs, tt.wantConfigName)
				require.NotNil(t, found, "expected config %q not found", tt.wantConfigName)
				if tt.wantHasInitConfig {
					assert.NotNil(t, found.InitConfig)
				}
			}
			if tt.wantCRTrackKey != "" {
				assert.Equal(t, tt.wantCRTrackValue, r.crToConfigName[tt.wantCRTrackKey])
			}
			if len(tt.wantConditions) > 0 {
				testutil.RequireConditions(t, tt.plugin.Status.Conditions, tt.wantConditions)
			}
		})
	}
}

func TestRemovePluginConfig(t *testing.T) {
	tests := []struct {
		name               string
		plugin             *artifactv1alpha1.Plugin
		initialConfig      *PluginsConfig
		wantErr            bool
		wantEmpty          bool
		wantRemainingCount int
		wantRemainingName  string
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
			wantEmpty:          false,
			wantRemainingCount: 1,
			wantRemainingName:  "k8saudit",
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

			if tt.wantRemainingCount > 0 {
				require.Len(t, r.PluginsConfig.Configs, tt.wantRemainingCount)
				found := findPluginConfig(r.PluginsConfig.Configs, tt.wantRemainingName)
				assert.NotNil(t, found, "expected remaining config %q not found", tt.wantRemainingName)
			}
		})
	}
}

func TestPluginsConfig_AddConfig(t *testing.T) {
	tests := []struct {
		name            string
		initial         *PluginsConfig
		plugin          *artifactv1alpha1.Plugin
		callTwice       bool
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
			name:      "skip identical config (no duplicate)",
			initial:   &PluginsConfig{},
			callTwice: true,
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "json"},
			},
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
					{Name: "json", LibraryPath: defaultLibraryPath("json"), OpenParams: "old-params"},
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
				{Name: "json", LibraryPath: defaultLibraryPath("json"), OpenParams: "new-params"},
			},
			expectedLoad: []string{"json"},
		},
		{
			name: "add second plugin preserves existing",
			initial: &PluginsConfig{
				Configs:     []PluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
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
				Configs:     []PluginConfig{{Name: "existing", LibraryPath: defaultLibraryPath("existing")}},
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

			if tt.callTwice {
				pc.addConfig(tt.plugin)
			}
			pc.addConfig(tt.plugin)

			assert.Equal(t, tt.expectedConfigs, pc.Configs)
			assert.Equal(t, tt.expectedLoad, pc.LoadPlugins)
		})
	}
}

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
				Configs:     []PluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
				LoadPlugins: []string{"json"},
			},
			plugin:          &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}},
			expectedConfigs: []PluginConfig{},
			expectedLoad:    []string{},
			expectedEmpty:   true,
		},
		{
			name: "remove plugin when spec.config.name differs from CR name",
			initial: &PluginsConfig{
				Configs:     []PluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("my-json-plugin")}},
				LoadPlugins: []string{"json"},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
				Spec: artifactv1alpha1.PluginSpec{
					Config: &artifactv1alpha1.PluginConfig{Name: "json"},
				},
			},
			expectedConfigs: []PluginConfig{},
			expectedLoad:    []string{},
			expectedEmpty:   true,
		},
		{
			name: "remove non-existent plugin is a no-op",
			initial: &PluginsConfig{
				Configs:     []PluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
				LoadPlugins: []string{"json"},
			},
			plugin:          &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "nonexistent"}},
			expectedConfigs: []PluginConfig{{Name: "json", LibraryPath: defaultLibraryPath("json")}},
			expectedLoad:    []string{"json"},
			expectedEmpty:   false,
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
			plugin:          &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json"}},
			expectedConfigs: []PluginConfig{{Name: "k8saudit", LibraryPath: defaultLibraryPath("k8saudit")}},
			expectedLoad:    []string{"k8saudit"},
			expectedEmpty:   false,
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

func TestPluginsConfig_AddThenRemove_RoundTrip(t *testing.T) {
	t.Run("add and remove with mismatched names cleans up fully", func(t *testing.T) {
		pc := &PluginsConfig{}

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-json-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{Name: "json"},
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

		plugin := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{Name: "json"},
			},
		}
		crToConfigName[plugin.Name] = resolveConfigName(plugin)
		pc.addConfig(plugin)
		require.Len(t, pc.Configs, 1)
		assert.Equal(t, "json", pc.Configs[0].Name)
		assert.Equal(t, []string{"json"}, pc.LoadPlugins)

		pluginRenamed := &artifactv1alpha1.Plugin{
			ObjectMeta: metav1.ObjectMeta{Name: "my-plugin"},
			Spec: artifactv1alpha1.PluginSpec{
				Config: &artifactv1alpha1.PluginConfig{Name: "json-v2"},
			},
		}

		newName := resolveConfigName(pluginRenamed)
		if oldName, ok := crToConfigName[pluginRenamed.Name]; ok && oldName != newName {
			pc.removeByName(oldName)
		}
		crToConfigName[pluginRenamed.Name] = newName
		pc.addConfig(pluginRenamed)

		require.Len(t, pc.Configs, 1)
		assert.Equal(t, "json-v2", pc.Configs[0].Name)
		assert.Equal(t, []string{"json-v2"}, pc.LoadPlugins)

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

		pc.addConfig(plugin)
		var initialConfig map[string]interface{}
		require.NoError(t, json.Unmarshal(pc.Configs[0].InitConfig.Raw, &initialConfig))
		assert.Equal(t, "https://initial.example.com", initialConfig["sssURL"])

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

		pc.removeConfig(pluginUpdated)
		assert.True(t, pc.isEmpty())
	})
}

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
			name: "nested init_config serializes as nested yaml",
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

func TestPluginsConfig_IsEmpty(t *testing.T) {
	assert.True(t, (&PluginsConfig{}).isEmpty())
	assert.False(t, (&PluginsConfig{Configs: []PluginConfig{{Name: "json"}}}).isEmpty())
	assert.False(t, (&PluginsConfig{LoadPlugins: []string{"json"}}).isEmpty())
}

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
					Config: &artifactv1alpha1.PluginConfig{Name: "custom-name"},
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

func TestEnforceReferenceResolution(t *testing.T) {
	tests := []struct {
		name             string
		objects          []client.Object
		plugin           *artifactv1alpha1.Plugin
		wantErr          bool
		wantConditions   []testutil.ConditionExpect
		wantNoConditions bool
		presetConditions []metav1.Condition
	}{
		{
			name: "no PullSecret has no references and removes stale ResolvedRefs",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Reference: "ghcr.io/falcosecurity/plugins/test:latest",
					},
				},
			},
			presetConditions: []metav1.Condition{
				common.NewResolvedRefsCondition(metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, 0),
			},
			wantNoConditions: true,
		},
		{
			name: "nil OCIArtifact has no references",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.Namespace},
			},
			wantNoConditions: true,
		},
		{
			name: "PullSecret exists sets ResolvedRefs true",
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: testutil.Namespace},
				},
			},
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Reference:  "ghcr.io/falcosecurity/plugins/test:latest",
						PullSecret: &commonv1alpha1.OCIPullSecret{SecretName: "my-pull-secret"},
					},
				},
			},
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReferenceResolved},
			},
		},
		{
			name: "PullSecret not found sets ResolvedRefs false and Programmed false",
			plugin: &artifactv1alpha1.Plugin{
				ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.Namespace},
				Spec: artifactv1alpha1.PluginSpec{
					OCIArtifact: &commonv1alpha1.OCIArtifact{
						Reference:  "ghcr.io/falcosecurity/plugins/test:latest",
						PullSecret: &commonv1alpha1.OCIPullSecret{SecretName: "missing-secret"},
					},
				},
			},
			wantErr: true,
			wantConditions: []testutil.ConditionExpect{
				{Type: commonv1alpha1.ConditionResolvedRefs.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
				{Type: commonv1alpha1.ConditionProgrammed.String(), Status: metav1.ConditionFalse, Reason: artifact.ReasonReferenceResolutionFailed},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestReconciler(t, tt.objects...)

			if len(tt.presetConditions) > 0 {
				tt.plugin.Status.Conditions = tt.presetConditions
			}

			err := r.enforceReferenceResolution(context.Background(), tt.plugin)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantNoConditions {
				assert.Empty(t, tt.plugin.Status.Conditions)
			}

			if len(tt.wantConditions) > 0 {
				testutil.RequireConditions(t, tt.plugin.Status.Conditions, tt.wantConditions)
			}
		})
	}
}

func TestPatchStatus(t *testing.T) {
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPluginName,
			Namespace: testutil.Namespace,
		},
	}
	r, cl := newTestReconciler(t, plugin)

	fetched := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testutil.Namespace}, fetched))

	fetched.Status.Conditions = []metav1.Condition{
		common.NewReconciledCondition(metav1.ConditionTrue, artifact.ReasonReconciled, artifact.MessagePluginReconciled, 1),
	}

	require.NoError(t, r.patchStatus(context.Background(), fetched))

	obj := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: testPluginName, Namespace: testutil.Namespace}, obj))
	testutil.RequireConditions(t, obj.Status.Conditions, []testutil.ConditionExpect{
		{Type: commonv1alpha1.ConditionReconciled.String(), Status: metav1.ConditionTrue, Reason: artifact.ReasonReconciled},
	})
}
