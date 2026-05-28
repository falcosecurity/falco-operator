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

package artifact

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// createTestScheme creates a runtime scheme with corev1 types registered.
func createTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	return scheme
}

func TestNewManager(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		opt       ManagerOption
		check     func(*Manager) bool
	}{
		{
			name:      "creates manager with namespace",
			namespace: "test-namespace",
		},
		{
			name:      "creates manager with default namespace",
			namespace: "default",
		},
		{
			name:      "creates manager with empty namespace",
			namespace: "",
		},
		{
			name:      "WithRulesfileDir sets custom rulesfile directory",
			namespace: "ns",
			opt:       WithRulesfileDir("/custom/rules"),
			check:     func(m *Manager) bool { return m.rulesfileDir == "/custom/rules" },
		},
		{
			name:      "WithPluginDir sets custom plugin directory",
			namespace: "ns",
			opt:       WithPluginDir("/custom/plugins"),
			check:     func(m *Manager) bool { return m.pluginDir == "/custom/plugins" },
		},
		{
			name:      "WithConfigDir sets custom config directory",
			namespace: "ns",
			opt:       WithConfigDir("/custom/config"),
			check:     func(m *Manager) bool { return m.configDir == "/custom/config" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			var opts []ManagerOption
			if tt.opt != nil {
				opts = append(opts, tt.opt)
			}
			manager := NewManagerWithOptions(fakeClient, tt.namespace, opts...)

			require.NotNil(t, manager)
			assert.NotNil(t, manager.files)
			assert.Equal(t, tt.namespace, manager.namespace)
			assert.NotNil(t, manager.client)
			assert.NotNil(t, manager.fs)
			if tt.check != nil {
				assert.True(t, tt.check(manager))
			}
		})
	}
}

func TestStoreFromConfigMap(t *testing.T) {
	const (
		testNamespace     = "test-namespace"
		testConfigMapName = "test-configmap"
		testKey           = "rules.yaml"
		testArtifactName  = "test-artifact"
		testData          = "- rule: test rule\n  desc: test description"
	)

	tests := []struct {
		name            string
		configMapRef    *commonv1alpha1.ConfigMapRef
		configMap       *corev1.ConfigMap
		artifactType    Type
		priority        int32
		existingFile    *File
		existingData    string
		noCorev1Scheme  bool
		fsWriteErr      error
		fsRemoveErr     error
		fsReadErr       error
		fsStatErr       error
		wantErr         bool
		wantErrMsg      string
		wantWriteCalls  int
		wantRemoveCalls int
		wantFilesLen    int
		wantFile        *File
		wantAction      StoreAction
	}{
		{
			name: "successfully stores new artifact from ConfigMap",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{
					testKey: testData,
				}).
				Build(),
			priority:        50,
			wantErr:         false,
			wantWriteCalls:  1,
			wantRemoveCalls: 0,
			wantAction:      StoreActionAdded,
		},
		{
			name:         "removes artifact when configMapRef is nil",
			configMapRef: nil,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml",
				Medium:   MediumConfigMap,
				Priority: 50,
			},
			wantErr:         false,
			wantWriteCalls:  0,
			wantRemoveCalls: 1,
			wantAction:      StoreActionRemoved,
		},
		{
			name: "returns nil when ConfigMap not found",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: "non-existent-configmap",
			},
			priority:        50,
			wantErr:         false,
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
			wantAction:      StoreActionNone,
		},
		{
			name: "returns nil when rules.yaml key not found in ConfigMap",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{
					"other-key": testData,
				}).
				Build(),
			priority:        50,
			wantErr:         false,
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
			wantAction:      StoreActionNone,
		},
		{
			name: "skips write when file content is unchanged",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{
					testKey: testData,
				}).
				Build(),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml",
				Medium:   MediumConfigMap,
				Priority: 50,
			},
			existingData:    testData,
			wantErr:         false,
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
			wantAction:      StoreActionUnchanged,
		},
		{
			name: "updates file when content changes",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{
					testKey: testData,
				}).
				Build(),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml",
				Medium:   MediumConfigMap,
				Priority: 50,
			},
			existingData:    "old content",
			wantErr:         false,
			wantWriteCalls:  1,
			wantRemoveCalls: 1,
			wantAction:      StoreActionUpdated,
		},
		{
			name: "updates file when priority changes",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{
					testKey: testData,
				}).
				Build(),
			priority: 60,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml",
				Medium:   MediumConfigMap,
				Priority: 50,
			},
			existingData:    testData,
			wantErr:         false,
			wantWriteCalls:  1,
			wantRemoveCalls: 1,
			wantFile:        &File{Path: "/etc/falco/rules.d/60-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 60},
			wantAction:      StoreActionPriorityChanged,
		},
		{
			name: "returns error when write fails",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{
					testKey: testData,
				}).
				Build(),
			priority:        50,
			fsWriteErr:      fmt.Errorf("disk full"),
			wantErr:         true,
			wantErrMsg:      "disk full",
			wantWriteCalls:  1,
			wantRemoveCalls: 0,
			wantAction:      StoreActionNone,
		},
		{
			name: "returns error when Exists check fails",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{
					testKey: testData,
				}).
				Build(),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml",
				Medium:   MediumConfigMap,
				Priority: 50,
			},
			fsStatErr:       fmt.Errorf("permission denied"),
			wantErr:         true,
			wantErrMsg:      "permission denied",
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
			wantAction:      StoreActionNone,
		},
		{
			name: "returns error when ReadFile fails",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{
					testKey: testData,
				}).
				Build(),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml",
				Medium:   MediumConfigMap,
				Priority: 50,
			},
			existingData:    testData,
			fsReadErr:       fmt.Errorf("I/O error"),
			wantErr:         true,
			wantErrMsg:      "I/O error",
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
			wantAction:      StoreActionNone,
		},
		{
			name: "returns error when Remove fails during update",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{
					testKey: testData,
				}).
				Build(),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml",
				Medium:   MediumConfigMap,
				Priority: 50,
			},
			existingData:    "old content",
			fsRemoveErr:     fmt.Errorf("cannot remove file"),
			wantErr:         true,
			wantErrMsg:      "cannot remove file",
			wantWriteCalls:  0,
			wantRemoveCalls: 1,
			wantAction:      StoreActionNone,
		},
		{
			name:            "removes existing file when ConfigMap is not found",
			configMapRef:    &commonv1alpha1.ConfigMapRef{Name: "non-existent"},
			priority:        50,
			existingFile:    &File{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			existingData:    testData,
			wantRemoveCalls: 1,
			wantAction:      StoreActionRemoved,
		},
		{
			name:            "returns error when Remove fails on ConfigMap not found",
			configMapRef:    &commonv1alpha1.ConfigMapRef{Name: "non-existent"},
			priority:        50,
			existingFile:    &File{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			existingData:    testData,
			fsRemoveErr:     fmt.Errorf("cannot remove"),
			wantErr:         true,
			wantErrMsg:      "cannot remove",
			wantRemoveCalls: 1,
			wantAction:      StoreActionNone,
		},
		{
			name:           "returns error on non-NotFound client error",
			configMapRef:   &commonv1alpha1.ConfigMapRef{Name: testConfigMapName},
			priority:       50,
			noCorev1Scheme: true,
			wantErr:        true,
			wantAction:     StoreActionNone,
		},
		{
			name:         "stores artifact using config.yaml key for TypeConfig",
			configMapRef: &commonv1alpha1.ConfigMapRef{Name: testConfigMapName},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{"config.yaml": testData}).
				Build(),
			artifactType:   TypeConfig,
			priority:       50,
			wantWriteCalls: 1,
			wantAction:     StoreActionAdded,
		},
		{
			name:         "returns error for unsupported artifact type",
			configMapRef: &commonv1alpha1.ConfigMapRef{Name: testConfigMapName},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{"anything": testData}).
				Build(),
			artifactType: TypePlugin,
			priority:     50,
			wantErr:      true,
			wantErrMsg:   "unsupported artifact type",
			wantAction:   StoreActionNone,
		},
		{
			name:         "removes existing file when ConfigMap key is not found",
			configMapRef: &commonv1alpha1.ConfigMapRef{Name: testConfigMapName},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{"other-key": testData}).
				Build(),
			priority:        50,
			existingFile:    &File{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			existingData:    testData,
			wantRemoveCalls: 1,
			wantAction:      StoreActionRemoved,
		},
		{
			name:         "returns error when Remove fails on missing ConfigMap key",
			configMapRef: &commonv1alpha1.ConfigMapRef{Name: testConfigMapName},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{"other-key": testData}).
				Build(),
			priority:        50,
			existingFile:    &File{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			existingData:    testData,
			fsRemoveErr:     fmt.Errorf("cannot remove"),
			wantErr:         true,
			wantErrMsg:      "cannot remove",
			wantRemoveCalls: 1,
			wantAction:      StoreActionNone,
		},
		{
			name:         "clears stale registration when file is registered but missing from disk",
			configMapRef: &commonv1alpha1.ConfigMapRef{Name: testConfigMapName},
			configMap: builders.NewConfigMap().
				WithName(testConfigMapName).
				WithNamespace(testNamespace).
				WithData(map[string]string{"rules.yaml": testData}).
				Build(),
			priority:       50,
			existingFile:   &File{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			wantWriteCalls: 1,
			wantFilesLen:   1,
			wantAction:     StoreActionAdded,
		},
		{
			name:            "returns error when removeArtifact fails on nil configMapRef",
			configMapRef:    nil,
			priority:        50,
			existingFile:    &File{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap},
			existingData:    testData,
			fsRemoveErr:     fmt.Errorf("remove failed"),
			wantErr:         true,
			wantErrMsg:      "remove failed",
			wantRemoveCalls: 1,
			wantAction:      StoreActionNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scheme *runtime.Scheme
			if tt.noCorev1Scheme {
				scheme = runtime.NewScheme()
			} else {
				scheme = createTestScheme(t)
			}
			clientBuilder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.configMap != nil {
				clientBuilder = clientBuilder.WithObjects(tt.configMap)
			}
			fakeClient := clientBuilder.Build()

			mockFS := filesystem.NewMockFileSystem()
			mockFS.WriteErr = tt.fsWriteErr
			mockFS.RemoveErr = tt.fsRemoveErr
			mockFS.ReadErr = tt.fsReadErr
			mockFS.StatErr = tt.fsStatErr
			manager := NewManagerWithOptions(fakeClient, testNamespace, WithFS(mockFS))

			if tt.existingFile != nil {
				manager.files[testArtifactName] = []File{*tt.existingFile}
				if tt.existingData != "" {
					mockFS.Files[tt.existingFile.Path] = []byte(tt.existingData)
				}
			}

			artifactType := tt.artifactType
			if artifactType == "" {
				artifactType = TypeRulesfile
			}

			ctx := context.Background()
			action, err := manager.StoreFromConfigMap(ctx, testArtifactName, testNamespace, tt.priority, tt.configMapRef, artifactType)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
			} else {
				require.NoError(t, err)
			}

			if tt.wantAction != "" {
				assert.Equal(t, tt.wantAction, action)
			}
			assert.Len(t, mockFS.WriteCalls, tt.wantWriteCalls)
			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveCalls)
			if tt.wantFilesLen > 0 {
				assert.Len(t, manager.files[testArtifactName], tt.wantFilesLen)
			}
			if tt.wantFile != nil {
				file := manager.getArtifactFile(testArtifactName, tt.wantFile.Medium)
				require.NotNil(t, file)
				assert.Equal(t, tt.wantFile.Path, file.Path)
				assert.Equal(t, tt.wantFile.Priority, file.Priority)
			}
		})
	}
}

func TestStoreFromInLineYaml(t *testing.T) {
	const (
		testNamespace    = "test-namespace"
		testArtifactName = "test-artifact"
		testData         = "- rule: test rule\n  desc: test description"
	)

	tests := []struct {
		name            string
		data            *string
		priority        int32
		existingFile    *File
		existingData    string
		fsWriteErr      error
		fsRemoveErr     error
		fsReadErr       error
		fsStatErr       error
		wantErr         bool
		wantErrMsg      string
		wantWriteCalls  int
		wantRemoveCalls int
		wantFilesLen    int
		wantFile        *File
		wantAction      StoreAction
	}{
		{
			name:            "successfully stores new artifact from inline YAML",
			data:            ptr.To(testData),
			priority:        50,
			wantErr:         false,
			wantWriteCalls:  1,
			wantRemoveCalls: 0,
			wantAction:      StoreActionAdded,
		},
		{
			name: "removes artifact when data is nil",
			data: nil,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-03-test-artifact-inline.yaml",
				Medium:   MediumInline,
				Priority: 50,
			},
			wantErr:         false,
			wantWriteCalls:  0,
			wantRemoveCalls: 1,
			wantAction:      StoreActionRemoved,
		},
		{
			name:            "does nothing when data is nil and no existing file",
			data:            nil,
			wantErr:         false,
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
			wantAction:      StoreActionNone,
		},
		{
			name:     "skips write when file content is unchanged",
			data:     ptr.To(testData),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-03-test-artifact-inline.yaml",
				Medium:   MediumInline,
				Priority: 50,
			},
			existingData:    testData,
			wantErr:         false,
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
			wantAction:      StoreActionUnchanged,
		},
		{
			name:     "updates file when content changes",
			data:     ptr.To(testData),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-03-test-artifact-inline.yaml",
				Medium:   MediumInline,
				Priority: 50,
			},
			existingData:    "old content",
			wantErr:         false,
			wantWriteCalls:  1,
			wantRemoveCalls: 1,
			wantAction:      StoreActionUpdated,
		},
		{
			name:     "updates file when priority changes",
			data:     ptr.To(testData),
			priority: 60,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-03-test-artifact-inline.yaml",
				Medium:   MediumInline,
				Priority: 50,
			},
			existingData:    testData,
			wantErr:         false,
			wantWriteCalls:  1,
			wantRemoveCalls: 1,
			wantFile:        &File{Path: "/etc/falco/rules.d/60-03-test-artifact-inline.yaml", Medium: MediumInline, Priority: 60},
			wantAction:      StoreActionPriorityChanged,
		},
		{
			name:            "returns error when write fails",
			data:            ptr.To(testData),
			priority:        50,
			fsWriteErr:      fmt.Errorf("disk full"),
			wantErr:         true,
			wantErrMsg:      "disk full",
			wantWriteCalls:  1,
			wantRemoveCalls: 0,
			wantAction:      StoreActionNone,
		},
		{
			name:     "returns error when Exists check fails",
			data:     ptr.To(testData),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-03-test-artifact-inline.yaml",
				Medium:   MediumInline,
				Priority: 50,
			},
			fsStatErr:       fmt.Errorf("permission denied"),
			wantErr:         true,
			wantErrMsg:      "permission denied",
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
			wantAction:      StoreActionNone,
		},
		{
			name:     "returns error when ReadFile fails",
			data:     ptr.To(testData),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-03-test-artifact-inline.yaml",
				Medium:   MediumInline,
				Priority: 50,
			},
			existingData:    testData,
			fsReadErr:       fmt.Errorf("I/O error"),
			wantErr:         true,
			wantErrMsg:      "I/O error",
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
			wantAction:      StoreActionNone,
		},
		{
			name:     "returns error when Remove fails during update",
			data:     ptr.To(testData),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-03-test-artifact-inline.yaml",
				Medium:   MediumInline,
				Priority: 50,
			},
			existingData:    "old content",
			fsRemoveErr:     fmt.Errorf("cannot remove file"),
			wantErr:         true,
			wantErrMsg:      "cannot remove file",
			wantWriteCalls:  0,
			wantRemoveCalls: 1,
			wantAction:      StoreActionNone,
		},
		{
			name:     "clears stale registration when file is registered but missing from disk",
			data:     ptr.To(testData),
			priority: 50,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-03-test-artifact-inline.yaml",
				Medium:   MediumInline,
				Priority: 50,
			},
			wantWriteCalls: 1,
			wantFilesLen:   1,
			wantAction:     StoreActionAdded,
		},
		{
			name: "returns error when removeArtifact fails on nil data",
			data: nil,
			existingFile: &File{
				Path:   "/etc/falco/rules.d/50-03-test-artifact-inline.yaml",
				Medium: MediumInline,
			},
			existingData:    "content",
			fsRemoveErr:     fmt.Errorf("remove failed"),
			wantErr:         true,
			wantErrMsg:      "remove failed",
			wantRemoveCalls: 1,
			wantAction:      StoreActionNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			mockFS := filesystem.NewMockFileSystem()
			mockFS.WriteErr = tt.fsWriteErr
			mockFS.RemoveErr = tt.fsRemoveErr
			mockFS.ReadErr = tt.fsReadErr
			mockFS.StatErr = tt.fsStatErr
			manager := NewManagerWithOptions(fakeClient, testNamespace, WithFS(mockFS))

			if tt.existingFile != nil {
				manager.files[testArtifactName] = []File{*tt.existingFile}
				if tt.existingData != "" {
					mockFS.Files[tt.existingFile.Path] = []byte(tt.existingData)
				}
			}

			ctx := context.Background()
			action, err := manager.StoreFromInLineYaml(ctx, testArtifactName, tt.priority, tt.data, TypeRulesfile)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
			} else {
				require.NoError(t, err)
			}

			if tt.wantAction != "" {
				assert.Equal(t, tt.wantAction, action)
			}
			assert.Len(t, mockFS.WriteCalls, tt.wantWriteCalls)
			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveCalls)
			if tt.wantFilesLen > 0 {
				assert.Len(t, manager.files[testArtifactName], tt.wantFilesLen)
			}
			if tt.wantFile != nil {
				file := manager.getArtifactFile(testArtifactName, tt.wantFile.Medium)
				require.NotNil(t, file)
				assert.Equal(t, tt.wantFile.Path, file.Path)
				assert.Equal(t, tt.wantFile.Priority, file.Priority)
			}
		})
	}
}

func TestRemoveAll(t *testing.T) {
	const testNamespace = "test-namespace"

	tests := []struct {
		name            string
		artifactName    string
		existingFiles   []File
		fsRemoveErr     error
		wantErr         bool
		wantRemoveCalls int
	}{
		{
			name:            "does nothing when no artifacts exist",
			artifactName:    "non-existent",
			existingFiles:   nil,
			wantErr:         false,
			wantRemoveCalls: 0,
		},
		{
			name:         "removes single artifact",
			artifactName: "test-artifact",
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			wantErr:         false,
			wantRemoveCalls: 1,
		},
		{
			name:         "removes multiple artifacts",
			artifactName: "test-artifact",
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
				{Path: "/etc/falco/rules.d/50-03-test-artifact-inline.yaml", Medium: MediumInline, Priority: 50},
			},
			wantErr:         false,
			wantRemoveCalls: 2,
		},
		{
			name:         "returns error when remove fails",
			artifactName: "test-artifact",
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			fsRemoveErr:     fmt.Errorf("permission denied"),
			wantErr:         true,
			wantRemoveCalls: 1,
		},
		{
			name:         "succeeds when registered file does not exist on disk",
			artifactName: "test-artifact",
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			wantErr:         false,
			wantRemoveCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			mockFS := filesystem.NewMockFileSystem()
			mockFS.RemoveErr = tt.fsRemoveErr

			manager := NewManagerWithOptions(fakeClient, testNamespace, WithFS(mockFS))

			if tt.existingFiles != nil {
				manager.files[tt.artifactName] = tt.existingFiles
			}

			ctx := context.Background()
			err := manager.RemoveAll(ctx, tt.artifactName)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveCalls)
		})
	}
}

func TestPath(t *testing.T) {
	tests := []struct {
		name         string
		artifactName string
		priority     int32
		Medium
		artifactType Type
		wantContains string
	}{
		{
			name:         "rulesfile with OCI Medium",
			artifactName: "my-rules",
			priority:     50,
			Medium:       MediumOCI,
			artifactType: TypeRulesfile,
			wantContains: "50-01-my-rules-oci.yaml",
		},
		{
			name:         "rulesfile with inline Medium",
			artifactName: "my-rules",
			priority:     50,
			Medium:       MediumInline,
			artifactType: TypeRulesfile,
			wantContains: "50-03-my-rules-inline.yaml",
		},
		{
			name:         "rulesfile with configmap Medium",
			artifactName: "my-rules",
			priority:     50,
			Medium:       MediumConfigMap,
			artifactType: TypeRulesfile,
			wantContains: "50-02-my-rules-configmap.yaml",
		},
		{
			name:         "plugin type",
			artifactName: "my-plugin",
			priority:     50,
			Medium:       MediumOCI,
			artifactType: TypePlugin,
			wantContains: "my-plugin.so",
		},
		{
			name:         "config type inline",
			artifactName: "my-config",
			priority:     50,
			Medium:       MediumInline,
			artifactType: TypeConfig,
			wantContains: "50-03-my-config-inline.yaml",
		},
		{
			name:         "config type configmap",
			artifactName: "my-config",
			priority:     50,
			Medium:       MediumConfigMap,
			artifactType: TypeConfig,
			wantContains: "50-02-my-config-configmap.yaml",
		},
		{
			name:         "rulesfile with unknown medium uses default subpriority",
			artifactName: "my-rules",
			priority:     50,
			Medium:       Medium("unknown"),
			artifactType: TypeRulesfile,
			wantContains: "50-99-my-rules-unknown.yaml",
		},
		{
			name:         "unknown artifact type uses default path",
			artifactName: "my-artifact",
			priority:     50,
			Medium:       MediumOCI,
			artifactType: Type("unknown"),
			wantContains: "50-my-artifact",
		},
		{
			name:         "config type with OCI medium uses default subpriority",
			artifactName: "my-config",
			priority:     50,
			Medium:       MediumOCI,
			artifactType: TypeConfig,
			wantContains: "50-99-my-config-oci.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewManager(nil, "").Path(tt.artifactName, tt.priority, tt.Medium, tt.artifactType)
			assert.Contains(t, result, tt.wantContains)
		})
	}
}

func TestRemoveArtifact(t *testing.T) {
	const testNamespace = "test-namespace"

	tests := []struct {
		name            string
		artifactName    string
		medium          Medium
		existingFiles   []File
		fsRemoveErr     error
		wantErr         bool
		wantRemoveCalls int
	}{
		{
			name:            "does nothing when no artifacts exist",
			artifactName:    "non-existent",
			medium:          MediumConfigMap,
			existingFiles:   nil,
			wantErr:         false,
			wantRemoveCalls: 0,
		},
		{
			name:         "removes artifact with matching Medium",
			artifactName: "test-artifact",
			medium:       MediumConfigMap,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			wantErr:         false,
			wantRemoveCalls: 1,
		},
		{
			name:         "does not remove artifact with different Medium",
			artifactName: "test-artifact",
			medium:       MediumInline,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			wantErr:         false,
			wantRemoveCalls: 0,
		},
		{
			name:         "removes only artifact with matching Medium from multiple",
			artifactName: "test-artifact",
			medium:       MediumConfigMap,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
				{Path: "/etc/falco/rules.d/50-03-test-artifact-inline.yaml", Medium: MediumInline, Priority: 50},
			},
			wantErr:         false,
			wantRemoveCalls: 1,
		},
		{
			name:         "returns error when remove fails",
			artifactName: "test-artifact",
			medium:       MediumConfigMap,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			fsRemoveErr:     fmt.Errorf("permission denied"),
			wantErr:         true,
			wantRemoveCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			mockFS := filesystem.NewMockFileSystem()
			mockFS.RemoveErr = tt.fsRemoveErr

			manager := NewManagerWithOptions(fakeClient, testNamespace, WithFS(mockFS))

			if tt.existingFiles != nil {
				manager.files[tt.artifactName] = tt.existingFiles
				for _, f := range tt.existingFiles {
					mockFS.Files[f.Path] = []byte("content")
				}
			}

			ctx := context.Background()
			err := manager.removeArtifact(ctx, tt.artifactName, tt.medium)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveCalls)
		})
	}
}

func TestGetArtifactFile(t *testing.T) {
	const testNamespace = "test-namespace"

	tests := []struct {
		name          string
		artifactName  string
		Medium        Medium
		existingFiles []File
		wantFile      *File
	}{
		{
			name:          "returns nil when no artifacts exist",
			artifactName:  "non-existent",
			Medium:        MediumConfigMap,
			existingFiles: nil,
			wantFile:      nil,
		},
		{
			name:         "returns file with matching Medium",
			artifactName: "test-artifact",
			Medium:       MediumConfigMap,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			wantFile: &File{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
		},
		{
			name:         "returns nil when Medium does not match",
			artifactName: "test-artifact",
			Medium:       MediumInline,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			wantFile: nil,
		},
		{
			name:         "returns correct file from multiple",
			artifactName: "test-artifact",
			Medium:       MediumInline,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
				{Path: "/etc/falco/rules.d/50-03-test-artifact-inline.yaml", Medium: MediumInline, Priority: 50},
			},
			wantFile: &File{Path: "/etc/falco/rules.d/50-03-test-artifact-inline.yaml", Medium: MediumInline, Priority: 50},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			manager := NewManagerWithOptions(fakeClient, testNamespace, WithFS(filesystem.NewMockFileSystem()))

			if tt.existingFiles != nil {
				manager.files[tt.artifactName] = tt.existingFiles
			}

			result := manager.getArtifactFile(tt.artifactName, tt.Medium)

			if tt.wantFile == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.wantFile.Path, result.Path)
				assert.Equal(t, tt.wantFile.Medium, result.Medium)
				assert.Equal(t, tt.wantFile.Priority, result.Priority)
			}
		})
	}
}

func TestAddArtifactFile(t *testing.T) {
	const testNamespace = "test-namespace"

	tests := []struct {
		name          string
		artifactName  string
		fileToAdd     File
		existingFiles []File
		wantCount     int
	}{
		{
			name:         "adds file when no artifacts exist",
			artifactName: "test-artifact",
			fileToAdd:    File{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			wantCount:    1,
		},
		{
			name:         "adds file to existing artifacts",
			artifactName: "test-artifact",
			fileToAdd:    File{Path: "/etc/falco/rules.d/50-03-test-artifact-inline.yaml", Medium: MediumInline, Priority: 50},
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			manager := NewManagerWithOptions(fakeClient, testNamespace, WithFS(filesystem.NewMockFileSystem()))

			if tt.existingFiles != nil {
				manager.files[tt.artifactName] = tt.existingFiles
			}

			manager.addArtifactFile(tt.artifactName, tt.fileToAdd)

			assert.Len(t, manager.files[tt.artifactName], tt.wantCount)
		})
	}
}

func TestRemoveArtifactFile(t *testing.T) {
	const testNamespace = "test-namespace"

	tests := []struct {
		name           string
		artifactName   string
		MediumToRemove Medium
		existingFiles  []File
		wantCount      int
	}{
		{
			name:           "does nothing when no artifacts exist",
			artifactName:   "non-existent",
			MediumToRemove: MediumConfigMap,
			wantCount:      0,
		},
		{
			name:           "removes file with matching Medium",
			artifactName:   "test-artifact",
			MediumToRemove: MediumConfigMap,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			wantCount: 0,
		},
		{
			name:           "does not remove file with different Medium",
			artifactName:   "test-artifact",
			MediumToRemove: MediumInline,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
			},
			wantCount: 1,
		},
		{
			name:           "removes only matching Medium from multiple",
			artifactName:   "test-artifact",
			MediumToRemove: MediumConfigMap,
			existingFiles: []File{
				{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
				{Path: "/etc/falco/rules.d/50-03-test-artifact-inline.yaml", Medium: MediumInline, Priority: 50},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			manager := NewManagerWithOptions(fakeClient, testNamespace, WithFS(filesystem.NewMockFileSystem()))

			if tt.existingFiles != nil {
				manager.files[tt.artifactName] = tt.existingFiles
			}

			manager.removeArtifactFile(tt.artifactName, tt.MediumToRemove)

			assert.Len(t, manager.files[tt.artifactName], tt.wantCount)
		})
	}
}

func TestStoreFromOCI(t *testing.T) {
	const (
		testNamespace    = "test-namespace"
		testArtifactName = "test-artifact"
	)

	testImage := commonv1alpha1.ImageSpec{
		Repository: "falcosecurity/rules/falco-rules",
		Tag:        "latest",
	}

	validLayer := func(t *testing.T) []byte {
		t.Helper()
		data, err := puller.MakeTarGz("rules.yaml", []byte("fake-rules-content"))
		require.NoError(t, err)
		return data
	}

	tests := []struct {
		name            string
		artifact        *commonv1alpha1.OCIArtifact
		objects         []client.Object
		priority        int32
		artifactType    Type
		existingFile    *File
		existingData    string
		layerContent    func(t *testing.T) []byte
		pullerResult    *puller.RegistryResult
		pullerErr       error
		allowNilResult  bool
		fsRenameErr     error
		fsRemoveErr     error
		fsStatErr       error
		fsWriteErr      error
		wantErr         bool
		wantErrMsg      string
		wantPullCalls   int
		wantWriteCalls  int
		wantRenameCalls int
		wantRemoveCalls int
		wantFile        *File
		wantFileContent string
		wantOpts        *puller.RegistryOptions
		wantAction      StoreAction
	}{
		{
			name:     "removes artifact when artifact is nil",
			artifact: nil,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
			},
			wantRemoveCalls: 1,
			wantAction:      StoreActionRemoved,
		},
		{
			name:       "does nothing when artifact is nil and no existing file",
			artifact:   nil,
			wantAction: StoreActionNone,
		},
		{
			name: "returns error when artifact already stored but file not found on filesystem",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
			},
			wantErr:    true,
			wantErrMsg: "not found on filesystem",
			wantAction: StoreActionNone,
		},
		{
			name: "renames file when only priority changes",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
			},
			priority:     60,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:            "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:          MediumOCI,
				Priority:        50,
				SourceSignature: computeOCISourceSignature(&commonv1alpha1.OCIArtifact{Image: testImage}, nil),
			},
			existingData:    "existing content",
			wantRenameCalls: 1,
			wantFile:        &File{Path: "/etc/falco/rules.d/60-01-test-artifact-oci.yaml", Medium: MediumOCI, Priority: 60},
			wantAction:      StoreActionPriorityChanged,
		},
		{
			name: "skips pull when file already exists with same signature and priority",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:            "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:          MediumOCI,
				Priority:        50,
				SourceSignature: computeOCISourceSignature(&commonv1alpha1.OCIArtifact{Image: testImage}, nil),
			},
			existingData: "existing content",
			wantAction:   StoreActionUnchanged,
		},
		{
			name: "returns error when credentials getter fails",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
				Registry: &commonv1alpha1.RegistryConfig{
					Auth: &commonv1alpha1.RegistryAuth{
						SecretRef: &commonv1alpha1.SecretRef{Name: "non-existent-secret"},
					},
				},
			},
			priority:     50,
			artifactType: TypeRulesfile,
			wantErr:      true,
			wantErrMsg:   "failed to get pull secret",
			wantAction:   StoreActionNone,
		},
		{
			name: "returns error when puller fails",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
			},
			priority:      50,
			artifactType:  TypeRulesfile,
			pullerErr:     fmt.Errorf("registry unavailable"),
			wantErr:       true,
			wantErrMsg:    "registry unavailable",
			wantPullCalls: 1,
			wantAction:    StoreActionNone,
		},
		{
			name:           "puller returns nil result",
			artifact:       &commonv1alpha1.OCIArtifact{Image: testImage},
			priority:       50,
			artifactType:   TypeRulesfile,
			allowNilResult: true,
			wantErr:        true,
			wantErrMsg:     "nil result",
			wantPullCalls:  1,
			wantAction:     StoreActionNone,
		},
		{
			name:          "returns error when layer content is not a valid gzip",
			artifact:      &commonv1alpha1.OCIArtifact{Image: testImage},
			priority:      50,
			artifactType:  TypeRulesfile,
			pullerResult:  &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:  func(t *testing.T) []byte { return []byte("not-a-valid-gzip") },
			wantErr:       true,
			wantPullCalls: 1,
			wantAction:    StoreActionNone,
		},
		{
			name:          "returns error when pulled artifact type does not match resource type",
			artifact:      &commonv1alpha1.OCIArtifact{Image: testImage},
			priority:      50,
			artifactType:  TypeRulesfile,
			pullerResult:  &puller.RegistryResult{Filename: "plugin.tar.gz", Type: puller.Plugin},
			layerContent:  validLayer,
			wantErr:       true,
			wantErrMsg:    "does not match expected type",
			wantPullCalls: 1,
			wantAction:    StoreActionNone,
		},
		{
			name:            "returns error when WriteFile fails on tmp",
			artifact:        &commonv1alpha1.OCIArtifact{Image: testImage},
			priority:        50,
			artifactType:    TypeRulesfile,
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			fsWriteErr:      fmt.Errorf("disk full"),
			wantErr:         true,
			wantErrMsg:      "disk full",
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRemoveCalls: 1,
			wantAction:      StoreActionNone,
		},
		{
			name:            "returns error when Rename of tmp to final path fails",
			artifact:        &commonv1alpha1.OCIArtifact{Image: testImage},
			priority:        50,
			artifactType:    TypeRulesfile,
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			fsRenameErr:     fmt.Errorf("rename failed"),
			wantErr:         true,
			wantErrMsg:      "rename failed",
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantRemoveCalls: 1,
			wantAction:      StoreActionNone,
		},
		{
			name: "passes plainHTTP option to puller",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
				Registry: &commonv1alpha1.RegistryConfig{
					PlainHTTP: new(true),
				},
			},
			priority:        50,
			artifactType:    TypeRulesfile,
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantOpts:        &puller.RegistryOptions{PlainHTTP: true},
			wantAction:      StoreActionAdded,
		},
		{
			name: "passes TLS insecureSkipVerify option to puller",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
				Registry: &commonv1alpha1.RegistryConfig{
					TLS: &commonv1alpha1.TLSConfig{InsecureSkipVerify: true},
				},
			},
			priority:        50,
			artifactType:    TypeRulesfile,
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantOpts:        &puller.RegistryOptions{InsecureSkipVerify: true},
			wantAction:      StoreActionAdded,
		},
		{
			name:            "successfully pulls, extracts and stores artifact",
			artifact:        &commonv1alpha1.OCIArtifact{Image: testImage},
			priority:        50,
			artifactType:    TypeRulesfile,
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantFileContent: "fake-rules-content",
			wantAction:      StoreActionAdded,
		},
		{
			name:     "returns error when removeArtifact fails on nil artifact",
			artifact: nil,
			existingFile: &File{
				Path:   "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium: MediumOCI,
			},
			existingData:    "content",
			fsRemoveErr:     fmt.Errorf("remove failed"),
			wantErr:         true,
			wantErrMsg:      "remove failed",
			wantRemoveCalls: 1,
			wantAction:      StoreActionNone,
		},
		{
			name: "re-pulls when OCI tag changes (signature drift)",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules",
					Tag:        "v2",
				},
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
				SourceSignature: computeOCISourceSignature(&commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{
						Repository: "falcosecurity/rules/falco-rules",
						Tag:        "v1",
					},
				}, nil),
			},
			existingData:    "v1 rules",
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantFileContent: "fake-rules-content",
			wantAction:      StoreActionUpdated,
		},
		{
			name: "re-pulls when OCI repository changes",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/rules/falco-rules-extras",
					Tag:        "latest",
				},
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:            "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:          MediumOCI,
				Priority:        50,
				SourceSignature: computeOCISourceSignature(&commonv1alpha1.OCIArtifact{Image: testImage}, nil),
			},
			existingData:    "original rules",
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantAction:      StoreActionUpdated,
		},
		{
			name: "re-pulls when OCI registry name changes",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
				Registry: &commonv1alpha1.RegistryConfig{
					Name: "quay.io",
				},
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:            "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:          MediumOCI,
				Priority:        50,
				SourceSignature: computeOCISourceSignature(&commonv1alpha1.OCIArtifact{Image: testImage}, nil),
			},
			existingData:    "original rules",
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantAction:      StoreActionUpdated,
		},
		{
			name: "re-pulls when plainHTTP toggles",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
				Registry: &commonv1alpha1.RegistryConfig{
					PlainHTTP: new(true),
				},
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:            "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:          MediumOCI,
				Priority:        50,
				SourceSignature: computeOCISourceSignature(&commonv1alpha1.OCIArtifact{Image: testImage}, nil),
			},
			existingData:    "original rules",
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantOpts:        &puller.RegistryOptions{PlainHTTP: true},
			wantAction:      StoreActionUpdated,
		},
		{
			name: "re-pulls when insecureSkipVerify toggles",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
				Registry: &commonv1alpha1.RegistryConfig{
					TLS: &commonv1alpha1.TLSConfig{InsecureSkipVerify: true},
				},
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:            "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:          MediumOCI,
				Priority:        50,
				SourceSignature: computeOCISourceSignature(&commonv1alpha1.OCIArtifact{Image: testImage}, nil),
			},
			existingData:    "original rules",
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantOpts:        &puller.RegistryOptions{InsecureSkipVerify: true},
			wantAction:      StoreActionUpdated,
		},
		{
			name: "re-pulls when auth secret reference name changes",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
				Registry: &commonv1alpha1.RegistryConfig{
					Auth: &commonv1alpha1.RegistryAuth{
						SecretRef: &commonv1alpha1.SecretRef{Name: "new-pull-secret"},
					},
				},
			},
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "new-pull-secret", Namespace: testNamespace},
					Data: map[string][]byte{
						commonv1alpha1.SecretUsernameKey: []byte("u"),
						commonv1alpha1.SecretPasswordKey: []byte("p"),
					},
				},
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
				SourceSignature: computeOCISourceSignature(&commonv1alpha1.OCIArtifact{
					Image: testImage,
					Registry: &commonv1alpha1.RegistryConfig{
						Auth: &commonv1alpha1.RegistryAuth{
							SecretRef: &commonv1alpha1.SecretRef{Name: "old-pull-secret"},
						},
					},
				}, nil),
			},
			existingData:    "original rules",
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantAction:      StoreActionUpdated,
		},
		{
			name: "re-pulls when auth secret data rotates",
			artifact: &commonv1alpha1.OCIArtifact{
				Image: testImage,
				Registry: &commonv1alpha1.RegistryConfig{
					Auth: &commonv1alpha1.RegistryAuth{
						SecretRef: &commonv1alpha1.SecretRef{Name: "rotating-secret"},
					},
				},
			},
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "rotating-secret", Namespace: testNamespace},
					Data: map[string][]byte{
						commonv1alpha1.SecretUsernameKey: []byte("u"),
						commonv1alpha1.SecretPasswordKey: []byte("rotated-password"),
					},
				},
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
				SourceSignature: computeOCISourceSignature(&commonv1alpha1.OCIArtifact{
					Image: testImage,
					Registry: &commonv1alpha1.RegistryConfig{
						Auth: &commonv1alpha1.RegistryAuth{
							SecretRef: &commonv1alpha1.SecretRef{Name: "rotating-secret"},
						},
					},
				}, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "rotating-secret", Namespace: testNamespace},
					Data: map[string][]byte{
						commonv1alpha1.SecretUsernameKey: []byte("u"),
						commonv1alpha1.SecretPasswordKey: []byte("pre-rotation-password"),
					},
				}),
			},
			existingData:    "original rules",
			pullerResult:    &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
			layerContent:    validLayer,
			wantPullCalls:   1,
			wantWriteCalls:  1,
			wantRenameCalls: 1,
			wantAction:      StoreActionUpdated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			clientBuilder := fake.NewClientBuilder().WithScheme(scheme)
			for _, obj := range tt.objects {
				clientBuilder = clientBuilder.WithObjects(obj)
			}
			fakeClient := clientBuilder.Build()
			tmpDir := t.TempDir()

			mockFS := filesystem.NewMockFileSystem()
			mockFS.RenameErr = tt.fsRenameErr
			mockFS.StatErr = tt.fsStatErr
			mockFS.RemoveErr = tt.fsRemoveErr
			mockFS.WriteErr = tt.fsWriteErr

			mockPuller := &puller.MockOCIPuller{
				Result:         tt.pullerResult,
				PullErr:        tt.pullerErr,
				AllowNilResult: tt.allowNilResult,
			}
			if tt.layerContent != nil {
				mockPuller.LayerContent = tt.layerContent(t)
			}

			manager := NewManagerWithOptions(fakeClient, testNamespace,
				WithFS(mockFS),
				WithRulesfileDir(tmpDir),
				WithOCIPuller(mockPuller),
			)

			if tt.existingFile != nil {
				if tt.existingFile.Medium == MediumOCI && tt.artifactType != "" {
					tt.existingFile.Path = manager.Path(testArtifactName, tt.existingFile.Priority, MediumOCI, tt.artifactType)
				}
				manager.files[testArtifactName] = []File{*tt.existingFile}
				if tt.existingData != "" {
					mockFS.Files[tt.existingFile.Path] = []byte(tt.existingData)
				}
			}

			ctx := context.Background()
			action, err := manager.StoreFromOCI(ctx, testArtifactName, tt.priority, tt.artifactType, tt.artifact)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
			} else {
				require.NoError(t, err)
			}

			if tt.wantAction != "" {
				assert.Equal(t, tt.wantAction, action)
			}
			assert.Len(t, mockPuller.PullCalls, tt.wantPullCalls)
			if tt.wantOpts != nil && len(mockPuller.PullCalls) > 0 {
				assert.Equal(t, tt.wantOpts, mockPuller.PullCalls[0].Opts)
			}
			assert.Len(t, mockFS.WriteCalls, tt.wantWriteCalls)
			assert.Len(t, mockFS.RenameCalls, tt.wantRenameCalls)
			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveCalls)

			if tt.wantFile != nil {
				file := manager.getArtifactFile(testArtifactName, tt.wantFile.Medium)
				require.NotNil(t, file)
				assert.Equal(t, filepath.Base(tt.wantFile.Path), filepath.Base(file.Path))
				assert.Equal(t, tt.wantFile.Priority, file.Priority)
			}
			if tt.wantFileContent != "" {
				path := manager.Path(testArtifactName, tt.priority, MediumOCI, tt.artifactType)
				data, ok := mockFS.Files[path]
				require.True(t, ok, "expected final file %q to exist", path)
				assert.Equal(t, tt.wantFileContent, string(data))
			}
		})
	}
}

func TestStoreFromOCI_TagChangeTriggersRePull(t *testing.T) {
	const (
		testNamespace    = "test-namespace"
		testArtifactName = "test-rules"
	)

	scheme := createTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	tmpDir := t.TempDir()

	realFS := filesystem.NewOSFileSystem()
	layerV1, err := puller.MakeTarGz("rules.yaml", []byte("v1-rules-content"))
	require.NoError(t, err)
	layerV2, err := puller.MakeTarGz("rules.yaml", []byte("v2-rules-content"))
	require.NoError(t, err)

	mockPuller := &puller.MockOCIPuller{
		Result:       &puller.RegistryResult{Filename: "falco-rules.tar.gz", Type: puller.Rulesfile},
		LayerContent: layerV1,
	}

	manager := NewManagerWithOptions(fakeClient, testNamespace,
		WithFS(realFS),
		WithRulesfileDir(tmpDir),
		WithOCIPuller(mockPuller),
	)

	ctx := context.Background()

	artifactV1 := &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{
			Repository: "falcosecurity/rules/falco-rules",
			Tag:        "v1",
		},
	}

	action, err := manager.StoreFromOCI(ctx, testArtifactName, 50, TypeRulesfile, artifactV1)
	require.NoError(t, err)
	assert.Equal(t, StoreActionAdded, action)
	require.Len(t, mockPuller.PullCalls, 1)
	assert.Contains(t, mockPuller.PullCalls[0].Ref, ":v1")

	action, err = manager.StoreFromOCI(ctx, testArtifactName, 50, TypeRulesfile, artifactV1)
	require.NoError(t, err)
	assert.Equal(t, StoreActionUnchanged, action)
	assert.Len(t, mockPuller.PullCalls, 1, "spec unchanged: must not pull again")

	artifactV2 := &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{
			Repository: "falcosecurity/rules/falco-rules",
			Tag:        "v2",
		},
	}
	mockPuller.LayerContent = layerV2
	action, err = manager.StoreFromOCI(ctx, testArtifactName, 50, TypeRulesfile, artifactV2)
	require.NoError(t, err)
	assert.Equal(t, StoreActionUpdated, action)
	require.Len(t, mockPuller.PullCalls, 2, "tag changed: must re-pull")
	assert.Contains(t, mockPuller.PullCalls[1].Ref, ":v2")

	stored := manager.getArtifactFile(testArtifactName, MediumOCI)
	require.NotNil(t, stored)
	expectedSig := computeOCISourceSignature(artifactV2, nil)
	assert.Equal(t, expectedSig, stored.SourceSignature, "cache entry must carry the new source signature")

	action, err = manager.StoreFromOCI(ctx, testArtifactName, 50, TypeRulesfile, artifactV2)
	require.NoError(t, err)
	assert.Equal(t, StoreActionUnchanged, action)
	assert.Len(t, mockPuller.PullCalls, 2, "spec stable on v2: must not pull again")
}

func TestStoreFromOCI_TagAndPriorityChange_RemovesOldPath(t *testing.T) {
	const (
		testNamespace = "test-namespace"
		artifactName  = "test-rules"
	)

	scheme := createTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	tmpDir := t.TempDir()
	realFS := filesystem.NewOSFileSystem()

	layerV1, err := puller.MakeTarGz("rules.yaml", []byte("v1-content"))
	require.NoError(t, err)
	layerV2, err := puller.MakeTarGz("rules.yaml", []byte("v2-content"))
	require.NoError(t, err)

	mockPuller := &puller.MockOCIPuller{
		Result:       &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
		LayerContent: layerV1,
	}
	manager := NewManagerWithOptions(fakeClient, testNamespace,
		WithFS(realFS),
		WithRulesfileDir(tmpDir),
		WithOCIPuller(mockPuller),
	)
	ctx := context.Background()

	artifactV1 := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "v1"}}
	_, err = manager.StoreFromOCI(ctx, artifactName, 50, TypeRulesfile, artifactV1)
	require.NoError(t, err)
	oldPath := manager.Path(artifactName, 50, MediumOCI, TypeRulesfile)
	require.FileExists(t, oldPath)

	mockPuller.LayerContent = layerV2
	artifactV2 := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "v2"}}
	action, err := manager.StoreFromOCI(ctx, artifactName, 60, TypeRulesfile, artifactV2)
	require.NoError(t, err)
	assert.Equal(t, StoreActionUpdated, action)

	newPath := manager.Path(artifactName, 60, MediumOCI, TypeRulesfile)
	require.FileExists(t, newPath)
	require.NoFileExists(t, oldPath, "old artifact path must be removed when priority changes alongside the signature")

	stored := manager.getArtifactFile(artifactName, MediumOCI)
	require.NotNil(t, stored)
	assert.Equal(t, newPath, stored.Path)
	assert.Equal(t, int32(60), stored.Priority)
}

func TestStoreFromOCI_PullFailureAfterDrift_PreservesOldFileAndCache(t *testing.T) {
	const (
		testNamespace = "test-namespace"
		artifactName  = "test-rules"
	)

	scheme := createTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	tmpDir := t.TempDir()
	realFS := filesystem.NewOSFileSystem()

	layerV1, err := puller.MakeTarGz("rules.yaml", []byte("v1-content"))
	require.NoError(t, err)
	mockPuller := &puller.MockOCIPuller{
		Result:       &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
		LayerContent: layerV1,
	}
	manager := NewManagerWithOptions(fakeClient, testNamespace,
		WithFS(realFS),
		WithRulesfileDir(tmpDir),
		WithOCIPuller(mockPuller),
	)
	ctx := context.Background()

	artifactV1 := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "v1"}}
	_, err = manager.StoreFromOCI(ctx, artifactName, 50, TypeRulesfile, artifactV1)
	require.NoError(t, err)
	path := manager.Path(artifactName, 50, MediumOCI, TypeRulesfile)
	require.FileExists(t, path)

	sigBefore := manager.getArtifactFile(artifactName, MediumOCI).SourceSignature

	mockPuller.PullErr = fmt.Errorf("registry unavailable")
	artifactV2 := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "v2"}}
	action, err := manager.StoreFromOCI(ctx, artifactName, 50, TypeRulesfile, artifactV2)
	require.Error(t, err)
	assert.Equal(t, StoreActionNone, action)

	require.FileExists(t, path, "previous artifact must remain on disk on pull failure")
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "v1-content", string(contents))

	stored := manager.getArtifactFile(artifactName, MediumOCI)
	require.NotNil(t, stored, "cache entry for previous artifact must remain after pull failure")
	assert.Equal(t, sigBefore, stored.SourceSignature)
}

func TestStoreFromOCI_RetryAfterPullFailure_Converges(t *testing.T) {
	const (
		testNamespace = "test-namespace"
		artifactName  = "test-rules"
	)

	scheme := createTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	tmpDir := t.TempDir()
	realFS := filesystem.NewOSFileSystem()

	layerV1, err := puller.MakeTarGz("rules.yaml", []byte("v1-content"))
	require.NoError(t, err)
	layerV2, err := puller.MakeTarGz("rules.yaml", []byte("v2-content"))
	require.NoError(t, err)

	mockPuller := &puller.MockOCIPuller{
		Result:       &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
		LayerContent: layerV1,
	}
	manager := NewManagerWithOptions(fakeClient, testNamespace,
		WithFS(realFS),
		WithRulesfileDir(tmpDir),
		WithOCIPuller(mockPuller),
	)
	ctx := context.Background()

	artifactV1 := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "v1"}}
	_, err = manager.StoreFromOCI(ctx, artifactName, 50, TypeRulesfile, artifactV1)
	require.NoError(t, err)
	oldPath := manager.Path(artifactName, 50, MediumOCI, TypeRulesfile)

	artifactV2 := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "v2"}}

	mockPuller.PullErr = fmt.Errorf("transient registry error")
	_, err = manager.StoreFromOCI(ctx, artifactName, 60, TypeRulesfile, artifactV2)
	require.Error(t, err)
	require.FileExists(t, oldPath)

	mockPuller.PullErr = nil
	mockPuller.LayerContent = layerV2
	action, err := manager.StoreFromOCI(ctx, artifactName, 60, TypeRulesfile, artifactV2)
	require.NoError(t, err)
	assert.Equal(t, StoreActionUpdated, action)

	newPath := manager.Path(artifactName, 60, MediumOCI, TypeRulesfile)
	require.FileExists(t, newPath)
	require.NoFileExists(t, oldPath, "old path must be removed after the successful retry")
}

func TestStoreFromOCI_OldPathRemoveFailure_RollsBackNewPathAndLeavesCacheUnchanged(t *testing.T) {
	const (
		testNamespace = "test-namespace"
		artifactName  = "test-rules"
	)

	scheme := createTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	tmpDir := t.TempDir()
	mockFS := filesystem.NewMockFileSystem()

	layerV1, err := puller.MakeTarGz("rules.yaml", []byte("v1-content"))
	require.NoError(t, err)
	layerV2, err := puller.MakeTarGz("rules.yaml", []byte("v2-content"))
	require.NoError(t, err)

	mockPuller := &puller.MockOCIPuller{
		Result:       &puller.RegistryResult{Filename: "rules.tar.gz", Type: puller.Rulesfile},
		LayerContent: layerV1,
	}
	manager := NewManagerWithOptions(fakeClient, testNamespace,
		WithFS(mockFS),
		WithRulesfileDir(tmpDir),
		WithOCIPuller(mockPuller),
	)
	ctx := context.Background()

	artifactV1 := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "v1"}}
	_, err = manager.StoreFromOCI(ctx, artifactName, 50, TypeRulesfile, artifactV1)
	require.NoError(t, err)
	oldPath := manager.Path(artifactName, 50, MediumOCI, TypeRulesfile)
	sigBefore := manager.getArtifactFile(artifactName, MediumOCI).SourceSignature

	mockPuller.LayerContent = layerV2
	mockFS.RemoveErrFor = map[string]error{oldPath: fmt.Errorf("device busy")}

	artifactV2 := &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "repo/rules", Tag: "v2"}}
	action, err := manager.StoreFromOCI(ctx, artifactName, 60, TypeRulesfile, artifactV2)
	require.Error(t, err)
	assert.Equal(t, StoreActionNone, action)
	assert.Contains(t, err.Error(), "device busy")

	stored := manager.getArtifactFile(artifactName, MediumOCI)
	require.NotNil(t, stored, "cache entry must be preserved when old path removal fails")
	assert.Equal(t, sigBefore, stored.SourceSignature, "cache must still point to the previous artifact")
	assert.Equal(t, oldPath, stored.Path)

	assert.Contains(t, mockFS.Files, oldPath, "old artifact must still be on disk after a failed Remove")
	newPath := manager.Path(artifactName, 60, MediumOCI, TypeRulesfile)
	assert.NotContains(t, mockFS.Files, newPath, "new artifact must be rolled back when the old path cannot be removed")
}

func TestCheckReferenceResolution(t *testing.T) {
	const testNamespace = "test-namespace"

	tests := []struct {
		name       string
		objects    []client.Object
		lookupName string
		wantErr    bool
	}{
		{
			name: "returns nil when resource exists",
			objects: []client.Object{
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: testNamespace}},
			},
			lookupName: "my-secret",
			wantErr:    false,
		},
		{
			name:       "returns error when resource does not exist",
			lookupName: "non-existent",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			clientBuilder := fake.NewClientBuilder().WithScheme(scheme)
			for _, obj := range tt.objects {
				clientBuilder = clientBuilder.WithObjects(obj)
			}
			manager := NewManager(clientBuilder.Build(), testNamespace)

			err := manager.CheckReferenceResolution(context.Background(), testNamespace, tt.lookupName, &corev1.Secret{})
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
