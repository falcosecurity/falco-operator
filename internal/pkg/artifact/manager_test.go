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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			manager := NewManager(fakeClient, tt.namespace)

			require.NotNil(t, manager)
			assert.NotNil(t, manager.files)
			assert.Equal(t, tt.namespace, manager.namespace)
			assert.NotNil(t, manager.client)
			assert.NotNil(t, manager.fs)
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
	}{
		{
			name: "successfully stores new artifact from ConfigMap",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigMapName,
					Namespace: testNamespace,
				},
				Data: map[string]string{
					testKey: testData,
				},
			},
			priority:        50,
			wantErr:         false,
			wantWriteCalls:  1,
			wantRemoveCalls: 0,
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
		},
		{
			name: "returns nil when rules.yaml key not found in ConfigMap",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigMapName,
					Namespace: testNamespace,
				},
				Data: map[string]string{
					"other-key": testData, // ConfigMap exists but doesn't have the required rules.yaml key
				},
			},
			priority:        50,
			wantErr:         false,
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
		},
		{
			name: "skips write when file content is unchanged",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigMapName,
					Namespace: testNamespace,
				},
				Data: map[string]string{
					testKey: testData,
				},
			},
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
		},
		{
			name: "updates file when content changes",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigMapName,
					Namespace: testNamespace,
				},
				Data: map[string]string{
					testKey: testData,
				},
			},
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
		},
		{
			name: "updates file when priority changes",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigMapName,
					Namespace: testNamespace,
				},
				Data: map[string]string{
					testKey: testData,
				},
			},
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
		},
		{
			name: "returns error when write fails",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigMapName,
					Namespace: testNamespace,
				},
				Data: map[string]string{
					testKey: testData,
				},
			},
			priority:        50,
			fsWriteErr:      fmt.Errorf("disk full"),
			wantErr:         true,
			wantErrMsg:      "disk full",
			wantWriteCalls:  1,
			wantRemoveCalls: 0,
		},
		{
			name: "returns error when Exists check fails",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigMapName,
					Namespace: testNamespace,
				},
				Data: map[string]string{
					testKey: testData,
				},
			},
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
		},
		{
			name: "returns error when ReadFile fails",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigMapName,
					Namespace: testNamespace,
				},
				Data: map[string]string{
					testKey: testData,
				},
			},
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
		},
		{
			name: "returns error when Remove fails during update",
			configMapRef: &commonv1alpha1.ConfigMapRef{
				Name: testConfigMapName,
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testConfigMapName,
					Namespace: testNamespace,
				},
				Data: map[string]string{
					testKey: testData,
				},
			},
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
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

			// Setup existing file if specified
			if tt.existingFile != nil {
				manager.files[testArtifactName] = []File{*tt.existingFile}
				if tt.existingData != "" {
					mockFS.Files[tt.existingFile.Path] = []byte(tt.existingData)
				}
			}

			ctx := context.Background()
			err := manager.StoreFromConfigMap(ctx, testArtifactName, testNamespace, tt.priority, tt.configMapRef, TypeRulesfile)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, mockFS.WriteCalls, tt.wantWriteCalls)
			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveCalls)
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
	}{
		{
			name:            "successfully stores new artifact from inline YAML",
			data:            ptr(testData),
			priority:        50,
			wantErr:         false,
			wantWriteCalls:  1,
			wantRemoveCalls: 0,
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
		},
		{
			name:            "does nothing when data is nil and no existing file",
			data:            nil,
			wantErr:         false,
			wantWriteCalls:  0,
			wantRemoveCalls: 0,
		},
		{
			name:     "skips write when file content is unchanged",
			data:     ptr(testData),
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
		},
		{
			name:     "updates file when content changes",
			data:     ptr(testData),
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
		},
		{
			name:     "updates file when priority changes",
			data:     ptr(testData),
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
		},
		{
			name:            "returns error when write fails",
			data:            ptr(testData),
			priority:        50,
			fsWriteErr:      fmt.Errorf("disk full"),
			wantErr:         true,
			wantErrMsg:      "disk full",
			wantWriteCalls:  1,
			wantRemoveCalls: 0,
		},
		{
			name:     "returns error when Exists check fails",
			data:     ptr(testData),
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
		},
		{
			name:     "returns error when ReadFile fails",
			data:     ptr(testData),
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
		},
		{
			name:     "returns error when Remove fails during update",
			data:     ptr(testData),
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
			err := manager.StoreFromInLineYaml(ctx, testArtifactName, tt.priority, tt.data, TypeRulesfile)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, mockFS.WriteCalls, tt.wantWriteCalls)
			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveCalls)
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
			name:         "config type",
			artifactName: "my-config",
			priority:     50,
			Medium:       MediumInline,
			artifactType: TypeConfig,
			wantContains: "50-my-config.yaml",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Path(tt.artifactName, tt.priority, tt.Medium, tt.artifactType)
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

func TestRemoveAllIgnoresNotExistError(t *testing.T) {
	const testNamespace = "test-namespace"

	scheme := createTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	mockFS := filesystem.NewMockFileSystem()
	// The file doesn't exist in the mock, so Remove will return os.ErrNotExist
	// RemoveAll should ignore this error

	manager := NewManagerWithOptions(fakeClient, testNamespace, WithFS(mockFS))
	manager.files["test-artifact"] = []File{
		{Path: "/etc/falco/rules.d/50-02-test-artifact-configmap.yaml", Medium: MediumConfigMap, Priority: 50},
	}
	// Note: we don't add the file to mockFS.files, so Remove will return os.ErrNotExist

	ctx := context.Background()
	err := manager.RemoveAll(ctx, "test-artifact")

	// Should not return error even though file doesn't exist
	require.NoError(t, err)
	assert.Len(t, mockFS.RemoveCalls, 1)
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

// ptr returns a pointer to the given string.
func ptr(s string) *string {
	return &s
}

func TestStoreFromOCI(t *testing.T) {
	const (
		testNamespace    = "test-namespace"
		testArtifactName = "test-artifact"
		testReference    = "ghcr.io/falcosecurity/rules/falco-rules:latest"
	)

	tests := []struct {
		name            string
		artifact        *commonv1alpha1.OCIArtifact
		priority        int32
		artifactType    Type
		existingFile    *File
		existingData    string
		pullerResult    *puller.RegistryResult
		pullerErr       error
		fsRenameErr     error
		fsStatErr       error
		fsOpenErr       error
		wantErr         bool
		wantErrMsg      string
		wantPullCalls   int
		wantRenameCalls int
		wantRemoveCalls int
	}{
		{
			name:     "removes artifact when artifact is nil",
			artifact: nil,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
			},
			wantErr:         false,
			wantPullCalls:   0,
			wantRenameCalls: 0,
			wantRemoveCalls: 1,
		},
		{
			name:            "does nothing when artifact is nil and no existing file",
			artifact:        nil,
			wantErr:         false,
			wantPullCalls:   0,
			wantRenameCalls: 0,
			wantRemoveCalls: 0,
		},
		{
			name: "returns error when artifact already stored but file not found on filesystem",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
			},
			// No existingData means file doesn't exist
			wantErr:         true,
			wantErrMsg:      "not found on filesystem",
			wantPullCalls:   0,
			wantRenameCalls: 0,
			wantRemoveCalls: 0,
		},
		{
			name: "renames file when priority changes",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
			},
			priority:     60,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
			},
			existingData:    "existing content",
			wantErr:         false,
			wantPullCalls:   0,
			wantRenameCalls: 1,
			wantRemoveCalls: 0,
		},
		{
			name: "skips pull when file already exists with same priority",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
			},
			existingData:    "existing content",
			wantErr:         false,
			wantPullCalls:   0,
			wantRenameCalls: 0,
			wantRemoveCalls: 0,
		},
		{
			name: "returns error when credentials getter fails",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
				PullSecret: &commonv1alpha1.OCIPullSecret{
					SecretName: "non-existent-secret",
				},
			},
			priority:        50,
			artifactType:    TypeRulesfile,
			wantErr:         true,
			wantErrMsg:      "failed to get pull secret",
			wantPullCalls:   0,
			wantRenameCalls: 0,
			wantRemoveCalls: 0,
		},
		{
			name: "returns error when puller fails",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
			},
			priority:        50,
			artifactType:    TypeRulesfile,
			pullerErr:       fmt.Errorf("registry unavailable"),
			wantErr:         true,
			wantErrMsg:      "registry unavailable",
			wantPullCalls:   1,
			wantRenameCalls: 0,
			wantRemoveCalls: 0,
		},
		{
			name: "returns error when rename fails during priority change",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
			},
			priority:     60,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
			},
			existingData:    "existing content",
			fsRenameErr:     fmt.Errorf("permission denied"),
			wantErr:         true,
			wantErrMsg:      "permission denied",
			wantPullCalls:   0,
			wantRenameCalls: 1,
			wantRemoveCalls: 0,
		},
		{
			name: "returns error when Exists check fails",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
			},
			priority:     50,
			artifactType: TypeRulesfile,
			existingFile: &File{
				Path:     "/etc/falco/rules.d/50-01-test-artifact-oci.yaml",
				Medium:   MediumOCI,
				Priority: 50,
			},
			fsStatErr:       fmt.Errorf("permission denied"),
			wantErr:         true,
			wantErrMsg:      "permission denied",
			wantPullCalls:   0,
			wantRenameCalls: 0,
			wantRemoveCalls: 0,
		},
		{
			name: "returns error when Open fails after successful pull",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
			},
			priority:     50,
			artifactType: TypeRulesfile,
			pullerResult: &puller.RegistryResult{
				Filename: "rules.tar.gz",
			},
			fsOpenErr:       fmt.Errorf("cannot open archive"),
			wantErr:         true,
			wantErrMsg:      "cannot open archive",
			wantPullCalls:   1,
			wantRenameCalls: 0,
			wantRemoveCalls: 0,
		},
		{
			name: "uses plugin directory for plugin artifact type",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
			},
			priority:     50,
			artifactType: TypePlugin,
			pullerResult: &puller.RegistryResult{
				Filename: "plugin.tar.gz",
			},
			fsOpenErr:       fmt.Errorf("cannot open archive"),
			wantErr:         true,
			wantErrMsg:      "cannot open archive",
			wantPullCalls:   1,
			wantRenameCalls: 0,
			wantRemoveCalls: 0,
		},
		{
			name: "uses empty directory for unknown artifact type",
			artifact: &commonv1alpha1.OCIArtifact{
				Reference: testReference,
			},
			priority:     50,
			artifactType: Type("unknown"),
			pullerResult: &puller.RegistryResult{
				Filename: "artifact.tar.gz",
			},
			fsOpenErr:       fmt.Errorf("cannot open archive"),
			wantErr:         true,
			wantErrMsg:      "cannot open archive",
			wantPullCalls:   1,
			wantRenameCalls: 0,
			wantRemoveCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := createTestScheme(t)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			mockFS := filesystem.NewMockFileSystem()
			mockFS.RenameErr = tt.fsRenameErr
			mockFS.StatErr = tt.fsStatErr
			mockFS.OpenErr = tt.fsOpenErr

			mockPuller := &puller.MockOCIPuller{
				Result:  tt.pullerResult,
				PullErr: tt.pullerErr,
			}

			manager := NewManagerWithOptions(
				fakeClient,
				testNamespace,
				WithFS(mockFS),
				WithOCIPuller(mockPuller),
			)

			// Setup existing file if specified
			if tt.existingFile != nil {
				manager.files[testArtifactName] = []File{*tt.existingFile}
				if tt.existingData != "" {
					mockFS.Files[tt.existingFile.Path] = []byte(tt.existingData)
				}
			}

			ctx := context.Background()
			err := manager.StoreFromOCI(ctx, testArtifactName, tt.priority, tt.artifactType, tt.artifact)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, mockPuller.PullCalls, tt.wantPullCalls)
			assert.Len(t, mockFS.RenameCalls, tt.wantRenameCalls)
			assert.Len(t, mockFS.RemoveCalls, tt.wantRemoveCalls)
		})
	}
}
