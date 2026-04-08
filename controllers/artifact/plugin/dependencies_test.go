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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"oras.land/oras-go/v2/registry/remote/auth"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

type inspectOnlyPuller struct {
	inspectResults map[string]*puller.RegistryResult
}

func (p *inspectOnlyPuller) Pull(context.Context, string, string, string, string, auth.CredentialFunc, *puller.RegistryOptions) (*puller.RegistryResult, error) {
	return nil, fmt.Errorf("unexpected pull call")
}

func (p *inspectOnlyPuller) Inspect(_ context.Context, ref, _, _ string, _ auth.CredentialFunc, _ *puller.RegistryOptions) (*puller.RegistryResult, error) {
	res, ok := p.inspectResults[ref]
	if !ok {
		return nil, fmt.Errorf("not found: %s", ref)
	}
	return res, nil
}

func TestEnsurePluginDependencies(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		Build()

	root := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root",
			Namespace: testutil.TestNamespace,
		},
		Spec: artifactv1alpha1.PluginSpec{
			OCIArtifact: &commonv1alpha1.OCIArtifact{
				Image: commonv1alpha1.ImageSpec{
					Repository: "falcosecurity/plugins/plugin/root",
					Tag:        "1.0.0",
				},
				Registry: &commonv1alpha1.RegistryConfig{Name: "ghcr.io"},
			},
		},
	}
	root.UID = "uid-root"

	rootRef := artifact.ResolveReference(root.Spec.OCIArtifact)
	depPluginRef := "ghcr.io/falcosecurity/plugins/plugin/json:0.7.3"
	depRulesRef := "ghcr.io/falcosecurity/plugins/ruleset/k8saudit:0.16.1"

	am := artifact.NewManagerWithOptions(cl, testutil.TestNamespace,
		artifact.WithFS(filesystem.NewMockFileSystem()),
		artifact.WithOCIPuller(&inspectOnlyPuller{
			inspectResults: map[string]*puller.RegistryResult{
				rootRef: {
					Type: puller.Plugin,
					Config: puller.ArtifactConfig{
						Name:    "root",
						Version: "1.0.0",
						Dependencies: []puller.ArtifactDependency{
							{Name: "json", Version: "0.7.3"},
							{Name: "k8saudit-rules", Version: "0.16.1"},
						},
					},
				},
				depPluginRef: {
					Type: puller.Plugin,
					Config: puller.ArtifactConfig{
						Name:    "json",
						Version: "0.7.3",
					},
				},
				depRulesRef: {
					Type: puller.Rulesfile,
					Config: puller.ArtifactConfig{
						Name:    "k8saudit-rules",
						Version: "0.16.1",
					},
				},
			},
		}),
	)

	r := &PluginReconciler{
		Client:          cl,
		Scheme:          s,
		recorder:        events.NewFakeRecorder(10),
		artifactManager: am,
		PluginsConfig:   &PluginsConfig{},
		nodeName:        testutil.TestNodeName,
		crToConfigName:  make(map[string]string),
	}

	require.NoError(t, r.ensurePluginDependencies(context.Background(), root))

	depPluginName := dependencyResourceName(puller.Plugin, "json", depPluginRef)
	depRulesName := dependencyResourceName(puller.Rulesfile, "k8saudit-rules", depRulesRef)

	gotPlugin := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: depPluginName, Namespace: testutil.TestNamespace}, gotPlugin))
	assert.Equal(t, dependencyManagedLabelValue, gotPlugin.Labels[dependencyManagedLabelKey])
	require.NotNil(t, gotPlugin.Spec.OCIArtifact)
	assert.Equal(t, "falcosecurity/plugins/plugin/json", gotPlugin.Spec.OCIArtifact.Image.Repository)
	assert.Equal(t, "0.7.3", gotPlugin.Spec.OCIArtifact.Image.Tag)
	require.NotNil(t, gotPlugin.Spec.Config)
	assert.Equal(t, "json", gotPlugin.Spec.Config.Name)
	assert.True(t, hasOwnerReference(gotPlugin, root))

	gotRulesfile := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Name: depRulesName, Namespace: testutil.TestNamespace}, gotRulesfile))
	assert.Equal(t, dependencyManagedLabelValue, gotRulesfile.Labels[dependencyManagedLabelKey])
	require.NotNil(t, gotRulesfile.Spec.OCIArtifact)
	assert.Equal(t, "falcosecurity/plugins/ruleset/k8saudit", gotRulesfile.Spec.OCIArtifact.Image.Repository)
	assert.Equal(t, "0.16.1", gotRulesfile.Spec.OCIArtifact.Image.Tag)
	assert.True(t, hasOwnerReference(gotRulesfile, root))
}

func TestEnsurePluginDependencies_CleansUpManagedDependencies(t *testing.T) {
	root := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root",
			Namespace: testutil.TestNamespace,
		},
	}
	root.UID = "uid-root"

	stalePluginName := "dep-plg-stale"
	sharedPluginName := "dep-plg-shared"
	staleRulesName := "dep-rul-stale"

	stalePlugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{
			Name:      stalePluginName,
			Namespace: testutil.TestNamespace,
			Labels: map[string]string{
				dependencyManagedLabelKey: dependencyManagedLabelValue,
			},
			OwnerReferences: []metav1.OwnerReference{dependencyOwnerReference(root)},
		},
	}
	sharedPlugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sharedPluginName,
			Namespace: testutil.TestNamespace,
			Labels: map[string]string{
				dependencyManagedLabelKey: dependencyManagedLabelValue,
			},
			OwnerReferences: []metav1.OwnerReference{
				dependencyOwnerReference(root),
				{
					APIVersion: "v1",
					Kind:       "ConfigMap",
					Name:       "other-owner",
					UID:        "uid-other",
				},
			},
		},
	}
	staleRules := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      staleRulesName,
			Namespace: testutil.TestNamespace,
			Labels: map[string]string{
				dependencyManagedLabelKey: dependencyManagedLabelValue,
			},
			OwnerReferences: []metav1.OwnerReference{dependencyOwnerReference(root)},
		},
	}

	r := newDependencyTestReconciler(t, root, stalePlugin, sharedPlugin, staleRules)
	require.NoError(t, r.ensurePluginDependencies(context.Background(), root))

	gotStalePlugin := &artifactv1alpha1.Plugin{}
	err := r.Client.Get(context.Background(), types.NamespacedName{Name: stalePluginName, Namespace: testutil.TestNamespace}, gotStalePlugin)
	require.Error(t, err)
	assert.True(t, k8serrors.IsNotFound(err))

	gotSharedPlugin := &artifactv1alpha1.Plugin{}
	require.NoError(t, r.Client.Get(context.Background(), types.NamespacedName{Name: sharedPluginName, Namespace: testutil.TestNamespace}, gotSharedPlugin))
	assert.False(t, hasOwnerReference(gotSharedPlugin, root))
	require.Len(t, gotSharedPlugin.GetOwnerReferences(), 1)
	assert.Equal(t, "ConfigMap", gotSharedPlugin.GetOwnerReferences()[0].Kind)

	gotStaleRules := &artifactv1alpha1.Rulesfile{}
	err = r.Client.Get(context.Background(), types.NamespacedName{Name: staleRulesName, Namespace: testutil.TestNamespace}, gotStaleRules)
	require.Error(t, err)
	assert.True(t, k8serrors.IsNotFound(err))
}

func TestResolveDependencyReference_UsesHeuristicCandidates(t *testing.T) {
	r := &PluginReconciler{}

	parentRef := "ghcr.io/falcosecurity/plugins/plugin/root:1.0.0"
	dependencyRef := "k8saudit-rules:0.16.1"

	var attempted []string
	expected := []string{
		"ghcr.io/falcosecurity/plugins/plugin/k8saudit-rules:0.16.1",
		"ghcr.io/falcosecurity/plugins/ruleset/k8saudit-rules:0.16.1",
		"ghcr.io/falcosecurity/plugins/ruleset/k8saudit:0.16.1",
	}

	resolved, err := r.resolveDependencyReference(parentRef, dependencyRef, func(ref string) (*puller.RegistryResult, error) {
		attempted = append(attempted, ref)
		if ref == expected[2] {
			return &puller.RegistryResult{
				Type: puller.Rulesfile,
				Config: puller.ArtifactConfig{
					Name:    "k8saudit-rules",
					Version: "0.16.1",
				},
			}, nil
		}
		return nil, fmt.Errorf("not found: %s", ref)
	})
	require.NoError(t, err)
	assert.Equal(t, expected[2], resolved)
	assert.Equal(t, expected, attempted)
}

func TestDependencyReferenceCandidates(t *testing.T) {
	tests := []struct {
		name      string
		parentRef string
		depName   string
		depVer    string
		want      []string
	}{
		{
			name:      "ruleset parent also tries plugin sibling",
			parentRef: "ghcr.io/falcosecurity/plugins/ruleset/aws:0.1.0",
			depName:   "cloudtrail",
			depVer:    "0.2.0",
			want: []string{
				"ghcr.io/falcosecurity/plugins/ruleset/cloudtrail:0.2.0",
				"ghcr.io/falcosecurity/plugins/plugin/cloudtrail:0.2.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dependencyReferenceCandidates(tt.parentRef, tt.depName, tt.depVer)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func newDependencyTestReconciler(t *testing.T, objects ...runtime.Object) *PluginReconciler {
	t.Helper()

	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithRuntimeObjects(objects...).
		Build()

	return &PluginReconciler{
		Client:         cl,
		Scheme:         s,
		recorder:       events.NewFakeRecorder(10),
		PluginsConfig:  &PluginsConfig{},
		nodeName:       testutil.TestNodeName,
		crToConfigName: make(map[string]string),
	}
}
