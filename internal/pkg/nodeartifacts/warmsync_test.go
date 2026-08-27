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

package nodeartifacts_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

func controllerRef(kind, name string) metav1.OwnerReference {
	t := true
	return metav1.OwnerReference{
		APIVersion: artifactv1alpha1.GroupVersion.String(),
		Kind:       kind,
		Name:       name,
		Controller: &t,
	}
}

func newWarmSyncTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	return s
}

func TestWarmSync_PopulatesFromExistingArtifactNodes(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "ns"},
	}
	pluginNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "plugin--container--minikube",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Plugin", "container")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/x", Medium: "oci"}},
		},
	}
	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
		Status: artifactv1alpha1.RulesfileStatus{
			ArtifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
			},
		},
	}
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "rulesfile--my-rules--minikube",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/y", Medium: "oci"}},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(plugin, pluginNode, rulesfile, rulesfileNode).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	store := &artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	// After warm sync, removing "container" must be blocked: the Rulesfile's requirement and the
	// Plugin's provides were both registered from durable status.
	err := mgr.RemovePluginConfigByName(context.Background(), &artifact.Fetcher{}, "container", "container")
	require.Error(t, err)
}

// TestWarmSync_IgnoresOtherNodes verifies ArtifactNodes that exist only on a different node are
// excluded from this node's dependency registry.
func TestWarmSync_IgnoresOtherNodes(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "ns"},
	}
	pluginNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "plugin--container--other-node",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "other-node"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Plugin", "container")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "other-node"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/x", Medium: "oci"}},
		},
	}
	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
		Status: artifactv1alpha1.RulesfileStatus{
			ArtifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
			},
		},
	}
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "rulesfile--my-rules--other-node",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "other-node"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "other-node"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/y", Medium: "oci"}},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(plugin, pluginNode, rulesfile, rulesfileNode).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	store := &artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))

	// Warm-syncing "minikube", which has no ArtifactNodes of its own, must not pick up
	// "other-node"'s entries.
	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	require.NoError(t, mgr.RemovePluginConfigByName(context.Background(), &artifact.Fetcher{}, "container", "container"))
}

func TestWarmSync_SkipsNodesBeingDeleted(t *testing.T) {
	sch := newWarmSyncTestScheme(t)
	now := metav1.Now()
	plugin := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "ns"},
	}
	pluginNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "plugin--container--minikube",
			Namespace:         "ns",
			Labels:            map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences:   []metav1.OwnerReference{controllerRef("Plugin", "container")},
			DeletionTimestamp: &now,
			Finalizers:        []string{"keep-alive-for-test"},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/x", Medium: "oci"}},
		},
	}
	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
		Status: artifactv1alpha1.RulesfileStatus{
			ArtifactMeta: &commonv1alpha1.ArtifactMeta{
				Dependencies: []commonv1alpha1.ArtifactMetaDependency{{Name: "container", Version: "0.4.0"}},
			},
		},
	}
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "rulesfile--my-rules--minikube",
			Namespace:         "ns",
			Labels:            map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences:   []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
			DeletionTimestamp: &now,
			Finalizers:        []string{"keep-alive-for-test"},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{{Path: "/y", Medium: "oci"}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(sch).WithObjects(plugin, pluginNode, rulesfile, rulesfileNode).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	store := &artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	// Both nodes are being deleted, so neither the Plugin's provides nor the Rulesfile's
	// requires should have been registered; removal must be allowed.
	require.NoError(t, mgr.RemovePluginConfigByName(context.Background(), &artifact.Fetcher{}, "container", "container"))
}
