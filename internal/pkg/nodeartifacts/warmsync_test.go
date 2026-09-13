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
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

func sha256hexForTest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

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

	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

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

	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	// Warm-syncing "minikube", which has no ArtifactNodes of its own, must not pick up
	// "other-node"'s entries.
	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	require.NoError(t, mgr.RemovePluginConfigByName(context.Background(), &artifact.Fetcher{}, "container", "container"))
}

// TestWarmSync_SeedsInstalledCacheFromDiskEvenWhenStatusDoesNotKnowAboutIt simulates the crash
// window where a file was written to disk but the process died before the status patch
// recording it landed: status is missing the inline medium's entry even though the file exists
// on disk. WarmSync must seed the manager's cache from disk ground truth regardless, since that
// cache (never status) is what every later filesystem decision reads from.
func TestWarmSync_SeedsInstalledCacheFromDiskEvenWhenStatusDoesNotKnowAboutIt(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
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
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{
				{Path: "/rulesfiles/50-01-my-rules-oci.yaml", Medium: "oci", Priority: 50, ContentHash: "oci-hash"},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(rulesfile, rulesfileNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-my-rules-oci.yaml"] = []byte("oci content")
	fsys.Files["/rulesfiles/50-03-my-rules-inline.yaml"] = []byte("inline content")
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "my-rules"}
	inlineEntry := mgr.FindInstalled(key, artifact.MediumInline)
	require.NotNil(t, inlineEntry, "the cache must reflect the file already on disk, regardless of what status says")
	assert.Equal(t, "/rulesfiles/50-03-my-rules-inline.yaml", inlineEntry.Path)

	// Status itself is never touched by WarmSync: it stays exactly as it was on disk/durably
	// stored, since it's read only by kubectl, never by a filesystem decision.
	got := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rulesfileNode), got))
	assert.Nil(t, artifact.FindInstalled(got.Status.InstalledArtifacts, artifact.MediumInline))

	// The file itself must not have been touched (still present, unmodified).
	assert.Equal(t, []byte("inline content"), fsys.Files["/rulesfiles/50-03-my-rules-inline.yaml"])
}

// TestWarmSync_RemovesOrphanedFilesWithNoArtifactNode covers a name with files on disk but no
// ArtifactNode at all for this node (e.g. its parent CR was deleted and fully garbage collected
// while this node had no durable status recording those files, or before this scan existed).
// Nothing will ever ask about that name again, so WarmSync must remove it immediately.
func TestWarmSync_RemovesOrphanedFilesWithNoArtifactNode(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-orphaned-oci.yaml"] = []byte("stray content")
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	_, exists := fsys.Files["/rulesfiles/50-01-orphaned-oci.yaml"]
	assert.False(t, exists, "orphaned file with no matching ArtifactNode must be removed")
}

// TestWarmSync_NeverPatchesStatus verifies WarmSync never writes to any ArtifactNode's status,
// since the cache it seeds (not status) is now the sole source filesystem decisions read from;
// status is a write-through mirror later reconciles maintain for observability only.
func TestWarmSync_NeverPatchesStatus(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
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
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{
				{Path: "/rulesfiles/50-01-my-rules-oci.yaml", Medium: "oci", Priority: 50, ContentHash: sha256hexForTest("oci content")},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(rulesfile, rulesfileNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	got := &artifactv1alpha1.ArtifactNode{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rulesfileNode), got))
	beforeRV := got.ResourceVersion

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-my-rules-oci.yaml"] = []byte("oci content")
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(rulesfileNode), got))
	assert.Equal(t, beforeRV, got.ResourceVersion, "no patch should be issued when disk already agrees with status")
}

// TestWarmSync_RecoversSpecHashFromStatusWhenContentMatches reproduces a real regression: cache
// entries seeded from disk never carried SpecHash (ScanAll can only recover ContentHash from file
// bytes), so every OCI-sourced artifact looked like its parent spec had changed on the first
// reconcile after every sidecar restart, forcing a needless re-fetch from the OCI artifact server.
// When status still describes the exact same on-disk content (matching ContentHash), WarmSync
// must recover SpecHash from it instead of leaving the seeded entry blank.
func TestWarmSync_RecoversSpecHashFromStatusWhenContentMatches(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	rulesfile := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rules", Namespace: "ns"},
	}
	ociContentHash := sha256hexForTest("oci content")
	rulesfileNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "rulesfile--my-rules--minikube",
			Namespace:       "ns",
			Labels:          map[string]string{"artifact.falcosecurity.dev/node": "minikube"},
			OwnerReferences: []metav1.OwnerReference{controllerRef("Rulesfile", "my-rules")},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: "minikube"},
		Status: artifactv1alpha1.ArtifactNodeStatus{
			InstalledArtifacts: []artifactv1alpha1.InstalledArtifact{
				{Path: "/rulesfiles/50-01-my-rules-oci.yaml", Medium: "oci", Priority: 50, ContentHash: ociContentHash, SpecHash: "spec-abc"},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithObjects(rulesfile, rulesfileNode).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/rulesfiles/50-01-my-rules-oci.yaml"] = []byte("oci content")
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	key := nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Namespace: "ns", Name: "my-rules"}
	ociEntry := mgr.FindInstalled(key, artifact.MediumOCI)
	require.NotNil(t, ociEntry)
	assert.Equal(t, "spec-abc", ociEntry.SpecHash,
		"SpecHash must be recovered from status when content on disk still matches it")
}

// TestWarmSync_FailsWhenScanAllErrors reproduces a real bug: a ScanAll error for one artifact
// Kind used to be logged and swallowed, letting WarmSync report success with that Kind's cache
// left completely unseeded. A later handleDeletion for an artifact of that Kind would then read
// nothing from the cache and release the finalizer without cleaning up whatever is actually on
// disk. WarmSync must instead fail loudly, since WarmSyncRunnable.Warmup surfaces its error by
// failing manager startup (see warmsync_runnable.go) rather than proceeding half-seeded.
func TestWarmSync_FailsWhenScanAllErrors(t *testing.T) {
	sch := newWarmSyncTestScheme(t)

	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithStatusSubresource(&artifactv1alpha1.ArtifactNode{}).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	fsys := fsfake.NewMockFileSystem()
	fsys.Files["/plugins/json.so"] = []byte("plugin content")
	fsys.ReadErr = assert.AnError
	store := &artifact.LocalStore{FS: fsys, Dirs: artifact.ArtifactDirs{Rulesfile: "/rulesfiles", Plugin: "/plugins", Config: "/configs"}}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	err := nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube")

	require.Error(t, err, "a ScanAll failure must fail WarmSync instead of leaving that Kind's cache silently unseeded")
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

	store := &artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compatfake.NewMockVersionsFetcher(nil))

	require.NoError(t, nodeartifacts.WarmSync(context.Background(), cl, mgr, "ns", "minikube"))

	// Both nodes are being deleted, so neither the Plugin's provides nor the Rulesfile's
	// requires should have been registered; removal must be allowed.
	require.NoError(t, mgr.RemovePluginConfigByName(context.Background(), &artifact.Fetcher{}, "container", "container"))
}
