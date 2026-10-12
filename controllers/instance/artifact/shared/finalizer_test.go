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

package shared_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/instance/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestReconcileInUseFinalizer(t *testing.T) {
	for _, tt := range []struct {
		name          string
		hasOCI        bool
		nodesInUse    bool
		failCleanup   bool
		wantFinalizer bool
	}{
		{name: "cache ownership survives last node", hasOCI: true, wantFinalizer: true},
		{name: "removed source releases cache and finalizer"},
		{name: "nodes still require finalizer", nodesInUse: true, wantFinalizer: true},
		{name: "failed cleanup retains ownership", failCleanup: true, wantFinalizer: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			meta := metav1.ObjectMeta{
				Name: "artifact", Namespace: "default",
				Finalizers: []string{controllerhelper.NodeObjectsInUseFinalizer, testutil.TestForeignFinalizer},
			}
			parent := &artifactv1alpha1.Rulesfile{ObjectMeta: meta}
			if tt.hasOCI {
				parent.Spec.OCIArtifact = &commonv1alpha1.OCIArtifact{
					Image: commonv1alpha1.ImageSpec{Repository: "example.org/artifact", Tag: "latest"},
				}
			}
			cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(parent).Build()
			dir := t.TempDir()
			cache := artifactcache.NewCache(dir)
			require.NoError(t, cache.Load())
			blobPath := filepath.Join(dir, "blobs", "owned")
			require.NoError(t, cache.Store(blobPath, []byte("blob"), 0o644))
			require.NoError(t, cache.Set(string(artifact.KindRulesfile), meta.Namespace, meta.Name, "", blobPath))
			if tt.failCleanup {
				require.NoError(t, os.Mkdir(filepath.Join(dir, "index.json.tmp"), 0o755))
			}
			a := shared.Aggregation[*artifactv1alpha1.Rulesfile]{
				Client: cl,
				Kind:   artifact.KindRulesfile,
				Cache:  cache,
			}

			err := shared.ReconcileInUseFinalizer(ctx, a, parent, tt.nodesInUse)
			if tt.failCleanup {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			got := &artifactv1alpha1.Rulesfile{}
			require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(parent), got))
			assert.Equal(t, tt.wantFinalizer, controllerutil.ContainsFinalizer(got, controllerhelper.NodeObjectsInUseFinalizer))
			assert.Contains(t, got.GetFinalizers(), testutil.TestForeignFinalizer)
			_, owned := cache.Lookup(string(artifact.KindRulesfile), meta.Namespace, meta.Name, "")
			assert.Equal(t, tt.hasOCI || tt.failCleanup, owned)
		})
	}
}

// A kind with no OCI source never touches the cache: only the nodes decide the finalizer.
func TestReconcileInUseFinalizer_KindWithoutOCISource(t *testing.T) {
	ctx := context.Background()
	parent := &artifactv1alpha1.Config{ObjectMeta: metav1.ObjectMeta{
		Name: "artifact", Namespace: "default", Finalizers: []string{controllerhelper.NodeObjectsInUseFinalizer},
	}}
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(parent).Build()
	a := shared.Aggregation[*artifactv1alpha1.Config]{Client: cl, Kind: artifact.KindConfig}

	require.NoError(t, shared.ReconcileInUseFinalizer(ctx, a, parent, false))

	got := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(parent), got))
	assert.False(t, controllerutil.ContainsFinalizer(got, controllerhelper.NodeObjectsInUseFinalizer))
}
