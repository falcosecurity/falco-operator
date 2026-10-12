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

package envtest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

// The artifact operator's cache holds its own node's ArtifactNode and no other, and keeps holding it when its
// labels are removed: an object that dropped out of the cache would look deleted, and the artifact operator
// would remove everything installed on the node.
func TestIntegration_TheSidecarCacheSelectsItsArtifactNodeByName(t *testing.T) {
	ctx := t.Context()
	own := testutil.NewArtifactNode(testutil.TestNamespace, testutil.TestNodeName)
	own.Labels = controllerhelper.ArtifactNodeLabels(testutil.TestNodeName)
	create(t, context.Background(), own)
	create(t, context.Background(), testutil.NewArtifactNode(testutil.TestNamespace, "other-node"))

	c, err := cache.New(restConfig, cache.Options{
		Scheme:            k8sClient.Scheme(),
		DefaultNamespaces: map[string]cache.Config{testutil.TestNamespace: {}},
		ByObject: map[client.Object]cache.ByObject{
			&artifactv1alpha1.ArtifactNode{}: controllerhelper.SidecarArtifactNodeCache(testutil.TestNodeName),
		},
	})
	require.NoError(t, err)
	cacheCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = c.Start(cacheCtx) }()
	require.True(t, c.WaitForCacheSync(ctx))

	cached := func() []string {
		list := &artifactv1alpha1.ArtifactNodeList{}
		require.NoError(t, c.List(ctx, list))
		names := make([]string, 0, len(list.Items))
		for i := range list.Items {
			names = append(names, list.Items[i].Name)
		}
		return names
	}
	require.Eventually(t, func() bool { return len(cached()) == 1 }, 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, []string{testutil.TestNodeName}, cached(), "only the node's own ArtifactNode is cached")

	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(own), own))
	own.Labels = nil
	require.NoError(t, k8sClient.Update(ctx, own))
	require.Eventually(t, func() bool {
		got := &artifactv1alpha1.ArtifactNode{}
		return c.Get(ctx, client.ObjectKeyFromObject(own), got) == nil && len(got.Labels) == 0
	}, 5*time.Second, 20*time.Millisecond, "the cache must follow the unlabelled object, not drop it")
	assert.Equal(t, []string{testutil.TestNodeName}, cached())
}
