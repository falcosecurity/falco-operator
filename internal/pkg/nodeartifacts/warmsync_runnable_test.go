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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

func TestWarmSyncRunnable_Warmup_Succeeds(t *testing.T) {
	sch := newWarmSyncTestScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(sch).
		WithIndex(&artifactv1alpha1.ArtifactNode{}, index.ArtifactNodeNodeName, index.ArtifactNodeNodeNameIndexer).
		Build()

	store := &artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))

	r := nodeartifacts.NewWarmSyncRunnable(cl, mgr, "ns", "minikube")
	require.NoError(t, r.Warmup(context.Background()))
}

func TestWarmSyncRunnable_Warmup_WrapsError(t *testing.T) {
	// A scheme with no types registered makes the underlying WarmSync List fail immediately,
	// exercising Warmup's error-wrapping path.
	cl := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()

	store := &artifact.LocalStore{FS: filesystem.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}
	mgr := nodeartifacts.NewManager(store, compat.NewMockVersionsFetcher(nil))

	r := nodeartifacts.NewWarmSyncRunnable(cl, mgr, "ns", "minikube")
	err := r.Warmup(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "warm-sync node artifact manager")
}

func TestWarmSyncRunnable_Start_ReturnsOnCancel(t *testing.T) {
	r := nodeartifacts.NewWarmSyncRunnable(nil, nil, "", "")
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}
