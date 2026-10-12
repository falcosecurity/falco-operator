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

// Package envtest holds the tests that run against a real API server (envtest): what the fake client does not
// reproduce faithfully, such as watches driving a manager, merge-patch semantics and resourceVersion bumps.
package envtest

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	compatfake "github.com/falcosecurity/falco-operator/internal/pkg/compat/fake"
	fsfake "github.com/falcosecurity/falco-operator/internal/pkg/filesystem/fake"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
	"github.com/falcosecurity/falco-operator/internal/testutil"
	"github.com/falcosecurity/falco-operator/internal/testutil/nodetest"
)

var (
	restConfig *rest.Config
	k8sClient  client.Client
)

func TestMain(m *testing.M) {
	cfg, cl, stop, err := testutil.StartEnvtestWithConfig(artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	if err != nil {
		ctrllog.Log.Error(err, "Failed to start envtest")
		os.Exit(1)
	}
	restConfig, k8sClient = cfg, cl
	code := m.Run()
	stop()
	os.Exit(code)
}

// create creates obj and deletes it, finalizers stripped, when the test ends.
func create[T client.Object](t *testing.T, ctx context.Context, obj T) T {
	t.Helper()
	require.NoError(t, k8sClient.Create(ctx, obj))
	t.Cleanup(func() { testutil.CleanupObject(t, ctx, k8sClient, obj) })
	return obj
}

// newTestNode returns the test node backed by the real API server but with an in-memory filesystem, so
// reconciles touch the cluster but not the disk. OCI artifacts are served from memory.
func newTestNode(t *testing.T) *node.Node {
	t.Helper()
	return nodetest.NewTestNode(t, k8sClient,
		nodetest.WithStore(&artifact.LocalStore{FS: fsfake.NewMockFileSystem(), Dirs: artifact.DefaultArtifactDirs()}),
		nodetest.WithFetcher(testutil.NewFakeFetcher(k8sClient)),
		nodetest.WithRecorder(events.NewFakeRecorder(100)),
		nodetest.WithFalcoFetcher(compatfake.NewMockVersionsFetcher(nil)))
}
