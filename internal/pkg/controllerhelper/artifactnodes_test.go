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

package controllerhelper_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

func TestAssignedArtifact(t *testing.T) {
	artifactNode := testutil.NewArtifactNode(nsTestNamespace, "node-a", testutil.WithAssigned(testutil.NodeArtifactRef("Rulesfile", "rf", "u1"), testutil.NodeArtifactRef("Plugin", "rf", "u2")))

	got := controllerhelper.AssignedArtifact(artifactNode, "Plugin", "rf")

	require.NotNil(t, got)
	assert.Equal(t, "u2", got.UID, "kind is part of the identity")
	assert.Nil(t, controllerhelper.AssignedArtifact(artifactNode, "Config", "rf"))
}

func TestGetArtifactNode(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(testutil.Scheme(t, artifactv1alpha1.AddToScheme)).WithObjects(testutil.NewArtifactNode(nsTestNamespace, "node-a")).Build()

	found, err := controllerhelper.GetArtifactNode(t.Context(), cl, nsTestNamespace, "node-a")
	require.NoError(t, err)
	require.NotNil(t, found)

	missing, err := controllerhelper.GetArtifactNode(t.Context(), cl, nsTestNamespace, "node-b")
	require.NoError(t, err, "not existing, or not visible to a scoped cache, is not an error")
	assert.Nil(t, missing)
}

func TestGetArtifactNode_Error(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build() // scheme without the type

	_, err := controllerhelper.GetArtifactNode(t.Context(), cl, nsTestNamespace, "node-a")

	require.Error(t, err)
}
