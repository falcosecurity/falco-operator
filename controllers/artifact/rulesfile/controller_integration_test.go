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

package rulesfile

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	"github.com/falcosecurity/falco-operator/internal/pkg/startupgate"
)

var k8sClient client.Client

func TestMain(m *testing.M) {
	cl, stop, err := testutil.StartEnvtest(artifactv1alpha1.AddToScheme)
	if err != nil {
		ctrllog.Log.Error(err, "Failed to start envtest")
		os.Exit(1)
	}
	k8sClient = cl
	code := m.Run()
	stop()
	os.Exit(code)
}

// newIntegrationReconciler builds a reconciler backed by the real API server but with an
// in-memory filesystem and OCI puller, so reconciles touch the cluster but not the disk/registry.
func newIntegrationReconciler() *RulesfileReconciler {
	am := artifact.NewManagerWithOptions(k8sClient, testutil.TestNamespace,
		artifact.WithFS(filesystem.NewMockFileSystem()),
		artifact.WithOCIPuller(&puller.MockOCIPuller{}),
	)
	return &RulesfileReconciler{
		Client:          k8sClient,
		Scheme:          k8sClient.Scheme(),
		recorder:        events.NewFakeRecorder(100),
		gate:            startupgate.NoopGateRecorder{},
		finalizer:       common.FormatFinalizerName(rulesfileFinalizerPrefix, testutil.TestNodeName),
		artifactManager: am,
		nodeName:        testutil.TestNodeName,
		namespace:       testutil.TestNamespace,
	}
}

func createRulesfile(t *testing.T, ctx context.Context, rf *artifactv1alpha1.Rulesfile) *artifactv1alpha1.Rulesfile {
	t.Helper()
	require.NoError(t, k8sClient.Create(ctx, rf))
	t.Cleanup(func() { testutil.CleanupObject(t, ctx, k8sClient, rf) })
	return rf
}

func rulesfileConditions(o client.Object) *[]metav1.Condition {
	return &o.(*artifactv1alpha1.Rulesfile).Status.Conditions
}

func applyRulesfileStatus(ctx context.Context, o client.Object) error {
	return controllerhelper.PatchStatusSSA(ctx, k8sClient, k8sClient.Scheme(), o, fieldManager)
}

func TestIntegration_Rulesfile_SteadyStateReconcileIsQuiet(t *testing.T) {
	ctx := context.Background()
	rf := createRulesfile(t, ctx, &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: "quiet", Namespace: testutil.TestNamespace},
		Spec: artifactv1alpha1.RulesfileSpec{
			InlineRules: &apiextensionsv1.JSON{Raw: []byte(`[{"rule":"r","desc":"d","condition":"always_true","output":"o","priority":"WARNING"}]`)},
		},
	})
	testutil.AssertReconcileQuiet(t, ctx, newIntegrationReconciler(), k8sClient,
		client.ObjectKeyFromObject(rf), &artifactv1alpha1.Rulesfile{}, 5, 5,
		rulesfileConditions,
		func(o client.Object) error { return applyRulesfileStatus(ctx, o) },
	)
}

func TestIntegration_Rulesfile_StatusApplyNoOpThenChange(t *testing.T) {
	ctx := context.Background()
	key := types.NamespacedName{Name: "ssa-semantics", Namespace: testutil.TestNamespace}
	createRulesfile(t, ctx, &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}})

	// Apply both conditions so the no-op contract is exercised on a multi-entry conditions list
	// (listType=map keyed by type), not just a single condition.
	applyConditions := func(programmed metav1.ConditionStatus, reason, msg string) error {
		cur := &artifactv1alpha1.Rulesfile{}
		if err := k8sClient.Get(ctx, key, cur); err != nil {
			return err
		}
		apimeta.SetStatusCondition(&cur.Status.Conditions,
			common.NewProgrammedCondition(programmed, reason, msg, cur.GetGeneration()))
		apimeta.SetStatusCondition(&cur.Status.Conditions,
			common.NewResolvedRefsCondition(metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, cur.GetGeneration()))
		return applyRulesfileStatus(ctx, cur)
	}

	testutil.AssertSSAApplyNoOpThenChange(t, ctx, k8sClient, key, &artifactv1alpha1.Rulesfile{},
		func() error {
			return applyConditions(metav1.ConditionTrue, artifact.ReasonProgrammed, artifact.MessageProgrammed)
		},
		func() error {
			return applyConditions(metav1.ConditionFalse, artifact.ReasonInlineRulesStoreFailed, "store failed")
		},
	)

	// Sanity: both conditions are present and Programmed reflects the final mutation.
	final := &artifactv1alpha1.Rulesfile{}
	require.NoError(t, k8sClient.Get(ctx, key, final))
	require.Equal(t, metav1.ConditionFalse,
		apimeta.FindStatusCondition(final.Status.Conditions, commonv1alpha1.ConditionProgrammed.String()).Status)
	require.NotNil(t, apimeta.FindStatusCondition(final.Status.Conditions, commonv1alpha1.ConditionResolvedRefs.String()))
}
