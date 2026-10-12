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

package config

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/instance/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

const testConfigName = "test-config"

func newTestNode() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: testutil.TestNodeName},
	}
}

func newTestConfig(opts ...func(*artifactv1alpha1.Config)) *artifactv1alpha1.Config {
	c := &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: testConfigName, Namespace: testutil.TestNamespace},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// withConfigConditions sets the conditions the node reports for the test Config.
func withConfigConditions(conditions []metav1.Condition) func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) { n.Status.Artifacts[0].Conditions = conditions }
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*ConfigAggregatorReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Config{}, &artifactv1alpha1.ArtifactNode{}).
		Build()
	return NewConfigAggregatorReconciler(cl, s), cl
}

func TestReconcile_NotFound(t *testing.T) {
	r, _ := newTestReconciler(t)
	result, err := r.Reconcile(context.Background(), testutil.Request("nonexistent"))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

// Parent status can land after a reconcile observed an older cached healthy value.
// With no further child/spec events, the parent's own status event must restore the
// aggregate, and the resulting self-event must not cause an endless status-write loop.
func TestSetupWithManager_ConvergesAfterParentStatusUpdate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		condition *metav1.Condition
	}{
		{name: "pending condition", condition: &metav1.Condition{
			Type: "Programmed", Status: metav1.ConditionUnknown, Reason: "Pending", Message: "Intermediate aggregate",
		}},
		{name: "missing condition"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			environment := &envtest.Environment{
				CRDDirectoryPaths:     []string{testutil.CRDDirPath()},
				ErrorIfCRDPathMissing: true,
			}
			cfg, err := environment.Start()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, environment.Stop()) })
			scheme := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
			skipNameValidation := true
			mgr, err := ctrl.NewManager(cfg, ctrl.Options{
				Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0",
				Controller: controllerconfig.Controller{SkipNameValidation: &skipNameValidation},
			})
			require.NoError(t, err)
			for _, idx := range index.InstanceOperator {
				require.NoError(t, mgr.GetFieldIndexer().IndexField(t.Context(), idx.Object, idx.Field, idx.ExtractValueFn))
			}
			direct, err := client.New(cfg, client.Options{Scheme: scheme})
			require.NoError(t, err)
			cached, err := client.NewWithWatch(cfg, client.Options{
				Scheme: scheme, Cache: &client.CacheOptions{Reader: mgr.GetCache()},
			})
			require.NoError(t, err)
			var statusApplies atomic.Int32
			counted := interceptor.NewClient(cached, interceptor.Funcs{
				SubResourceApply: func(
					ctx context.Context, cl client.Client, subresource string,
					obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption,
				) error {
					if subresource == "status" {
						statusApplies.Add(1)
					}
					return cl.SubResource(subresource).Apply(ctx, obj, opts...)
				},
			})
			r := NewConfigAggregatorReconciler(counted, scheme)
			require.NoError(t, r.SetupWithManager(mgr))

			parent := newTestConfig()
			require.NoError(t, direct.Create(t.Context(), parent))
			require.NoError(t, direct.Create(t.Context(), newTestNode()))
			require.NoError(t, direct.Create(t.Context(), testutil.NewTestFalco()))
			pod := testutil.NewRunningFalcoPod()
			pod.Spec.Containers = []corev1.Container{{Name: "falco", Image: "unused"}}
			require.NoError(t, direct.Create(t.Context(), pod))
			pod.Status.Phase = corev1.PodRunning
			require.NoError(t, direct.Status().Update(t.Context(), pod))
			child := testutil.NewReportingArtifactNode(artifact.KindConfig, parent.Name)
			child.Spec.Artifacts[0].UID = string(parent.UID)
			require.NoError(t, direct.Create(t.Context(), child))
			child.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{{Kind: artifact.KindConfig, Name: parent.Name, UID: string(parent.UID)}}
			child.Status.Artifacts[0].Conditions = []metav1.Condition{{
				Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed",
				Message: "Installed", ObservedGeneration: parent.Generation, LastTransitionTime: metav1.Now(),
			}}
			require.NoError(t, direct.Status().Update(t.Context(), child))
			childVersion := child.ResourceVersion

			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- mgr.Start(ctx) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(10 * time.Second):
					t.Error("manager did not stop")
				}
			})
			key := client.ObjectKeyFromObject(parent)
			healthy := func(cl client.Reader) bool {
				current := &artifactv1alpha1.Config{}
				if err := cl.Get(ctx, key, current); err != nil {
					return false
				}
				condition := apimeta.FindStatusCondition(current.Status.Conditions, "Programmed")
				return condition != nil && condition.Status == metav1.ConditionTrue &&
					condition.ObservedGeneration == current.Generation
			}
			waitForQuiet := func() {
				t.Helper()
				lastCount, lastChange := statusApplies.Load(), time.Now()
				require.Eventually(t, func() bool {
					count := statusApplies.Load()
					if count != lastCount {
						lastCount, lastChange = count, time.Now()
					}
					return time.Since(lastChange) >= 500*time.Millisecond
				}, 5*time.Second, 20*time.Millisecond, "status Apply calls must settle")
			}
			require.Eventually(t, func() bool { return healthy(direct) && healthy(mgr.GetClient()) },
				10*time.Second, 20*time.Millisecond)
			waitForQuiet()
			require.NoError(t, direct.Get(ctx, key, parent))
			generation := parent.Generation
			beforeCorrection := statusApplies.Load()

			// Simulate an intermediate aggregate write landing after the healthy-child event
			// was consumed. No child update, spec change or manual reconcile follows this write.
			if tc.condition == nil {
				apimeta.RemoveStatusCondition(&parent.Status.Conditions, "Programmed")
			} else {
				condition := *tc.condition
				condition.ObservedGeneration = generation
				apimeta.SetStatusCondition(&parent.Status.Conditions, condition)
			}
			require.NoError(t, direct.Status().Update(ctx, parent))
			require.Equal(t, generation, parent.Generation)
			require.Eventually(t, func() bool { return healthy(direct) && healthy(mgr.GetClient()) },
				5*time.Second, 20*time.Millisecond, "a status-only parent event must restore the healthy child aggregate")
			waitForQuiet()
			afterCorrection := statusApplies.Load()
			require.Positive(t, afterCorrection-beforeCorrection, "recovery must apply corrected status")
			require.LessOrEqual(t, afterCorrection-beforeCorrection, int32(3), "self-events must not cause a status-write storm")
			require.Never(t, func() bool { return statusApplies.Load() != afterCorrection },
				500*time.Millisecond, 20*time.Millisecond, "a settled aggregate must remain a write-free no-op")
			require.NoError(t, direct.Get(ctx, key, parent))
			require.Equal(t, generation, parent.Generation, "recovery must not require a spec update")
			require.NoError(t, direct.Get(ctx, client.ObjectKeyFromObject(child), child))
			require.Equal(t, childVersion, child.ResourceVersion, "the child must remain unchanged throughout recovery")
		})
	}
}

func TestReconcile_GetError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return fmt.Errorf("api server error")
			},
		}).
		Build()
	r := NewConfigAggregatorReconciler(cl, s)
	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
}

func TestReconcile_NewAssignmentWaitsForStatus(t *testing.T) {
	ctx := t.Context()
	config := newTestConfig(func(c *artifactv1alpha1.Config) {
		c.Generation = 1
		c.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: "config-data"}
	})
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "config-data", Namespace: config.Namespace},
		Data:       map[string]string{commonv1alpha1.ConfigMapConfigKey: "json_output: true"},
	}
	programmed := []metav1.Condition{{
		Type: "Programmed", Status: metav1.ConditionTrue,
		Reason: "Programmed", ObservedGeneration: config.Generation,
	}}
	ready := testutil.NewReportingArtifactNode("Config", testConfigName, withConfigConditions(programmed))
	r, cl := newTestReconciler(t, config, cm, newTestNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), ready)
	_, err := r.Reconcile(ctx, testutil.Request(config.Name))
	require.NoError(t, err)
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(config), config))
	require.True(t, apimeta.IsStatusConditionTrue(config.Status.Conditions, "Programmed"))

	newNode := newTestNode()
	newNode.Name = "new-node"
	require.NoError(t, cl.Create(ctx, newNode))
	newPod := testutil.NewRunningFalcoPod()
	newPod.Name = "new-falco-pod"
	newPod.Spec.NodeName = newNode.Name
	require.NoError(t, cl.Create(ctx, newPod))

	// The new node runs Falco but its artifact operator has not reported yet.
	_, err = r.Reconcile(ctx, testutil.Request(config.Name))
	require.NoError(t, err)
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(config), config))
	assert.False(t, apimeta.IsStatusConditionTrue(config.Status.Conditions, "Programmed"),
		"one ready node must not certify the node that has not reported")

	// Its ArtifactNode appears and reports.
	reported := testutil.NewReportingArtifactNode("Config", testConfigName, withConfigConditions(programmed))
	reported.Name, reported.Spec.NodeName = newNode.Name, newNode.Name
	require.NoError(t, cl.Create(ctx, reported))
	_, err = r.Reconcile(ctx, testutil.Request(config.Name))
	require.NoError(t, err)
	require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(config), config))
	assert.True(t, apimeta.IsStatusConditionTrue(config.Status.Conditions, "Programmed"))
}

func TestReconcile_NoMatchingNodes(t *testing.T) {
	config := newTestConfig()
	r, cl := newTestReconciler(t, config)

	result, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Status should have Programmed=Unknown (no nodes assigned).
	got := &artifactv1alpha1.Config{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(config), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionUnknown, cond.Status)
}

func TestReconcile_ListMatchingNodesError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	listCallCount := 0
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.NodeList); ok {
					listCallCount++
					if listCallCount == 1 {
						return fmt.Errorf("node list failed")
					}
				}
				return c.List(ctx, list, opts...)
			},
		}).
		Build()
	r := NewConfigAggregatorReconciler(cl, s)

	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node list failed")
}

func TestReconcile_EnsureInUseFinalizerError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	config := newTestConfig()
	node := newTestNode()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(config, node, testutil.NewTestFalco(), testutil.NewRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return fmt.Errorf("patch failed")
			},
		}).
		Build()
	r := NewConfigAggregatorReconciler(cl, s)

	_, err := r.Reconcile(context.Background(), testutil.Request(testConfigName))
	require.Error(t, err)
}

func TestFindConfigsForNode(t *testing.T) {
	config := newTestConfig()
	r, _ := newTestReconciler(t, config)

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), r.Client, &artifactv1alpha1.ConfigList{})
	require.Len(t, reqs, 1)
	assert.Equal(t, testConfigName, reqs[0].Name)
	assert.Equal(t, testutil.TestNamespace, reqs[0].Namespace)
}

func TestFindConfigsForNode_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.ConfigList); ok {
					return fmt.Errorf("list error")
				}
				return nil
			},
		}).
		Build()

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, &artifactv1alpha1.ConfigList{})
	assert.Nil(t, reqs)
}

func TestFindConfigsForNode_EmptyList(t *testing.T) {
	r, _ := newTestReconciler(t)
	reqs := controllerhelper.EnqueueAllOfType(context.Background(), r.Client, &artifactv1alpha1.ConfigList{})
	assert.Empty(t, reqs)
}

// ── Reconcile remaining error paths ─────────────────────────────────────────

func newTestConfigWithSource(uid string) (*artifactv1alpha1.Config, *corev1.ConfigMap) {
	config := newTestConfig(func(c *artifactv1alpha1.Config) {
		c.Generation, c.UID = 1, "config-uid"
		if uid != "" {
			c.UID = types.UID(uid)
		}
		c.Spec.ConfigMapRef = &commonv1alpha1.ConfigMapRef{Name: "config-data"}
	})
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "config-data", Namespace: config.Namespace},
		Data:       map[string]string{commonv1alpha1.ConfigMapConfigKey: "json_output: true"},
	}
	return config, cm
}

func TestReconcile_AggregatesFromTheArtifactNode(t *testing.T) {
	programmed := func(status metav1.ConditionStatus) []metav1.Condition {
		return []metav1.Condition{{Type: "Programmed", Status: status, Reason: "Programmed", ObservedGeneration: 1}}
	}

	for name, tc := range map[string]struct {
		conditions     []metav1.Condition
		wantProgrammed bool
	}{
		"the node reports programmed":   {programmed(metav1.ConditionTrue), true},
		"the node reports failure":      {programmed(metav1.ConditionFalse), false},
		"the node reports unknown":      {programmed(metav1.ConditionUnknown), false},
		"the node has not reported yet": {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			config, cm := newTestConfigWithSource("")
			node := testutil.NewReportingArtifactNode("Config", testConfigName, func(n *artifactv1alpha1.ArtifactNode) {
				n.Status.Artifacts[0].UID = string(config.UID)
				n.Status.Artifacts[0].Conditions = tc.conditions
			})
			r, cl := newTestReconciler(t, config, cm, newTestNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), node)

			_, err := r.Reconcile(t.Context(), testutil.Request(config.Name))
			require.NoError(t, err)

			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(config), config))
			assert.Equal(t, tc.wantProgrammed, apimeta.IsStatusConditionTrue(config.Status.Conditions, "Programmed"))
		})
	}
}

func TestReconcile_ANodeWithoutAnArtifactNodeIsPending(t *testing.T) {
	config, cm := newTestConfigWithSource("")
	r, cl := newTestReconciler(t, config, cm, newTestNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod())

	_, err := r.Reconcile(t.Context(), testutil.Request(config.Name))
	require.NoError(t, err)

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(config), config))
	cond := apimeta.FindStatusCondition(config.Status.Conditions, "Programmed")
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionUnknown, cond.Status)
	assert.Equal(t, "Pending", cond.Reason)
}

func TestReconcile_APreviousIncarnationsEntryIsNotCreditedToTheNewArtifact(t *testing.T) {
	config, cm := newTestConfigWithSource("new-uid")
	node := testutil.NewReportingArtifactNode("Config", testConfigName, func(n *artifactv1alpha1.ArtifactNode) {
		n.Spec.Artifacts[0].UID = string(config.UID)
		n.Status.Artifacts[0].UID = "old-uid"
		n.Status.Artifacts[0].Conditions = []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed", ObservedGeneration: 1},
		}
	})
	r, cl := newTestReconciler(t, config, cm, newTestNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), node)

	_, err := r.Reconcile(t.Context(), testutil.Request(config.Name))
	require.NoError(t, err)

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(config), config))
	assert.False(t, apimeta.IsStatusConditionTrue(config.Status.Conditions, "Programmed"),
		"the deleted artifact's success must not make its replacement look programmed")
}

func TestReconcile_TheParentKeepsItsFinalizerWhileANodeListsIt(t *testing.T) {
	// The Config selects no node that runs Falco, yet a node still lists it: files may be there.
	config, cm := newTestConfigWithSource("")
	config.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"nothing": "matches"}}
	node := testutil.NewReportingArtifactNode("Config", testConfigName)
	r, cl := newTestReconciler(t, config, cm, newTestNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), node)

	_, err := r.Reconcile(t.Context(), testutil.Request(config.Name))
	require.NoError(t, err)

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(config), config))
	assert.Contains(t, config.Finalizers, "artifact.falcosecurity.dev/node-objects-in-use")
}

// A Falco pod being replaced leaves a moment with none on the node. The assignment controller keeps the node's
// ArtifactNode for a grace period, and the parent must keep reporting from it rather than flap to NoNodesAssigned.
func TestReconcile_AKeptArtifactNodeIsStillReportedWhileFalcoIsAway(t *testing.T) {
	config, cm := newTestConfigWithSource("")
	node := testutil.NewReportingArtifactNode("Config", testConfigName, func(n *artifactv1alpha1.ArtifactNode) {
		n.Spec.Artifacts[0].UID = string(config.UID)
		n.Status.Artifacts[0].UID = string(config.UID)
		n.Status.Artifacts[0].Conditions = []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed", ObservedGeneration: 1},
		}
	})
	// No Falco pod: the node does not run Falco at the moment.
	r, cl := newTestReconciler(t, config, cm, newTestNode(), testutil.NewTestFalco(), node)

	_, err := r.Reconcile(t.Context(), testutil.Request(config.Name))
	require.NoError(t, err)

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(config), config))
	assert.True(t, apimeta.IsStatusConditionTrue(config.Status.Conditions, "Programmed"),
		"the node's report is still what the parent shows until the ArtifactNode is deleted")
}

func TestReconcile_ANodeWithoutFalcoAndWithoutAnArtifactNodeIsNotExpected(t *testing.T) {
	config, cm := newTestConfigWithSource("")
	r, cl := newTestReconciler(t, config, cm, newTestNode(), testutil.NewTestFalco())

	_, err := r.Reconcile(t.Context(), testutil.Request(config.Name))
	require.NoError(t, err)

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(config), config))
	cond := apimeta.FindStatusCondition(config.Status.Conditions, "Programmed")
	require.NotNil(t, cond)
	assert.Equal(t, "NoNodesAssigned", cond.Reason)
}

func TestReconcile_DeletionWaitsForNodeCleanup(t *testing.T) {
	config := newTestConfig(func(c *artifactv1alpha1.Config) {
		c.Finalizers = []string{controllerhelper.NodeObjectsInUseFinalizer}
	})
	artifactNode := testutil.NewTestArtifactNode()
	artifactNode.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{{Kind: "Config", Name: config.Name}}
	r, cl := newTestReconciler(t, config, artifactNode)
	require.NoError(t, cl.Delete(t.Context(), config))

	_, err := r.Reconcile(t.Context(), testutil.Request(config.Name))
	require.NoError(t, err)
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(config), config))
	assert.Contains(t, config.Finalizers, controllerhelper.NodeObjectsInUseFinalizer,
		"a node still reports on the config, so its files may remain: the parent must stay")

	// The node removes its files and withdraws the entry.
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(artifactNode), artifactNode))
	artifactNode.Status.Artifacts = nil
	require.NoError(t, cl.Status().Update(t.Context(), artifactNode))

	_, err = r.Reconcile(t.Context(), testutil.Request(config.Name))
	require.NoError(t, err)
	err = cl.Get(t.Context(), client.ObjectKeyFromObject(config), config)
	assert.True(t, k8serrors.IsNotFound(err), "with every node clean the parent is released")
}

var errBoom = errors.New("boom")

func TestHandleDeletion_Errors(t *testing.T) {
	deleting := func() *artifactv1alpha1.Config {
		return newTestConfig(func(p *artifactv1alpha1.Config) {
			now := metav1.Now()
			p.DeletionTimestamp = &now
			p.Finalizers = []string{controllerhelper.NodeObjectsInUseFinalizer}
		})
	}
	tests := []struct {
		name  string
		funcs interceptor.Funcs
	}{
		{
			name: "the ArtifactNodes cannot be listed",
			funcs: interceptor.Funcs{List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return errBoom
			}},
		},
		{
			name: "the finalizer cannot be released",
			funcs: interceptor.Funcs{Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
				return errBoom
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := deleting()
			r, cl := newTestReconciler(t, config)
			r.Client = interceptor.NewClient(cl.(client.WithWatch), tt.funcs)

			_, err := shared.HandleDeletion(t.Context(), r.aggregation(), config)

			require.ErrorIs(t, err, errBoom)
		})
	}
}

func TestSetupWithManager(t *testing.T) {
	r, _ := newTestReconciler(t)
	mgr := testutil.NewUnstartedManager(t, testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme))

	require.NoError(t, r.SetupWithManager(mgr))
}

func TestReconcile_AnUnchangedStatusIsNotWrittenAgain(t *testing.T) {
	config := newTestConfig(func(c *artifactv1alpha1.Config) { c.Generation = 1 })
	patches := 0
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().WithScheme(s).
		WithObjects(config, newTestNode(), testutil.NewTestFalco(), testutil.NewRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Config{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(
				ctx context.Context, c client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption,
			) error {
				if _, isConfig := obj.(*artifactv1alpha1.Config); isConfig {
					patches++
				}
				return c.SubResource(sub).Patch(ctx, obj, p, opts...)
			},
		}).Build()
	r := NewConfigAggregatorReconciler(cl, s)

	for range 4 {
		_, err := r.Reconcile(t.Context(), testutil.Request(config.Name))
		require.NoError(t, err)
	}

	assert.LessOrEqual(t, patches, 2, "once written, an unchanged status must not cost an API call per reconcile")
}
