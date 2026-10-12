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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	"k8s.io/client-go/tools/events"
	"oras.land/oras-go/v2/registry/remote/auth"
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
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactserver"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	pullerfake "github.com/falcosecurity/falco-operator/internal/pkg/oci/puller/fake"
	"github.com/falcosecurity/falco-operator/internal/testutil"
)

const (
	testStatusSubresource = "status"
	testPluginName        = "test-plugin"
	testPluginDigest      = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func testOCIArtifact() *commonv1alpha1.OCIArtifact {
	return &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{Repository: "ghcr.io/test/plugin", Tag: "latest"},
	}
}

func newTestNode(name string, labels map[string]string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func newTestPlugin(opts ...func(*artifactv1alpha1.Plugin)) *artifactv1alpha1.Plugin {
	p := &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: testPluginName, Namespace: testutil.TestNamespace},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func withPluginOCI() func(*artifactv1alpha1.Plugin) {
	return func(p *artifactv1alpha1.Plugin) {
		p.Spec.OCIArtifact = testOCIArtifact()
	}
}

func withPluginSelector() func(*artifactv1alpha1.Plugin) {
	return func(p *artifactv1alpha1.Plugin) {
		p.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}
	}
}

// withPluginConditions sets the conditions the node reports for the test Plugin.
func withPluginConditions(conditions []metav1.Condition) func(*artifactv1alpha1.ArtifactNode) {
	return func(n *artifactv1alpha1.ArtifactNode) { n.Status.Artifacts[0].Conditions = conditions }
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*PluginAggregatorReconciler, client.Client) {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}, &artifactv1alpha1.ArtifactNode{}).
		Build()
	return NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil), cl
}

func newTestReconcilerWithPuller(t *testing.T, mockPuller puller.Puller, objs ...client.Object) (*PluginAggregatorReconciler, client.Client) {
	t.Helper()
	r, cl := newTestReconciler(t, objs...)
	r.ociPuller = mockPuller
	return r, cl
}

func TestReconcile_NotFound(t *testing.T) {
	r, _ := newTestReconciler(t)
	result, err := r.Reconcile(context.Background(), testutil.Request("nonexistent"))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

func TestReconcile_MissingCacheOwner(t *testing.T) {
	const (
		sharedBlob   = "shared"
		grace        = "grace"
		readError    = "read error"
		persistError = "persist error"
	)
	for _, scenario := range []string{"unreferenced", sharedBlob, grace, readError, persistError} {
		t.Run(scenario, func(t *testing.T) {
			cacheDir := t.TempDir()
			r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir)
			if scenario == grace {
				r.cache = artifactcache.NewCache(cacheDir)
				require.NoError(t, r.cache.Load())
			}
			platforms := []string{"linux-amd64", "linux-arm64"}
			paths := make([]string, 0, len(platforms))
			for _, platform := range platforms {
				path := artifactcache.BlobPath(cacheDir, string(artifact.KindPlugin), "repo:tag", testPluginDigest,
					"linux", strings.TrimPrefix(platform, "linux-"))
				require.NoError(t, r.cache.Store(path, []byte("retained content"), 0o644))
				require.NoError(t, r.cache.Set(string(artifact.KindPlugin), testutil.TestNamespace, testPluginName, platform, path))
				if scenario == sharedBlob {
					require.NoError(t, r.cache.Set(string(artifact.KindPlugin), testutil.TestNamespace, "other", platform, path))
				}
				paths = append(paths, path)
			}

			originalClient := r.Client
			if scenario == readError {
				r.Client = fake.NewClientBuilder().WithScheme(r.Scheme).WithInterceptorFuncs(testutil.FailGet(fmt.Errorf("API unavailable"))).Build()
			}
			snapshot := filepath.Join(cacheDir, "index.json")
			if scenario == persistError {
				require.NoError(t, os.Rename(snapshot, snapshot+".backup"))
				require.NoError(t, os.Mkdir(snapshot, 0o750))
			}
			_, err := r.Reconcile(t.Context(), testutil.Request(testPluginName))
			if scenario == readError || scenario == persistError {
				require.Error(t, err)
				require.NotEmpty(t, r.cache.Owners(string(artifact.KindPlugin)), "failed cleanup must retain the live index")
				for _, path := range paths {
					require.FileExists(t, path)
				}
				r.Client = originalClient
				if scenario == persistError {
					require.NoError(t, os.Remove(snapshot))
					require.NoError(t, os.Rename(snapshot+".backup", snapshot))
				}
				reloaded := artifactcache.NewCache(cacheDir)
				require.NoError(t, reloaded.Load())
				require.Contains(t, reloaded.Owners(string(artifact.KindPlugin)), types.NamespacedName{
					Namespace: testutil.TestNamespace, Name: testPluginName,
				}, "failed cleanup must retain the durable index")
				_, err = r.Reconcile(t.Context(), testutil.Request(testPluginName))
			}
			require.NoError(t, err)
			require.NotContains(t, r.cache.Owners(string(artifact.KindPlugin)), types.NamespacedName{
				Namespace: testutil.TestNamespace, Name: testPluginName,
			})
			reloaded := artifactcache.NewCache(cacheDir)
			require.NoError(t, reloaded.Load())
			require.NotContains(t, reloaded.Owners(string(artifact.KindPlugin)), types.NamespacedName{
				Namespace: testutil.TestNamespace, Name: testPluginName,
			}, "successful cleanup must survive restart")
			removed, err := r.cache.Sweep(t.Context())
			require.NoError(t, err)
			require.Zero(t, removed, "shared/grace blobs are protected; immediate mode already removed unreferenced blobs")
			for _, path := range paths {
				if scenario == sharedBlob || scenario == grace {
					require.FileExists(t, path)
					require.True(t, r.cache.BlobExists(path))
				} else {
					require.NoFileExists(t, path)
					require.NoFileExists(t, path+artifactcache.PermSuffix)
				}
			}
			response := httptest.NewRecorder()
			artifactserver.New(r.cache).Handler().ServeHTTP(response, httptest.NewRequestWithContext(
				t.Context(), http.MethodGet, "/v1/artifacts/plugins/default/"+testPluginName+"?os=linux&arch=amd64&digest="+testPluginDigest, http.NoBody,
			))
			require.Equal(t, http.StatusServiceUnavailable, response.Code, "a removed name must not serve even a shared or retained blob")
		})
	}
}

func TestSetupWithManager_ReconcilesPersistedCacheOwners(t *testing.T) {
	for _, tc := range []struct {
		name      string
		namespace string
	}{
		{name: "default namespace", namespace: testutil.TestNamespace},
		{name: "custom namespace", namespace: "cache-owner-recovery"},
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
			survivor := newTestPlugin(withPluginOCI())
			if tc.namespace != testutil.TestNamespace {
				require.NoError(t, direct.Create(t.Context(), &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: tc.namespace},
				}))
			}
			survivor.Name = "survivor"
			survivor.Namespace = tc.namespace
			require.NoError(t, direct.Create(t.Context(), survivor))

			seed := artifactcache.NewCache(t.TempDir(), artifactcache.WithEvictionGracePeriod(0))
			require.NoError(t, seed.Load())
			missingPath := artifactcache.BlobPath(seed.Dir(), string(artifact.KindPlugin), "deleted:tag", testPluginDigest, "linux", "amd64")
			sharedPath := artifactcache.BlobPath(seed.Dir(), string(artifact.KindPlugin), "shared:tag", testPluginDigest, "linux", "amd64")
			require.NoError(t, seed.Store(missingPath, []byte("deleted content"), 0o644))
			require.NoError(t, seed.Store(sharedPath, []byte("surviving content"), 0o644))
			require.NoError(t, seed.Set(string(artifact.KindPlugin), tc.namespace, "missing", "linux-amd64", missingPath))
			require.NoError(t, seed.Set(string(artifact.KindPlugin), tc.namespace, "missing-shared", "linux-amd64", sharedPath))
			require.NoError(t, seed.Set(string(artifact.KindPlugin), tc.namespace, survivor.Name, "linux-amd64", sharedPath))
			cache := artifactcache.NewCache(seed.Dir(), artifactcache.WithEvictionGracePeriod(0))
			require.NoError(t, cache.Load())
			r := NewPluginAggregatorReconciler(mgr.GetClient(), scheme, events.NewFakeRecorder(100), cache)
			// A failed registry fetch must not remove a still-existing owner's previous reference.
			r.ociPuller = &pullerfake.MockOCIPuller{FetchConfigErr: fmt.Errorf("registry unavailable")}
			require.NoError(t, r.SetupWithManager(mgr))

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

			// Neither missing name has ever existed in this API server. Only the controller's
			// persisted-owner source can enqueue it; this test never invokes Reconcile or a queue.
			require.Eventually(t, func() bool {
				_, missing := cache.Lookup(string(artifact.KindPlugin), tc.namespace, "missing", "linux-amd64")
				_, sharedFound := cache.Lookup(string(artifact.KindPlugin), tc.namespace, "missing-shared", "linux-amd64")
				return !missing && !sharedFound
			}, 10*time.Second, 20*time.Millisecond)
			require.Eventually(t, func() bool {
				current := &artifactv1alpha1.Plugin{}
				if err := direct.Get(t.Context(), client.ObjectKeyFromObject(survivor), current); err != nil {
					return false
				}
				condition := apimeta.FindStatusCondition(current.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
				return condition != nil && condition.Status == metav1.ConditionFalse
			}, 10*time.Second, 20*time.Millisecond, "the existing owner must also reconcile through the synced informer")
			require.Equal(t, []types.NamespacedName{{Namespace: tc.namespace, Name: survivor.Name}}, cache.Owners(string(artifact.KindPlugin)))
			require.NoFileExists(t, missingPath)
			require.FileExists(t, sharedPath)
			reloaded := artifactcache.NewCache(seed.Dir())
			require.NoError(t, reloaded.Load())
			require.Equal(t, cache.Owners(string(artifact.KindPlugin)), reloaded.Owners(string(artifact.KindPlugin)))

			for _, name := range []string{"missing", "missing-shared", survivor.Name} {
				response := httptest.NewRecorder()
				request := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					"/v1/artifacts/plugins/"+tc.namespace+"/"+name+"?os=linux&arch=amd64&digest="+testPluginDigest, http.NoBody)
				artifactserver.New(cache).Handler().ServeHTTP(response, request)
				if name == survivor.Name {
					require.Equal(t, http.StatusOK, response.Code)
					require.Equal(t, "surviving content", response.Body.String())
				} else {
					require.Equal(t, http.StatusServiceUnavailable, response.Code)
				}
			}
		})
	}
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
					if subresource == testStatusSubresource {
						statusApplies.Add(1)
					}
					return cl.SubResource(subresource).Apply(ctx, obj, opts...)
				},
			})
			r := NewPluginAggregatorReconciler(counted, scheme, events.NewFakeRecorder(100), nil)
			require.NoError(t, r.SetupWithManager(mgr))

			parent := newTestPlugin()
			require.NoError(t, direct.Create(t.Context(), parent))
			require.NoError(t, direct.Create(t.Context(), newTestNode(testutil.TestNodeName, nil)))
			require.NoError(t, direct.Create(t.Context(), testutil.NewTestFalco()))
			pod := testutil.NewRunningFalcoPod()
			pod.Spec.Containers = []corev1.Container{{Name: "falco", Image: "unused"}}
			require.NoError(t, direct.Create(t.Context(), pod))
			pod.Status.Phase = corev1.PodRunning
			require.NoError(t, direct.Status().Update(t.Context(), pod))
			child := testutil.NewReportingArtifactNode(artifact.KindPlugin, parent.Name)
			child.Spec.Artifacts[0].UID = string(parent.UID)
			require.NoError(t, direct.Create(t.Context(), child))
			child.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{{Kind: artifact.KindPlugin, Name: parent.Name, UID: string(parent.UID)}}
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
				current := &artifactv1alpha1.Plugin{}
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

func TestReconcile_MetadataFailurePreservesFinalConditionAndAvoidsWrites(t *testing.T) {
	for _, tc := range []struct {
		name             string
		programmed       metav1.ConditionStatus
		programmedReason string
	}{
		{name: "healthy child", programmed: metav1.ConditionTrue, programmedReason: "Programmed"},
		{name: "pending child", programmed: metav1.ConditionUnknown, programmedReason: "Pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetchErr := fmt.Errorf("registry down")
			parent := newTestPlugin(withPluginOCI())
			parent.Generation = 1
			child := testutil.NewReportingArtifactNode(artifact.KindPlugin, parent.Name)
			child.Status.Artifacts[0].Conditions = []metav1.Condition{
				{Type: "Programmed", Status: tc.programmed, Reason: tc.programmedReason, ObservedGeneration: 1},
				{Type: "ResolvedRefs", Status: metav1.ConditionTrue, Reason: "ReferenceResolved", ObservedGeneration: 1},
			}
			scheme := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
			var statusApplies int
			cl := fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(parent, child, newTestNode(testutil.TestNodeName, nil), testutil.NewTestFalco(), testutil.NewRunningFalcoPod()).
				WithStatusSubresource(&artifactv1alpha1.Plugin{}, &artifactv1alpha1.ArtifactNode{}).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceApply: func(
						ctx context.Context, c client.Client, subresource string,
						obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption,
					) error {
						if subresource == testStatusSubresource {
							statusApplies++
						}
						return c.SubResource(subresource).Apply(ctx, obj, opts...)
					},
				}).Build()
			r := NewPluginAggregatorReconciler(cl, scheme, events.NewFakeRecorder(100), nil)
			r.ociPuller = &pullerfake.MockOCIPuller{FetchConfigErr: fetchErr}
			ctx := t.Context()
			request := testutil.Request(parent.Name)
			_, err := r.Reconcile(ctx, request)
			require.ErrorIs(t, err, fetchErr)
			require.NoError(t, cl.Get(ctx, request.NamespacedName, parent))
			failure := apimeta.FindStatusCondition(parent.Status.Conditions, "Programmed")
			require.NotNil(t, failure)
			require.Equal(t, metav1.ConditionFalse, failure.Status)
			// Backdating makes transient True -> False restamping observable without sleeping.
			oldTransition := metav1.NewTime(time.Now().Add(-time.Hour)).Rfc3339Copy()
			failure.LastTransitionTime = oldTransition
			require.NoError(t, cl.Status().Update(ctx, parent))
			beforeRetry := statusApplies
			for range 3 {
				_, err = r.Reconcile(ctx, request)
				require.ErrorIs(t, err, fetchErr, "the original error must still drive normal retry backoff")
				require.NoError(t, cl.Get(ctx, request.NamespacedName, parent))
				failure = apimeta.FindStatusCondition(parent.Status.Conditions, "Programmed")
				require.NotNil(t, failure)
				assert.Equal(t, metav1.ConditionFalse, failure.Status)
				assert.True(t, failure.LastTransitionTime.Equal(&oldTransition), "only the final condition is an observable transition")
			}
			require.Equal(t, beforeRetry, statusApplies, "an unchanged metadata failure must not generate status self-events")

			// A real child reference failure must still reach the parent while metadata fails.
			require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(child), child))
			apimeta.SetStatusCondition(&child.Status.Artifacts[0].Conditions, metav1.Condition{
				Type: "ResolvedRefs", Status: metav1.ConditionFalse, Reason: "ReferenceNotFound",
				Message: "Missing reference", ObservedGeneration: parent.Generation,
			})
			require.NoError(t, cl.Status().Update(ctx, child))
			_, err = r.Reconcile(ctx, request)
			require.ErrorIs(t, err, fetchErr)
			require.Equal(t, beforeRetry+1, statusApplies)
			require.NoError(t, cl.Get(ctx, request.NamespacedName, parent))
			references := apimeta.FindStatusCondition(parent.Status.Conditions, "ResolvedRefs")
			require.NotNil(t, references)
			assert.Equal(t, metav1.ConditionFalse, references.Status)
			assert.Equal(t, "ReferenceNotFound", references.Reason)
			failure = apimeta.FindStatusCondition(parent.Status.Conditions, "Programmed")
			require.NotNil(t, failure)
			assert.True(t, failure.LastTransitionTime.Equal(&oldTransition))
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
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestReconcile_NoMatchingNodes(t *testing.T) {
	plugin := newTestPlugin()
	r, cl := newTestReconciler(t, plugin)

	result, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionUnknown, cond.Status)
}

func TestReconcile_ListMatchingNodesError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.NodeList); ok {
					return fmt.Errorf("node list failed")
				}
				return c.List(ctx, list, opts...)
			},
		}).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestHandleDeletion_EvictsCacheEntries(t *testing.T) {
	plugin := newTestPlugin()
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, plugin)

	// An exclusively-referenced blob: gone once no node holds this Plugin any more.
	ownBlob := filepath.Join(cacheDir, "blobs", "own")
	require.NoError(t, r.cache.Store(ownBlob, []byte("x"), 0o755))
	require.NoError(t, r.cache.Set(string(artifact.KindPlugin), testutil.TestNamespace, testPluginName, "linux-amd64", ownBlob))

	// A blob shared with another CR: refcount drops but the file survives.
	sharedBlob := filepath.Join(cacheDir, "blobs", "shared")
	require.NoError(t, r.cache.Store(sharedBlob, []byte("y"), 0o755))
	require.NoError(t, r.cache.Set(string(artifact.KindPlugin), testutil.TestNamespace, testPluginName, "linux-arm64", sharedBlob))
	require.NoError(t, r.cache.Set(string(artifact.KindPlugin), testutil.TestNamespace, "other-plugin", "", sharedBlob))

	// No node lists or reports on this Plugin, so the deletion evicts the cache entries.
	_, err := shared.HandleDeletion(context.Background(), r.aggregation(), plugin)
	require.NoError(t, err)

	_, ok := r.cache.Lookup(string(artifact.KindPlugin), testutil.TestNamespace, testPluginName, "linux-amd64")
	assert.False(t, ok)
	_, err = os.Stat(ownBlob)
	assert.True(t, os.IsNotExist(err), "exclusively-referenced blob must be removed from disk")

	got, ok := r.cache.Lookup(string(artifact.KindPlugin), testutil.TestNamespace, "other-plugin", "")
	require.True(t, ok, "other CR's entry for the shared blob must survive")
	assert.Equal(t, sharedBlob, got)
	_, err = os.Stat(sharedBlob)
	assert.NoError(t, err, "shared blob must survive: another CR still references it")
}

func TestHandleDeletion_NodesRemaining_DoesNotEvictCache(t *testing.T) {
	plugin := newTestPlugin()
	pluginNode := testutil.NewReportingArtifactNode("Plugin", testPluginName)
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, plugin, pluginNode)

	blobPath := filepath.Join(cacheDir, "blobs", "own")
	require.NoError(t, r.cache.Store(blobPath, []byte("x"), 0o755))
	require.NoError(t, r.cache.Set(string(artifact.KindPlugin), testutil.TestNamespace, testPluginName, "linux-amd64", blobPath))

	_, err := shared.HandleDeletion(context.Background(), r.aggregation(), plugin)
	require.NoError(t, err)

	got, ok := r.cache.Lookup(string(artifact.KindPlugin), testutil.TestNamespace, testPluginName, "linux-amd64")
	require.True(t, ok, "cache entry must survive while a node still lists the plugin")
	assert.Equal(t, blobPath, got)
}

func TestHandleDeletion_SurfacesDeletionBlockedCondition(t *testing.T) {
	plugin := newTestPlugin()
	pluginNode := testutil.NewReportingArtifactNode("Plugin", testPluginName, withPluginConditions([]metav1.Condition{
		{
			Type:    commonv1alpha1.ConditionDeletionBlocked.String(),
			Status:  metav1.ConditionTrue,
			Reason:  artifact.ReasonPluginConfigStillRequired,
			Message: `"container" is still required by [{Rulesfile some-rulesfile}]`,
		},
	}))
	r, cl := newTestReconciler(t, plugin, pluginNode)

	_, err := shared.HandleDeletion(context.Background(), r.aggregation(), plugin)
	require.NoError(t, err)

	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	cond := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionDeletionBlocked.String())
	require.NotNil(t, cond, "aggregator must surface the per-node DeletionBlocked condition onto the parent Plugin")
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, artifact.ReasonPluginConfigStillRequired, cond.Reason)
}

func TestFetchAndCacheArtifactMeta_NoOCI(t *testing.T) {
	plugin := newTestPlugin()
	r, _ := newTestReconciler(t, plugin)

	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: "old"}
	err := r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	assert.Nil(t, plugin.Status.ArtifactMeta)
}

func TestFetchAndCacheArtifactMeta_CacheHit(t *testing.T) {
	mockPuller := &pullerfake.MockOCIPuller{}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	specHash, err := artifact.ComputeOCIArtifactSpecHash(plugin.Spec.OCIArtifact)
	require.NoError(t, err)
	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{
		SpecHash: specHash,
		Digest:   "sha256:abc123",
	}

	err = r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	assert.Empty(t, mockPuller.FetchConfigCalls)
	assert.Equal(t, "sha256:abc123", plugin.Status.ArtifactMeta.Digest)
}

func TestFetchAndCacheArtifactMeta_CacheHitIgnoresDigest(t *testing.T) {
	// Spec hash matches even though the stored digest is stale, so the cache is still a hit.
	// Picking up a new image pushed to the same tag requires an explicit spec change.
	mockPuller := &pullerfake.MockOCIPuller{}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	specHash, err := artifact.ComputeOCIArtifactSpecHash(plugin.Spec.OCIArtifact)
	require.NoError(t, err)
	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{
		SpecHash: specHash,
		Digest:   "sha256:old",
	}

	err = r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	assert.Empty(t, mockPuller.FetchConfigCalls, "spec hash match must skip FetchConfig regardless of digest")
	assert.Equal(t, "sha256:old", plugin.Status.ArtifactMeta.Digest, "stale digest must not be updated on cache hit")
}

func TestFetchAndCacheArtifactMeta_ResolutionPolicy(t *testing.T) {
	const nextDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct {
		name    string
		change  func(*artifactv1alpha1.Plugin)
		resolve bool
	}{
		{"tag moves without a spec change", func(_ *artifactv1alpha1.Plugin) {}, false},
		{"plugin configuration changes", func(p *artifactv1alpha1.Plugin) {
			p.Spec.Config = &artifactv1alpha1.PluginConfig{OpenParams: "new params"}
		}, false},
		{"selector changes", withPluginSelector(), false},
		{"tag changes", func(p *artifactv1alpha1.Plugin) { p.Spec.OCIArtifact.Image.Tag = "v2" }, true},
		{"repository changes", func(p *artifactv1alpha1.Plugin) { p.Spec.OCIArtifact.Image.Repository = "test/replacement" }, true},
		{"digest is explicitly pinned", func(p *artifactv1alpha1.Plugin) { p.Spec.OCIArtifact.Image.Tag = nextDigest }, true},
		{"CR is recreated", func(p *artifactv1alpha1.Plugin) {
			p.UID = "replacement"
			p.Status = artifactv1alpha1.PluginStatus{}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			plugin := newTestPlugin(withPluginOCI())
			mockPuller := &pullerfake.MockOCIPuller{ConfigResult: &puller.ArtifactConfig{}, ConfigDigest: testPluginDigest}
			r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)
			require.NoError(t, r.fetchAndCacheArtifactMeta(ctx, plugin))
			previous := plugin.Status.ArtifactMeta.DeepCopy()
			firstRef := artifact.ResolveReference(plugin.Spec.OCIArtifact)
			mockPuller.ConfigDigest = nextDigest
			tc.change(plugin)
			require.NoError(t, r.fetchAndCacheArtifactMeta(ctx, plugin))
			if tc.resolve {
				require.Equal(t, nextDigest, plugin.Status.ArtifactMeta.Digest)
				require.Equal(t, []string{firstRef, artifact.ResolveReference(plugin.Spec.OCIArtifact)}, mockPuller.FetchConfigCalls)
			} else {
				require.Equal(t, previous, plugin.Status.ArtifactMeta)
				require.Equal(t, []string{firstRef}, mockPuller.FetchConfigCalls, "unchanged OCI metadata must be reused without fetching")
			}
		})
	}
}

func TestFetchAndCacheArtifactMeta_NoCacheNoStatus(t *testing.T) {
	mockPuller := &pullerfake.MockOCIPuller{
		ConfigResult: &puller.ArtifactConfig{},
		ConfigDigest: "sha256:fresh",
	}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	err := r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	assert.Len(t, mockPuller.FetchConfigCalls, 1)
	require.NotNil(t, plugin.Status.ArtifactMeta)
	assert.Equal(t, "sha256:fresh", plugin.Status.ArtifactMeta.Digest)
}

func TestFetchAndCacheArtifactMeta_FetchConfigError(t *testing.T) {
	mockPuller := &pullerfake.MockOCIPuller{
		FetchConfigErr: fmt.Errorf("registry unavailable"),
	}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	err := r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry unavailable")
	// Records a Warning event on the Plugin describing the OCI config fetch failure.
	testutil.RequireEvents(t, r.recorder.(*events.FakeRecorder).Events,
		[]string{"Warning OCIArtifactProgramFailed Failed to fetch OCI config layer: registry unavailable"})
}

func TestFetchAndCacheArtifactMeta_WithDependencies(t *testing.T) {
	mockPuller := &pullerfake.MockOCIPuller{
		ConfigResult: &puller.ArtifactConfig{
			Dependencies: []puller.ArtifactDependency{
				{
					Name:    "json",
					Version: ">=0.7.0",
					Alternatives: []puller.Dependency{
						{Name: "json-alt", Version: ">=0.6.0"},
					},
				},
			},
		},
		ConfigDigest: "sha256:deps",
	}
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconcilerWithPuller(t, mockPuller, plugin)

	err := r.fetchAndCacheArtifactMeta(context.Background(), plugin)
	require.NoError(t, err)
	require.NotNil(t, plugin.Status.ArtifactMeta)
	require.Len(t, plugin.Status.ArtifactMeta.Dependencies, 1)
	assert.Equal(t, "json", plugin.Status.ArtifactMeta.Dependencies[0].Name)
	require.Len(t, plugin.Status.ArtifactMeta.Dependencies[0].Alternatives, 1)
	assert.Equal(t, "json-alt", plugin.Status.ArtifactMeta.Dependencies[0].Alternatives[0].Name)
}

func TestFindPluginsForNode(t *testing.T) {
	plugin := newTestPlugin()
	r, _ := newTestReconciler(t, plugin)

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), r.Client, &artifactv1alpha1.PluginList{})
	require.Len(t, reqs, 1)
	assert.Equal(t, testPluginName, reqs[0].Name)
}

func TestFindPluginsForNode_ListError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*artifactv1alpha1.PluginList); ok {
					return fmt.Errorf("list error")
				}
				return nil
			},
		}).
		Build()
	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, &artifactv1alpha1.PluginList{})
	assert.Nil(t, reqs)
}

func TestFindPluginsForNode_EmptyList(t *testing.T) {
	r, _ := newTestReconciler(t)
	reqs := controllerhelper.EnqueueAllOfType(context.Background(), r.Client, &artifactv1alpha1.PluginList{})
	assert.Empty(t, reqs)
}

// ── Reconcile remaining error paths ─────────────────────────────────────────

func TestReconcile_EnsureInUseFinalizerError(t *testing.T) {
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	plugin := newTestPlugin()
	node := newTestNode(testutil.TestNodeName, nil)
	pluginNode := testutil.NewReportingArtifactNode("Plugin", testPluginName)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(plugin, node, pluginNode, testutil.NewTestFalco(), testutil.NewRunningFalcoPod()).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return fmt.Errorf("patch failed")
			},
		}).
		Build()
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), nil)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
}

func TestReconcile_FetchAndCacheError(t *testing.T) {
	mockPuller := &pullerfake.MockOCIPuller{
		FetchConfigErr: fmt.Errorf("registry down"),
	}
	plugin := newTestPlugin(withPluginOCI())
	node := newTestNode(testutil.TestNodeName, nil)
	pluginNode := testutil.NewReportingArtifactNode("Plugin", testPluginName)
	r, cl := newTestReconcilerWithPuller(t, mockPuller, plugin, node, pluginNode)
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.ErrorContains(t, err, "registry down")

	// The failure is on the Plugin, where its user looks, and not only in the operator's log.
	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, cl.Get(context.Background(), client.ObjectKeyFromObject(plugin), got))
	programmed := apimeta.FindStatusCondition(got.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())
	require.NotNil(t, programmed)
	assert.Equal(t, metav1.ConditionFalse, programmed.Status)
	assert.Contains(t, programmed.Message, "registry down")
}

// ── HandleDeletion delete error ──────────────────────────────────────────────

// newTestReconcilerWithCacheAndPuller creates a PluginAggregatorReconciler with a real,
// loaded artifact Cache rooted at cacheDir, and an injected mock OCI puller.
func newTestReconcilerWithCacheAndPuller(
	t *testing.T, mockPuller puller.Puller, cacheDir string, objs ...client.Object,
) *PluginAggregatorReconciler {
	t.Helper()
	s := testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&artifactv1alpha1.Plugin{}).
		Build()
	// Zero grace period: dereferenced blobs are removed from disk immediately.
	cache := artifactcache.NewCache(cacheDir, artifactcache.WithEvictionGracePeriod(0))
	require.NoError(t, cache.Load())
	r := NewPluginAggregatorReconciler(cl, s, events.NewFakeRecorder(100), cache)
	r.ociPuller = mockPuller
	return r
}

func TestFetchAndCacheBinaries_NoCache(t *testing.T) {
	// A nil cache disables caching; fetchAndCacheBlobs returns immediately.
	plugin := newTestPlugin(withPluginOCI())
	r, _ := newTestReconciler(t, plugin) // cache = nil
	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	err := r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node})
	require.NoError(t, err)
}

func TestFetchAndCacheBinaries_NoOCIArtifact(t *testing.T) {
	// No OCI spec → noop regardless of cacheDir.
	plugin := newTestPlugin() // no OCIArtifact
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, plugin)
	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	err := r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node})
	require.NoError(t, err)
}

func TestFetchAndCacheBinaries_NoOSArchLabels(t *testing.T) {
	// Nodes without kubernetes.io/os or kubernetes.io/arch labels → empty platform set → noop.
	plugin := newTestPlugin(withPluginOCI())
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, plugin)
	node := newTestNode(testutil.TestNodeName, nil)
	err := r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node})
	require.NoError(t, err)
}

func TestFetchAndCacheBinaries_FastPath(t *testing.T) {
	// This CR's cache entry already points at the blob for the known digest: no registry
	// call needed.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())
	mockPuller := &pullerfake.MockOCIPuller{} // must not be called
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	ref := artifact.ResolveReference(plugin.Spec.OCIArtifact)
	const digest = testPluginDigest
	blobPath := artifactcache.BlobPath(cacheDir, string(artifact.KindPlugin), ref, digest, "linux", "amd64")
	require.NoError(t, r.cache.Store(blobPath, []byte("fake-plugin"), 0o755))
	require.NoError(t, r.cache.Set(string(artifact.KindPlugin), testutil.TestNamespace, testPluginName, "linux-amd64", blobPath))

	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: digest}

	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	require.NoError(t, r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node}))

	assert.Empty(t, mockPuller.ResolveDigestCalls)
	assert.Empty(t, mockPuller.PullCalls)

	idx, ok := r.cache.Lookup(string(artifact.KindPlugin), testutil.TestNamespace, testPluginName, "linux-amd64")
	require.True(t, ok)
	assert.Equal(t, blobPath, idx)
}

func TestFetchAndCacheBinaries_SlowPath(t *testing.T) {
	// Blob is missing: EnsureBlob pulls from registry and writes the index.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())

	tarGz, err := pullerfake.MakeTarGz("plugin.so", []byte("plugin-binary-content"))
	require.NoError(t, err)

	mockPuller := &pullerfake.MockOCIPuller{
		ResolveDigestResult: testPluginDigest,
		Result:              &puller.RegistryResult{RootDigest: testPluginDigest, Type: puller.Plugin},
		LayerContent:        tarGz,
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	require.NoError(t, r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node}))

	require.Len(t, mockPuller.PullCalls, 1)
	assert.Equal(t, "linux", mockPuller.PullCalls[0].OS)
	assert.Equal(t, "amd64", mockPuller.PullCalls[0].Arch)

	_, ok := r.cache.Lookup(string(artifact.KindPlugin), testutil.TestNamespace, testPluginName, "linux-amd64")
	require.True(t, ok)
}

func TestFetchAndCacheBinaries_PullError(t *testing.T) {
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())
	mockPuller := &pullerfake.MockOCIPuller{
		ResolveDigestResult: testPluginDigest,
		PullErr:             fmt.Errorf("registry unreachable"),
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	err := r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry unreachable")
}

func TestFetchAndCacheBinaries_DeduplicatesPlatforms(t *testing.T) {
	// Two nodes with the same (os, arch) should trigger only one pull.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())

	tarGz, err := pullerfake.MakeTarGz("plugin.so", []byte("data"))
	require.NoError(t, err)

	mockPuller := &pullerfake.MockOCIPuller{
		ResolveDigestResult: testPluginDigest,
		Result:              &puller.RegistryResult{RootDigest: testPluginDigest, Type: puller.Plugin},
		LayerContent:        tarGz,
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	labels := map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}
	node1 := newTestNode("node-1", labels)
	node2 := newTestNode("node-2", labels)

	require.NoError(t, r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node1, *node2}))
	assert.Len(t, mockPuller.PullCalls, 1)
}

func TestFetchAndCacheBinaries_MultiplePlatforms(t *testing.T) {
	// Two nodes with different (os, arch) pairs must each trigger a pull.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())

	tarGz, err := pullerfake.MakeTarGz("plugin.so", []byte("data"))
	require.NoError(t, err)

	mockPuller := &pullerfake.MockOCIPuller{
		ResolveDigestResult: testPluginDigest,
		Result:              &puller.RegistryResult{RootDigest: testPluginDigest, Type: puller.Plugin},
		LayerContent:        tarGz,
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin)

	node1 := newTestNode("node-1", map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
	node2 := newTestNode("node-2", map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "arm64"})

	require.NoError(t, r.fetchAndCacheBlobs(context.Background(), plugin, []corev1.Node{*node1, *node2}))
	assert.Len(t, mockPuller.PullCalls, 2)
}

// Each platform has distinct bytes so a cross-architecture cache mix-up is observable.
type platformPluginPuller struct {
	*pullerfake.MockOCIPuller
	layers map[string][]byte
}

func (p *platformPluginPuller) Pull(
	ctx context.Context, ref, goos, goarch string, creds auth.CredentialFunc, opts *puller.RegistryOptions, dst io.Writer,
) (*puller.RegistryResult, error) {
	p.LayerContent = p.layers[goarch]
	return p.MockOCIPuller.Pull(ctx, ref, goos, goarch, creds, opts, dst)
}

func TestReconcile_NewNodesKeepResolvedRevision(t *testing.T) {
	const amd64Arch, arm64Arch = "amd64", "arm64"
	const emptyCache = "empty after restart"
	ctx := context.Background()
	plugin := newTestPlugin(withPluginOCI())
	plugin.Spec.OCIArtifact.Image.Repository = "test/plugin"
	plugin.Generation = 1
	node := newTestNode(testutil.TestNodeName, map[string]string{corev1.LabelOSStable: "linux", corev1.LabelArchStable: amd64Arch})
	mockPuller := &platformPluginPuller{
		MockOCIPuller: &pullerfake.MockOCIPuller{
			ConfigResult: &puller.ArtifactConfig{}, ConfigDigest: testPluginDigest,
			Result: &puller.RegistryResult{RootDigest: testPluginDigest, Type: puller.Plugin},
		},
		layers: make(map[string][]byte),
	}
	for _, arch := range []string{amd64Arch, arm64Arch} {
		layer, err := pullerfake.MakeTarGz("plugin.so", []byte("revision A for "+arch))
		require.NoError(t, err)
		mockPuller.layers[arch] = layer
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, t.TempDir(), plugin, node, testutil.NewTestFalco(), testutil.NewRunningFalcoPod())
	_, err := r.Reconcile(ctx, testutil.Request(plugin.Name))
	require.NoError(t, err)
	require.Len(t, mockPuller.FetchConfigCalls, 1)
	require.Len(t, mockPuller.PullCalls, 1)

	// Any accidental new tag resolution now yields B, even though the CR still desires A.
	mockPuller.ConfigDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	mockPuller.ResolveDigestResult = mockPuller.ConfigDigest
	for _, arch := range []string{amd64Arch, arm64Arch} {
		t.Run("new node "+arch, func(t *testing.T) {
			added := newTestNode("new-"+arch, map[string]string{corev1.LabelOSStable: "linux", corev1.LabelArchStable: arch})
			require.NoError(t, r.Create(ctx, added))
			pod := testutil.NewRunningFalcoPod()
			pod.Name = "falco-" + arch
			pod.Spec.NodeName = added.Name
			require.NoError(t, r.Create(ctx, pod))
			if arch == arm64Arch {
				mockPuller.PullErr = fmt.Errorf("platform unavailable")
				_, reconcileErr := r.Reconcile(ctx, testutil.Request(plugin.Name))
				require.ErrorContains(t, reconcileErr, "platform unavailable")
				_, ok := r.cache.Lookup(string(artifact.KindPlugin), plugin.Namespace, plugin.Name, "linux-"+arm64Arch)
				require.False(t, ok, "a failed pull must not publish a cache entry")
				mockPuller.PullErr = nil
			}
			_, reconcileErr := r.Reconcile(ctx, testutil.Request(plugin.Name))
			require.NoError(t, reconcileErr)
			if arch == amd64Arch {
				require.Len(t, mockPuller.PullCalls, 1, "a new node of a cached architecture needs no new registry pull")
			}
		})
	}

	for _, state := range []string{"warm", "reloaded", emptyCache} {
		t.Run(state, func(t *testing.T) {
			if state != "warm" {
				cacheDir := r.cache.Dir()
				if state == emptyCache {
					cacheDir = t.TempDir()
				}
				r.cache = artifactcache.NewCache(cacheDir)
				require.NoError(t, r.cache.Load())
			}
			pullsBefore := len(mockPuller.PullCalls)
			_, reconcileErr := r.Reconcile(ctx, testutil.Request(plugin.Name))
			require.NoError(t, reconcileErr)
			wantPulls := pullsBefore
			if state == emptyCache {
				wantPulls += 2
			}
			require.Len(t, mockPuller.PullCalls, wantPulls)
			got := &artifactv1alpha1.Plugin{}
			require.NoError(t, r.Get(ctx, client.ObjectKeyFromObject(plugin), got))
			require.Equal(t, testPluginDigest, got.Status.ArtifactMeta.Digest)
			require.Equal(t, got.Generation, got.Status.ObservedGeneration)
			require.Len(t, mockPuller.FetchConfigCalls, 1)
			require.Empty(t, mockPuller.ResolveDigestCalls)
			for _, call := range mockPuller.PullCalls {
				require.Equal(t, "ghcr.io/test/plugin@"+testPluginDigest, call.Ref)
				require.Equal(t, "linux", call.OS)
			}
			for _, arch := range []string{amd64Arch, arm64Arch} {
				request := httptest.NewRequestWithContext(ctx, http.MethodGet,
					"/v1/artifacts/plugins/"+plugin.Namespace+"/"+plugin.Name+"?os=linux&arch="+arch+"&digest="+testPluginDigest, http.NoBody)
				response := httptest.NewRecorder()
				artifactserver.New(r.cache).Handler().ServeHTTP(response, request)
				require.Equal(t, http.StatusOK, response.Code)
				require.Equal(t, "revision A for "+arch, response.Body.String())
				require.Equal(t, testPluginDigest, response.Header().Get(artifact.ArtifactDigestHeader))
			}
		})
	}
}

func TestReconcile_FetchAndCacheBinariesError(t *testing.T) {
	// fetchAndCacheArtifactMeta succeeds and sets Status.ArtifactMeta.Digest.
	// fetchAndCacheBlobs uses that digest as knownDigest → skips ResolveDigest,
	// goes straight to Pull → Pull fails.
	cacheDir := t.TempDir()
	plugin := newTestPlugin(withPluginOCI())
	node := newTestNode(testutil.TestNodeName, map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})

	mockPuller := &pullerfake.MockOCIPuller{
		ConfigResult: &puller.ArtifactConfig{},
		ConfigDigest: testPluginDigest,
		PullErr:      fmt.Errorf("registry down"),
	}
	r := newTestReconcilerWithCacheAndPuller(t, mockPuller, cacheDir, plugin, node, testutil.NewTestFalco(), testutil.NewRunningFalcoPod())
	_, err := r.Reconcile(context.Background(), testutil.Request(testPluginName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry down")
}

func TestReconcile_CacheOwnershipSurvivesLastNodeRemoval(t *testing.T) {
	ctx := context.Background()
	plugin := newTestPlugin(withPluginOCI(), withPluginSelector())
	plugin.Generation = 2
	plugin.Finalizers = []string{controllerhelper.NodeObjectsInUseFinalizer}
	specHash, err := artifact.ComputeOCIArtifactSpecHash(plugin.Spec.OCIArtifact)
	require.NoError(t, err)
	plugin.Status.ArtifactMeta = &commonv1alpha1.ArtifactMeta{Digest: testPluginDigest, SpecHash: specHash}
	plugin.Status.ObservedGeneration = plugin.Generation

	// A prior successful reconcile left the cache populated. The selector has now
	// stopped matching all nodes and the previous child cleanup has completed.
	cacheDir := t.TempDir()
	r := newTestReconcilerWithCacheAndPuller(t, nil, cacheDir, plugin)
	ref := artifact.ResolveReference(plugin.Spec.OCIArtifact)
	blobPath := artifactcache.BlobPath(cacheDir, string(artifact.KindPlugin), ref, testPluginDigest, "linux", "amd64")
	require.NoError(t, r.cache.Store(blobPath, []byte("previously-installed-plugin"), 0o755))
	require.NoError(t, r.cache.Set(string(artifact.KindPlugin), plugin.Namespace, plugin.Name, "linux-amd64", blobPath))

	_, err = r.Reconcile(ctx, testutil.Request(testPluginName))
	require.NoError(t, err)
	got := &artifactv1alpha1.Plugin{}
	require.NoError(t, r.Get(ctx, client.ObjectKeyFromObject(plugin), got))
	t.Logf("after zero matches: finalizers=%v", got.Finalizers)
	require.NoError(t, r.Delete(ctx, got))
	_, err = r.Reconcile(ctx, testutil.Request(testPluginName))
	require.NoError(t, err)
	removed, err := r.cache.Sweep(ctx)
	require.NoError(t, err)
	t.Logf("deleted parent; cache sweep removed=%d", removed)
	_, cached := r.cache.Lookup(string(artifact.KindPlugin), plugin.Namespace, plugin.Name, "linux-amd64")
	require.False(t, cached, "deleting the parent must release its cache reference even after its selector stopped matching nodes")
}

const newUID = "new-uid"

func TestReconcile_AggregatesFromTheArtifactNode(t *testing.T) {
	const uid = "plugin-uid"
	programmed := func(status metav1.ConditionStatus) []metav1.Condition {
		return []metav1.Condition{{Type: "Programmed", Status: status, Reason: "Programmed", ObservedGeneration: 1}}
	}

	for name, tc := range map[string]struct {
		conditions     []metav1.Condition
		wantProgrammed bool
	}{
		"the node reports programmed":   {programmed(metav1.ConditionTrue), true},
		"the node reports failure":      {programmed(metav1.ConditionFalse), false},
		"the node has not reported yet": {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			plugin := newTestPlugin(func(p *artifactv1alpha1.Plugin) { p.Generation, p.UID = 1, uid })
			node := testutil.NewReportingArtifactNode("Plugin", testPluginName, func(n *artifactv1alpha1.ArtifactNode) {
				n.Status.Artifacts[0].UID = uid
				n.Status.Artifacts[0].Conditions = tc.conditions
			})
			r, cl := newTestReconciler(t, plugin, newTestNode(testutil.TestNodeName, nil), testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), node)

			_, err := r.Reconcile(t.Context(), testutil.Request(plugin.Name))
			require.NoError(t, err)

			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(plugin), plugin))
			assert.Equal(t, tc.wantProgrammed, apimeta.IsStatusConditionTrue(plugin.Status.Conditions, "Programmed"))
		})
	}
}

func TestReconcile_APreviousIncarnationsEntryIsNotCreditedToTheNewPlugin(t *testing.T) {
	plugin := newTestPlugin(func(p *artifactv1alpha1.Plugin) { p.Generation, p.UID = 1, newUID })
	node := testutil.NewReportingArtifactNode("Plugin", testPluginName, func(n *artifactv1alpha1.ArtifactNode) {
		n.Spec.Artifacts[0].UID = newUID
		n.Status.Artifacts[0].UID = "old-uid"
		n.Status.Artifacts[0].Conditions = []metav1.Condition{
			{Type: "Programmed", Status: metav1.ConditionTrue, Reason: "Programmed", ObservedGeneration: 1},
		}
	})
	r, cl := newTestReconciler(t, plugin, newTestNode(testutil.TestNodeName, nil), testutil.NewTestFalco(), testutil.NewRunningFalcoPod(), node)

	_, err := r.Reconcile(t.Context(), testutil.Request(plugin.Name))
	require.NoError(t, err)

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(plugin), plugin))
	assert.False(t, apimeta.IsStatusConditionTrue(plugin.Status.Conditions, "Programmed"),
		"the deleted plugin's success must not make its replacement look programmed")
}

func TestReconcile_DeletionWaitsForNodeCleanup(t *testing.T) {
	plugin := newTestPlugin(func(p *artifactv1alpha1.Plugin) {
		p.Finalizers = []string{controllerhelper.NodeObjectsInUseFinalizer}
	})
	artifactNode := testutil.NewTestArtifactNode()
	artifactNode.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{{Kind: "Plugin", Name: plugin.Name}}
	r, cl := newTestReconciler(t, plugin, artifactNode)
	require.NoError(t, cl.Delete(t.Context(), plugin))

	_, err := r.Reconcile(t.Context(), testutil.Request(plugin.Name))
	require.NoError(t, err)
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(plugin), plugin))
	assert.Contains(t, plugin.Finalizers, controllerhelper.NodeObjectsInUseFinalizer,
		"a node still reports on the plugin, so its files may remain: the parent must stay")

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(artifactNode), artifactNode))
	artifactNode.Status.Artifacts = nil
	require.NoError(t, cl.Status().Update(t.Context(), artifactNode))

	_, err = r.Reconcile(t.Context(), testutil.Request(plugin.Name))
	require.NoError(t, err)
	err = cl.Get(t.Context(), client.ObjectKeyFromObject(plugin), plugin)
	assert.True(t, k8serrors.IsNotFound(err), "with every node clean the parent is released")
}

func TestReconcile_DeletionShowsABlockPublishedThroughTheArtifactNode(t *testing.T) {
	plugin := newTestPlugin(func(p *artifactv1alpha1.Plugin) {
		p.Generation = 1
		p.Finalizers = []string{controllerhelper.NodeObjectsInUseFinalizer}
	})
	artifactNode := testutil.NewTestArtifactNode()
	artifactNode.Status.Artifacts = []artifactv1alpha1.NodeArtifactStatus{{
		Kind: "Plugin", Name: plugin.Name,
		Conditions: []metav1.Condition{{
			Type: "DeletionBlocked", Status: metav1.ConditionTrue, Reason: "PluginConfigStillRequired",
			Message: "required by rulesfile x", ObservedGeneration: 1,
		}},
	}}
	// The node is running Falco, so the aggregate reports on it.
	r, cl := newTestReconciler(t, plugin, artifactNode, newTestNode(testutil.TestNodeName, nil), testutil.NewTestFalco(), testutil.NewRunningFalcoPod())
	require.NoError(t, cl.Delete(t.Context(), plugin))

	_, err := r.Reconcile(t.Context(), testutil.Request(plugin.Name))
	require.NoError(t, err)

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(plugin), plugin))
	blocked := apimeta.FindStatusCondition(plugin.Status.Conditions, "DeletionBlocked")
	require.NotNil(t, blocked, "the block the sidecar published through the ArtifactNode must reach the parent")
	assert.Equal(t, metav1.ConditionTrue, blocked.Status)
}

var errBoom = errors.New("boom")

func TestHandleDeletion_Errors(t *testing.T) {
	deleting := func() *artifactv1alpha1.Plugin {
		return newTestPlugin(func(p *artifactv1alpha1.Plugin) {
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
			plugin := deleting()
			r, cl := newTestReconciler(t, plugin)
			r.Client = interceptor.NewClient(cl.(client.WithWatch), tt.funcs)

			_, err := shared.HandleDeletion(t.Context(), r.aggregation(), plugin)

			require.ErrorIs(t, err, errBoom)
		})
	}
}

func TestSetupWithManager(t *testing.T) {
	r, _ := newTestReconciler(t)
	mgr := testutil.NewUnstartedManager(t, testutil.Scheme(t, artifactv1alpha1.AddToScheme, instancev1alpha1.AddToScheme))

	require.NoError(t, r.SetupWithManager(mgr))
}
