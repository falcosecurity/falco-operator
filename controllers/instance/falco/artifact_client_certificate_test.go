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

package falco

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
)

func getArtifactClientCertificate(t *testing.T, ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	t.Helper()
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"})
	err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, cert)
	return cert, err
}

func TestEnsureArtifactClientCertificate(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		enabled                       bool
		duration, renewBefore         time.Duration
		wantDuration, wantRenewBefore string
	}{
		{name: "disabled"},
		{
			name: "enabled", enabled: true,
			wantDuration: DefaultArtifactClientCertDuration.String(), wantRenewBefore: DefaultArtifactClientCertRenewBefore.String(),
		},
		{
			name: "custom-duration", enabled: true, duration: 48 * time.Hour, renewBefore: 12 * time.Hour,
			wantDuration: "48h0m0s", wantRenewBefore: "12h0m0s",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			falco := createFalco(t, ctx, &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cert-" + tc.name, Namespace: testutil.TestNamespace},
			})
			reconciler := newTestReconciler()
			if tc.enabled {
				reconciler = NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100),
					WithArtifactMTLS("my-cluster-issuer", "my-falco-operator-artifact-ca-bundle", tc.duration, tc.renewBefore))
			}
			require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))
			wantName := artifactClientCertSecretName(falco)
			cert, err := getArtifactClientCertificate(t, ctx, falco.Namespace, wantName)
			if !tc.enabled {
				assert.True(t, errors.IsNotFound(err), "no Certificate should be created when mTLS is disabled")
				return
			}
			require.NoError(t, err)
			secretName, _, _ := unstructured.NestedString(cert.Object, "spec", "secretName")
			assert.Equal(t, wantName, secretName)
			issuerName, _, _ := unstructured.NestedString(cert.Object, "spec", "issuerRef", "name")
			assert.Equal(t, "my-cluster-issuer", issuerName)
			issuerKind, _, _ := unstructured.NestedString(cert.Object, "spec", "issuerRef", "kind")
			assert.Equal(t, "ClusterIssuer", issuerKind)
			uris, _, _ := unstructured.NestedStringSlice(cert.Object, "spec", "uris")
			require.Len(t, uris, 1)
			assert.Equal(t, fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s", falco.Namespace, falco.Name), uris[0])
			duration, _, _ := unstructured.NestedString(cert.Object, "spec", "duration")
			assert.Equal(t, tc.wantDuration, duration)
			renewBefore, _, _ := unstructured.NestedString(cert.Object, "spec", "renewBefore")
			assert.Equal(t, tc.wantRenewBefore, renewBefore)
			ownerRefs := cert.GetOwnerReferences()
			require.Len(t, ownerRefs, 1)
			assert.Equal(t, falco.Name, ownerRefs[0].Name)
			assert.Equal(t, falco.UID, ownerRefs[0].UID)
			assert.Equal(t, "Falco", ownerRefs[0].Kind)
			require.NotNil(t, ownerRefs[0].Controller)
			assert.True(t, *ownerRefs[0].Controller)

			beforeVersion := cert.GetResourceVersion()
			cl, err := client.NewWithWatch(testEnv.Config, client.Options{Scheme: k8sClient.Scheme()})
			require.NoError(t, err)
			reconciler.Client = interceptor.NewClient(cl, interceptor.Funcs{
				Apply: func(context.Context, client.WithWatch, runtime.ApplyConfiguration, ...client.ApplyOption) error {
					return fmt.Errorf("unchanged Certificate must not be applied")
				},
			})
			require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))
			cert, err = getArtifactClientCertificate(t, ctx, falco.Namespace, wantName)
			require.NoError(t, err)
			assert.Equal(t, beforeVersion, cert.GetResourceVersion())
		})
	}
}

func TestEnsureArtifactClientCertificateRecreatedOwner(t *testing.T) {
	for _, tc := range []struct {
		name       string
		extraOwner bool
	}{
		{name: "controller-only"},
		{name: "unrelated-owner", extraOwner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			falco := createFalco(t, ctx, &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cert-recreated-owner-" + tc.name, Namespace: testutil.TestNamespace},
			})
			reconciler := NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100),
				WithArtifactMTLS("my-cluster-issuer", "my-falco-operator-artifact-ca-bundle", 0, 0))
			require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))
			cert, err := getArtifactClientCertificate(t, ctx, falco.Namespace, artifactClientCertSecretName(falco))
			require.NoError(t, err)
			original := cert.DeepCopy()

			// Preserve an unrelated owner and annotation while replacing the controller UID.
			unrelatedOwner := metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "unrelated", UID: "unrelated-uid"}
			if tc.extraOwner {
				cert.SetOwnerReferences(append(cert.GetOwnerReferences(), unrelatedOwner))
			}
			cert.SetAnnotations(map[string]string{"test.falcosecurity.dev/retain": "true"})
			require.NoError(t, k8sClient.Update(ctx, cert, client.FieldOwner("certificate-observer")))
			require.NoError(t, unstructured.SetNestedField(cert.Object, "Ready", "status", "testState"))
			require.NoError(t, k8sClient.Status().Update(ctx, cert))

			// Envtest has no garbage collector, making the otherwise transient old-owner
			// state deterministic without changing the Certificate's SSA field ownership.
			require.NoError(t, k8sClient.Delete(ctx, falco))
			replacement := createFalco(t, ctx, &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{Name: falco.Name, Namespace: falco.Namespace},
			})
			require.NotEqual(t, falco.UID, replacement.UID)
			require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, replacement))

			cert, err = getArtifactClientCertificate(t, ctx, replacement.Namespace, artifactClientCertSecretName(replacement))
			require.NoError(t, err)
			owner := metav1.GetControllerOf(cert)
			require.NotNil(t, owner)
			assert.Equal(t, replacement.UID, owner.UID)
			assert.Equal(t, original.GetUID(), cert.GetUID(), "repair must not recreate the Certificate")
			assert.Equal(t, original.Object["spec"], cert.Object["spec"])
			wantOwnerCount := 1
			if tc.extraOwner {
				assert.Contains(t, cert.GetOwnerReferences(), unrelatedOwner)
				wantOwnerCount++
			}
			require.Len(t, cert.GetOwnerReferences(), wantOwnerCount, "SSA must remove the previous controller reference")
			assert.Equal(t, "true", cert.GetAnnotations()["test.falcosecurity.dev/retain"])
			state, _, err := unstructured.NestedString(cert.Object, "status", "testState")
			require.NoError(t, err)
			assert.Equal(t, "Ready", state)

			cl, err := client.NewWithWatch(testEnv.Config, client.Options{Scheme: k8sClient.Scheme()})
			require.NoError(t, err)
			reconciler.Client = interceptor.NewClient(cl, interceptor.Funcs{
				Apply: func(context.Context, client.WithWatch, runtime.ApplyConfiguration, ...client.ApplyOption) error {
					return fmt.Errorf("unrelated owner and status must not trigger another Apply")
				},
			})
			require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, replacement))
		})
	}
}

func TestEnsureArtifactClientCertificateOwnerDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*unstructured.Unstructured)
	}{
		{name: "missing", mutate: func(cert *unstructured.Unstructured) { cert.SetOwnerReferences(nil) }},
		{name: "not-controller", mutate: func(cert *unstructured.Unstructured) {
			refs := cert.GetOwnerReferences()
			refs[0].Controller = new(false)
			cert.SetOwnerReferences(refs)
		}},
		{name: "not-blocking-deletion", mutate: func(cert *unstructured.Unstructured) {
			refs := cert.GetOwnerReferences()
			refs[0].BlockOwnerDeletion = new(false)
			cert.SetOwnerReferences(refs)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			falco := createFalco(t, ctx, &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cert-owner-" + tc.name, Namespace: testutil.TestNamespace},
			})
			reconciler := NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100),
				WithArtifactMTLS("my-cluster-issuer", "my-falco-operator-artifact-ca-bundle", 0, 0))
			require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))
			cert, err := getArtifactClientCertificate(t, ctx, falco.Namespace, artifactClientCertSecretName(falco))
			require.NoError(t, err)
			want := cert.GetOwnerReferences()
			tc.mutate(cert)
			require.NoError(t, k8sClient.Update(ctx, cert))
			require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))
			cert, err = getArtifactClientCertificate(t, ctx, falco.Namespace, artifactClientCertSecretName(falco))
			require.NoError(t, err)
			assert.Equal(t, want, cert.GetOwnerReferences())
		})
	}
}

func TestEnsureArtifactClientCertificateErrors(t *testing.T) {
	for _, operation := range []string{"get", "apply", "disabled"} {
		t.Run(operation, func(t *testing.T) {
			if operation == "disabled" {
				reconciler := NewReconciler(nil, k8sClient.Scheme(), events.NewFakeRecorder(100), WithArtifactMTLS("", "", 0, 0))
				require.NoError(t, reconciler.ensureArtifactClientCertificate(t.Context(), &instancev1alpha1.Falco{}))
				return
			}
			ctx := context.Background()
			falco := createFalco(t, ctx, &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cert-error-" + operation, Namespace: testutil.TestNamespace},
			})
			reconciler := NewReconciler(k8sClient, k8sClient.Scheme(), events.NewFakeRecorder(100),
				WithArtifactMTLS("my-cluster-issuer", "my-falco-operator-artifact-ca-bundle", 0, 0))
			require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))
			cert, err := getArtifactClientCertificate(t, ctx, falco.Namespace, artifactClientCertSecretName(falco))
			require.NoError(t, err)
			refs := cert.GetOwnerReferences()
			refs[0].Controller = new(false)
			cert.SetOwnerReferences(refs)
			require.NoError(t, k8sClient.Update(ctx, cert))
			cl, err := client.NewWithWatch(testEnv.Config, client.Options{Scheme: k8sClient.Scheme()})
			require.NoError(t, err)
			failure := fmt.Errorf("injected %s failure", operation)
			fail := true
			intercepted := interceptor.NewClient(cl, interceptor.Funcs{
				Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if fail && operation == "get" {
						return failure
					}
					return cl.Get(ctx, key, obj, opts...)
				},
				Apply: func(ctx context.Context, cl client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					if fail && operation == "apply" {
						return failure
					}
					return cl.Apply(ctx, obj, opts...)
				},
			})
			reconciler.Client = intercepted
			require.ErrorIs(t, reconciler.ensureArtifactClientCertificate(ctx, falco), failure)
			cert, err = getArtifactClientCertificate(t, ctx, falco.Namespace, artifactClientCertSecretName(falco))
			require.NoError(t, err)
			assert.Equal(t, refs, cert.GetOwnerReferences(), "failed repair must leave existing state intact")
			fail = false
			require.NoError(t, reconciler.ensureArtifactClientCertificate(ctx, falco))
			cert, err = getArtifactClientCertificate(t, ctx, falco.Namespace, artifactClientCertSecretName(falco))
			require.NoError(t, err)
			owner := metav1.GetControllerOf(cert)
			require.NotNil(t, owner)
			assert.Equal(t, falco.UID, owner.UID)
		})
	}
}

func TestArtifactClientCertificateWatch(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("mtls-%t", enabled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			syncPeriod := 24 * time.Hour
			mgr, err := ctrl.NewManager(testEnv.Config, ctrl.Options{
				Scheme:     k8sClient.Scheme(),
				Metrics:    metricsserver.Options{BindAddress: "0"},
				Cache:      cache.Options{SyncPeriod: &syncPeriod, ReaderFailOnMissingInformer: true},
				Controller: controllerconfig.Controller{SkipNameValidation: new(true)},
			})
			require.NoError(t, err)
			var options []Option
			if enabled {
				options = append(options, WithArtifactMTLS("my-cluster-issuer", "my-falco-operator-artifact-ca-bundle", 0, 0))
			}
			// Count parent reads to establish quiescence before each Certificate-only
			// mutation; residual startup events must not masquerade as watch recovery.
			cl, err := client.NewWithWatch(testEnv.Config, client.Options{
				Scheme: k8sClient.Scheme(),
				Cache:  &client.CacheOptions{Reader: mgr.GetCache()},
			})
			require.NoError(t, err)
			var parentReads atomic.Uint64
			var failCertificateApply atomic.Bool
			reconciler := NewReconciler(interceptor.NewClient(cl, interceptor.Funcs{
				Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*instancev1alpha1.Falco); ok {
						parentReads.Add(1)
					}
					return cl.Get(ctx, key, obj, opts...)
				},
				Apply: func(ctx context.Context, cl client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					if resource, ok := obj.(runtime.Object); ok && resource.GetObjectKind().GroupVersionKind().Kind == "Certificate" &&
						failCertificateApply.CompareAndSwap(true, false) {
						return fmt.Errorf("injected transient Certificate Apply failure")
					}
					return cl.Apply(ctx, obj, opts...)
				},
			}), mgr.GetScheme(), mgr.GetEventRecorder("falco-certificate-test"), options...)
			require.NoError(t, reconciler.SetupWithManager(mgr))
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
			falco := createFalco(t, context.Background(), &instancev1alpha1.Falco{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("test-cert-watch-%t", enabled), Namespace: testutil.TestNamespace},
			})
			require.Eventually(t, func() bool {
				return cl.Get(ctx, client.ObjectKeyFromObject(falco), &appsv1.DaemonSet{}) == nil
			}, 10*time.Second, 20*time.Millisecond)
			certificate := &unstructured.Unstructured{}
			certificate.SetGroupVersionKind(schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"})
			key := client.ObjectKey{Namespace: falco.Namespace, Name: artifactClientCertSecretName(falco)}
			if !enabled {
				err := mgr.GetCache().Get(ctx, key, certificate)
				var notCached *cache.ErrResourceNotCached
				require.ErrorAs(t, err, &notCached, "disabled mTLS must not register a Certificate informer")
				require.True(t, errors.IsNotFound(cl.Get(ctx, key, certificate)))
				return
			}
			require.NoError(t, cl.Get(ctx, key, certificate))
			waitForQuiet := func() {
				t.Helper()
				previous, lastChange := parentReads.Load(), time.Now()
				require.Eventually(t, func() bool {
					current := parentReads.Load()
					if current != previous {
						previous, lastChange = current, time.Now()
					}
					return time.Since(lastChange) >= 300*time.Millisecond
				}, 10*time.Second, 20*time.Millisecond, "controller must settle before testing an isolated Certificate event")
			}
			waitForQuiet()
			originalUID := certificate.GetUID()
			failCertificateApply.Store(true)
			require.NoError(t, cl.Delete(ctx, certificate))
			require.Eventually(t, func() bool {
				return cl.Get(ctx, key, certificate) == nil && certificate.GetUID() != originalUID
			}, 10*time.Second, 20*time.Millisecond, "Certificate deletion must recover without a Falco edit")
			assert.False(t, failCertificateApply.Load(), "recovery must retry the injected Apply failure")
			assert.Equal(t, falco.UID, metav1.GetControllerOf(certificate).UID)
			waitForQuiet()
			require.NoError(t, cl.Get(ctx, key, certificate))
			require.NoError(t, unstructured.SetNestedField(certificate.Object, "1h0m0s", "spec", "duration"))
			require.NoError(t, cl.Update(ctx, certificate))
			require.Eventually(t, func() bool {
				if err := cl.Get(ctx, key, certificate); err != nil {
					return false
				}
				duration, _, _ := unstructured.NestedString(certificate.Object, "spec", "duration")
				return duration == DefaultArtifactClientCertDuration.String()
			}, 10*time.Second, 20*time.Millisecond, "Certificate drift must recover without a Falco edit")
			waitForQuiet()
			require.NoError(t, cl.Get(ctx, key, certificate))
			certificate.SetOwnerReferences(nil)
			require.NoError(t, cl.Update(ctx, certificate))
			require.Eventually(t, func() bool {
				if err := cl.Get(ctx, key, certificate); err != nil {
					return false
				}
				owner := metav1.GetControllerOf(certificate)
				return owner != nil && owner.UID == falco.UID
			}, 10*time.Second, 20*time.Millisecond, "owner-only drift must reconcile using the old event owner")
		})
	}
}
