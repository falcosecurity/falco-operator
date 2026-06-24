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

package testutil

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// StartEnvtest boots an envtest API server with the project CRDs installed and a freshly built
// scheme (Kubernetes built-ins plus the given adders), returning a client and a stop function to
// defer. The scheme is local to this call, never the client-go global, so concurrent suites and
// repeated calls cannot contaminate one another.
func StartEnvtest(adders ...func(*runtime.Scheme) error) (client.Client, func(), error) {
	ctrllog.SetLogger(zap.New(zap.WriteTo(io.Discard), zap.UseDevMode(true)))

	s := runtime.NewScheme()
	for _, add := range append([]func(*runtime.Scheme) error{clientgoscheme.AddToScheme}, adders...) {
		if err := add(s); err != nil {
			return nil, nil, err
		}
	}

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{CRDDirPath()},
		ErrorIfCRDPathMissing: true,
	}
	if dir := GetFirstFoundEnvTestBinaryDir(); dir != "" {
		env.BinaryAssetsDirectory = dir
	}

	cfg, err := env.Start()
	if err != nil {
		return nil, nil, err
	}

	cl, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		_ = env.Stop()
		return nil, nil, err
	}

	stop := func() {
		if err := env.Stop(); err != nil {
			ctrllog.Log.Error(err, "failed to stop envtest")
		}
	}
	return cl, stop, nil
}

// CleanupObject removes finalizers (retrying on conflict) and deletes obj, tolerating an
// already-deleted object. Use it from t.Cleanup so a finalized object never strands and blocks
// a later test reusing the same name.
func CleanupObject(t *testing.T, ctx context.Context, cl client.Client, obj client.Object) {
	t.Helper()
	key := client.ObjectKeyFromObject(obj)

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fetched := obj.DeepCopyObject().(client.Object)
		if err := cl.Get(ctx, key, fetched); err != nil {
			return client.IgnoreNotFound(err)
		}
		if len(fetched.GetFinalizers()) == 0 {
			return nil
		}
		fetched.SetFinalizers(nil)
		return cl.Update(ctx, fetched)
	})
	require.NoError(t, err, "cleanup: stripping finalizers from %s", key)

	if err := cl.Delete(ctx, obj); err != nil && !k8serrors.IsNotFound(err) {
		require.NoError(t, err, "cleanup: deleting %s", key)
	}
}

// AssertReconcileQuiet settles the object via repeated reconciles until its resourceVersion stops
// changing, then backdates every status condition's LastTransitionTime so a per-reconcile
// re-stamp becomes observable regardless of wall-clock (second) granularity (a fast in-process
// test would otherwise hide it), and finally asserts that further reconciles move neither
// resourceVersion nor any condition timestamp. Drift in either is the reconcile-storm signature.
//
// obj is a non-nil empty typed object used for fetching. conditions returns a pointer to obj's
// status conditions slice; applyStatus persists obj's status under the controller's field manager.
func AssertReconcileQuiet(
	t *testing.T,
	ctx context.Context,
	r reconcile.Reconciler,
	cl client.Client,
	key types.NamespacedName,
	obj client.Object,
	maxSettle, checkRounds int,
	conditions func(obj client.Object) *[]metav1.Condition,
	applyStatus func(obj client.Object) error,
) {
	t.Helper()
	req := reconcile.Request{NamespacedName: key}

	// Settle until two consecutive reconciles leave resourceVersion unchanged (bounded by
	// maxSettle), so the backdate below never lands while the object is still converging.
	prev := ""
	settled := false
	for range maxSettle {
		_, err := r.Reconcile(ctx, req)
		require.NoError(t, err, "settle reconcile failed")
		require.NoError(t, cl.Get(ctx, key, obj))
		rv := obj.GetResourceVersion()
		if rv == prev {
			settled = true
			break
		}
		prev = rv
	}
	require.Truef(t, settled, "object did not converge within %d reconciles", maxSettle)

	// Rfc3339Copy truncates to second precision to match what the API server persists.
	old := metav1.NewTime(time.Now().Add(-time.Hour)).Rfc3339Copy()
	require.NoError(t, cl.Get(ctx, key, obj))
	conds := conditions(obj)
	require.NotEmpty(t, *conds, "no status conditions to guard after settle")
	for i := range *conds {
		(*conds)[i].LastTransitionTime = old
	}
	require.NoError(t, applyStatus(obj))

	require.NoError(t, cl.Get(ctx, key, obj))
	baselineRV := obj.GetResourceVersion()
	assertAllBackdated(t, *conditions(obj), old, "backdate did not take")

	for i := range checkRounds {
		_, err := r.Reconcile(ctx, req)
		require.NoErrorf(t, err, "steady-state reconcile %d failed", i+1)
		require.NoError(t, cl.Get(ctx, key, obj))
		require.Equalf(t, baselineRV, obj.GetResourceVersion(),
			"resourceVersion changed on steady-state reconcile %d (reconcile-storm regression)", i+1)
		assertAllBackdatedf(t, *conditions(obj), old,
			"a condition timestamp re-stamped on steady-state reconcile %d (reconcile-storm regression)", i+1)
	}
}

func assertAllBackdated(t *testing.T, conds []metav1.Condition, old metav1.Time, msg string) {
	t.Helper()
	for _, c := range conds {
		ltt := c.LastTransitionTime
		require.Truef(t, ltt.Equal(&old), "%s: condition %q has %v, want %v", msg, c.Type, ltt, old)
	}
}

func assertAllBackdatedf(t *testing.T, conds []metav1.Condition, old metav1.Time, format string, args ...any) {
	t.Helper()
	for _, c := range conds {
		ltt := c.LastTransitionTime
		require.Truef(t, ltt.Equal(&old), format+" (condition %q = %v)", append(args, c.Type, ltt)...)
	}
}

// AssertSSAApplyNoOpThenChange proves the server-side-apply contract the steady-state quiet relies
// on: re-applying identical status content does not bump resourceVersion (no watch event), while a
// real change does. apply must be idempotent; mutate must change the status. obj is a non-nil empty
// typed object used for fetching. RV-equality holds only because status writes use client.Apply
// with ForceOwnership; a switch to Status().Update would bump resourceVersion every apply.
func AssertSSAApplyNoOpThenChange(
	t *testing.T,
	ctx context.Context,
	cl client.Client,
	key types.NamespacedName,
	obj client.Object,
	apply func() error,
	mutate func() error,
) {
	t.Helper()

	require.NoError(t, apply())
	require.NoError(t, cl.Get(ctx, key, obj))
	rv := obj.GetResourceVersion()

	require.NoError(t, apply())
	require.NoError(t, cl.Get(ctx, key, obj))
	require.Equal(t, rv, obj.GetResourceVersion(),
		"identical status apply must be a server-side no-op (no resourceVersion bump)")

	require.NoError(t, mutate())
	require.NoError(t, cl.Get(ctx, key, obj))
	require.NotEqual(t, rv, obj.GetResourceVersion(),
		"a real status change must bump resourceVersion")
}
