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
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

// StartManager runs a manager against the envtest API server described by cfg, with the operator's field
// indexes registered, after setup has registered the controllers under test. The manager stops with the test.
func StartManager(t *testing.T, cfg *rest.Config, scheme *runtime.Scheme, setup func(ctrl.Manager) error) ctrl.Manager {
	t.Helper()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	require.NoError(t, err)
	for _, idx := range index.All {
		require.NoError(t, mgr.GetFieldIndexer().IndexField(t.Context(), idx.Object, idx.Field, idx.ExtractValueFn))
	}
	require.NoError(t, setup(mgr))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(ctx) }()
	return mgr
}

// NewUnstartedManager returns a manager that is never started and cannot reach an API server, for checking that a
// controller registers with it. Controller names are not checked for uniqueness: that check is process-wide, and
// would fail a test run more than once in one process (go test -count).
func NewUnstartedManager(t *testing.T, scheme *runtime.Scheme) ctrl.Manager {
	t.Helper()
	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, ctrl.Options{
		Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: new(true)},
	})
	require.NoError(t, err)
	return mgr
}

// WaitForQuiet blocks until count has not changed for settle, failing the test with msg after timeout. It
// establishes quiescence before a mutation, so that residual reconciles cannot masquerade as event-driven recovery.
func WaitForQuiet(t *testing.T, count func() uint64, settle, timeout time.Duration, msg string) {
	t.Helper()
	last, lastChange := count(), time.Now()
	require.Eventually(t, func() bool {
		if current := count(); current != last {
			last, lastChange = current, time.Now()
		}
		return time.Since(lastChange) >= settle
	}, timeout, 20*time.Millisecond, msg)
}

// RecoveryManager is a manager for tests that check a controller recovers from watch events alone. Its resync
// period is long enough never to fire, and its client reads through the manager's cache while counting reads of the
// parent object.
type RecoveryManager struct {
	ctrl.Manager
	// Client reads through the manager's cache and must be given to the reconciler under test.
	Client      client.Client
	parentReads atomic.Uint64
}

// NewRecoveryManager returns a RecoveryManager against the envtest API server described by cfg. Reads of objects of
// the same type as parent are counted; extra optionally adds further interceptors, and its Get interceptor runs after
// the count. cacheOpts, if set, configures the cache, and its SyncPeriod defaults to 24 hours. The manager is not
// started: register the controller under test with SetupWithManager, then call Run.
func NewRecoveryManager(
	t *testing.T, cfg *rest.Config, scheme *runtime.Scheme, parent client.Object,
	extra *interceptor.Funcs, cacheOpts *cache.Options,
) *RecoveryManager {
	t.Helper()
	var opts cache.Options
	if cacheOpts != nil {
		opts = *cacheOpts
	}
	if opts.SyncPeriod == nil {
		syncPeriod := 24 * time.Hour
		opts.SyncPeriod = &syncPeriod
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:     scheme,
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Cache:      opts,
		Controller: config.Controller{SkipNameValidation: new(true)},
	})
	require.NoError(t, err)
	base, err := client.NewWithWatch(cfg, client.Options{
		Scheme: scheme,
		Cache:  &client.CacheOptions{Reader: mgr.GetCache()},
	})
	require.NoError(t, err)
	rm := &RecoveryManager{Manager: mgr}
	parentType := reflect.TypeOf(parent)
	var funcs interceptor.Funcs
	if extra != nil {
		funcs = *extra
	}
	get := funcs.Get
	funcs.Get = func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if reflect.TypeOf(obj) == parentType {
			rm.parentReads.Add(1)
		}
		if get != nil {
			return get(ctx, cl, key, obj, opts...)
		}
		return cl.Get(ctx, key, obj, opts...)
	}
	rm.Client = interceptor.NewClient(base, funcs)
	return rm
}

// Run starts the manager until the test ends, and fails the test if it does not stop cleanly.
func (m *RecoveryManager) Run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("manager did not stop")
		}
	})
}

// WaitForQuiet blocks until the controller has stopped reading the parent object, which means it has settled.
func (m *RecoveryManager) WaitForQuiet(t *testing.T) {
	t.Helper()
	WaitForQuiet(t, m.parentReads.Load, 300*time.Millisecond, 10*time.Second, "controller must settle before testing an isolated event")
}
