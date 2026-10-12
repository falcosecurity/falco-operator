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
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
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
