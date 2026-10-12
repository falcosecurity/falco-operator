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

	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// StartEnvtestWithConfig boots an envtest API server with the project CRDs installed and a freshly built
// scheme (Kubernetes built-ins plus the given adders), returning its REST config, a client and a stop function to
// defer. The scheme is local to this call, never the client-go global, so concurrent suites and repeated calls
// cannot contaminate one another.
func StartEnvtestWithConfig(adders ...func(*runtime.Scheme) error) (*rest.Config, client.Client, func(), error) {
	ctrllog.SetLogger(zap.New(zap.WriteTo(io.Discard), zap.UseDevMode(true)))

	s := runtime.NewScheme()
	for _, add := range append([]func(*runtime.Scheme) error{clientgoscheme.AddToScheme}, adders...) {
		if err := add(s); err != nil {
			return nil, nil, nil, err
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
		return nil, nil, nil, err
	}

	cl, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		_ = env.Stop()
		return nil, nil, nil, err
	}

	stop := func() {
		if err := env.Stop(); err != nil {
			ctrllog.Log.Error(err, "failed to stop envtest")
		}
	}
	return cfg, cl, stop, nil
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
