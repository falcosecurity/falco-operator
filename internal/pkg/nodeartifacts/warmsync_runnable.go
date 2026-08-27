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

package nodeartifacts

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// WarmSyncRunnable defers WarmSync until the manager's cache has synced, using the manager's own
// cache-backed client to avoid a fleet-wide direct-apiserver request storm on a cluster-wide
// sidecar restart. It implements controller-runtime's warmupRunnable interface (satisfied
// structurally by any Warmup(context.Context) error method): Warmup runs in a dedicated phase of
// mgr.Start(), after WaitForCacheSync succeeds and before any Controller starts reconciling;
// mgr.Add(NewWarmSyncRunnable(...)) before mgr.Start(ctx) is all a caller needs to do.
type WarmSyncRunnable struct {
	client    client.Client
	manager   *Manager
	namespace string
	nodeName  string
}

// NewWarmSyncRunnable creates a WarmSyncRunnable. cl should be the manager's own cache-backed
// client (mgr.GetClient()); see WarmSync's doc comment for why.
func NewWarmSyncRunnable(cl client.Client, mgr *Manager, namespace, nodeName string) *WarmSyncRunnable {
	return &WarmSyncRunnable{client: cl, manager: mgr, namespace: namespace, nodeName: nodeName}
}

// Start is an inert background runnable; the real work happens in Warmup. Implements the
// plain manager.Runnable interface (required alongside warmupRunnable).
func (w *WarmSyncRunnable) Start(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Warmup runs WarmSync using the manager's now-synced, cache-backed client.
func (w *WarmSyncRunnable) Warmup(ctx context.Context) error {
	if err := WarmSync(ctx, w.client, w.manager, w.namespace, w.nodeName); err != nil {
		return fmt.Errorf("warm-sync node artifact manager: %w", err)
	}
	ctrllog.FromContext(ctx).Info("Node artifact manager warm-synced from existing ArtifactNode status")
	return nil
}
