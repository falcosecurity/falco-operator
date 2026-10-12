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

package node

import (
	"context"
	"fmt"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// WarmSyncRunnable runs the node's warm sync once the manager's cache has synced, using the manager's own
// cache-backed client to avoid a fleet-wide direct-apiserver request storm on a cluster-wide sidecar
// restart. It implements controller-runtime's warmupRunnable interface (satisfied structurally by any
// Warmup(context.Context) error method): Warmup runs in a dedicated phase of mgr.Start(), after
// WaitForCacheSync succeeds and before leader election.
//
// controller-runtime does not wait for Warmup to finish before starting the controllers, so the node's
// reconcilers wait for it themselves: creating the runnable arms Node.WaitWarmSync, and Warmup opens it.
// Node.AddToManager creates and registers it.
type WarmSyncRunnable struct {
	node *Node
}

// NewWarmSyncRunnable returns the warm-sync runnable of n. From here on n's reconcilers wait for it to have
// run: see Node.WaitWarmSync.
func NewWarmSyncRunnable(n *Node) *WarmSyncRunnable {
	n.armWarmSync()
	return &WarmSyncRunnable{node: n}
}

// Start is an inert background runnable; the real work happens in Warmup. Implements the
// plain manager.Runnable interface (required alongside warmupRunnable).
func (w *WarmSyncRunnable) Start(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// NeedLeaderElection reports that the warm sync runs on every node's sidecar, not just one. It implements
// manager.LeaderElectionRunnable: without it, controller-runtime puts Start in the leader-election group
// (see Node.AddToManager, where every runnable is per-node).
func (w *WarmSyncRunnable) NeedLeaderElection() bool { return false }

// Warmup runs the node's warm sync using the manager's now-synced, cache-backed client, and then lets the
// node's reconcilers go.
func (w *WarmSyncRunnable) Warmup(ctx context.Context) error {
	if err := w.node.warmup(ctx); err != nil {
		return fmt.Errorf("warm-sync node artifacts: %w", err)
	}
	ctrllog.FromContext(ctx).Info("Node observed installed files and current plugin assignments")
	return nil
}
