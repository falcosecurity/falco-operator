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

// Package artifactnode implements the artifact operator's controller of the node's ArtifactNode. It decides what
// the node must stop holding:
//   - Every artifact the node holds files or a status entry for but the ArtifactNode's spec no longer lists.
//   - Everything, when the ArtifactNode is being deleted or there is none.
//
// It never removes anything itself. It asks the per-artifact reconciler of each such artifact to reconcile it,
// which finds it unassigned and removes it. That keeps every change to an artifact's files, an install and a
// removal alike, in one reconcile of that artifact at a time, which the work queue guarantees.
//
// It also holds a finalizer on the ArtifactNode and releases it once nothing is left on the node, so that a
// deleted ArtifactNode still gets everything removed.
package artifactnode

import (
	"context"
	"slices"
	"time"

	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
)

const (
	// ControllerName identifies this controller in logs.
	ControllerName = "artifact-artifactnode"

	// ReasonBulkRemoval is the reason of the Event emitted when one reconcile asks for the removal of many
	// artifacts.
	ReasonBulkRemoval = "BulkRemoval"

	// finalizePollDelay is how often an ArtifactNode being deleted is checked for having been emptied.
	finalizePollDelay = time.Second

	// bulkRemovalThreshold is the number of artifacts removed by one reconcile at which it logs it and emits a Warning
	// event; the removal itself still goes ahead. The node removes whatever the spec of its ArtifactNode does not
	// list, so a spec that lists too little (an assignment bug, a wrong selector) would strip its rules and plugins.
	// Removing this many at once is more likely such a mistake than an intended change, so it must be visible.
	bulkRemovalThreshold = 10
)

// Reconciler reconciles this node's ArtifactNode.
type Reconciler struct {
	client.Client
	recorder events.EventRecorder
	node     *node.Node

	// lastSpec is what the spec listed when this node's ArtifactNode was last reconciled. A drop from it is counted
	// from the spec itself: the per-artifact reconcilers watch the ArtifactNode too and remove what it no longer
	// lists at the same time, so what the node still holds by the time this runs can already be far less. The
	// workqueue never reconciles one key twice at once, and there is one key, so it needs no lock.
	lastSpec map[artifact.Ref]struct{}
	// deletionSeen is whether the deletion of the node's ArtifactNode has already been checked for being a bulk
	// removal, so that the polls of one deletion warn once. Like lastSpec, only the one reconcile at a time
	// touches it.
	deletionSeen bool
	// staleSeen is what the node held and the spec did not list at the last reconcile. Something that cannot be
	// removed yet, a plugin a Rulesfile requires, stays that way across reconciles, and counts once.
	staleSeen map[artifact.Ref]struct{}
}

// NewReconciler returns a Reconciler for the node's ArtifactNode. Removals are requested through n.
func NewReconciler(
	cl client.Client, recorder events.EventRecorder, n *node.Node,
) *Reconciler {
	return &Reconciler{Client: cl, recorder: recorder, node: n}
}

// Reconcile asks for the removal of what the node holds and its ArtifactNode no longer assigns: whatever the spec
// does not list, and, when the ArtifactNode is being deleted or does not exist, everything.
func (r *Reconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	// What the node holds is unknown until the warm sync has recovered it: the startup reconcile asked for below
	// would otherwise find no orphans on a node that has them.
	if err := r.node.WaitWarmSync(ctx); err != nil {
		return ctrl.Result{}, err
	}
	artifactNode, err := controllerhelper.GetArtifactNode(ctx, r.Client, r.node.Namespace(), r.node.Name())
	if err != nil {
		return ctrl.Result{}, err
	}
	if artifactNode == nil {
		r.lastSpec, r.deletionSeen = nil, false
		return ctrl.Result{}, r.removeOrphans(ctx)
	}
	r.node.ObserveArtifactNode(artifactNode)
	dropped := r.observeSpec(artifactNode)

	if !artifactNode.DeletionTimestamp.IsZero() {
		// A deleted ArtifactNode takes everything the node holds with it, whatever its spec still lists. That counts
		// as a bulk removal like a drop from the spec does, once per deletion and not on every poll of finalize.
		removed := len(dropped)
		if !r.deletionSeen {
			r.deletionSeen = true
			removed = max(removed, len(r.node.HeldKeys()))
		}
		r.warnBulkRemoval(ctx, artifactNode, removed)
		return r.finalize(ctx, artifactNode)
	}
	r.deletionSeen = false
	if _, err := controllerhelper.EnsureFinalizer(ctx, r.Client, controllerhelper.ArtifactNodeSidecarFinalizer, artifactNode); err != nil {
		return controllerhelper.ResultForWriteError(err)
	}
	return ctrl.Result{}, r.removeUnassigned(ctx, artifactNode, dropped)
}

// observeSpec records what the spec of artifactNode lists and returns what the previously recorded spec listed and
// this one does not.
func (r *Reconciler) observeSpec(artifactNode *artifactv1alpha1.ArtifactNode) map[artifact.Ref]struct{} {
	current := make(map[artifact.Ref]struct{}, len(artifactNode.Spec.Artifacts))
	for _, ref := range artifactNode.Spec.Artifacts {
		current[artifact.RefOfAssignment(ref)] = struct{}{}
	}
	dropped := map[artifact.Ref]struct{}{}
	for a := range r.lastSpec {
		if _, ok := current[a]; !ok {
			dropped[a] = struct{}{}
		}
	}
	r.lastSpec = current
	return dropped
}

// removeUnassigned requests the removal of what the node holds and the spec does not list. dropped is what the spec
// stopped listing since the last reconcile, which counts towards a bulk removal whether or not the node still holds it.
func (r *Reconciler) removeUnassigned(
	ctx context.Context, artifactNode *artifactv1alpha1.ArtifactNode, dropped map[artifact.Ref]struct{},
) error {
	var stale []artifact.Ref
	seen := map[artifact.Ref]struct{}{}
	for _, key := range r.node.HeldKeys() {
		if controllerhelper.AssignedArtifact(artifactNode, key.Kind, key.Name) == nil {
			stale = append(stale, key)
			seen[key] = struct{}{}
			if _, counted := r.staleSeen[key]; !counted {
				dropped[key] = struct{}{}
			}
		}
	}
	r.staleSeen = seen
	r.warnBulkRemoval(ctx, artifactNode, len(dropped))
	return r.requestRemoval(ctx, stale)
}

// warnBulkRemoval logs and records a Warning event on artifactNode when count artifacts are being removed at once.
func (r *Reconciler) warnBulkRemoval(ctx context.Context, artifactNode *artifactv1alpha1.ArtifactNode, count int) {
	if count < bulkRemovalThreshold {
		return
	}
	log.FromContext(ctx).Info("Removing many artifacts no longer assigned to this node", "count", count)
	artifact.RecordWarning(r.recorder, artifactNode, ReasonBulkRemoval,
		"Removing %d artifacts that are no longer assigned to this node", count)
}

// removeOrphans requests the removal of whatever is installed on a node that has no ArtifactNode. Nothing will
// ever ask about it again.
func (r *Reconciler) removeOrphans(ctx context.Context) error {
	keys := r.node.HeldKeys()
	if len(keys) == 0 {
		return nil
	}
	log.FromContext(ctx).Info("Removing the artifacts installed on a node that has no ArtifactNode", "count", len(keys))
	return r.requestRemoval(ctx, keys)
}

// finalize requests the removal of everything the node holds, for an ArtifactNode being deleted, and releases the
// finalizer once nothing is left. The removals are the per-artifact reconcilers', which retry what has to wait,
// so this only looks again for the end of them.
func (r *Reconciler) finalize(ctx context.Context, artifactNode *artifactv1alpha1.ArtifactNode) (ctrl.Result, error) {
	if !slices.Contains(artifactNode.Finalizers, controllerhelper.ArtifactNodeSidecarFinalizer) {
		return ctrl.Result{}, nil
	}
	keys := r.node.HeldKeys()
	if len(keys) == 0 {
		err := controllerhelper.RemoveFinalizer(ctx, r.Client, controllerhelper.ArtifactNodeSidecarFinalizer, artifactNode)
		return controllerhelper.ResultForWriteError(err)
	}

	// Every poll asks again for everything still held. Asking twice costs nothing, since the workqueue behind
	// the removal channel coalesces the requests naming the same artifact, and asking again is what recovers a
	// request that a full channel refused.
	log.FromContext(ctx).V(1).Info("Waiting for the removal of the artifacts of a deleted ArtifactNode", "count", len(keys))
	if err := r.requestRemoval(ctx, keys); err != nil {
		return ctrl.Result{}, err
	}
	// Something is still installed, or still waiting on something else, so the finalizer stays.
	return ctrl.Result{RequeueAfter: finalizePollDelay}, nil
}

// requestRemoval asks the reconciler of each key to reconcile it, in a deterministic order. Each kind's
// reconciler works independently, so a plugin a rulesfile still requires is simply retried by its reconciler
// until the rulesfile is gone.
func (r *Reconciler) requestRemoval(ctx context.Context, keys []artifact.Ref) error {
	slices.SortFunc(keys, artifact.Ref.Compare)
	for _, key := range keys {
		if err := r.node.RequestRemoval(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// SetupWithManager registers the controller with the Manager. It reconciles the node's ArtifactNode when it is
// created, when its spec changes, and when it is being deleted: never for the sidecar's own status writes.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.ArtifactNode{}, builder.WithPredicates(controllerhelper.SpecChangedOrDeleting())).
		// A node with files and no ArtifactNode has no event to start from, so one reconcile is asked for at
		// startup. Reconcile waits for the warm sync to have recovered what is installed.
		WatchesRawSource(source.Func(func(_ context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
			q.Add(reconcile.Request{NamespacedName: client.ObjectKey{Namespace: r.node.Namespace(), Name: r.node.Name()}})
			return nil
		})).
		Named(ControllerName).
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), ControllerName, &artifactv1alpha1.ArtifactNode{})).
		Complete(r)
}
