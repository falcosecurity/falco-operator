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

// Package shared holds what the sidecar's artifact reconcilers (Rulesfile, Plugin, Config) have in common.
package shared

import (
	"context"
	"errors"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
)

// BlockedRetryDelay is how long to wait before retrying the removal of an artifact something on the node
// still needs, such as a plugin a Rulesfile requires.
const BlockedRetryDelay = 5 * time.Second

// CleanupFunc removes everything installed on the node for the artifact of a controller's kind named name. It is
// idempotent, and reports a removal that has to wait for something else with a *node.BlockedError.
type CleanupFunc func(ctx context.Context, name string) error

// ReconcileArtifact is the reconcile of every artifact reconciler of the sidecar: it reads the artifact req names
// into parent through cl, and decides from the node's ArtifactNode whether to install it, with ApplyAndPublish, or
// to remove what the node holds for it, with cleanup.
func ReconcileArtifact(
	ctx context.Context, cl client.Client, n *node.Node, req reconcile.Request,
	parent artifactv1alpha1.Artifact, cleanup CleanupFunc,
) (reconcile.Result, error) {
	return reconcileArtifact(ctx, cl, n, req, parent, cleanup, func(
		ctx context.Context, parent artifactv1alpha1.Artifact, status *artifactv1alpha1.NodeArtifactStatus,
	) (reconcile.Result, error) {
		return ApplyAndPublish(ctx, n, parent, status)
	})
}

// installFunc runs the install flow for parent, an artifact the node's ArtifactNode assigns to the node. status is
// the artifact's status on the node: the one it starts from, and the one the flow leaves behind.
type installFunc func(
	ctx context.Context, parent artifactv1alpha1.Artifact, status *artifactv1alpha1.NodeArtifactStatus,
) (reconcile.Result, error)

// reconcileArtifact is ReconcileArtifact with the install flow as a parameter.
func reconcileArtifact(
	ctx context.Context, cl client.Client, n *node.Node, req reconcile.Request,
	parent artifactv1alpha1.Artifact, cleanup CleanupFunc, install installFunc,
) (reconcile.Result, error) {
	// What the node holds is unknown until the warm sync has recovered it.
	if err := n.WaitWarmSync(ctx); err != nil {
		return reconcile.Result{}, err
	}
	kind := parent.GetArtifactKind()
	key := artifact.Ref{Kind: kind, Name: req.Name}
	if err := cl.Get(ctx, req.NamespacedName, parent); err != nil {
		if !k8serrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		// The artifact is gone: what the node still holds for it is removed once the spec of its ArtifactNode stops
		// listing it.
		return removeUnlisted(ctx, cl, n, key, cleanup)
	}
	if !parent.GetDeletionTimestamp().IsZero() {
		return removeUnlisted(ctx, cl, n, key, cleanup)
	}

	assignment, err := ResolveAssignment(ctx, cl, n.Namespace(), n.Name(), kind, parent)
	if err != nil {
		return reconcile.Result{}, err
	}
	switch assignment {
	case NotAssigned:
		return removeUnassigned(ctx, n, key, cleanup)
	case AssignmentPending:
		return reconcile.Result{RequeueAfter: AssignmentRetryDelay}, nil
	case Assigned:
	}

	status, stale := n.StatusFor(kind, parent)
	if stale {
		// The artifact was deleted and recreated under the same name: what the old incarnation installed goes
		// before the new one is installed. When something else on the node still needs it, which cleanup
		// reports with a *node.BlockedError, it cannot go, and waiting would keep the new incarnation from ever
		// being installed: it takes over what is there instead, and its install updates it in place, as the
		// update of a live artifact does.
		if err := cleanup(ctx, parent.GetName()); err != nil {
			if _, blocked := errors.AsType[*node.BlockedError](err); !blocked {
				return reconcile.Result{}, err
			}
			n.TakeOver(key, parent.GetUID())
		}
	}
	return install(ctx, parent, status)
}

// removeUnassigned removes what the node holds for the artifact, which its ArtifactNode does not assign, with cleanup,
// and then withdraws its status entry: an artifact that never had a file has an entry the removal did not
// touch. Nothing held is nothing to do. A removal that has to wait for something else, which cleanup reports
// with a *node.BlockedError, is retried after BlockedRetryDelay.
func removeUnassigned(ctx context.Context, n *node.Node, key artifact.Ref, cleanup CleanupFunc) (reconcile.Result, error) {
	if !n.Holds(key) {
		return reconcile.Result{}, nil
	}
	if err := cleanup(ctx, key.Name); err != nil {
		if _, blocked := errors.AsType[*node.BlockedError](err); blocked {
			return reconcile.Result{RequeueAfter: BlockedRetryDelay}, nil
		}
		return reconcile.Result{}, err
	}
	n.WithdrawStatus(key)
	return reconcile.Result{}, nil
}

// removeUnlisted is removeUnassigned for an artifact that is gone or being deleted: while the spec of the node's
// ArtifactNode still lists it, files may be about to be needed or the operator has yet to drop it, so nothing is
// removed until the spec stops listing it, which reconciles the artifact again.
func removeUnlisted(
	ctx context.Context, cl client.Client, n *node.Node, key artifact.Ref, cleanup CleanupFunc,
) (reconcile.Result, error) {
	listed, err := IsListed(ctx, cl, n.Namespace(), n.Name(), key.Kind, key.Name)
	if err != nil || listed {
		return reconcile.Result{}, err
	}
	return removeUnassigned(ctx, n, key, cleanup)
}

// Remove removes everything n holds for the artifact of kind named name. It is the cleanup of a kind whose
// removal nothing on the node can block. It is idempotent.
func Remove(ctx context.Context, n *node.Node, kind artifact.Kind, name string) error {
	if err := n.Remove(ctx, artifact.Ref{Kind: kind, Name: name}); err != nil {
		log.FromContext(ctx).Error(err, "unable to remove installed artifacts from disk", "kind", kind, "name", name)
		return err
	}
	return nil
}

// AssignedRequests maps any event to a request for every artifact of kind that n's ArtifactNode assigns. A change
// of Falco's reported capabilities uses it: it can satisfy a requirement that blocked an install.
func AssignedRequests(cl client.Client, n *node.Node, kind artifact.Kind) handler.MapFunc {
	return func(ctx context.Context, _ client.Object) []reconcile.Request {
		return assignedRequests(ctx, cl, n.Namespace(), n.Name(), kind)
	}
}

// ApplyAndPublish runs the flow of parent on n, and publishes status on every return path.
//
// Programmed is a gateway condition: True only when all other conditions are True. For an artifact of a kind that
// declares requirements (a Rulesfile or a Plugin) on a node that does not enforce them (advise mode),
// DependenciesSatisfied is advisory, so it does not gate Programmed, and parent is programmed against its own
// generation rather than waiting for the instance operator to observe it. Any other artifact, a Config, always
// waits for the instance operator to have observed its generation.
//
// A transient fetch failure requeues via RequeueAfter instead of returning an error, which would otherwise tie up
// the worker for controller-runtime's retry backoff. So does a change blocked by something else on the node, after
// BlockedRetryDelay.
func ApplyAndPublish(
	ctx context.Context, n *node.Node, parent artifactv1alpha1.Artifact, status *artifactv1alpha1.NodeArtifactStatus,
) (reconcile.Result, error) {
	info, err := artifact.InfoForKind(parent.GetArtifactKind())
	if err != nil {
		return reconcile.Result{}, err
	}
	kind := info.Kind
	defer func() {
		advisory := info.DeclaresRequirements && !n.EnforceRequirements()
		skipDependenciesSatisfied := func(condType string) bool {
			return advisory && condType == commonv1alpha1.ConditionDependenciesSatisfied.String()
		}
		// The generation of parent the instance operator has processed.
		observedGeneration := *parent.GetStatusObservedGeneration()
		if advisory {
			observedGeneration = parent.GetGeneration()
		}
		apimeta.SetStatusCondition(&status.Conditions, common.ComputeProgrammedCondition(
			status.Conditions, skipDependenciesSatisfied,
			artifact.ReasonProgrammed, artifact.MessageProgrammed, artifact.ReasonProgramFailed,
			parent.GetGeneration(), observedGeneration,
		))
		n.PublishStatus(kind, parent, status)
	}()

	if err := n.ApplyArtifact(ctx, parent, status); err != nil {
		// A change that has to wait for something else on the node, a plugin's config name a Rulesfile still requires,
		// is tried again shortly, as a blocked removal is. The flow has said so in the status.
		if _, blocked := errors.AsType[*node.BlockedError](err); blocked {
			return reconcile.Result{RequeueAfter: BlockedRetryDelay}, nil
		}
		return controllerhelper.ResultForEnsureError(log.FromContext(ctx), err)
	}
	// The artifact is installed, so whatever a removal blocked earlier concluded no longer holds. Nothing
	// else ever clears DeletionBlocked: left behind, and stamped with the generation of the time, it makes
	// ComputeProgrammedCondition report Programmed=Unknown for good once the artifact's spec moves on.
	apimeta.RemoveStatusCondition(&status.Conditions, commonv1alpha1.ConditionDeletionBlocked.String())
	return reconcile.Result{}, nil
}
