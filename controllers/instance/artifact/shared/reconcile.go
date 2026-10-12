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

// Package shared holds what the instance operator's artifact aggregators (Rulesfile, Plugin, Config) have in
// common: the reconcile that writes the aggregate of what the nodes report back to the artifact, the release of
// its finalizer once no node holds it, and the watches that wake it.
package shared

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

// Aggregation is what the aggregate reconcile of one artifact kind needs: how to reach the artifacts of the kind,
// and what the kind adds to the common flow.
type Aggregation[T artifactv1alpha1.Artifact] struct {
	Client client.Client
	Scheme *runtime.Scheme
	// FieldManager is the controller's name, the SSA field manager of its status writes.
	FieldManager string
	Kind         artifact.Kind
	// Cache is the shared artifact blob cache, whose entries for an artifact are evicted when it goes. Nil means
	// the kind has none, or local caching is disabled.
	Cache *artifactcache.Cache

	// New returns an empty artifact to read into.
	New func() T
	// PatchStatus writes an artifact's status. Reconcile calls it only when the status differs from the one it
	// read or last wrote. Nil writes it with server-side apply, as FieldManager.
	PatchStatus func(context.Context, T) error
	// StatusValue returns a copy of an artifact's whole status, the value Reconcile compares to tell whether
	// anything changed.
	StatusValue func(T) any

	// HoldForSelectedNodes keeps the finalizer while any node is selected, rather than only while a selected node
	// runs Falco: the artifact's blob is pre-fetched for every selected node.
	HoldForSelectedNodes bool
	// Metadata builds and caches the metadata the nodes read from the artifact's status. Nil for a kind that has
	// none. On failure, Programmed is False with MetadataFailedReason and MetadataFailedMessage (a format taking
	// the error), and, with ResetObservedGenerationOnMetadataFailure, the observed generation is reset so the
	// nodes enforcing requirements wait for a complete rebuild.
	Metadata                                 func(context.Context, T) error
	MetadataFailedReason                     string
	MetadataFailedMessage                    string
	ResetObservedGenerationOnMetadataFailure bool
	// Prefetch warms the blob cache for the selected nodes, so a node's sidecar finds the blob ready. A failure is
	// returned once the status is written: the node then fetches on its own and reports what fails. Nil for a
	// kind that has no blob.
	Prefetch func(ctx context.Context, parent T, selected []corev1.Node) error
	// AggregateOnDeletion writes the conditions the nodes report while the artifact is being deleted, so that one
	// that cannot go yet, such as a plugin a Rulesfile requires, shows why.
	AggregateOnDeletion bool
}

// Reconcile reconciles the artifact req names: manages its in-use finalizer, prepares its metadata and blob
// cache, and writes the aggregate of the conditions its nodes published back to it.
func Reconcile[T artifactv1alpha1.Artifact](ctx context.Context, req ctrl.Request, a Aggregation[T]) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.V(1).Info("Reconciling " + string(a.Kind))

	parent := a.New()
	if err := a.Client.Get(ctx, req.NamespacedName, parent); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// An artifact deleted while this replica was not running never went through HandleDeletion here, so
		// its cache entries may still be on disk. Only this artifact's references go: a blob another artifact
		// shares stays.
		return ctrl.Result{}, a.evict(req.Namespace, req.Name)
	}
	if !parent.GetDeletionTimestamp().IsZero() {
		logger.V(1).Info(string(a.Kind) + " marked for deletion, running cleanup")
		return HandleDeletion(ctx, a, parent)
	}
	// The status is written only when it changes. The comparison is with the object just read: the controller
	// also reconciles on its own status events, so a read from a cache that has not caught up with an earlier
	// write is followed by another reconcile once it has, and a status someone else changed is put back.
	status := &statusWriter[T]{a: a, last: a.StatusValue(parent)}

	// An invalid selector is not rejected at admission, and selects no node: the assignment controller leaves the
	// artifact out, and the nodes that held it remove it. The status says so, since nothing else would.
	if _, err := metav1.LabelSelectorAsSelector(parent.GetSelector()); err != nil {
		return ctrl.Result{}, invalidSelector(ctx, status, parent, err)
	}

	// allMatchingNodes are the nodes the selector matches; matchingNodes, those of them where a Falco pod runs,
	// the only ones with a sidecar that can report on the artifact.
	allMatchingNodes, err := controllerhelper.ListMatchingNodes(ctx, a.Client, parent.GetSelector())
	if err != nil {
		return ctrl.Result{}, err
	}
	runningFalcoNodes, err := controllerhelper.ListFalcoRunningNodeNames(ctx, a.Client, parent.GetNamespace())
	if err != nil {
		return ctrl.Result{}, err
	}
	matchingNodes := controllerhelper.FilterNodesByName(allMatchingNodes, runningFalcoNodes)
	logger.V(1).Info("Listed matching nodes", "total", len(allMatchingNodes), "withFalco", len(matchingNodes))

	// The ArtifactNodes are listed once. Those being deleted count for the finalizer below, since their sidecar
	// may still be removing the artifact; the aggregate reads only the others.
	allArtifactNodes, err := ListAllArtifactNodes(ctx, a.Client, parent.GetNamespace())
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list ArtifactNodes: %w", err)
	}

	// The parent stays alive while nodes are selected for it, while any node lists it or reports on it, and while
	// its cache entry is referenced.
	onNodes := AnyHoldsArtifact(allArtifactNodes, a.Kind, parent.GetName())
	selected := matchingNodes
	if a.HoldForSelectedNodes {
		selected = allMatchingNodes
	}
	if err := a.reconcileInUseFinalizer(ctx, parent, len(selected) > 0 || onNodes); err != nil {
		return ctrl.Result{}, err
	}

	// The desired nodes are those selected that run a Falco pod, and those whose ArtifactNode still lists the
	// artifact, which the assignment controller keeps for a while when a Falco pod is being replaced. The
	// aggregate expects a report from each. The same ArtifactNodes are read again for the per-node conditions
	// below.
	artifactNodes := ArtifactNodesByNode(allArtifactNodes)
	desired := DesiredNodes(artifactNodes, a.Kind, parent, matchingNodes)

	conditions, observedGeneration := parent.GetStatusConditions(), parent.GetStatusObservedGeneration()
	var prefetchErr error
	if a.Metadata != nil {
		if err := a.Metadata(ctx, parent); err != nil {
			return ctrl.Result{}, metadataFailed(ctx, a, status, parent, artifactNodes, desired, err)
		}
		// ObservedGeneration tells the nodes this generation has been processed. It is written in the same patch
		// as the metadata so it never advances ahead of it.
		*observedGeneration = parent.GetGeneration()
		if err := status.write(ctx, parent); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		*observedGeneration = parent.GetGeneration()
	}
	if a.Prefetch != nil {
		prefetchErr = a.Prefetch(ctx, parent, allMatchingNodes)
	}

	nodeConditions := NodeConditionsFromArtifactNodes(artifactNodes, desired, a.Kind, parent)
	controllerhelper.ComputeAggregateConditions(ctx, parent, conditions, nodeConditions)
	explainNoNodes(*conditions, len(allMatchingNodes) > 0)
	if err := status.write(ctx, parent); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, prefetchErr
}

// explainNoNodes says, in the message of a Programmed condition whose reason is NoNodesAssigned, which of the two
// things that leave an artifact with no node is the case: a selector that matches none, or matching nodes on
// which no Falco pod runs. Only the message changes, which leaves the condition's transition time alone.
func explainNoNodes(conditions []metav1.Condition, selectorMatches bool) {
	programmed := apimeta.FindStatusCondition(conditions, commonv1alpha1.ConditionProgrammed.String())
	if programmed == nil || programmed.Reason != common.ReasonNoNodesAssigned {
		return
	}
	programmed.Message = "No nodes are assigned to this artifact: its selector matches no node."
	if selectorMatches {
		programmed.Message = "No nodes are assigned to this artifact: no Falco pod runs on the nodes its selector matches."
	}
}

// evict drops the blob cache entries of the artifact named name in namespace. Only this artifact's references go:
// a blob another artifact shares stays. It does nothing for a kind that has no cache.
func (a Aggregation[T]) evict(namespace, name string) error {
	if a.Cache == nil {
		return nil
	}
	if err := a.Cache.RemoveAll(string(a.Kind), namespace, name); err != nil {
		return fmt.Errorf("evict %s cache entries: %w", a.Kind, err)
	}
	return nil
}

// statusWriter writes an artifact's status when it differs from the status last read or written.
type statusWriter[T artifactv1alpha1.Artifact] struct {
	a    Aggregation[T]
	last any
}

func (w *statusWriter[T]) write(ctx context.Context, parent T) error {
	current := w.a.StatusValue(parent)
	if apiequality.Semantic.DeepEqual(w.last, current) {
		return nil
	}
	patch := w.a.PatchStatus
	if patch == nil {
		patch = func(ctx context.Context, parent T) error {
			return controllerhelper.PatchStatusSSA(ctx, w.a.Client, w.a.Scheme, parent, w.a.FieldManager)
		}
	}
	if err := patch(ctx, parent); err != nil {
		return err
	}
	w.last = current
	return nil
}

// metadataFailed writes the status of an artifact whose metadata could not be built, and returns err.
func metadataFailed[T artifactv1alpha1.Artifact](
	ctx context.Context, a Aggregation[T], status *statusWriter[T], parent T,
	artifactNodes map[string]*artifactv1alpha1.ArtifactNode, desired map[string]struct{}, err error,
) error {
	conditions, observedGeneration := parent.GetStatusConditions(), parent.GetStatusObservedGeneration()
	if a.ResetObservedGenerationOnMetadataFailure {
		*observedGeneration = 0
	}
	// The per-node conditions are still aggregated: a broken reference (a missing ConfigMap or auth Secret) fails
	// the metadata too, and a node's ResolvedRefs=False would otherwise never reach the artifact's status.
	nodeConditions := NodeConditionsFromArtifactNodes(artifactNodes, desired, a.Kind, parent)
	aggregated := controllerhelper.AggregateConditions(nodeConditions, parent.GetGeneration())

	// The metadata failure is the more specific cause of Programmed=False, so it wins over the aggregate. Only
	// the final conditions are applied: applying the aggregate first would flip Programmed to True and back on
	// every retry, restamping its transition time and writing a status that changed nothing.
	apimeta.SetStatusCondition(&aggregated, metav1.Condition{
		Type:               commonv1alpha1.ConditionProgrammed.String(),
		Status:             metav1.ConditionFalse,
		Reason:             a.MetadataFailedReason,
		Message:            fmt.Sprintf(a.MetadataFailedMessage, err.Error()),
		ObservedGeneration: parent.GetGeneration(),
	})
	controllerhelper.LogConditionTransitions(ctx, *conditions, aggregated)
	controllerhelper.ApplyAggregateConditions(conditions, aggregated)
	if patchErr := status.write(ctx, parent); patchErr != nil {
		return patchErr
	}
	return err
}

// invalidSelector writes the status of an artifact whose selector is invalid: Programmed=False, alone, since no
// node is asked to report on it. Nothing is returned to retry for: only a change of the spec can fix it, and that
// reconciles the artifact again.
func invalidSelector[T artifactv1alpha1.Artifact](ctx context.Context, status *statusWriter[T], parent T, err error) error {
	conditions := parent.GetStatusConditions()
	programmed := []metav1.Condition{{
		Type:               commonv1alpha1.ConditionProgrammed.String(),
		Status:             metav1.ConditionFalse,
		Reason:             artifact.ReasonInvalidSelector,
		Message:            fmt.Sprintf("The node selector is invalid, so the artifact is assigned to no node: %v", err),
		ObservedGeneration: parent.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}}
	controllerhelper.LogConditionTransitions(ctx, *conditions, programmed)
	controllerhelper.ApplyAggregateConditions(conditions, programmed)
	return status.write(ctx, parent)
}

// HandleDeletion releases the parent once no node lists it or reports on it: until then files for it may still be
// on a node. The assignment controller drops an artifact that is being deleted from every node's spec, each node's
// sidecar removes what it installed and withdraws its status entry, and the ArtifactNode events wake the reconcile
// again once the last node is clean. The artifact's cache entries go in that last reconcile, before the finalizer
// is released and the object is removed.
//
// A node that has been unreachable for longer than lostNodeGrace does not hold the parent back: see lostNodes.
func HandleDeletion[T artifactv1alpha1.Artifact](ctx context.Context, a Aggregation[T], parent T) (ctrl.Result, error) {
	// One listing serves both the conditions reported while the artifact goes and the decision to release it.
	artifactNodes, err := ListAllArtifactNodes(ctx, a.Client, parent.GetNamespace())
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list ArtifactNodes: %w", err)
	}
	if a.AggregateOnDeletion {
		status := &statusWriter[T]{a: a, last: a.StatusValue(parent)}
		conditions := parent.GetStatusConditions()
		controllerhelper.ComputeAggregateConditions(ctx, parent, conditions,
			NodeConditionsOnDeletion(artifactNodes, a.Kind, parent))
		if err := status.write(ctx, parent); err != nil {
			return ctrl.Result{}, err
		}
	}
	if AnyHoldsArtifact(artifactNodes, a.Kind, parent.GetName()) {
		lost, recheck, err := lostNodes(ctx, a.Client, time.Now())
		if err != nil {
			return ctrl.Result{}, err
		}
		if holder := holderNotLost(artifactNodes, a.Kind, parent.GetName(), lost); holder != "" {
			// A node that is unreachable but still within the grace is looked at again when it runs out: nothing
			// else would wake this reconcile then.
			return ctrl.Result{RequeueAfter: recheck}, nil
		}
		log.FromContext(ctx).Info("Releasing the artifact although unreachable nodes still hold it: "+
			"each removes it by itself if it comes back", "lostNodes", len(lost))
	}

	if err := a.evict(parent.GetNamespace(), parent.GetName()); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, controllerhelper.ReconcileInUseFinalizer(ctx, a.Client, parent, controllerhelper.NodeObjectsInUseFinalizer, false)
}

// NewControllerManagedBy starts the controller of an aggregator of kind, over the artifacts obj stands for, with the
// watches every aggregator needs: the artifact itself, the Nodes (a selector may start or stop matching one, and
// one may become unreachable), the Falco pods (which make a node desired) and the Falcos they belong to, and the
// ArtifactNodes (whose entries for the kind make up the aggregate). The caller adds its own watches and completes it.
//
// With a cache, every artifact the cache holds entries for is also reconciled once at startup. The informer's
// initial events only cover the artifacts that still exist, so one deleted while this replica was not running
// would otherwise keep its cache entries for good.
func NewControllerManagedBy(
	mgr ctrl.Manager, cl client.Client, name string, kind artifact.Kind, obj client.Object,
	newList func() client.ObjectList, cache *artifactcache.Cache,
) *builder.Builder {
	return ctrl.NewControllerManagedBy(mgr).
		WatchesRawSource(source.Func(func(_ context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
			if cache != nil {
				for _, owner := range cache.Owners(string(kind)) {
					queue.Add(reconcile.Request{NamespacedName: owner})
				}
			}
			return nil
		})).
		// Status events reconcile too: a status someone else changed, such as a condition reset, is put back.
		// The reconcile that follows the controller's own status write finds nothing to change and writes nothing.
		For(obj).
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
				return controllerhelper.EnqueueAllOfType(ctx, cl, newList())
			}),
			builder.WithPredicates(predicate.Or(
				predicate.GenerationChangedPredicate{},
				predicate.LabelChangedPredicate{},
				// A node that became unreachable starts the grace after which it no longer holds a deleted artifact.
				reachabilityChanged(),
			)),
		).
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, pod client.Object) []reconcile.Request {
				return controllerhelper.EnqueueAllOfType(ctx, cl, newList(), client.InNamespace(pod.GetNamespace()))
			}),
			builder.WithPredicates(controllerhelper.FalcoPodChangePredicate()),
		).
		// A pod counts as a Falco pod only while its Falco exists, and a Falco deleted with its pods orphaned, or
		// created over pods that are already there, changes that with no pod event.
		Watches(&instancev1alpha1.Falco{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, falco client.Object) []reconcile.Request {
				return controllerhelper.EnqueueAllOfType(ctx, cl, newList(), client.InNamespace(falco.GetNamespace()))
			}),
			builder.WithPredicates(controllerhelper.CreatedOrDeleted()),
		).
		Watches(&artifactv1alpha1.ArtifactNode{}, ArtifactNodeHandler(mgr.GetClient(), kind, newList)).
		Named(name).
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), name, obj))
}
