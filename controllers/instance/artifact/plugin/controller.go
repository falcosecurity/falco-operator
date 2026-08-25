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

// Package plugin implements the Plugin node-object aggregator controller.
// It runs in the instance operator (singleton Deployment) and is responsible for:
//   - Creating one ArtifactNode per cluster node that matches the Plugin selector.
//   - Deleting ArtifactNode objects when a node no longer matches.
//   - Fetching and caching the OCI artifact's requirements/dependencies as
//     Status.ArtifactMeta, and pre-fetching its binary blob into the shared cache.
//   - Aggregating per-node conditions into the parent Plugin status (sole writer).
//   - Managing the NodeObjectsInUseFinalizer on the parent Plugin.
package plugin

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// ControllerName identifies this controller in logs and as the SSA field manager.
const ControllerName = "instance-artifact-plugin"

// NewPluginAggregatorReconciler returns a new PluginAggregatorReconciler.
// cache is the shared artifact blob cache also used by the artifact HTTP server.
// Pass nil to disable local caching (direct-pull mode).
func NewPluginAggregatorReconciler(
	cl client.Client, scheme *runtime.Scheme, recorder events.EventRecorder, cache *artifactcache.Cache,
) *PluginAggregatorReconciler {
	return &PluginAggregatorReconciler{Client: cl, Scheme: scheme, recorder: recorder, cache: cache}
}

// PluginAggregatorReconciler manages ArtifactNode objects and aggregates their
// conditions into the parent Plugin status.
type PluginAggregatorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// recorder emits events on the parent Plugin, notably for ArtifactMeta fetch failures in
	// fetchAndCacheArtifactMeta.
	recorder events.EventRecorder
	// cache is the shared artifact blob cache. Nil disables local caching.
	cache *artifactcache.Cache
	// ociPuller overrides the OCI puller used in fetchAndCacheArtifactMeta; nil uses the default.
	ociPuller puller.Puller
}

// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=plugins,verbs=get;list;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=plugins/status,verbs=patch;update
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=plugins/finalizers,verbs=patch;update
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=artifactnodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=artifactnodes/status,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos,verbs=get;list;watch

// Reconcile reconciles a Plugin: ensures ArtifactNode objects exist for matching nodes,
// removes stale ones, and writes the aggregate conditions back to the Plugin.
func (r *PluginAggregatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.V(1).Info("Reconciling Plugin")

	plugin := &artifactv1alpha1.Plugin{}
	if err := r.Get(ctx, req.NamespacedName, plugin); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Deletion is gated by NodeObjectsInUseFinalizer, which stays set while owned ArtifactNode
	// objects exist. A per-node artifact operator keeps its ArtifactNode's finalizer in place as
	// long as a Rulesfile on that node still depends on this plugin.
	if !plugin.DeletionTimestamp.IsZero() {
		logger.V(1).Info("Plugin marked for deletion, running cleanup")
		return ctrl.Result{}, r.handleDeletion(ctx, plugin)
	}

	// allMatchingNodes: all nodes matching the selector, used for blob pre-fetching (all
	// platforms) and the in-use finalizer (ensures eviction runs even when no Falco pods land
	// on a node, e.g. a KWOK fake arm64 node in artifact-cache-lifecycle).
	allMatchingNodes, err := controllerhelper.ListMatchingNodes(ctx, r.Client, plugin.Spec.Selector)
	if err != nil {
		return ctrl.Result{}, err
	}
	// matchingNodes: subset of allMatchingNodes where a Running Falco pod exists; these are
	// the nodes that currently have an artifact operator able to reconcile an ArtifactNode.
	runningFalcoNodes, err := controllerhelper.ListFalcoRunningNodeNames(ctx, r.Client, plugin.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	matchingNodes := controllerhelper.FilterNodesByName(allMatchingNodes, runningFalcoNodes)
	logger.V(1).Info("Listed matching nodes", "total", len(allMatchingNodes), "withFalco", len(matchingNodes))

	existingNodes, err := controllerhelper.ListOwnedNodes(ctx, r.Client, plugin.Namespace, plugin.Name, controllerhelper.KindPlugin)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(1).Info("Listed existing ArtifactNode objects", "count", len(existingNodes.Items))

	// Keep the parent alive when nodes are desired or until every existing child is
	// physically gone. The desired-node check also covers a just-created child that the
	// informer cache may not expose in the immediate re-list yet.
	if err := controllerhelper.ReconcileInUseFinalizer(
		ctx, r.Client, plugin,
		controllerhelper.NodeObjectsInUseFinalizer,
		len(allMatchingNodes) > 0 || len(existingNodes.Items) > 0,
	); err != nil {
		return ctrl.Result{}, err
	}

	// ArtifactNode existence is the desired per-node assignment. Use the same set for
	// creation, stale deletion, and status aggregation. If a Falco pod moves away, its old
	// ArtifactNode is removed; a later pod on that node causes it to be created again.
	desired := make(map[string]struct{}, len(matchingNodes))
	for i := range matchingNodes {
		desired[matchingNodes[i].Name] = struct{}{}
	}

	if err := controllerhelper.DeleteStaleNodeObjects(
		ctx, r.Client, existingNodes.Items, desired, runningFalcoNodes,
	); err != nil {
		return ctrl.Result{}, err
	}

	// Snapshot before any status mutation so we can skip the first SSA when nothing changed.
	oldStatus := plugin.Status.DeepCopy()

	// Fetch OCI config layer once and cache it in parent.Status.ArtifactMeta so that
	// per-node artifact operators can read requirements without hitting the registry.
	if err := r.fetchAndCacheArtifactMeta(ctx, plugin); err != nil {
		// Surfaces the failure directly on the parent Plugin status. ObservedGeneration is not
		// advanced, so enforce-mode per-node operators stay deferred, and no ArtifactNodes are
		// created since they cannot be programmed without metadata.
		apimeta.SetStatusCondition(&plugin.Status.Conditions, metav1.Condition{
			Type:               commonv1alpha1.ConditionProgrammed.String(),
			Status:             metav1.ConditionFalse,
			Reason:             artifact.ReasonOCIArtifactProgramFailed,
			Message:            fmt.Sprintf("Failed to fetch OCI artifact metadata: %s", err.Error()),
			ObservedGeneration: plugin.Generation,
		})
		if patchErr := controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, plugin, ControllerName); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, err
	}

	// Stamps ObservedGeneration so per-node operators know this spec generation has been processed.
	// Written in the same SSA patch as ArtifactMeta so ObservedGeneration never advances ahead of it.
	plugin.Status.ObservedGeneration = plugin.Generation
	if !apiequality.Semantic.DeepEqual(*oldStatus, plugin.Status) {
		if err := controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, plugin, ControllerName); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Pulls the OCI binary for every platform present in selector-matching nodes before creating
	// ArtifactNode objects, so the blob cache is warm when the per-node operator requests it over HTTP.
	// If the pre-fetch fails, node creation still proceeds: the per-node operator fetches
	// independently and surfaces any failure in its own conditions.
	fetchBinErr := r.fetchAndCacheBlobs(ctx, plugin, allMatchingNodes)

	// Re-checks deletion status right before creating node objects; see IsBeingDeleted's doc.
	if deleting, err := controllerhelper.IsBeingDeleted(ctx, r.Client, plugin); err != nil {
		return ctrl.Result{}, err
	} else if deleting {
		logger.Info("Plugin marked for deletion; skipping node object creation")
		return ctrl.Result{}, nil
	}

	// Ensure an ArtifactNode exists for each matching node.
	pluginGVK := artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindPlugin)
	for i := range matchingNodes {
		if err := controllerhelper.EnsureNodeObject(
			ctx, r.Client, plugin, pluginGVK, controllerhelper.ArtifactKindPlugin, matchingNodes[i].Name,
		); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Re-list node objects: EnsureNodeObject may have just created new ones that are
	// not in the earlier existingNodes snapshot.
	existingNodes, err = controllerhelper.ListOwnedNodes(ctx, r.Client, plugin.Namespace, plugin.Name, controllerhelper.KindPlugin)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(1).Info("Re-listed ArtifactNode objects", "count", len(existingNodes.Items))

	// A stale or terminating child no longer represents the desired assignment and must not
	// keep its last condition in the aggregate while deletion is pending.
	activeNodes := &artifactv1alpha1.ArtifactNodeList{}
	for i := range existingNodes.Items {
		nodeObject := &existingNodes.Items[i]
		if !nodeObject.DeletionTimestamp.IsZero() {
			continue
		}
		if _, ok := desired[nodeObject.Spec.NodeName]; !ok {
			continue
		}
		activeNodes.Items = append(activeNodes.Items, *nodeObject)
	}

	condSnap := make([]metav1.Condition, len(plugin.Status.Conditions))
	copy(condSnap, plugin.Status.Conditions)
	controllerhelper.ComputeAggregateConditions(ctx, plugin, &plugin.Status.Conditions, activeNodes)
	if !apiequality.Semantic.DeepEqual(condSnap, plugin.Status.Conditions) {
		if err := controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, plugin, ControllerName); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, fetchBinErr
}

// fetchAndCacheArtifactMeta fetches the OCI config layer for the Plugin's OCI artifact
// and stores the parsed requirements and dependencies in parent.Status.ArtifactMeta.
// The result is included in the SSA patch made by updateAggregateConditions.
// If the artifact has no OCI source, ArtifactMeta is cleared.
func (r *PluginAggregatorReconciler) fetchAndCacheArtifactMeta(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	logger := log.FromContext(ctx)

	if plugin.Spec.OCIArtifact == nil {
		logger.V(4).Info("No OCI artifact configured, clearing ArtifactMeta")
		plugin.Status.ArtifactMeta = nil
		return nil
	}

	specHash, err := artifact.ComputeOCIArtifactSpecHash(plugin.Spec.OCIArtifact)
	if err != nil {
		return fmt.Errorf("compute OCI spec hash: %w", err)
	}

	var opts []artifact.ManagerOption
	if r.ociPuller != nil {
		opts = append(opts, artifact.WithOCIPuller(r.ociPuller))
	}
	am := artifact.NewManagerWithOptions(r.Client, plugin.Namespace, opts...)

	if artifact.ArtifactMetaCacheHit(plugin.Status.ArtifactMeta, specHash) {
		return nil
	}

	ref := artifact.ResolveReference(plugin.Spec.OCIArtifact)
	logger.Info("Fetching plugin ArtifactMeta from OCI config layer", "ref", ref)
	fetched, digest, fetchErr := am.FetchConfig(ctx, plugin.Spec.OCIArtifact)
	if fetchErr != nil {
		logger.Error(fetchErr, "Unable to fetch plugin OCI config; ArtifactMeta will remain stale", "ref", ref)
		artifact.RecordWarning(r.recorder, plugin, artifact.ReasonOCIArtifactProgramFailed,
			"Failed to fetch OCI config layer: %s", fetchErr.Error())
		return fetchErr
	}

	meta := &commonv1alpha1.ArtifactMeta{
		Digest:   digest,
		SpecHash: specHash,
	}
	artifact.AppendConfigLayerRequirements(meta, fetched)
	artifact.DeduplicateArtifactMeta(meta)
	logger.Info("Plugin ArtifactMeta updated from OCI config layer",
		"ref", ref,
		"digest", digest,
		"requirements", len(meta.Requirements),
		"dependencies", len(meta.Dependencies),
	)
	plugin.Status.ArtifactMeta = meta
	return nil
}

// handleDeletion deletes all ArtifactNode objects so each per-node artifact operator can clean up and
// remove its own finalizer (skipping this would deadlock: GC cascade only fires after the owner is
// deleted, but the in-use finalizer keeps the owner alive).
func (r *PluginAggregatorReconciler) handleDeletion(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	existing, err := controllerhelper.ListOwnedNodes(ctx, r.Client, plugin.Namespace, plugin.Name, controllerhelper.KindPlugin)
	if err != nil {
		return err
	}

	// Surfaces each node's current conditions onto the parent before triggering deletion below,
	// notably DeletionBlocked, set by a per-node operator refusing removal while a Rulesfile on
	// that node still depends on this plugin.
	if err := controllerhelper.UpdateAggregateConditions(
		ctx, r.Client, r.Scheme, plugin, &plugin.Status.Conditions, existing, ControllerName,
	); err != nil {
		return err
	}

	runningFalcoNodes := map[string]struct{}{}
	if len(existing.Items) > 0 {
		runningFalcoNodes, err = controllerhelper.ListFalcoRunningNodeNames(ctx, r.Client, plugin.Namespace)
		if err != nil {
			return err
		}
	}

	nodesRemaining, err := controllerhelper.DeleteNodeObjectsForParentDeletion(
		ctx, r.Client, existing.Items, runningFalcoNodes,
	)
	if err != nil {
		return err
	}

	// Evicts this CR's cache entries here, in the last reconcile before the finalizer is
	// released and the object is removed from etcd.
	if !nodesRemaining && r.cache != nil {
		if err := r.cache.RemoveAll(string(artifact.TypePlugin), plugin.Namespace, plugin.Name); err != nil {
			return fmt.Errorf("evict plugin cache entries: %w", err)
		}
	}

	return controllerhelper.ReconcileInUseFinalizer(
		ctx, r.Client, plugin,
		controllerhelper.NodeObjectsInUseFinalizer,
		nodesRemaining,
	)
}

// SetupWithManager registers this controller with the manager.
func (r *PluginAggregatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Plugin{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return !obj.GetDeletionTimestamp().IsZero()
			}),
		))).
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
				return controllerhelper.EnqueueAllOfType(ctx, r.Client, &artifactv1alpha1.PluginList{})
			}),
			builder.WithPredicates(predicate.Or(
				predicate.GenerationChangedPredicate{},
				predicate.LabelChangedPredicate{},
			)),
		).
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, pod client.Object) []reconcile.Request {
				return controllerhelper.EnqueueAllOfType(ctx, r.Client, &artifactv1alpha1.PluginList{}, client.InNamespace(pod.GetNamespace()))
			}),
			builder.WithPredicates(controllerhelper.FalcoPodChangePredicate()),
		).
		Watches(&artifactv1alpha1.ArtifactNode{},
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &artifactv1alpha1.Plugin{}),
		).
		Named(ControllerName).
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), ControllerName, &artifactv1alpha1.Plugin{})).
		Complete(r)
}

// fetchAndCacheBlobs pulls the plugin binary for every distinct (os, arch) pair present
// in nodes and stores each blob in the artifact cache. This runs in the instance operator so
// that per-node artifact-operator sidecars can fetch the pre-extracted binary over HTTP
// without touching the OCI registry directly.
//
// Fast path: fetchAndCacheArtifactMeta already resolved the current digest and wrote it to
// plugin.Status.ArtifactMeta.Digest. If r.cache already indexes that exact blob, no
// filesystem or registry access is needed at all. EnsureBlob (which re-resolves the digest)
// is only called when the cache doesn't already have the answer: first install or after a
// digest change.
func (r *PluginAggregatorReconciler) fetchAndCacheBlobs(ctx context.Context, plugin *artifactv1alpha1.Plugin, nodes []corev1.Node) error {
	if r.cache == nil || plugin.Spec.OCIArtifact == nil {
		return nil
	}

	logger := log.FromContext(ctx)

	// Collect distinct (os, arch) pairs from node labels.
	type platform struct{ goos, goarch string }
	seen := make(map[platform]struct{})
	for i := range nodes {
		goos := nodes[i].Labels["kubernetes.io/os"]
		goarch := nodes[i].Labels["kubernetes.io/arch"]
		if goos != "" && goarch != "" {
			seen[platform{goos, goarch}] = struct{}{}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	ref := artifact.ResolveReference(plugin.Spec.OCIArtifact)

	var opts []artifact.ManagerOption
	if r.ociPuller != nil {
		opts = append(opts, artifact.WithOCIPuller(r.ociPuller))
	}
	am := artifact.NewManagerWithOptions(r.Client, plugin.Namespace, opts...)

	for p := range seen {
		platformKey := p.goos + "-" + p.goarch

		// Fast path: this CR's index already points at the blob for the known digest.
		// Pure in-memory comparison, no filesystem or registry access on a warm cache.
		if meta := plugin.Status.ArtifactMeta; meta != nil && meta.Digest != "" {
			want := artifactcache.BlobPath(r.cache.Dir(), string(artifact.TypePlugin), ref, meta.Digest, p.goos, p.goarch)
			if current, ok := r.cache.Lookup(string(artifact.TypePlugin), plugin.Namespace, plugin.Name, platformKey); ok && current == want {
				logger.V(2).Info("Plugin blob already cached", "os", p.goos, "arch", p.goarch, "digest", meta.Digest)
				continue
			}
		}

		// Slow path: cache doesn't already have the answer.
		// Pass the digest already resolved by fetchAndCacheArtifactMeta to avoid a
		// second GET /manifests call. Falls back to resolving if digest is not known.
		var knownDigest string
		if meta := plugin.Status.ArtifactMeta; meta != nil {
			knownDigest = meta.Digest
		}
		logger.Info("Pulling plugin blob", "os", p.goos, "arch", p.goarch)
		blobPath, err := am.EnsureBlob(ctx, plugin.Spec.OCIArtifact, artifact.TypePlugin, p.goos, p.goarch, r.cache, knownDigest)
		if err != nil {
			return fmt.Errorf("cache plugin blob (%s/%s): %w", p.goos, p.goarch, err)
		}
		if err := r.cache.Set(string(artifact.TypePlugin), plugin.Namespace, plugin.Name, platformKey, blobPath); err != nil {
			return fmt.Errorf("index plugin blob (%s/%s): %w", p.goos, p.goarch, err)
		}
	}

	return nil
}
