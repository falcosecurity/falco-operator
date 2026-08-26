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

// Package rulesfile implements the Rulesfile node-object aggregator controller.
// It runs in the instance operator (singleton Deployment) and is responsible for:
//   - Creating one ArtifactNode per cluster node that matches the Rulesfile selector.
//   - Deleting ArtifactNode objects when a node no longer matches.
//   - Aggregating per-node conditions into the parent Rulesfile status (sole writer).
//   - Managing the NodeObjectsInUseFinalizer on the parent Rulesfile.
package rulesfile

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
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// ControllerName identifies this controller in logs and as the SSA field manager.
const ControllerName = "instance-artifact-rulesfile"

// NewRulesfileAggregatorReconciler returns a new RulesfileAggregatorReconciler.
// cache is the shared artifact blob cache also used by the artifact HTTP server.
// Pass nil to disable local caching (direct-pull mode).
func NewRulesfileAggregatorReconciler(
	cl client.Client, scheme *runtime.Scheme, recorder events.EventRecorder, cache *artifactcache.Cache,
) *RulesfileAggregatorReconciler {
	return &RulesfileAggregatorReconciler{Client: cl, Scheme: scheme, recorder: recorder, cache: cache}
}

// RulesfileAggregatorReconciler manages ArtifactNode objects and aggregates their
// conditions into the parent Rulesfile status.
type RulesfileAggregatorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// recorder emits events on the parent Rulesfile, notably for ArtifactMeta fetch failures in
	// fetchAndCacheArtifactMeta.
	recorder events.EventRecorder
	// cache is the shared artifact blob cache. Nil disables local caching.
	cache *artifactcache.Cache
	// ociPuller overrides the OCI puller used in fetchAndCacheArtifactMeta; nil uses the default.
	ociPuller puller.Puller
}

// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=rulesfiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=rulesfiles/status,verbs=patch;update
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=rulesfiles/finalizers,verbs=patch;update
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=artifactnodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=artifactnodes/status,verbs=get;list;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=plugins,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos,verbs=get;list;watch

// Reconcile reconciles a Rulesfile: ensures ArtifactNode objects exist for matching nodes,
// removes stale ones, and writes the aggregate conditions back to the Rulesfile.
func (r *RulesfileAggregatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.V(1).Info("Reconciling Rulesfile")

	rulesfile := &artifactv1alpha1.Rulesfile{}
	if err := r.Get(ctx, req.NamespacedName, rulesfile); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion: remove the in-use finalizer once all node objects are gone.
	if !rulesfile.DeletionTimestamp.IsZero() {
		logger.V(1).Info("Rulesfile marked for deletion, running cleanup")
		return ctrl.Result{}, r.handleDeletion(ctx, rulesfile)
	}

	// allMatchingNodes: all nodes matching the selector; the blob is pre-fetched unconditionally
	// (fetchAndCacheBlob is not per-node), but the in-use finalizer is anchored here so that
	// handleDeletion runs cache eviction even when matchingNodes is empty.
	allMatchingNodes, err := controllerhelper.ListMatchingNodes(ctx, r.Client, rulesfile.Spec.Selector)
	if err != nil {
		return ctrl.Result{}, err
	}
	// matchingNodes: subset that also has a Running Falco pod; only these nodes get ArtifactNode
	// objects (avoids stale Pending objects on nodes where no sidecar will ever run).
	runningFalcoNodes, err := controllerhelper.ListFalcoRunningNodeNames(ctx, r.Client, rulesfile.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	matchingNodes := controllerhelper.FilterNodesByName(allMatchingNodes, runningFalcoNodes)
	logger.V(1).Info("Listed matching nodes", "total", len(allMatchingNodes), "withFalco", len(matchingNodes))

	// List all existing ArtifactNode objects for this Rulesfile.
	existingNodes, err := controllerhelper.ListOwnedNodes(ctx, r.Client, rulesfile.Namespace, rulesfile.Name, controllerhelper.KindRulesfile)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(1).Info("Listed existing ArtifactNode objects", "count", len(existingNodes.Items))

	// Keep the parent alive when nodes are desired or until every existing child is
	// physically gone. The desired-node check also covers a just-created child that the
	// informer cache may not expose in the immediate re-list yet.
	// The SSA variant also strips any legacy per-node finalizers left by old operators.
	if err := controllerhelper.ReconcileInUseFinalizer(
		ctx, r.Client, rulesfile,
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
	oldStatus := rulesfile.Status.DeepCopy()

	// Fetch OCI config layer once and cache it in parent.Status.ArtifactMeta so that
	// per-node artifact operators can read requirements without hitting the registry.
	if err := r.fetchAndCacheArtifactMeta(ctx, rulesfile); err != nil {
		// Surfaces the failure directly on the parent Rulesfile status. ObservedGeneration is not
		// advanced, so enforce-mode per-node operators stay deferred, and no ArtifactNodes are
		// created since they cannot be programmed without metadata.
		apimeta.SetStatusCondition(&rulesfile.Status.Conditions, metav1.Condition{
			Type:               commonv1alpha1.ConditionProgrammed.String(),
			Status:             metav1.ConditionFalse,
			Reason:             artifact.ReasonOCIArtifactProgramFailed,
			Message:            fmt.Sprintf("Failed to fetch OCI artifact metadata: %s", err.Error()),
			ObservedGeneration: rulesfile.Generation,
		})
		if patchErr := controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, rulesfile, ControllerName); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{}, err
	}

	// Stamps ObservedGeneration so per-node operators know this spec generation has been processed.
	// Written in the same SSA patch as ArtifactMeta so ObservedGeneration never advances ahead of it.
	rulesfile.Status.ObservedGeneration = rulesfile.Generation
	if !apiequality.Semantic.DeepEqual(*oldStatus, rulesfile.Status) {
		if err := controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, rulesfile, ControllerName); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Pulls the OCI binary before creating ArtifactNode objects, so the blob cache is warm
	// when the per-node operator requests it over HTTP.
	// If the pre-fetch fails, node creation still proceeds: the per-node operator fetches
	// independently and surfaces any failure in its own conditions.
	fetchBinErr := r.fetchAndCacheBlob(ctx, rulesfile)

	// Re-checks deletion status right before creating node objects; see IsBeingDeleted's doc.
	if deleting, err := controllerhelper.IsBeingDeleted(ctx, r.Client, rulesfile); err != nil {
		return ctrl.Result{}, err
	} else if deleting {
		logger.Info("Rulesfile marked for deletion; skipping node object creation")
		return ctrl.Result{}, nil
	}

	// Ensure an ArtifactNode exists for each matching node.
	rulesfileGVK := artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindRulesfile)
	for i := range matchingNodes {
		if err := controllerhelper.EnsureNodeObject(
			ctx, r.Client, rulesfile, rulesfileGVK, controllerhelper.ArtifactKindRulesfile, matchingNodes[i].Name,
		); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Re-fetch node objects (some may have just been created) to compute the aggregate.
	existingNodes, err = controllerhelper.ListOwnedNodes(ctx, r.Client, rulesfile.Namespace, rulesfile.Name, controllerhelper.KindRulesfile)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(1).Info("Re-listed ArtifactNode objects after sync", "count", len(existingNodes.Items))

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

	condSnap := make([]metav1.Condition, len(rulesfile.Status.Conditions))
	copy(condSnap, rulesfile.Status.Conditions)
	controllerhelper.ComputeAggregateConditions(ctx, rulesfile, &rulesfile.Status.Conditions, activeNodes)
	if !apiequality.Semantic.DeepEqual(condSnap, rulesfile.Status.Conditions) {
		if err := controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, rulesfile, ControllerName); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, fetchBinErr
}

// fetchAndCacheArtifactMeta collects all requirements for the Rulesfile from every source
// (OCI config layer, OCI content YAML, ConfigMap, or inline rules) and stores the merged
// result in parent.Status.ArtifactMeta. This single status field is then read by every
// per-node artifact operator, eliminating per-node registry calls.
//
// For OCI sources a digest-based cache avoids redundant registry round-trips: if the
// spec and current digest match what is already stored, the cached value is kept as-is.
// ConfigMap and inline sources are always re-parsed on each reconcile (cheap k8s API / in-memory).
func (r *RulesfileAggregatorReconciler) fetchAndCacheArtifactMeta(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	logger := log.FromContext(ctx)

	if rulesfile.Spec.OCIArtifact == nil && rulesfile.Spec.ConfigMapRef == nil && rulesfile.Spec.InlineRules == nil {
		logger.V(4).Info("No artifact source configured, clearing ArtifactMeta")
		rulesfile.Status.ArtifactMeta = nil
		return nil
	}

	var opts []artifact.ManagerOption
	if r.ociPuller != nil {
		opts = append(opts, artifact.WithOCIPuller(r.ociPuller))
	}
	am := artifact.NewManagerWithOptions(r.Client, rulesfile.Namespace, opts...)

	if rulesfile.Spec.OCIArtifact != nil {
		specHash, err := artifact.ComputeOCIArtifactSpecHash(rulesfile.Spec.OCIArtifact)
		if err != nil {
			return fmt.Errorf("compute OCI spec hash: %w", err)
		}

		if artifact.ArtifactMetaCacheHit(rulesfile.Status.ArtifactMeta, specHash) {
			return nil
		}

		ref := artifact.ResolveReference(rulesfile.Spec.OCIArtifact)
		logger.Info("Fetching rulesfile ArtifactMeta from OCI config layer", "ref", ref)
		fetched, digest, fetchErr := am.FetchConfig(ctx, rulesfile.Spec.OCIArtifact)
		if fetchErr != nil {
			logger.Error(fetchErr, "Unable to fetch rulesfile OCI config; ArtifactMeta will remain stale", "ref", ref)
			artifact.RecordWarning(r.recorder, rulesfile, artifact.ReasonOCIArtifactProgramFailed,
				"Failed to fetch OCI config layer: %s", fetchErr.Error())
			return fetchErr
		}

		meta := &commonv1alpha1.ArtifactMeta{
			Digest:   digest,
			SpecHash: specHash,
		}
		artifact.AppendConfigLayerRequirements(meta, fetched)
		logger.Info("Rulesfile ArtifactMeta parsed from OCI config layer",
			"ref", ref,
			"requirements", len(meta.Requirements),
			"dependencies", len(meta.Dependencies),
		)

		// Also parses the YAML content layer, since some artifacts declare
		// required_engine_version/required_plugin_versions there but not in the config layer.
		// Deduplication below keeps the strictest version when both sources report the same
		// capability.
		//
		// A fetch failure here is fatal: returning leaves ArtifactMeta stale and ObservedGeneration
		// unadvanced, rather than persisting an incomplete ArtifactMeta that could let a per-node
		// operator install the rulesfile without its real plugin dependencies enforced.
		logger.Info("Fetching rulesfile ArtifactMeta from OCI content layer", "ref", ref)
		content, contentErr := am.FetchContent(ctx, rulesfile.Spec.OCIArtifact)
		if contentErr != nil {
			logger.Error(contentErr, "Unable to fetch rulesfile OCI content; ArtifactMeta will remain stale", "ref", ref)
			artifact.RecordWarning(r.recorder, rulesfile, artifact.ReasonOCIArtifactProgramFailed,
				"Failed to fetch OCI content layer: %s", contentErr.Error())
			return contentErr
		}
		beforeReqs, beforeDeps := len(meta.Requirements), len(meta.Dependencies)
		appendYAMLRequirements(meta, content)
		logger.Info("Rulesfile ArtifactMeta parsed from OCI content layer",
			"ref", ref,
			"newRequirements", len(meta.Requirements)-beforeReqs,
			"newDependencies", len(meta.Dependencies)-beforeDeps,
		)

		artifact.DeduplicateArtifactMeta(meta)
		logger.Info("Rulesfile ArtifactMeta updated from OCI artifact",
			"ref", ref,
			"digest", digest,
			"requirements", len(meta.Requirements),
			"dependencies", len(meta.Dependencies),
		)
		rulesfile.Status.ArtifactMeta = meta
		return nil
	}

	// Non-OCI sources: ConfigMap and/or inline. Always re-parse (cheap).
	meta := &commonv1alpha1.ArtifactMeta{}
	if rulesfile.Spec.ConfigMapRef != nil {
		cm := &corev1.ConfigMap{}
		key := client.ObjectKey{Name: rulesfile.Spec.ConfigMapRef.Name, Namespace: rulesfile.Namespace}
		if err := r.Get(ctx, key, cm); err != nil {
			logger.Error(err, "Unable to fetch ConfigMap for requirements", "configMap", rulesfile.Spec.ConfigMapRef.Name)
		} else {
			appendYAMLRequirements(meta, []byte(cm.Data[commonv1alpha1.ConfigMapRulesKey]))
		}
		logger.Info("Parsing rulesfile ArtifactMeta from ConfigMap", "configMap", rulesfile.Spec.ConfigMapRef.Name)
	}
	if rulesfile.Spec.InlineRules != nil {
		logger.Info("Parsing rulesfile ArtifactMeta from inline rules")
		appendYAMLRequirements(meta, rulesfile.Spec.InlineRules.Raw)
	}
	artifact.DeduplicateArtifactMeta(meta)
	logger.Info("Rulesfile ArtifactMeta updated from YAML content",
		"requirements", len(meta.Requirements),
		"dependencies", len(meta.Dependencies),
	)
	rulesfile.Status.ArtifactMeta = meta
	return nil
}

// appendYAMLRequirements parses required_engine_version and required_plugin_versions from
// a Falco rules YAML document and appends the results to meta.
func appendYAMLRequirements(meta *commonv1alpha1.ArtifactMeta, content []byte) {
	rulesReqs, err := compat.ParseRulesRequirements(content)
	if err != nil || rulesReqs == nil {
		return
	}
	if rulesReqs.EngineVersion != "" {
		capName := "engine_version_semver"
		if rulesReqs.EngineVersionIsInt {
			capName = "engine_version"
		}
		meta.Requirements = append(meta.Requirements, commonv1alpha1.ArtifactMetaRequirement{
			Name: capName, Version: rulesReqs.EngineVersion,
		})
	}
	for _, pv := range rulesReqs.PluginVersions {
		d := commonv1alpha1.ArtifactMetaDependency{Name: pv.Name, Version: pv.Version}
		for _, alt := range pv.Alternatives {
			d.Alternatives = append(d.Alternatives, commonv1alpha1.ArtifactMetaDependencyVariant{
				Name: alt.Name, Version: alt.Version,
			})
		}
		meta.Dependencies = append(meta.Dependencies, d)
	}
}

// handleDeletion deletes all ArtifactNode objects so each per-node artifact operator can clean up
// and remove its own finalizer (skipping this would deadlock: GC cascade only fires after the owner
// is deleted, but the in-use finalizer keeps the owner alive).
func (r *RulesfileAggregatorReconciler) handleDeletion(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	existing, err := controllerhelper.ListOwnedNodes(ctx, r.Client, rulesfile.Namespace, rulesfile.Name, controllerhelper.KindRulesfile)
	if err != nil {
		return err
	}

	runningFalcoNodes := map[string]struct{}{}
	if len(existing.Items) > 0 {
		runningFalcoNodes, err = controllerhelper.ListFalcoRunningNodeNames(ctx, r.Client, rulesfile.Namespace)
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
	if nodesRemaining {
		return nil
	}

	// Evicts this CR's cache entry here, in the last reconcile before the finalizer is
	// released and the object is removed from etcd.
	if r.cache != nil {
		if err := r.cache.RemoveAll(string(artifact.TypeRulesfile), rulesfile.Namespace, rulesfile.Name); err != nil {
			return fmt.Errorf("evict rulesfile cache entries: %w", err)
		}
	}

	return controllerhelper.ReconcileInUseFinalizer(
		ctx, r.Client, rulesfile,
		controllerhelper.NodeObjectsInUseFinalizer,
		false,
	)
}

// SetupWithManager registers this controller with the manager.
func (r *RulesfileAggregatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Rulesfile{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return !obj.GetDeletionTimestamp().IsZero()
			}),
		))).
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
				return controllerhelper.EnqueueAllOfType(ctx, r.Client, &artifactv1alpha1.RulesfileList{})
			}),
			builder.WithPredicates(predicate.Or(
				predicate.GenerationChangedPredicate{},
				predicate.LabelChangedPredicate{},
			)),
		).
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, pod client.Object) []reconcile.Request {
				return controllerhelper.EnqueueAllOfType(ctx, r.Client, &artifactv1alpha1.RulesfileList{}, client.InNamespace(pod.GetNamespace()))
			}),
			builder.WithPredicates(controllerhelper.FalcoPodChangePredicate()),
		).
		Watches(&artifactv1alpha1.ArtifactNode{},
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &artifactv1alpha1.Rulesfile{}),
		).
		Watches(&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findRulesfilesForConfigMap),
		).
		Watches(&artifactv1alpha1.Plugin{},
			handler.EnqueueRequestsFromMapFunc(r.findRulesfilesForPlugin),
		).
		Named(ControllerName).
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), ControllerName, &artifactv1alpha1.Rulesfile{})).
		Complete(r)
}

// fetchAndCacheBlob pulls the rulesfile OCI blob (tar.gz of YAML files) and stores it in the artifact cache.
// Rulesfiles are platform-agnostic so a single blob is shared across all nodes.
// This runs in the instance operator so that per-node sidecars can fetch from HTTP
// without touching the registry.
//
// Fast path: fetchAndCacheArtifactMeta already resolved the current digest and wrote it to
// rulesfile.Status.ArtifactMeta.Digest. If r.cache already indexes that exact blob, no
// filesystem or registry access is needed at all. EnsureBlob is only called when the cache
// doesn't already have the answer.
func (r *RulesfileAggregatorReconciler) fetchAndCacheBlob(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	if r.cache == nil || rulesfile.Spec.OCIArtifact == nil {
		return nil
	}

	logger := log.FromContext(ctx)
	ref := artifact.ResolveReference(rulesfile.Spec.OCIArtifact)

	// Fast path: this CR's index already points at the blob for the known digest.
	// Pure in-memory comparison, no filesystem or registry access on a warm cache.
	if meta := rulesfile.Status.ArtifactMeta; meta != nil && meta.Digest != "" {
		want := artifactcache.BlobPath(r.cache.Dir(), string(artifact.TypeRulesfile), ref, meta.Digest, "", "")
		if current, ok := r.cache.Lookup(string(artifact.TypeRulesfile), rulesfile.Namespace, rulesfile.Name, ""); ok && current == want {
			logger.V(2).Info("Rulesfile blob already cached", "digest", meta.Digest)
			return nil
		}
	}

	// Slow path: cache doesn't already have the answer.
	// Pass the digest already resolved by fetchAndCacheArtifactMeta to avoid a
	// second GET /manifests call. Falls back to resolving if digest is not known.
	var knownDigest string
	if meta := rulesfile.Status.ArtifactMeta; meta != nil {
		knownDigest = meta.Digest
	}
	logger.Info("Pulling rulesfile blob")
	var opts []artifact.ManagerOption
	if r.ociPuller != nil {
		opts = append(opts, artifact.WithOCIPuller(r.ociPuller))
	}
	am := artifact.NewManagerWithOptions(r.Client, rulesfile.Namespace, opts...)

	blobPath, err := am.EnsureBlob(ctx, rulesfile.Spec.OCIArtifact, artifact.TypeRulesfile, "", "", r.cache, knownDigest)
	if err != nil {
		return fmt.Errorf("cache rulesfile blob: %w", err)
	}
	if err := r.cache.Set(string(artifact.TypeRulesfile), rulesfile.Namespace, rulesfile.Name, "", blobPath); err != nil {
		return fmt.Errorf("index rulesfile blob: %w", err)
	}
	return nil
}

// findRulesfilesForConfigMap maps a ConfigMap event to the parent Rulesfiles that reference it,
// so their ArtifactMeta is refreshed when the ConfigMap content changes.
func (r *RulesfileAggregatorReconciler) findRulesfilesForConfigMap(ctx context.Context, cm client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	list := &artifactv1alpha1.RulesfileList{}
	indexKey := cm.GetNamespace() + "/" + cm.GetName()
	if err := r.List(ctx, list, client.MatchingFields{index.ConfigMapOnRulesfile: indexKey}); err != nil {
		logger.Error(err, "unable to list Rulesfiles by ConfigMap index")
		return nil
	}
	reqs := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		reqs[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return reqs
}

// findRulesfilesForPlugin re-enqueues all Rulesfiles in the same namespace that list this
// plugin as a dependency (primary or alternative) in their Status.ArtifactMeta. This ensures
// that when a Plugin is deleted, including force-deleted, its dependent Rulesfiles are
// reconciled so they can reflect the changed dependency state.
func (r *RulesfileAggregatorReconciler) findRulesfilesForPlugin(ctx context.Context, obj client.Object) []reconcile.Request {
	// Resolve the canonical plugin name (spec.config.name if set, else metadata.name).
	// The PluginOnRulesfile index is keyed by canonical names from the OCI config / rules
	// YAML, not by Kubernetes CR names, so we must query with the same key.
	canonicalName := obj.GetName()
	if plugin, ok := obj.(*artifactv1alpha1.Plugin); ok {
		if plugin.Spec.Config != nil && plugin.Spec.Config.Name != "" {
			canonicalName = plugin.Spec.Config.Name
		}
	}
	list := &artifactv1alpha1.RulesfileList{}
	if err := r.List(ctx, list,
		client.InNamespace(obj.GetNamespace()),
		client.MatchingFields{index.PluginOnRulesfile: canonicalName},
	); err != nil {
		log.FromContext(ctx).Error(err, "unable to list RulesFiles for Plugin change")
		return nil
	}
	reqs := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		reqs[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
	}
	return reqs
}
