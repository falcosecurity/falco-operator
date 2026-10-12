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

// Package rulesfile implements the Rulesfile aggregator controller.
// It runs in the instance operator (singleton Deployment) and is responsible for:
//   - Aggregating the per-node conditions that each node's artifact operator publishes on its
//     ArtifactNode into the parent Rulesfile status (sole writer).
//   - Managing the NodeObjectsInUseFinalizer on the parent Rulesfile.
//
// Which nodes get the Rulesfile is decided by the ArtifactNode assignment controller.
package rulesfile

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/instance/artifact/shared"
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

// RulesfileAggregatorReconciler aggregates the per-node conditions published on ArtifactNodes into the
// parent Rulesfile status.
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
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=plugins,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos,verbs=get;list;watch

// Reconcile reconciles a Rulesfile: prepares its metadata and blob cache, manages its in-use finalizer and
// writes the aggregate of the conditions its nodes published back to the Rulesfile.
func (r *RulesfileAggregatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return shared.Reconcile(ctx, req, r.aggregation())
}

// aggregation is what the aggregate reconcile needs of the Rulesfiles.
func (r *RulesfileAggregatorReconciler) aggregation() shared.Aggregation[*artifactv1alpha1.Rulesfile] {
	return shared.Aggregation[*artifactv1alpha1.Rulesfile]{
		Client:                                   r.Client,
		Scheme:                                   r.Scheme,
		FieldManager:                             ControllerName,
		Kind:                                     artifact.KindRulesfile,
		Cache:                                    r.cache,
		New:                                      func() *artifactv1alpha1.Rulesfile { return &artifactv1alpha1.Rulesfile{} },
		StatusValue:                              func(rulesfile *artifactv1alpha1.Rulesfile) any { return *rulesfile.Status.DeepCopy() },
		HoldForSelectedNodes:                     true,
		Metadata:                                 r.fetchAndCacheArtifactMeta,
		MetadataFailedReason:                     artifact.ReasonProgramFailed,
		MetadataFailedMessage:                    "Failed to compute artifact metadata: %s",
		ResetObservedGenerationOnMetadataFailure: true,
		Prefetch: func(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, _ []corev1.Node) error {
			return r.fetchAndCacheBlob(ctx, rulesfile)
		},
	}
}

// fetchAndCacheArtifactMeta collects requirements for the Rulesfile from every configured
// source and atomically stores the merged result in parent.Status.ArtifactMeta. The cached
// aggregate is reused only when ArtifactMetaSourcesHash proves that every source input is
// unchanged; ArtifactMeta.SpecHash retains its narrower OCI-only meaning for blob lifecycle.
func (r *RulesfileAggregatorReconciler) fetchAndCacheArtifactMeta(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	logger := log.FromContext(ctx)

	if rulesfile.Spec.OCIArtifact == nil && rulesfile.Spec.ConfigMapRef == nil && rulesfile.Spec.InlineRules == nil {
		logger.V(4).Info("No artifact source configured, clearing ArtifactMeta")
		rulesfile.Status.ArtifactMeta = nil
		rulesfile.Status.ArtifactMetaSourcesHash = ""
		return nil
	}

	sources, err := artifact.ResolveRulesfileSources(ctx, &artifact.Fetcher{K8sClient: r.Client}, rulesfile)
	if err != nil {
		return err
	}
	sourcesHash, err := sources.Hash()
	if err != nil {
		return err
	}
	if rulesfile.Status.ArtifactMeta != nil && rulesfile.Status.ArtifactMetaSourcesHash == sourcesHash {
		return nil
	}

	// Build into a fresh value and publish it only after every configured source succeeds.
	// This prevents both stale entries after a source is removed and partial entries when a
	// source cannot be read or parsed.
	ociSpecHash, err := sources.OCISpecHash()
	if err != nil {
		return err
	}
	meta := &commonv1alpha1.ArtifactMeta{SpecHash: ociSpecHash}

	if sources.OCIArtifact != nil {
		// A ConfigMap/inline change rebuilds the aggregate, but must not update an unchanged
		// OCI source by following its tag. Re-read that source at its previously resolved digest.
		var knownDigest string
		if cached := rulesfile.Status.ArtifactMeta; artifact.ArtifactMetaCacheHit(cached, ociSpecHash) {
			knownDigest = cached.Digest
		}
		am := shared.NewOCIManager(r.Client, rulesfile.Namespace, r.ociPuller)
		if err := shared.FetchConfigLayer(ctx, am, r.recorder, rulesfile, sources.OCIArtifact, knownDigest, meta); err != nil {
			return err
		}
		ref := artifact.ResolveReference(sources.OCIArtifact)

		// Also parses the YAML content layer, since some artifacts declare
		// required_engine_version/required_plugin_versions there but not in the config layer.
		// Deduplication below keeps the strictest version when both sources report the same
		// capability.
		//
		// A fetch failure here is fatal: returning leaves ArtifactMeta stale and ObservedGeneration
		// unadvanced, rather than persisting an incomplete ArtifactMeta that could let a per-node
		// operator install the rulesfile without its real plugin dependencies enforced.
		logger.Info("Fetching rulesfile ArtifactMeta from OCI content layer", "ref", ref)
		content, contentErr := am.FetchContent(ctx, sources.OCIArtifact, meta.Digest)
		if contentErr != nil {
			logger.Error(contentErr, "Unable to fetch rulesfile OCI content; ArtifactMeta will remain stale", "ref", ref)
			artifact.RecordWarning(r.recorder, rulesfile, artifact.ReasonOCIArtifactProgramFailed,
				"Failed to fetch OCI content layer: %s", contentErr.Error())
			return contentErr
		}
		beforeReqs, beforeDeps := len(meta.Requirements), len(meta.Dependencies)
		if err := appendYAMLRequirements(meta, content); err != nil {
			parseErr := fmt.Errorf("parse OCI content requirements: %w", err)
			logger.Error(parseErr, "Unable to parse rulesfile OCI content; ArtifactMeta will remain stale", "ref", ref)
			artifact.RecordWarning(r.recorder, rulesfile, artifact.ReasonOCIArtifactProgramFailed,
				"Failed to parse OCI content layer: %s", err.Error())
			return parseErr
		}
		logger.Info("Rulesfile ArtifactMeta parsed from OCI content layer",
			"ref", ref,
			"newRequirements", len(meta.Requirements)-beforeReqs,
			"newDependencies", len(meta.Dependencies)-beforeDeps,
		)
	}

	if sources.ConfigMap != nil {
		logger.Info("Parsing rulesfile ArtifactMeta from ConfigMap", "configMap", sources.ConfigMapName)
		if err := appendYAMLRequirements(meta, sources.ConfigMap.Content); err != nil {
			return fmt.Errorf("parse requirements from ConfigMap %q: %w", sources.ConfigMapName, err)
		}
	}
	if sources.InlineRules != nil {
		logger.Info("Parsing rulesfile ArtifactMeta from inline rules")
		if err := appendYAMLRequirements(meta, sources.InlineRules.Raw); err != nil {
			return fmt.Errorf("parse requirements from inline rules: %w", err)
		}
	}

	artifact.DeduplicateArtifactMeta(meta)
	logger.Info("Rulesfile ArtifactMeta updated from all configured sources",
		"sourcesHash", sourcesHash,
		"requirements", len(meta.Requirements),
		"dependencies", len(meta.Dependencies),
	)
	rulesfile.Status.ArtifactMeta = meta
	rulesfile.Status.ArtifactMetaSourcesHash = sourcesHash
	return nil
}

// appendYAMLRequirements parses required_engine_version and required_plugin_versions from
// all documents in a Falco rules YAML stream and appends the results to meta.
func appendYAMLRequirements(meta *commonv1alpha1.ArtifactMeta, content []byte) error {
	rulesReqs, err := compat.ParseRulesRequirements(content)
	if err != nil {
		return err
	}
	rulesReqs.AppendTo(meta)
	return nil
}

// SetupWithManager registers this controller with the manager.
func (r *RulesfileAggregatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return shared.NewControllerManagedBy(mgr, r.Client, ControllerName, artifact.KindRulesfile, &artifactv1alpha1.Rulesfile{},
		func() client.ObjectList { return &artifactv1alpha1.RulesfileList{} }, r.cache).
		Watches(&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findRulesfilesForConfigMap),
		).
		Watches(&artifactv1alpha1.Plugin{},
			handler.EnqueueRequestsFromMapFunc(r.findRulesfilesForPlugin),
		).
		Complete(r)
}

// fetchAndCacheBlob pulls the rulesfile OCI blob (tar.gz of YAML files) and stores it in the artifact cache.
// Rulesfiles are platform-agnostic so a single blob is shared across all nodes.
// This runs in the instance operator so that per-node sidecars can fetch from HTTP
// without touching the registry.
//
// Cache.Ensure owns reuse, writes and reference registration. Registry access is skipped
// when the resolved blob is already present, including reuse after a previous dereference.
func (r *RulesfileAggregatorReconciler) fetchAndCacheBlob(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	if r.cache == nil || rulesfile.Spec.OCIArtifact == nil {
		return nil
	}

	logger := log.FromContext(ctx)

	am := shared.NewOCIManager(r.Client, rulesfile.Namespace, r.ociPuller)

	var knownDigest string
	if meta := rulesfile.Status.ArtifactMeta; meta != nil {
		knownDigest = meta.Digest
	}
	logger.V(2).Info("Ensuring rulesfile blob is cached", "digest", knownDigest)
	_, err := am.EnsureBlob(ctx, rulesfile.Name, rulesfile.Spec.OCIArtifact, artifact.KindRulesfile, "", "", r.cache, knownDigest)
	if err != nil {
		return fmt.Errorf("cache rulesfile blob: %w", err)
	}
	return nil
}

// findRulesfilesForConfigMap maps a ConfigMap event to the parent Rulesfiles that reference it,
// so their ArtifactMeta is refreshed when the ConfigMap content changes.
func (r *RulesfileAggregatorReconciler) findRulesfilesForConfigMap(ctx context.Context, cm client.Object) []reconcile.Request {
	return controllerhelper.RequestsReferencing(ctx, r.Client, &artifactv1alpha1.RulesfileList{}, index.ConfigMapOnRulesfile, cm)
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
