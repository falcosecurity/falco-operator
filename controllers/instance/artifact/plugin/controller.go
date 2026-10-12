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

// Package plugin implements the Plugin aggregator controller.
// It runs in the instance operator (singleton Deployment) and is responsible for:
//   - Fetching and caching the OCI artifact's requirements/dependencies as
//     Status.ArtifactMeta, and pre-fetching its binary blob into the shared cache.
//   - Aggregating the per-node conditions that each node's artifact operator publishes on its
//     ArtifactNode into the parent Plugin status (sole writer).
//   - Managing the NodeObjectsInUseFinalizer on the parent Plugin.
//
// Which nodes get the Plugin is decided by the ArtifactNode assignment controller.
package plugin

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/instance/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
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

// PluginAggregatorReconciler aggregates the per-node conditions published on ArtifactNodes into the
// parent Plugin status.
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
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos,verbs=get;list;watch

// Reconcile reconciles a Plugin: prepares its metadata and blob cache, manages its in-use finalizer and
// writes the aggregate of the conditions its nodes published back to the Plugin.
func (r *PluginAggregatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return shared.Reconcile(ctx, req, r.aggregation())
}

// aggregation is what the aggregate reconcile needs of the Plugins.
func (r *PluginAggregatorReconciler) aggregation() shared.Aggregation[*artifactv1alpha1.Plugin] {
	return shared.Aggregation[*artifactv1alpha1.Plugin]{
		Client:                r.Client,
		Scheme:                r.Scheme,
		FieldManager:          ControllerName,
		Kind:                  artifact.KindPlugin,
		Cache:                 r.cache,
		New:                   func() *artifactv1alpha1.Plugin { return &artifactv1alpha1.Plugin{} },
		StatusValue:           func(plugin *artifactv1alpha1.Plugin) any { return *plugin.Status.DeepCopy() },
		HoldForSelectedNodes:  true,
		Metadata:              r.fetchAndCacheArtifactMeta,
		MetadataFailedReason:  artifact.ReasonOCIArtifactProgramFailed,
		MetadataFailedMessage: "Failed to fetch OCI artifact metadata: %s",
		Prefetch:              r.fetchAndCacheBlobs,
		AggregateOnDeletion:   true,
	}
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

	if artifact.ArtifactMetaCacheHit(plugin.Status.ArtifactMeta, specHash) {
		return nil
	}

	meta := &commonv1alpha1.ArtifactMeta{SpecHash: specHash}
	am := shared.NewOCIManager(r.Client, plugin.Namespace, r.ociPuller)
	if err := shared.FetchConfigLayer(ctx, am, r.recorder, plugin, plugin.Spec.OCIArtifact, "", meta); err != nil {
		return err
	}
	artifact.DeduplicateArtifactMeta(meta)
	plugin.Status.ArtifactMeta = meta
	return nil
}

// SetupWithManager registers this controller with the manager.
func (r *PluginAggregatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return shared.NewControllerManagedBy(mgr, r.Client, ControllerName, artifact.KindPlugin, &artifactv1alpha1.Plugin{},
		func() client.ObjectList { return &artifactv1alpha1.PluginList{} }, r.cache).
		Complete(r)
}

// fetchAndCacheBlobs pulls the plugin binary for every distinct (os, arch) pair present
// in nodes and stores each blob in the artifact cache. This runs in the instance operator so
// that per-node artifact-operator sidecars can fetch the pre-extracted binary over HTTP
// without touching the OCI registry directly.
//
// Cache.Ensure owns reuse, writes and reference registration. Registry access is skipped
// when the resolved blob is already present, including reuse after a previous dereference.
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

	am := shared.NewOCIManager(r.Client, plugin.Namespace, r.ociPuller)

	for p := range seen {
		// Pass the digest already resolved by fetchAndCacheArtifactMeta to avoid a
		// second GET /manifests call. Falls back to resolving if digest is not known.
		var knownDigest string
		if meta := plugin.Status.ArtifactMeta; meta != nil {
			knownDigest = meta.Digest
		}
		logger.Info("Ensuring plugin blob is cached", "os", p.goos, "arch", p.goarch)
		_, err := am.EnsureBlob(ctx, plugin.Name, plugin.Spec.OCIArtifact, artifact.KindPlugin, p.goos, p.goarch, r.cache, knownDigest)
		if err != nil {
			return fmt.Errorf("cache plugin blob (%s/%s): %w", p.goos, p.goarch, err)
		}
	}

	return nil
}
