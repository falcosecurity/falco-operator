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
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

// WarmSync populates mgr's dependency registry from durable ArtifactNode status before the
// artifact-operator sidecar's controller-runtime manager starts serving reconciles, so a Plugin
// removal reconciled immediately after a sidecar restart is evaluated against accurate
// dependency data instead of an empty registry.
//
// cl is expected to be the manager's own cache-backed client (mgr.GetClient()): WarmSync is
// only ever called from WarmSyncRunnable.Warmup, which controller-runtime guarantees runs after
// the manager's cache has synced (see WarmSyncRunnable's doc comment); so the
// index.ArtifactNodeNodeName field index below is safe to use, giving a real cached indexed
// lookup instead of a label-selector List.
//
// Parent Plugins/Rulesfiles are fetched with at most one List each (rather than one Get per
// ArtifactNode) so this issues a constant number of requests regardless of how many artifacts
// are installed on this node; even served from cache, this keeps memory/CPU use bounded
// rather than fanning out one Get per artifact.
func WarmSync(ctx context.Context, cl client.Client, mgr *Manager, namespace, nodeName string) error {
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	if err := cl.List(ctx, nodeList,
		client.InNamespace(namespace),
		client.MatchingFields{index.ArtifactNodeNodeName: nodeName},
	); err != nil {
		return fmt.Errorf("listing ArtifactNodes for warm sync: %w", err)
	}

	type ownedNode struct {
		ownerKind string
		ownerName string
	}
	var owned []ownedNode
	needPlugins, needRulesfiles := false, false

	for i := range nodeList.Items {
		n := &nodeList.Items[i]
		if !n.DeletionTimestamp.IsZero() || len(n.Status.InstalledArtifacts) == 0 {
			continue
		}

		ownerKind, ownerName := "", ""
		for _, ref := range n.OwnerReferences {
			if ref.Controller != nil && *ref.Controller {
				ownerKind, ownerName = ref.Kind, ref.Name
				break
			}
		}

		switch ownerKind {
		case controllerhelper.KindPlugin:
			needPlugins = true
		case controllerhelper.KindRulesfile:
			needRulesfiles = true
		default:
			continue
		}
		owned = append(owned, ownedNode{ownerKind, ownerName})
	}

	plugins := map[string]*artifactv1alpha1.Plugin{}
	if needPlugins {
		list := &artifactv1alpha1.PluginList{}
		if err := cl.List(ctx, list, client.InNamespace(namespace)); err != nil {
			return fmt.Errorf("listing Plugins for warm sync: %w", err)
		}
		for i := range list.Items {
			plugins[list.Items[i].Name] = &list.Items[i]
		}
	}

	rulesfiles := map[string]*artifactv1alpha1.Rulesfile{}
	if needRulesfiles {
		list := &artifactv1alpha1.RulesfileList{}
		if err := cl.List(ctx, list, client.InNamespace(namespace)); err != nil {
			return fmt.Errorf("listing Rulesfiles for warm sync: %w", err)
		}
		for i := range list.Items {
			rulesfiles[list.Items[i].Name] = &list.Items[i]
		}
	}

	for _, o := range owned {
		switch o.ownerKind {
		case controllerhelper.KindPlugin:
			plugin, ok := plugins[o.ownerName]
			if !ok {
				continue // parent deleted concurrently with this warm sync
			}
			configName := o.ownerName
			if plugin.Spec.Config != nil && plugin.Spec.Config.Name != "" {
				configName = plugin.Spec.Config.Name
			}
			mgr.SyncProvides(PluginConfigKey, configName)

		case controllerhelper.KindRulesfile:
			rulesfile, ok := rulesfiles[o.ownerName]
			if !ok || rulesfile.Status.ArtifactMeta == nil {
				continue
			}
			mgr.Sync(Key{Kind: KindRulesfile, Namespace: namespace, Name: o.ownerName},
				RequirementGroupsFromDependencies(rulesfile.Status.ArtifactMeta.Dependencies))
		}
	}

	return seedInstalledCacheFromDisk(ctx, mgr, nodeList, namespace)
}

// seedInstalledCacheFromDisk populates mgr's installed-artifact cache from disk ground truth for
// every artifact still known to this node, and removes any file whose artifact name has no
// ArtifactNode at all on this node.
//
// The cache, not any ArtifactNode's status, is what every filesystem decision (skip vs. rewrite,
// what to remove) is based on from here on; status is a write-through mirror for observability
// only. Seeding it from disk rather than from status means a crash between writing a file and
// patching status recording it (or any other way status drifted from reality while this process
// wasn't running) can never leave a file invisible to cleanup: the cache reflects what's actually
// there, not what a possibly-stale status object last said.
//
// A name with files on disk but no ArtifactNode for this node at all (its parent CR was deleted
// and fully garbage collected while nothing else was ever going to ask about it again) is removed
// immediately, mirroring the removal cleanupStaleMedium already performs during normal reconciles.
func seedInstalledCacheFromDisk(ctx context.Context, mgr *Manager, nodeList *artifactv1alpha1.ArtifactNodeList, namespace string) error {
	logger := log.FromContext(ctx)

	kinds := []struct {
		ownerKind    string
		cacheKind    Kind
		artifactType artifact.Type
	}{
		{controllerhelper.KindPlugin, KindPlugin, artifact.TypePlugin},
		{controllerhelper.KindRulesfile, KindRulesfile, artifact.TypeRulesfile},
		{controllerhelper.KindConfig, KindConfig, artifact.TypeConfig},
	}

	liveNames := map[string]map[string]bool{}
	statusByName := map[string]map[string][]artifactv1alpha1.InstalledArtifact{}
	for i := range nodeList.Items {
		n := &nodeList.Items[i]
		for _, ref := range n.OwnerReferences {
			if ref.Controller == nil || !*ref.Controller {
				continue
			}
			if liveNames[ref.Kind] == nil {
				liveNames[ref.Kind] = map[string]bool{}
			}
			liveNames[ref.Kind][ref.Name] = true
			if statusByName[ref.Kind] == nil {
				statusByName[ref.Kind] = map[string][]artifactv1alpha1.InstalledArtifact{}
			}
			statusByName[ref.Kind][ref.Name] = n.Status.InstalledArtifacts
			break
		}
	}

	for _, kt := range kinds {
		disk, err := mgr.ScanAll(ctx, kt.artifactType)
		if err != nil {
			return fmt.Errorf("warm sync: scan installed %s artifacts from disk: %w", kt.ownerKind, err)
		}

		// The shared plugins-config aggregate lives in the same directory as Config CRs' own
		// files but isn't one: it belongs to the single node-level PluginConfigKey, not to any
		// Config ArtifactNode, and must never be treated as orphaned.
		if kt.ownerKind == controllerhelper.KindConfig {
			if files, ok := disk[pluginConfigFileName]; ok {
				mgr.SeedInstalled(PluginConfigKey, files)
				delete(disk, pluginConfigFileName)
			}
		}

		live := liveNames[kt.ownerKind]
		statusForKind := statusByName[kt.ownerKind]
		for name, files := range disk {
			key := Key{Kind: kt.cacheKind, Namespace: namespace, Name: name}
			if !live[name] {
				logger.Info("Removing orphaned artifact files with no ArtifactNode on this node",
					"kind", kt.ownerKind, "name", name)
				if err := mgr.Remove(ctx, key, files); err != nil {
					logger.Error(err, "warm sync: unable to remove orphaned artifact files",
						"kind", kt.ownerKind, "name", name)
				}
				continue
			}
			recoverSpecHashFromStatus(files, statusForKind[name])
			mgr.SeedInstalled(key, files)
		}
	}
	return nil
}

// recoverSpecHashFromStatus backfills SpecHash on disk-derived entries from status, for any
// medium where status still describes the exact same on-disk content (matching ContentHash).
// ScanAll can only recover ContentHash from file bytes; SpecHash reflects the parent spec, which
// isn't recoverable from content alone. Without this, every OCI/inline artifact would look like
// its parent spec had changed on the very first reconcile after a sidecar restart, forcing a
// needless re-fetch from the OCI artifact server even though nothing actually changed.
func recoverSpecHashFromStatus(files, status []artifactv1alpha1.InstalledArtifact) {
	for i := range files {
		for _, s := range status {
			if s.Medium == files[i].Medium && s.ContentHash == files[i].ContentHash && s.SpecHash != "" {
				files[i].SpecHash = s.SpecHash
				break
			}
		}
	}
}
