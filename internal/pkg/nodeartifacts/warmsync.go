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

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
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
			mgr.Sync(Key{Kind: KindRulesfile, Name: o.ownerName},
				RequirementGroupsFromDependencies(rulesfile.Status.ArtifactMeta.Dependencies))
		}
	}
	return nil
}
