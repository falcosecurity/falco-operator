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
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// WarmSync observes installed files before controllers start. Current Plugin assignments
// determine which observed aggregate entries remain owned; historical rule dependencies
// are not recovered and must be registered by normal source reconciliation.
//
// Call after the manager cache has synced, but before controllers start. The reader must
// provide the ArtifactNodeNodeName index; labels are not authoritative for node assignment.
func WarmSync(ctx context.Context, cl client.Reader, mgr *Manager, namespace, nodeName string) error {
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	if err := cl.List(ctx, nodeList, client.InNamespace(namespace), client.MatchingFields{index.ArtifactNodeNodeName: nodeName}); err != nil {
		return fmt.Errorf("listing ArtifactNodes for warm sync: %w", err)
	}
	pluginList := &artifactv1alpha1.PluginList{}
	if err := cl.List(ctx, pluginList, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("listing current Plugins for warm sync: %w", err)
	}
	byName := make(map[string]*artifactv1alpha1.Plugin, len(pluginList.Items))
	for i := range pluginList.Items {
		plugin := &pluginList.Items[i]
		byName[plugin.Name] = plugin
	}
	var plugins []*artifactv1alpha1.Plugin
	for i := range nodeList.Items {
		node := &nodeList.Items[i]
		ref := metav1.GetControllerOf(node)
		if !node.DeletionTimestamp.IsZero() || ref == nil || ref.Kind != controllerhelper.KindPlugin {
			continue
		}
		plugin := byName[ref.Name]
		if plugin == nil || plugin.UID != ref.UID || !plugin.DeletionTimestamp.IsZero() || plugin.Spec.OCIArtifact == nil {
			continue
		}
		plugins = append(plugins, plugin)
		delete(byName, plugin.Name) // Multiple assignments for the same owner are not alias collisions.
	}

	orphans, err := seedInstalledCacheFromDisk(ctx, mgr, nodeList, namespace)
	if err != nil {
		return err
	}
	if err := mgr.restorePluginsConfig(ctx, plugins); err != nil {
		return err
	}
	return mgr.removeOrphanedArtifacts(ctx, orphans)
}

// seedInstalledCacheFromDisk recovers files from disk and identifies orphaned names.
// Cleanup waits until the observed shared config has been reconciled with current owners.
//
// The cache, not any ArtifactNode's status, is what every filesystem decision (skip vs. rewrite,
// what to remove) is based on from here on; status is a write-through mirror for observability
// only. Seeding it from disk rather than from status means a crash between writing a file and
// patching status recording it (or any other way status drifted from reality while this process
// wasn't running) can never leave a file invisible to cleanup: the cache reflects what's actually
// there, not what a possibly-stale status object last said.
func seedInstalledCacheFromDisk(ctx context.Context, mgr *Manager, nodeList *artifactv1alpha1.ArtifactNodeList, namespace string) ([]Key, error) {
	var orphans []Key

	kinds := []struct {
		ownerKind    string
		cacheKind    Kind
		artifactType artifact.Type
	}{
		{controllerhelper.KindRulesfile, KindRulesfile, artifact.TypeRulesfile},
		{controllerhelper.KindConfig, KindConfig, artifact.TypeConfig},
		{controllerhelper.KindPlugin, KindPlugin, artifact.TypePlugin},
	}

	liveNames := map[string]map[string]bool{}
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
			break
		}
	}

	for _, kt := range kinds {
		disk, err := mgr.ScanAll(ctx, kt.artifactType)
		if err != nil {
			return nil, fmt.Errorf("warm sync: scan installed %s artifacts from disk: %w", kt.ownerKind, err)
		}

		// The shared plugins-config aggregate lives in the same directory as Config CRs' own
		// files but isn't one: it belongs to the single node-level PluginConfigKey, not to any
		// Config ArtifactNode, and must never be treated as orphaned.
		if kt.ownerKind == controllerhelper.KindConfig {
			if files, ok := disk[pluginConfigFileName]; ok {
				sharedName := filepath.Base(artifact.ArtifactPath(artifact.DefaultArtifactDirs(), pluginConfigFileName,
					priority.MaxPriority, artifact.MediumInline, artifact.TypeConfig))
				var ordinary []artifactv1alpha1.InstalledArtifact
				for _, file := range files {
					if filepath.Base(file.Path) == sharedName {
						mgr.SeedInstalled(PluginConfigKey, []artifactv1alpha1.InstalledArtifact{file})
					} else {
						ordinary = append(ordinary, file)
					}
				}
				if len(ordinary) == 0 {
					delete(disk, pluginConfigFileName)
				} else {
					disk[pluginConfigFileName] = ordinary
				}
			}
		}

		live := liveNames[kt.ownerKind]
		for name, files := range disk {
			key := Key{Kind: kt.cacheKind, Namespace: namespace, Name: name}
			if !live[name] {
				orphans = append(orphans, key)
			}
			mgr.SeedInstalled(key, files)
		}
	}
	return orphans, nil
}

// Cleanup follows recovery so a plugin library still referenced by the aggregate is retained.
func (m *Manager) removeOrphanedArtifacts(ctx context.Context, orphans []Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, key := range orphans {
		files := m.installed[key]
		if key.Kind == KindPlugin && m.pluginFilesReferencedLocked(files) {
			continue
		}
		log.FromContext(ctx).Info("Removing orphaned artifact files with no ArtifactNode on this node", "kind", key.Kind, "name", key.Name)
		if err := m.removeLocked(ctx, key, files); err != nil {
			return fmt.Errorf("warm sync: remove orphaned %s %q: %w", key.Kind, key.Name, err)
		}
	}
	return nil
}
