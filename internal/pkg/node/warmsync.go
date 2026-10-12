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

package node

import (
	"context"
	"fmt"
	"path/filepath"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// runWarmSync observes installed files before controllers start, and restores plugin ownership from the
// artifacts the node's ArtifactNode assigns. The ArtifactNode is the assignment; the disk is the source of truth
// for what is installed.
//
// It never removes an artifact's files at startup. Orphaned files are the ArtifactNode controller's concern, which
// acts on the ArtifactNode it observes, or on the lack of one. The one thing it prunes is the shared plugin
// configuration, of entries that no assigned Plugin owns and no installed Rulesfile requires. When there is no ArtifactNode, it only recovers the
// installed files from disk and observes the shared plugin configuration exactly as found, since pruning it
// against an empty assignment would destroy working configuration.
//
// The node's client is expected to be the manager's own cache-backed client (mgr.GetClient()): runWarmSync is
// only ever called from WarmSyncRunnable.Warmup, which controller-runtime runs after the manager's cache has
// synced. The reconcilers wait for it through Node.WaitWarmSync (see WarmSyncRunnable's doc comment).
func (n *Node) runWarmSync(ctx context.Context) error {
	artifactNode := &artifactv1alpha1.ArtifactNode{}
	if err := n.cl.Get(ctx, client.ObjectKey{Namespace: n.namespace, Name: n.name}, artifactNode); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("getting the ArtifactNode for warm sync: %w", err)
		}
		return n.recoverInstalled(ctx, nil, false)
	}

	n.ObserveArtifactNode(artifactNode)
	assigned := artifactNode.Spec.Artifacts
	if !artifactNode.DeletionTimestamp.IsZero() {
		// Everything is being removed, so nothing is assigned any longer.
		assigned = nil
	}
	return n.recoverInstalled(ctx, assigned, true)
}

// recoverInstalled recovers the installed files from disk and, when the assignment is known, restores the
// ownership of the shared plugin configuration from the assigned plugins.
func (n *Node) recoverInstalled(ctx context.Context, assigned []artifactv1alpha1.NodeArtifactRef, assignmentKnown bool) error {
	if err := n.seedInstalledFromDisk(ctx); err != nil {
		return err
	}
	if err := n.seedRequirementsFromDisk(ctx); err != nil {
		return err
	}
	if !assignmentKnown {
		// With no ArtifactNode to say whose the entries are, the shared plugin configuration is observed as
		// found and left alone; see observePluginsConfig for what happens to it from there.
		return n.observePluginsConfig(ctx)
	}

	pluginList := &artifactv1alpha1.PluginList{}
	if err := n.cl.List(ctx, pluginList, client.InNamespace(n.namespace)); err != nil {
		return fmt.Errorf("listing current Plugins for warm sync: %w", err)
	}
	byName := make(map[string]*artifactv1alpha1.Plugin, len(pluginList.Items))
	for i := range pluginList.Items {
		byName[pluginList.Items[i].Name] = &pluginList.Items[i]
	}
	var plugins []*artifactv1alpha1.Plugin
	for _, ref := range assigned {
		if ref.Kind != artifact.KindPlugin {
			continue
		}
		plugin := byName[ref.Name]
		if plugin == nil || plugin.UID != types.UID(ref.UID) || !plugin.DeletionTimestamp.IsZero() || plugin.Spec.OCIArtifact == nil {
			continue
		}
		plugins = append(plugins, plugin)
	}
	return n.restorePluginsConfig(ctx, plugins)
}

// seedInstalledFromDisk recovers the installed files from disk into the node's record of them.
//
// The record, not any status entry, is what every filesystem decision (skip vs. rewrite, what to remove) is
// based on from here on; status is a write-through mirror for observability only. Seeding it from disk
// rather than from status means a crash between writing a file and publishing the status that records it
// (or any other way status drifted from reality while this process wasn't running) can never leave a file
// invisible to cleanup: the record reflects what's actually there, not what a possibly-stale status last said.
func (n *Node) seedInstalledFromDisk(ctx context.Context) error {
	// Every registered kind is recovered, whatever they happen to be.
	infos := artifact.Kinds()
	for i := range infos {
		info := &infos[i]
		found, err := n.ScanAll(ctx, info.Kind)
		if err != nil {
			return fmt.Errorf("warm sync: scan installed %s artifacts from disk: %w", info.Kind, err)
		}

		// The shared plugins-config aggregate lives in the same directory as Config CRs' own
		// files but isn't one: it is the node's own file, not any Config's, and must never be
		// treated as one.
		if info.Kind == artifact.KindConfig {
			sharedPath, err := artifact.ArtifactPath(n.dirs, pluginConfigFileName,
				priority.MaxPriority, artifact.MediumInline, artifact.KindConfig)
			if err != nil {
				return fmt.Errorf("warm sync: resolve shared plugin configuration path: %w", err)
			}

			if files, ok := found[pluginConfigFileName]; ok {
				sharedName := filepath.Base(sharedPath)
				var ordinary []artifactv1alpha1.InstalledArtifact
				for _, file := range files {
					if filepath.Base(file.Path) == sharedName {
						n.seedPluginsConfigFile(file)
					} else {
						ordinary = append(ordinary, file)
					}
				}
				if len(ordinary) == 0 {
					delete(found, pluginConfigFileName)
				} else {
					found[pluginConfigFileName] = ordinary
				}
			}
		}

		for name, files := range found {
			n.SeedInstalled(artifact.Ref{Kind: info.Kind, Name: name}, files)
		}
	}
	return nil
}

// seedRequirementsFromDisk recovers what each installed rulesfile requires by reading the file and
// parsing its own required_engine_version and required_plugin_versions directives.
//
// The rules file is the source of truth for this: it is what the instance operator parsed to fill
// in Status.ArtifactMeta in the first place, so recovering it here needs no CR and no API call, and
// cannot disagree with what is installed. A file that cannot be read or parsed is skipped: it will
// be rewritten by its own reconcile, and a missing requirement only ever fails safe, by leaving a
// removal unblocked that a later reconcile will block.
func (n *Node) seedRequirementsFromDisk(ctx context.Context) error {
	logger := log.FromContext(ctx)
	for _, key := range n.installedKeys() {
		if key.Kind != artifact.KindRulesfile {
			continue
		}
		for _, file := range n.GetInstalled(key) {
			content, err := n.disk.Read(ctx, file.Path)
			if err != nil {
				logger.V(3).Info("warm sync: unable to read installed rulesfile; its requirements stay unknown until it reconciles",
					"path", file.Path, "err", err)
				continue
			}
			requirements, err := compat.ParseRulesRequirements(content)
			if err != nil {
				logger.V(3).Info("warm sync: unable to parse installed rulesfile; its requirements stay unknown until it reconciles",
					"path", file.Path, "err", err)
				continue
			}
			metadata := &commonv1alpha1.ArtifactMeta{}
			requirements.AppendTo(metadata)
			n.seedRulesfileRequirements(key, artifact.Medium(file.Medium), file.ContentHash, metadata)
		}
	}
	return nil
}
