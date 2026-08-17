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

package controllerhelper

import (
	"context"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

// GetVerifiedOwner resolves nodeObj's controlling owner reference of the given kind, fetches
// the live object into out, and verifies via UID that it's actually still the same object the
// reference was set for.
//
// ArtifactNode names are deterministic (kind+artifactName+nodeName), so the same name gets
// reused every time a parent artifact (Plugin/Rulesfile/Config) is deleted and recreated. A
// stale ownerRef left on an ArtifactNode that hasn't caught up yet would, if matched by name
// alone, resolve to a live parent that isn't actually the one that owns it, silently adopting
// the wrong generation's spec. The UID check catches that; a mismatch is treated the same as
// "owner not found" (false, nil) rather than an error, since the correct response in both
// cases is the same: wait for garbage collection.
//
// Returns (true, nil) with out populated when the owner is live and verified; (false, nil)
// when there's no such ownerRef, the referenced object is gone, or its UID no longer matches.
func GetVerifiedOwner(ctx context.Context, cl client.Client, nodeObj *artifactv1alpha1.ArtifactNode, kind string, out client.Object) (bool, error) {
	for _, ref := range nodeObj.OwnerReferences {
		if ref.Kind != kind {
			continue
		}
		err := cl.Get(ctx, client.ObjectKey{Namespace: nodeObj.Namespace, Name: ref.Name}, out)
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if out.GetUID() != ref.UID {
			log.FromContext(ctx).Info("Owner reference is stale; a live object of that name exists but isn't the referenced generation",
				"kind", kind, "name", ref.Name, "refUID", ref.UID, "liveUID", out.GetUID())
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

// ListOwnedNodes returns all ArtifactNode objects labeled as belonging to parentName and
// indexed under ownerKind (the controlling owner's Kind, e.g. "Plugin", "Rulesfile", "Config").
// Shared by the three aggregator controllers (Plugin, Rulesfile, Config), which otherwise
// each reimplement this identical List call.
func ListOwnedNodes(ctx context.Context, cl client.Client, namespace, parentName, ownerKind string) (*artifactv1alpha1.ArtifactNodeList, error) {
	list := &artifactv1alpha1.ArtifactNodeList{}
	if err := cl.List(ctx, list,
		client.InNamespace(namespace),
		client.MatchingLabels{LabelArtifactParent: parentName},
		client.MatchingFields{index.ArtifactNodeOwnerKind: ownerKind},
	); err != nil {
		return nil, fmt.Errorf("listing ArtifactNodes owned by %s %s/%s: %w", ownerKind, namespace, parentName, err)
	}
	return list, nil
}

// deleteNodeObject deletes a single ArtifactNode and logs the distinct outcome (deleted,
// already gone, or failed) so a stuck deletion is traceable from logs alone without having to
// correlate reconcile IDs across multiple controllers.
func deleteNodeObject(ctx context.Context, cl client.Client, node *artifactv1alpha1.ArtifactNode) error {
	logger := log.FromContext(ctx)
	logger.Info("Deleting ArtifactNode", "artifactNode", node.Name, "resourceVersion", node.ResourceVersion)
	switch err := cl.Delete(ctx, node); {
	case err == nil:
		logger.Info("Deleted ArtifactNode", "artifactNode", node.Name)
		return nil
	case k8serrors.IsNotFound(err):
		logger.Info("ArtifactNode already gone", "artifactNode", node.Name)
		return nil
	default:
		logger.Error(err, "unable to delete ArtifactNode", "artifactNode", node.Name)
		return err
	}
}

// DeleteStaleNodeObjects deletes every node in existing whose Spec.NodeName is not present in
// desired (the node no longer matches the parent's selector). ClearFinalizersIfNodeGone runs
// first for each so a node object orphaned by its underlying Kubernetes Node being removed
// doesn't block forever waiting for an evicted per-node operator to release its finalizer.
func DeleteStaleNodeObjects(ctx context.Context, cl client.Client, existing []artifactv1alpha1.ArtifactNode, desired map[string]struct{}) error {
	for i := range existing {
		node := &existing[i]
		if _, ok := desired[node.Spec.NodeName]; ok {
			continue
		}
		if err := ClearFinalizersIfNodeGone(ctx, cl, node.Spec.NodeName, node); err != nil {
			return err
		}
		if err := deleteNodeObject(ctx, cl, node); err != nil {
			return err
		}
	}
	return nil
}

// DeleteNodeObjectsForParentDeletion deletes every still-live node in existing as part of
// tearing down the parent artifact. It returns nodesRemaining=true when any node object was
// present at the start of the call, regardless of whether this call's Delete requests have
// already taken effect server-side. The caller uses this to decide whether the in-use
// finalizer can be released yet. A subsequent reconcile (triggered by the ArtifactNode watch
// once each one is actually removed) re-lists and eventually observes zero remaining.
func DeleteNodeObjectsForParentDeletion(ctx context.Context, cl client.Client, existing []artifactv1alpha1.ArtifactNode) (nodesRemaining bool, err error) {
	logger := log.FromContext(ctx)

	for i := range existing {
		node := &existing[i]
		if err := ClearFinalizersIfNodeGone(ctx, cl, node.Spec.NodeName, node); err != nil {
			return false, err
		}
		if node.DeletionTimestamp.IsZero() {
			if err := deleteNodeObject(ctx, cl, node); err != nil {
				return false, err
			}
		}
	}

	nodesRemaining = len(existing) > 0
	if nodesRemaining {
		logger.V(1).Info("Waiting for ArtifactNodes to be fully deleted", "remaining", len(existing))
	}
	return nodesRemaining, nil
}
