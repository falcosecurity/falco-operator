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
	"crypto/sha256"
	"fmt"
	"maps"
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
)

const (
	// LabelArtifactParent is the label key storing the parent artifact name, or its hash if too long.
	LabelArtifactParent = "artifact.falcosecurity.dev/parent"
	// LabelArtifactNode is the label key storing the node name, or its hash if too long.
	LabelArtifactNode = "artifact.falcosecurity.dev/node"
	// LabelArtifactKind is the label key storing the artifact kind (plugin, rulesfile, config)
	// on ArtifactNode objects. Useful for user-facing filtering with kubectl.
	LabelArtifactKind = "artifact.falcosecurity.dev/kind"

	// ArtifactKindPlugin identifies a Plugin-owned ArtifactNode.
	ArtifactKindPlugin = "plugin"
	// ArtifactKindRulesfile identifies a Rulesfile-owned ArtifactNode.
	ArtifactKindRulesfile = "rulesfile"
	// ArtifactKindConfig identifies a Config-owned ArtifactNode.
	ArtifactKindConfig = "config"

	// KindPlugin is the exact Kubernetes API Kind string for the Plugin CRD. Used in
	// OwnerReference.Kind comparisons, MatchingFields index values, and GroupVersion.WithKind
	// calls. Distinct from ArtifactKindPlugin above, which is the lowercase
	// artifact.falcosecurity.dev/kind label value instead.
	KindPlugin = "Plugin"
	// KindRulesfile is the exact Kubernetes API Kind string for the Rulesfile CRD.
	KindRulesfile = "Rulesfile"
	// KindConfig is the exact Kubernetes API Kind string for the Config CRD.
	KindConfig = "Config"
	// KindArtifactNode is the exact Kubernetes API Kind string for the ArtifactNode CRD.
	KindArtifactNode = "ArtifactNode"

	// NodeObjectsInUseFinalizer is placed on a parent artifact by the instance operator
	// while at least one node object exists. Blocks artifact deletion until all per-node
	// cleanup (filesystem resources) has completed.
	NodeObjectsInUseFinalizer = "artifact.falcosecurity.dev/node-objects-in-use"

	// maxK8sNameLen is the maximum length of a Kubernetes object name.
	maxK8sNameLen = 253
	// maxLabelValueLen is the maximum length of a Kubernetes label value.
	maxLabelValueLen = 63
	// nodeObjectSeparator separates segments in node object names.
	nodeObjectSeparator = "--"
)

// NodeObjectName returns the deterministic name for a per-node artifact object.
// Ordinary names retain "<kind>--<artifactName>--<nodeName>". Ambiguous or long
// tuples use a hash in a separate naming domain, without the legacy separator.
func NodeObjectName(kind, artifactName, nodeName string) string {
	full := kind + nodeObjectSeparator + artifactName + nodeObjectSeparator + nodeName
	if len(full) <= maxK8sNameLen && !strings.Contains(artifactName, nodeObjectSeparator) && !strings.Contains(nodeName, nodeObjectSeparator) {
		return full
	}
	// Kubernetes names cannot contain NUL, so different tuples have different hash inputs.
	return fmt.Sprintf("%s-%x", kind, sha256.Sum256([]byte(kind+"\x00"+artifactName+"\x00"+nodeName)))
}

// NodeObjectLabels returns searchable labels. Full identities remain in the owner
// reference and spec.nodeName when their names are too long for label values.
func NodeObjectLabels(kind, artifactName, nodeName string) map[string]string {
	return map[string]string{
		LabelArtifactParent: nodeObjectLabelValue(artifactName),
		LabelArtifactNode:   nodeObjectLabelValue(nodeName),
		LabelArtifactKind:   kind,
	}
}

func nodeObjectLabelValue(name string) string {
	if len(name) <= maxLabelValueLen {
		return name
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(name)))[:maxLabelValueLen]
}

// EnforceNodeObjectMeta restores any missing or incorrect labels and the controlling
// owner reference on an existing ArtifactNode. It does nothing and returns nil when
// the object already matches the desired state.
func EnforceNodeObjectMeta(
	ctx context.Context,
	c client.Client,
	node client.Object,
	desiredLabels map[string]string,
	desiredOwnerRef *metav1.OwnerReference,
) error {
	needsPatch := false

	// Check that every desired label is present with the correct value.
	labels := node.GetLabels()
	for k, want := range desiredLabels {
		if got, ok := labels[k]; !ok || got != want {
			needsPatch = true
			break
		}
	}

	// Check that the controlling owner reference is present and points at the current
	// generation of the owner. Matching by Kind+Name alone would treat a stale ownerRef
	// (pointing at a deleted-and-recreated owner sharing the same name) as already correct.
	ownerRefPresent := false
	for _, ref := range node.GetOwnerReferences() {
		if ref.Kind == desiredOwnerRef.Kind && ref.Name == desiredOwnerRef.Name && ref.UID == desiredOwnerRef.UID {
			ownerRefPresent = true
			break
		}
	}
	if !ownerRefPresent {
		needsPatch = true
	}

	if !needsPatch {
		return nil
	}

	logger := log.FromContext(ctx)
	logger.Info("Enforcing ArtifactNode metadata", "name", node.GetName())

	patch := client.MergeFrom(node.DeepCopyObject().(client.Object))

	// Merge desired labels onto existing ones (preserving any user-added labels).
	merged := make(map[string]string, len(labels)+len(desiredLabels))
	maps.Copy(merged, labels)
	maps.Copy(merged, desiredLabels)
	node.SetLabels(merged)

	if !ownerRefPresent {
		// Drop any stale ref of the same Kind (e.g. pointing at a deleted-and-recreated
		// owner reusing the same name) before adding the current one. Appending without
		// removing it would leave two conflicting controller owner references.
		existing := node.GetOwnerReferences()
		kept := existing[:0]
		for _, ref := range existing {
			if ref.Kind != desiredOwnerRef.Kind {
				kept = append(kept, ref)
			}
		}
		node.SetOwnerReferences(append(kept, *desiredOwnerRef))
	}

	return c.Patch(ctx, node, patch)
}

// EnsureNodeObject creates an ArtifactNode for nodeName if it does not already exist, or enforces
// its labels/owner reference if it does. Shared by the three aggregator controllers (Plugin,
// Rulesfile, Config), which otherwise each reimplement this identical create-or-enforce logic.
// artifactKind is the lowercase artifact.falcosecurity.dev/kind label value (e.g. "plugin"),
// ownerGVK the owner's GroupVersionKind (e.g. artifactv1alpha1.GroupVersion.WithKind("Plugin")).
func EnsureNodeObject(
	ctx context.Context,
	cl client.Client,
	owner client.Object,
	ownerGVK schema.GroupVersionKind,
	artifactKind, nodeName string,
) error {
	logger := log.FromContext(ctx)
	name := NodeObjectName(artifactKind, owner.GetName(), nodeName)

	desiredLabels := NodeObjectLabels(artifactKind, owner.GetName(), nodeName)
	desiredOwnerRef := *metav1.NewControllerRef(owner, ownerGVK)

	existing := &artifactv1alpha1.ArtifactNode{}
	err := cl.Get(ctx, client.ObjectKey{Namespace: owner.GetNamespace(), Name: name}, existing)
	if err == nil {
		ref := metav1.GetControllerOf(existing)
		if existing.Spec.NodeName != nodeName || (ref != nil && (ref.Kind != ownerGVK.Kind || ref.Name != owner.GetName())) {
			return fmt.Errorf("ArtifactNode %s/%s belongs to a different artifact or node", existing.Namespace, existing.Name)
		}
		if !existing.DeletionTimestamp.IsZero() {
			return nil
		}
		if err := EnforceNodeObjectMeta(ctx, cl, existing, desiredLabels, &desiredOwnerRef); err != nil {
			logger.Error(err, "unable to enforce ArtifactNode metadata", "node", nodeName, "artifactNode", name)
			return err
		}
		return nil
	}
	if !k8serrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch ArtifactNode", "node", nodeName, "artifactNode", name)
		return err
	}

	nodeObj := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       owner.GetNamespace(),
			Labels:          desiredLabels,
			OwnerReferences: []metav1.OwnerReference{desiredOwnerRef},
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: nodeName},
	}
	logger.Info("Creating ArtifactNode", "node", nodeName, "artifactNode", name)
	if err := cl.Create(ctx, nodeObj); err != nil {
		logger.Error(err, "unable to create ArtifactNode", "node", nodeName, "artifactNode", name)
		return err
	}
	return nil
}
