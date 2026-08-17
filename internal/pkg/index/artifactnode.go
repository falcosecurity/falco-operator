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

package index

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
)

// ArtifactNodeOwnerKind is the field index name for ArtifactNode indexed by
// the Kind of their controlling owner reference.
// Used by instance controllers to list only the ArtifactNodes they own
// (e.g. only Plugin-owned ones).
const ArtifactNodeOwnerKind = "ArtifactNodeOwnerKind"

// ArtifactNodeNodeName is the field index name for ArtifactNode indexed by Spec.NodeName.
// Used by the per-node artifact-operator sidecar's warm sync (nodeartifacts.WarmSync) to list
// only the ArtifactNodes assigned to its own node, once the manager's cache has synced.
const ArtifactNodeNodeName = "ArtifactNodeNodeName"

// ArtifactNodeIndexes holds all field indexes for ArtifactNode resources.
var ArtifactNodeIndexes = []Entry{
	{
		Object:         &artifactv1alpha1.ArtifactNode{},
		Field:          ArtifactNodeOwnerKind,
		ExtractValueFn: ArtifactNodeOwnerKindIndexer,
	},
	{
		Object:         &artifactv1alpha1.ArtifactNode{},
		Field:          ArtifactNodeNodeName,
		ExtractValueFn: ArtifactNodeNodeNameIndexer,
	},
}

// ArtifactNodeOwnerKindIndexer extracts the Kind of the controlling owner reference
// from an ArtifactNode. Used as the index function for ArtifactNodeOwnerKind.
func ArtifactNodeOwnerKindIndexer(obj client.Object) []string {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			return []string{ref.Kind}
		}
	}
	return nil
}

// ArtifactNodeNodeNameIndexer extracts Spec.NodeName from an ArtifactNode. Used as the index
// function for ArtifactNodeNodeName.
func ArtifactNodeNodeNameIndexer(obj client.Object) []string {
	node, ok := obj.(*artifactv1alpha1.ArtifactNode)
	if !ok {
		return nil
	}
	return []string{node.Spec.NodeName}
}
