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
	"crypto/sha256"
	"fmt"

	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

const (
	// LabelArtifactNode is the label key storing the node name, or its hash if too long.
	LabelArtifactNode = "artifact.falcosecurity.dev/node"

	// NodeObjectsInUseFinalizer is placed on a parent artifact by the instance operator
	// while at least one node lists it or reports on it. Blocks artifact deletion until all per-node
	// cleanup (filesystem resources) has completed. The name predates the per-node ArtifactNode and is
	// kept so that parents that already carry it are released by the same finalizer.
	NodeObjectsInUseFinalizer = "artifact.falcosecurity.dev/node-objects-in-use"

	// maxLabelValueLen is the maximum length of a Kubernetes label value.
	maxLabelValueLen = 63
)

// ArtifactNodeLabels returns the labels of the ArtifactNode of nodeName, which let tools and the instance
// operator list a node's ArtifactNodes across namespaces. The artifact operator does not rely on them: it
// selects its own ArtifactNode by name (see SidecarArtifactNodeCache). The node name is hashed when it is too
// long for a label value.
func ArtifactNodeLabels(nodeName string) map[string]string {
	return map[string]string{LabelArtifactNode: nodeObjectLabelValue(nodeName)}
}

func nodeObjectLabelValue(name string) string {
	if len(name) <= maxLabelValueLen {
		return name
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(name)))[:maxLabelValueLen]
}

// SidecarArtifactNodeCache restricts what an artifact operator caches of ArtifactNodes to the one of its own node.
//
// The object is selected by name, which is the node's name and cannot change, never by label: an ArtifactNode
// whose label someone removed or edited would drop out of the cache and look deleted, and the artifact operator
// would remove everything installed on the node until the instance operator put the label back.
func SidecarArtifactNodeCache(nodeName string) cache.ByObject {
	return cache.ByObject{Field: fields.OneTermEqualSelector("metadata.name", nodeName)}
}
