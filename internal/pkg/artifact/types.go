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

package artifact

import (
	"cmp"
	"io/fs"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
)

// Kind is an artifact kind, spelled as the Kubernetes API Kind of its CRD. It is the API's own type, so a kind
// read from or written to an ArtifactNode needs no conversion.
type Kind = artifactv1alpha1.ArtifactKind

const (
	// KindRulesfile is the kind of a Rulesfile.
	KindRulesfile = artifactv1alpha1.KindRulesfile
	// KindPlugin is the kind of a Plugin.
	KindPlugin = artifactv1alpha1.KindPlugin
	// KindConfig is the kind of a Config.
	KindConfig = artifactv1alpha1.KindConfig
)

// Ref identifies an artifact within its namespace: an ArtifactNode, its spec and its status all live in the
// artifact's namespace, so kind and name are all it takes to tell artifacts apart there.
type Ref struct {
	Kind Kind
	Name string
}

// Compare orders refs by kind, then by name: the order of every list of artifacts the operators write.
func (r Ref) Compare(other Ref) int {
	return cmp.Or(cmp.Compare(r.Kind, other.Kind), cmp.Compare(r.Name, other.Name))
}

// RefOfAssignment is the Ref of the artifact an entry of an ArtifactNode's spec assigns, whichever incarnation of
// it (uid) is meant.
func RefOfAssignment(assigned artifactv1alpha1.NodeArtifactRef) Ref {
	return Ref{Kind: assigned.Kind, Name: assigned.Name}
}

// RefOfStatus is the Ref of the artifact an entry of an ArtifactNode's status reports on.
func RefOfStatus(reported *artifactv1alpha1.NodeArtifactStatus) Ref {
	return Ref{Kind: reported.Kind, Name: reported.Name}
}

// RefOf is the Ref of obj, an artifact of kind.
func RefOf(kind Kind, obj metav1.Object) Ref {
	return Ref{Kind: kind, Name: obj.GetName()}
}

// Medium represents how the artifact is distributed.
type Medium string

const (
	// MediumInline represents an inline artifact.
	MediumInline Medium = "inline"
	// MediumOCI represents an OCI artifact.
	MediumOCI Medium = "oci"
	// MediumConfigMap represents an artifact from a ConfigMap.
	MediumConfigMap Medium = "configmap"
)

// StoreAction represents the operation performed by a Store method.
type StoreAction string

const (
	// StoreActionNone means the input was absent and no existing artifact was found; no filesystem change occurred.
	StoreActionNone StoreAction = "None"
	// StoreActionRemoved means a previously stored artifact was removed from the filesystem.
	StoreActionRemoved StoreAction = "Removed"
	// StoreActionAdded means a new artifact was written to the filesystem for the first time.
	StoreActionAdded StoreAction = "Added"
	// StoreActionUpdated means an existing artifact was replaced because its content changed.
	StoreActionUpdated StoreAction = "Updated"
	// StoreActionUnchanged means the artifact already existed and was up-to-date; nothing was written.
	StoreActionUnchanged StoreAction = "Unchanged"
	// StoreActionPriorityChanged means the artifact content is unchanged but the priority changed;
	// the file was moved/renamed to reflect the new load order.
	StoreActionPriorityChanged StoreAction = "PriorityChanged"
)

// File represents a tracked artifact file for any source medium.
type File struct {
	Path        string // Full path on the filesystem
	Medium      Medium // How the artifact is sourced
	Priority    int32  // Load-order priority encoded in the filename
	ContentHash string // SHA-256 hex digest of the bytes written to disk
	SpecHash    string // SHA-256 of the parent OCI artifact spec; only meaningful for MediumOCI
}

// PermFor returns the filesystem permission registered for kind: the execute bit for plugins,
// which Falco dlopens, read-only for the rules and config files it merely reads. An
// unregistered kind is an error rather than a default, so a kind that was never given a mode
// cannot be written with someone else's.
func PermFor(kind Kind) (fs.FileMode, error) {
	info, err := InfoForKind(kind)
	if err != nil {
		return 0, err
	}
	return info.Perm, nil
}
