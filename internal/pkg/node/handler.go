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

	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// ApplyArtifact makes the node hold what obj describes and fills status with what to publish for it.
//
// It is the whole of what a controller asks of the node: everything between reading the CR and
// publishing its status happens here: resolving references, reading sources, judging against Falco,
// writing to disk, recording conditions and emitting events. Each kind has its own flow
// (applyConfig, applyRulesfile, applyPlugin), and the order of the steps inside one is that flow's
// business: a plugin writes its binary before its entry in the shared configuration, and a
// rulesfile reads its ConfigMap before it judges anything and writes the bytes it judged.
//
// It leaves a usable status even when it returns an error, because the controller publishes on
// every path.
func (n *Node) ApplyArtifact(ctx context.Context, obj artifactv1alpha1.Artifact,
	status *artifactv1alpha1.NodeArtifactStatus,
) error {
	var apply func() error
	switch parent := obj.(type) {
	case *artifactv1alpha1.Config:
		apply = func() error { return n.applyConfig(ctx, parent, status) }
	case *artifactv1alpha1.Rulesfile:
		apply = func() error { return n.applyRulesfile(ctx, parent, status) }
	case *artifactv1alpha1.Plugin:
		apply = func() error { return n.applyPlugin(ctx, parent, status) }
	default:
		return fmt.Errorf("the node does not install %T", obj)
	}

	// A file must never exist without a status entry naming it: the cleanup and the parent's
	// finalizer rely on that. The node does the writing, so the node persists the entry first.
	key := artifact.RefOf(obj.GetArtifactKind(), obj)
	if err := n.ensureStatusEntry(ctx, key, string(obj.GetUID()), status.Conditions); err != nil {
		return err
	}
	return apply()
}

// awaitObservedGeneration reports whether the rest of an apply must wait for the instance operator
// to publish metadata for this spec generation.
//
// It is always consulted *after* reference resolution, never before. A broken reference is a fact
// about the spec that this node can establish on its own, without any metadata; and it is usually
// the very reason the instance operator cannot finish the generation, since computing ArtifactMeta
// reads the same ConfigMap. Gating reference resolution therefore hides the cause: the operator
// resets ObservedGeneration to 0 on a source failure, every node defers, nobody reports
// ResolvedRefs=False, and the parent sits on "Waiting for nodes to report ResolvedRefs" forever.
//
// Everything after it (compatibility, fetching, writing) does need that metadata, so it waits.
func (n *Node) awaitObservedGeneration(ctx context.Context, observed, generation int64) bool {
	logger := log.FromContext(ctx)
	if observed != generation {
		logger.Info("instance operator has not yet processed current spec generation; deferring",
			"observedGeneration", observed, "specGeneration", generation)
		return true
	}
	logger.V(1).Info("instance operator has processed current spec generation; proceeding",
		"observedGeneration", observed, "specGeneration", generation)
	return false
}
