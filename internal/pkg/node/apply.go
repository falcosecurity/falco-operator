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
	"slices"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// sourceInput is where one source's bytes come from. Which fields carry the answer follows from
// the medium, which is the key this is filed under in desired.Sources: a deferred source (OCI) is
// described by SpecHash and ExpectedDigest and fetched by the node, every other source by Content.
type sourceInput struct {
	// Content is the bytes themselves, for a source whose bytes the kind's flow already has: inline
	// content out of the CR, or a ConfigMap it read. The flow converts first where the CR's
	// encoding differs from the file's, so the node never has to know that inline config is stored
	// as JSON and written as YAML. Reading a ConfigMap in the flow also means that what is written
	// is exactly what the flow judged, never a newer version read at write time.
	Content []byte
	// SpecHash identifies the revision a deferred source is pinned to. An installed file
	// recorded under a different one is stale regardless of its content, and an empty one means
	// the node cannot confirm what it holds and must fetch.
	SpecHash string
	// ExpectedDigest is the revision the artifact server must confirm. Empty means the parent's
	// metadata does not describe this spec yet, which the fetch reports as not-yet-resolved.
	ExpectedDigest string
}

// desired is what a controller wants the node to hold for one artifact. It is intent only: which
// sources exist and what identifies them, never what the node should do about it.
//
// A source the kind accepts but desired does not list is removed. Listing no sources at all
// therefore means remove everything, never "nothing to do": removing a file is also what
// releases the dependencies it registered.
type desired struct {
	// Sources are the sources this artifact currently has. A medium the kind does not accept is
	// an error rather than an ignored entry.
	Sources map[artifact.Medium]sourceInput
	// Retain are sources the node must leave exactly as they are: neither written nor removed.
	// It is how a controller says "I cannot currently tell you what this source should be",
	// which is not the same as saying it is gone. A Config whose spec.config is present but
	// carries no bytes is the case it exists for: the source has not been withdrawn, so its
	// installed file must survive, but there is nothing to write either.
	Retain []artifact.Medium
	// Priority is the artifact's load-order priority. A change to it renames the files of a kind
	// whose filenames encode priority.
	Priority int32
	// claim is who is claiming this artifact's entry in a shared generated file, for a kind that
	// feeds one. The node checks it before writing anything: a recreated CR must not overwrite a
	// binary whose shared-file entry still belongs to the one it replaced.
	claim *claim
	// Metadata is the artifact metadata the controller judged to describe these sources. It is
	// what a kind that tracks dependencies registers when it writes one, and what the node
	// re-checks to confirm an installed source is still current. Nil means none is known, which
	// a kind that tracks dependencies refuses to write against in enforce mode.
	Metadata *commonv1alpha1.ArtifactMeta
}

// claim identifies who holds a shared file's entry, by the Falco-visible name it is keyed under
// and the object that owns it.
type claim struct {
	Name  string
	Owner ownerRef
}

// result is what the node did, in enough detail for a controller to set its conditions and emit
// its events, and nothing more. It never carries a reason or a message: the wording is the
// controller's, because the words belong to the CR's API, not to the node.
type result struct {
	// Actions is what happened to each source the node touched, including StoreActionRemoved for
	// a source that was dropped from desired.
	Actions map[artifact.Medium]artifact.StoreAction
	// Failed names the source whose handling returned the error, so a controller can set the
	// right source's condition. Empty when applySources returned no error.
	Failed artifact.Medium
}

// applySources makes the node hold what want describes for key, doing whatever that takes: dropping the
// sources that are gone, resolving the ones that are present, writing them, and recording the
// result. Sources are handled in the order their kind registers them.
//
// The error it returns is the first source failure, and result.Failed says which source it was;
// the sources handled before it keep their entries in result.Actions, so a controller reports what
// did land rather than losing it to the failure.
func (n *Node) applySources(ctx context.Context, key artifact.Ref, want desired) (result, error) {
	info, err := artifact.InfoForKind(key.Kind)
	if err != nil {
		return result{}, err
	}
	for medium := range want.Sources {
		if !info.Accepts(medium) {
			return result{}, fmt.Errorf("artifact kind %q cannot be installed from medium %q", info.Kind, medium)
		}
	}

	res := result{Actions: make(map[artifact.Medium]artifact.StoreAction, len(info.Sources))}

	// Dropped sources go first. Removing the file is also what releases the dependencies it
	// registered, so this runs even when nothing is left to install afterwards.
	for _, medium := range info.Sources {
		if _, wanted := want.Sources[medium]; wanted {
			continue
		}
		if slices.Contains(want.Retain, medium) {
			// Retained, so deliberately left alone: still a source the apply decided about, and its
			// installed file survives, so it keeps reporting what it reported before.
			res.Actions[medium] = artifact.StoreActionNone
			continue
		}
		_, removed, removeErr := n.removeIfInstalled(ctx, key, medium)
		if removeErr != nil {
			res.Failed = medium
			return res, removeErr
		}
		// Recorded even when there was nothing to remove: an entry in Actions is what tells the status
		// which sources the apply actually reached (see storeFailures.record).
		res.Actions[medium] = artifact.StoreActionNone
		if removed {
			res.Actions[medium] = artifact.StoreActionRemoved
		}
	}

	for _, medium := range info.Sources {
		input, wanted := want.Sources[medium]
		if !wanted {
			continue
		}
		action, applyErr := n.applySource(ctx, &info, key, medium, input, want)
		if applyErr != nil {
			res.Failed = medium
			return res, applyErr
		}
		res.Actions[medium] = action
	}
	return res, nil
}

// applySource brings one source to what want describes and reports what that took.
func (n *Node) applySource(ctx context.Context, info *artifact.KindInfo, key artifact.Ref,
	medium artifact.Medium, input sourceInput, want desired,
) (artifact.StoreAction, error) {
	source, err := artifact.InfoForMedium(medium)
	if err != nil {
		return artifact.StoreActionNone, err
	}
	if source.Deferred {
		return n.fetchSource(ctx, info, key, medium, input, want)
	}

	fetched, err := n.fetcher.FetchInline(ctx, input.Content)
	if err != nil {
		return artifact.StoreActionNone, err
	}
	return n.storeSource(ctx, info, key, medium, want, fetched)
}

// fetchSource brings a source whose bytes live on the artifact server up to date, fetching only
// when the node cannot confirm that what it already holds is what was asked for.
func (n *Node) fetchSource(ctx context.Context, info *artifact.KindInfo, key artifact.Ref,
	medium artifact.Medium, input sourceInput, want desired,
) (artifact.StoreAction, error) {
	confirmed, err := n.confirmInstalled(ctx, info, key, medium, input.SpecHash, want)
	if err != nil {
		return artifact.StoreActionNone, err
	}
	if confirmed {
		// Nothing was written, so nothing is reported: StoreActionUnchanged records no event.
		return artifact.StoreActionUnchanged, nil
	}

	fetched, err := n.fetcher.FetchOCI(ctx, n.namespace, key.Name, info.Kind, input.ExpectedDigest)
	if err != nil {
		return artifact.StoreActionNone, err
	}
	action, err := n.storeSource(ctx, info, key, medium, want, fetched)
	if err != nil {
		return action, err
	}
	// The spec hash is what identifies the revision, and it is recorded even when the content
	// turned out to be unchanged: the same bytes can be reached from a different spec.
	n.UpdateInstalledSpecHash(key, medium, input.SpecHash)
	return action, nil
}

// confirmInstalled reports whether what the node already holds for a source satisfies the request,
// so that it does not have to be fetched again.
//
// The spec hash and the priority have to match whatever the node recorded: a different spec is a
// different revision even when the bytes would be identical, and a different priority is a
// different filename. What proves the rest depends on the kind. A kind that tracks dependencies
// confirms by re-checking the metadata it registered, since the dependency graph, not the file, is
// what its installation produced; every other kind confirms by hashing the file on disk.
func (n *Node) confirmInstalled(ctx context.Context, info *artifact.KindInfo, key artifact.Ref,
	medium artifact.Medium, specHash string, want desired,
) (bool, error) {
	current := n.FindInstalled(key, medium)
	if current == nil || specHash == "" || current.SpecHash != specHash || current.Priority != want.Priority {
		return false, nil
	}
	if info.TracksDependencies {
		return n.syncRulesfileDependencies(ctx, key, medium, want.Metadata, n.enforceRequirements)
	}
	ok, err := n.Verify(ctx, current)
	if err != nil {
		//nolint:nilerr // a file that cannot be read is simply fetched again; the read failure is
		// not the artifact's problem to report, and surfacing it here would fail the reconcile
		// instead of repairing the file.
		return false, nil
	}
	return ok, nil
}

// storeSource writes one resolved source, after refusing to write over a shared generated file.
func (n *Node) storeSource(ctx context.Context, info *artifact.KindInfo, key artifact.Ref,
	medium artifact.Medium, want desired, fetched artifact.FetchResult,
) (artifact.StoreAction, error) {
	if err := n.refuseAggregatePath(info, key, medium, want.Priority); err != nil {
		return artifact.StoreActionNone, err
	}
	if want.claim != nil {
		n.mu.Lock()
		err := n.checkClaimLocked(want.claim)
		n.mu.Unlock()
		if err != nil {
			return artifact.StoreActionNone, err
		}
	}
	// A kind that tracks dependencies publishes them in the same critical section as the write,
	// so that the graph never names a file that failed to land.
	if info.TracksDependencies {
		action, _, err := n.StoreRulesfile(ctx, key.Name, want.Priority,
			medium, fetched, want.Metadata, n.enforceRequirements)
		return action, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	action, _, err := n.storeLocked(ctx, key.Name, want.Priority, info.Kind, medium, fetched)
	return action, err
}

// refuseAggregatePath stops an ordinary artifact from landing on the path the shared plugins-config
// file owns. The check is a path comparison rather than a name-and-priority-and-medium triple, so
// it keeps holding if the aggregate's own naming ever changes.
func (n *Node) refuseAggregatePath(info *artifact.KindInfo, key artifact.Ref, medium artifact.Medium, artifactPriority int32) error {
	candidate, err := artifact.ArtifactPath(n.dirs, key.Name, artifactPriority, medium, info.Kind)
	if err != nil {
		return err
	}
	reserved, err := artifact.ArtifactPath(n.dirs, pluginConfigFileName, priority.MaxPriority,
		artifact.MediumInline, artifact.KindConfig)
	if err != nil {
		return err
	}
	if candidate == reserved {
		return fmt.Errorf("config path is reserved for the shared plugin configuration")
	}
	return nil
}

// Remove takes the artifact away and releases what it provided. It is what a controller calls when the
// artifact is gone or the node is no longer assigned it.
//
// Removal needs only what installation recorded, which the node holds under key. Nothing about the CR that
// created the artifact is consulted, which is what lets a controller remove an artifact whose parent object
// is already gone, or has been replaced by another incarnation of the same name.
//
// For a plugin, its entry in the shared plugin configuration goes first: the entry names the binary, so
// removing the binary while the entry still points at it would leave Falco loading something that is no
// longer there. Withdrawing it can be refused, with a *BlockedError saying the name is still required by
// something else on this node, and nothing is removed then.
func (n *Node) Remove(ctx context.Context, key artifact.Ref) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if key.Kind == artifact.KindPlugin {
		if err := n.withdrawClaimOfLocked(ctx, key); err != nil {
			return err
		}
	}
	if err := n.removeLocked(ctx, key, slices.Clone(n.filesLocked(key))); err != nil {
		return err
	}
	// Everything of the artifact is gone: withdraw its status entry. Every removal of an artifact, from a
	// reconciler's cleanup to the removal of an orphan, ends here, so none can leave one behind. An apply that
	// drops a source goes through removeLocked alone and keeps the entry, even when that was the artifact's last
	// file: it is still installing the artifact, and publishes the entry itself when it is done.
	if n.status != nil {
		n.status.Remove(key.Kind, key.Name)
	}
	return nil
}
