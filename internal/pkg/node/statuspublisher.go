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
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

const (
	// defaultStatusDebounce is how long the publisher lets a burst of updates settle before writing,
	// so that many artifacts reporting at once cost a few patches, not one each.
	defaultStatusDebounce = 200 * time.Millisecond
	// defaultStatusMinInterval is the shortest time between two writes driven by a burst of updates. The whole
	// list is sent each time, so on a node with many artifacts, and on many nodes at once, writes are worth
	// spacing out. The write that precedes an installation (ensureEntry) is never delayed.
	defaultStatusMinInterval = 2 * time.Second
	// defaultStatusRetry is how long the publisher waits before trying again when the ArtifactNode
	// does not exist yet (the operator has not created it) or a write failed.
	defaultStatusRetry = 2 * time.Second
	// statusStopFlushTimeout bounds the last write, the one made when the publisher stops.
	statusStopFlushTimeout = 5 * time.Second
	// defaultStatusMaxRetry is the longest the publisher waits between two attempts at a write that keeps
	// failing. Every node has a publisher, so while the API server is failing they must back off, not keep
	// asking it every defaultStatusRetry.
	defaultStatusMaxRetry = time.Minute
)

// statusPublisher writes this node's per-artifact status to the status of its ArtifactNode.
//
// The sidecar is the only writer of that status, so the publisher owns status.artifacts entirely: every
// write replaces the whole list with a merge patch on the status subresource and carries no
// resourceVersion precondition, which would only make it conflict with the operator's spec writes.
// Reconcilers report entries with Set and withdraw them with Remove. The publisher never reads
// status back to decide what to write.
//
// It compares what it wants to write against its own last successful write, not against the informer
// cache. A cache that still shows an older status equal to the wanted one must not suppress a write,
// because the server may already hold something newer that only this publisher wrote.
//
// Entries a previous process published are kept until their artifact is removed, so that a restart
// does not make an installed artifact's entry vanish while its reconciler has not run yet.
//
// Every artifact in the ArtifactNode's spec gets an entry, empty until its reconciler reports, written together with
// the first write that follows. The reconcilers then find their entries already persisted, so a node given many
// artifacts at once costs a few writes and not one per artifact.
//
// The mutex only guards in-memory maps and is never held across a call to the API server. The maps are also read
// by the reconcilers, which start from their artifact's previous status and ask what the node holds, so they are
// shared state and not a stream of messages.
type statusPublisher struct {
	cl          client.Client
	namespace   string
	nodeName    string
	debounce    time.Duration
	minInterval time.Duration
	retry       time.Duration
	maxRetry    time.Duration

	// wake nudges Start's loop; a buffered token, so a nudge is never lost and never blocks.
	wake chan struct{}
	// flushMu serializes writes, so the background loop and ensureEntry never patch concurrently.
	flushMu sync.Mutex

	mu      sync.Mutex
	entries map[artifact.Ref]artifactv1alpha1.NodeArtifactStatus
	// baseline holds the entries found on the object the first time it was read, minus those this
	// process has since set or removed. removedEarly remembers removals that happened before that read.
	baseline     map[artifact.Ref]artifactv1alpha1.NodeArtifactStatus
	removedEarly map[artifact.Ref]struct{}
	baselined    bool
	// lastWritten is what this process last wrote to, or found on, the ArtifactNode whose uid is objectUID. An
	// ArtifactNode deleted and created again is another object with an empty status: nothing was written to it.
	lastWritten []artifactv1alpha1.NodeArtifactStatus
	written     bool
	objectUID   types.UID
	lastWriteAt time.Time
	// version counts the changes to what would be written, and writtenVersion is the one last written or found
	// to be on the server: when they are equal there is nothing to compute.
	version, writtenVersion uint64
}

// StatusTimings are the status publisher's delays. Production runs on the defaults; tests shorten them.
type StatusTimings struct {
	// Debounce is how long a burst of updates is allowed to settle before it is written.
	Debounce time.Duration
	// MinInterval is the shortest time between two writes driven by a burst of updates.
	MinInterval time.Duration
	// Retry is how long to wait before retrying when the object is missing or a write failed.
	Retry time.Duration
}

// newStatusPublisher returns a publisher for the ArtifactNode of nodeName in namespace. cl is
// expected to be the manager's cache-backed client, scoped to that one object.
func newStatusPublisher(cl client.Client, namespace, nodeName string, timings *StatusTimings) *statusPublisher {
	p := &statusPublisher{
		cl:           cl,
		namespace:    namespace,
		nodeName:     nodeName,
		debounce:     defaultStatusDebounce,
		minInterval:  defaultStatusMinInterval,
		retry:        defaultStatusRetry,
		maxRetry:     defaultStatusMaxRetry,
		wake:         make(chan struct{}, 1),
		entries:      make(map[artifact.Ref]artifactv1alpha1.NodeArtifactStatus),
		baseline:     make(map[artifact.Ref]artifactv1alpha1.NodeArtifactStatus),
		removedEarly: make(map[artifact.Ref]struct{}),
	}
	if timings != nil {
		p.debounce, p.minInterval, p.retry = timings.Debounce, timings.MinInterval, timings.Retry
	}
	return p
}

// Set records the status of one artifact, replacing any earlier entry for the same kind and name. The
// arguments are copied.
func (p *statusPublisher) Set(
	kind artifact.Kind, name, uid string, conditions []metav1.Condition, installed []artifactv1alpha1.InstalledArtifact,
) {
	entry := artifactv1alpha1.NodeArtifactStatus{
		Kind: kind, Name: name, UID: uid, Conditions: conditions, InstalledArtifacts: installed,
	}
	key := artifact.Ref{Kind: kind, Name: name}
	p.mu.Lock()
	if current, ok := p.entries[key]; ok && apiequality.Semantic.DeepEqual(current, entry) {
		p.mu.Unlock() // a reconcile that changed nothing
		return
	}
	p.entries[key] = *entry.DeepCopy()
	p.version++
	p.mu.Unlock()
	p.nudge()
}

// Remove withdraws the entry of one artifact. Call it once the artifact's files are gone.
func (p *statusPublisher) Remove(kind artifact.Kind, name string) {
	key := artifact.Ref{Kind: kind, Name: name}
	p.mu.Lock()
	delete(p.entries, key)
	delete(p.baseline, key)
	if !p.baselined {
		p.removedEarly[key] = struct{}{}
	}
	p.version++
	p.mu.Unlock()
	p.nudge()
}

// Has reports whether the publisher holds an entry for the artifact, without copying it.
func (p *statusPublisher) Has(kind artifact.Kind, name string) bool {
	key := artifact.Ref{Kind: kind, Name: name}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, inEntries := p.entries[key]
	_, inBaseline := p.baseline[key]
	return inEntries || inBaseline
}

// Entry returns a copy of the status held for the artifact: the one this process set, otherwise the one
// found on the object. A reconciler starts from it, so an artifact's conditions survive a restart.
func (p *statusPublisher) Entry(kind artifact.Kind, name string) (artifactv1alpha1.NodeArtifactStatus, bool) {
	key := artifact.Ref{Kind: kind, Name: name}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[key]; ok {
		return *e.DeepCopy(), true
	}
	if e, ok := p.baseline[key]; ok {
		return *e.DeepCopy(), true
	}
	return artifactv1alpha1.NodeArtifactStatus{}, false
}

// Keys returns the artifacts the publisher holds an entry for, whether it set them or found them on the
// object. Call Observe first so that entries found on the object are included.
func (p *statusPublisher) Keys() []artifact.Ref {
	p.mu.Lock()
	defer p.mu.Unlock()
	keys := make([]artifact.Ref, 0, len(p.entries)+len(p.baseline))
	for k := range p.baseline {
		keys = append(keys, k)
	}
	for k := range p.entries {
		if _, dup := p.baseline[k]; !dup {
			keys = append(keys, k)
		}
	}
	return keys
}

// Observe records the entries already on artifactNode, once, as the baseline the publisher starts from. The first
// flush does the same; calling it earlier lets Keys and Entry see what a previous process published. It also
// gives the artifacts in artifactNode's spec an entry each, to be written with the next write.
func (p *statusPublisher) Observe(artifactNode *artifactv1alpha1.ArtifactNode) {
	p.mu.Lock()
	replaced := p.sawObjectLocked(artifactNode)
	p.takeBaselineLocked(artifactNode.Status.Artifacts)
	reserved := p.reserveLocked(artifactNode)
	p.mu.Unlock()
	if reserved || replaced {
		p.nudge()
	}
}

// sawObjectLocked records which ArtifactNode the publisher is looking at, and reports whether it is another one
// than the one it last wrote to: the ArtifactNode was deleted and created again. What was written is then on an
// object that no longer exists, so it is forgotten, and the next write puts the entries on the new one.
// Caller holds p.mu.
func (p *statusPublisher) sawObjectLocked(artifactNode *artifactv1alpha1.ArtifactNode) bool {
	if p.objectUID == artifactNode.UID {
		return false
	}
	replaced := p.written
	p.objectUID, p.written, p.lastWritten = artifactNode.UID, false, nil
	return replaced
}

// reserveLocked gives every artifact in artifactNode's spec that has no entry an empty one, with the uid the spec
// gives the artifact, and reports whether it added any. An entry the artifact's reconciler has yet to fill is what
// the reconciler would have written before installing anything. An ArtifactNode being deleted gets none: what its
// spec lists no longer says what the node holds, and an entry added after a removal would never be withdrawn.
// Caller holds p.mu.
func (p *statusPublisher) reserveLocked(artifactNode *artifactv1alpha1.ArtifactNode) bool {
	if !artifactNode.DeletionTimestamp.IsZero() {
		return false
	}
	reserved := false
	for _, r := range artifactNode.Spec.Artifacts {
		key := artifact.RefOfAssignment(r)
		_, inEntries := p.entries[key]
		_, inBaseline := p.baseline[key]
		if inEntries || inBaseline {
			continue
		}
		p.entries[key] = artifactv1alpha1.NodeArtifactStatus{Kind: r.Kind, Name: r.Name, UID: r.UID}
		reserved = true
	}
	if reserved {
		p.version++
	}
	return reserved
}

// ensureEntry persists an entry for the artifact before it returns. A reconciler calls it before the
// first file of an artifact is written, so that if the file exists, so does an entry naming it: the
// cleanup and the parent's finalizer rely on that. It returns an error when the entry could not be
// persisted, notably because the ArtifactNode does not exist, and the caller must then not install.
//
// conditions seed a new entry; an entry the publisher already holds for the same uid is kept as it is.
func (p *statusPublisher) ensureEntry(ctx context.Context, kind artifact.Kind, name, uid string, conditions []metav1.Condition) error {
	key := artifact.Ref{Kind: kind, Name: name}
	p.mu.Lock()
	current, ok := p.entries[key]
	if !ok {
		current, ok = p.baseline[key]
	}
	if !ok || current.UID != uid {
		entry := artifactv1alpha1.NodeArtifactStatus{Kind: kind, Name: name, UID: uid, Conditions: conditions}
		p.entries[key] = *entry.DeepCopy()
		p.version++
	} else if p.persistedLocked(kind, name, uid) {
		// The entry is already on the ArtifactNode: there is nothing to persist first. What other artifacts have
		// changed since is left to the batched write, rather than written now, on every reconcile.
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	done, err := p.flush(ctx)
	if err != nil {
		return err
	}
	if !done {
		return fmt.Errorf("ArtifactNode %s/%s does not exist yet", p.namespace, p.nodeName)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.persistedLocked(kind, name, uid) {
		return fmt.Errorf("status entry of %s %q was not persisted: the node still holds artifacts being removed, and reports at most %d",
			kind, name, artifactv1alpha1.MaxNodeArtifacts)
	}
	return nil
}

// persistedLocked reports whether the last write put an entry for this incarnation of the artifact on the
// ArtifactNode. Call it with p.mu held.
func (p *statusPublisher) persistedLocked(kind artifact.Kind, name, uid string) bool {
	return p.written && slices.ContainsFunc(p.lastWritten, func(e artifactv1alpha1.NodeArtifactStatus) bool {
		return e.Kind == kind && e.Name == name && e.UID == uid
	})
}

func (p *statusPublisher) nudge() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Start publishes until ctx is done, and then writes once more what is still pending: a removal reported just
// before the sidecar stops would otherwise stay unpublished, and keep the artifact's parent from going, until the
// sidecar is back. It implements manager.Runnable.
func (p *statusPublisher) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("node-status-publisher")
	ctx = log.IntoContext(ctx, logger)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusStopFlushTimeout)
		defer cancel()
		if _, err := p.flush(stopCtx); err != nil {
			logger.Error(err, "Unable to publish the node artifact status before stopping")
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-p.wake:
		}
		if !sleepContext(ctx, p.debounce) || !sleepContext(ctx, p.untilNextWrite()) {
			return nil
		}
		failures := 0
		for {
			done, err := p.flush(ctx)
			if done {
				break
			}
			// A missing ArtifactNode is looked for again at a steady pace: that is a read of the cache. A failed
			// write is retried with a growing, jittered delay, so that the publishers of every node do not keep a
			// failing API server busy, nor all come back at the same moment.
			delay := p.retry
			if err != nil {
				failures++
				delay = wait.Jitter(p.retryDelay(failures), 0.5)
				logger.Error(err, "Unable to publish the node artifact status, will retry", "after", delay)
			} else {
				failures = 0
			}
			if !sleepContext(ctx, delay) {
				return nil
			}
		}
	}
}

// retryDelay returns how long to wait, before jitter, after the given number of consecutive failed writes: the
// retry delay, doubled with each failure after the first, up to maxRetry.
func (p *statusPublisher) retryDelay(failures int) time.Duration {
	delay := p.retry
	for i := 1; i < failures && delay < p.maxRetry; i++ {
		delay *= 2
	}
	return max(p.retry, min(delay, p.maxRetry))
}

// untilNextWrite returns how much of the minimum interval since the last write is left.
func (p *statusPublisher) untilNextWrite() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return max(0, p.minInterval-time.Since(p.lastWriteAt))
}

// NeedLeaderElection reports that every node's sidecar publishes its own node's status, regardless of
// leader election. It implements manager.LeaderElectionRunnable.
func (p *statusPublisher) NeedLeaderElection() bool { return false }

// flush writes the current status if it differs from the last write. It reports false, without an
// error, when the ArtifactNode does not exist (yet), so the caller retries later with the entries
// still held.
func (p *statusPublisher) flush(ctx context.Context) (bool, error) {
	p.flushMu.Lock()
	defer p.flushMu.Unlock()

	// The object is only read, and not kept, so it is not copied out of the cache.
	artifactNode := &artifactv1alpha1.ArtifactNode{}
	if err := p.cl.Get(ctx, client.ObjectKey{Namespace: p.namespace, Name: p.nodeName}, artifactNode, client.UnsafeDisableDeepCopy); err != nil {
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	p.mu.Lock()
	p.sawObjectLocked(artifactNode)
	p.takeBaselineLocked(artifactNode.Status.Artifacts)
	p.reserveLocked(artifactNode)
	// Over the schema cap the entries kept depend on the spec, which is not in the version. A key can be
	// in both maps (an entry that replaced a baseline one), and counts once: what is published is the union.
	tracked := len(p.entries)
	for key := range p.baseline {
		if _, replaced := p.entries[key]; !replaced {
			tracked++
		}
	}
	overCap := tracked > artifactv1alpha1.MaxNodeArtifacts
	if p.written && p.version == p.writtenVersion && !overCap {
		p.mu.Unlock()
		return true, nil
	}
	version := p.version
	desired := p.desiredLocked(ctx, artifactNode.Spec.Artifacts)
	unchanged := p.written && apiequality.Semantic.DeepEqual(desired, p.lastWritten)
	if !p.written && apiequality.Semantic.DeepEqual(desired, artifactNode.Status.Artifacts) {
		// Nothing has been written by this process yet, so what was read is what a previous one left: it
		// already holds the desired list, as after a restart that changes nothing.
		p.lastWritten, p.written, unchanged = desired, true, true
	}
	if unchanged {
		p.writtenVersion = version
		p.mu.Unlock()
		return true, nil
	}
	p.mu.Unlock()

	body, err := json.Marshal(map[string]any{"status": map[string]any{"artifacts": desired}})
	if err != nil {
		return false, err
	}
	// The response is decoded into a bare object, so nothing of the cache is touched.
	target := &artifactv1alpha1.ArtifactNode{ObjectMeta: metav1.ObjectMeta{Namespace: p.namespace, Name: p.nodeName}}
	if err := p.cl.Status().Patch(ctx, target, client.RawPatch(types.MergePatchType, body)); err != nil {
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	p.mu.Lock()
	p.lastWritten, p.written, p.writtenVersion, p.lastWriteAt = desired, true, version, time.Now()
	p.mu.Unlock()
	return true, nil
}

// takeBaselineLocked records, once, the entries already on the object. Caller holds p.mu.
func (p *statusPublisher) takeBaselineLocked(found []artifactv1alpha1.NodeArtifactStatus) {
	if p.baselined {
		return
	}
	for i := range found {
		key := artifact.RefOfStatus(&found[i])
		if _, removed := p.removedEarly[key]; removed {
			continue
		}
		if _, present := p.entries[key]; present {
			continue
		}
		p.baseline[key] = *found[i].DeepCopy()
	}
	p.baselined = true
	p.removedEarly = nil
	p.version++
}

// desiredLocked returns the list to publish: this process's entries plus the baseline ones it has not
// replaced, sorted by kind and name.
//
// Over the schema cap it keeps first the entries of artifacts the spec no longer assigns. Such an artifact is
// held by its entry alone: it is what tells the parent's finalizer that the node still has its files, and what
// carries a blocked removal to the parent, so leaving it out would release a parent whose files are still here.
// An assigned artifact is held by the spec, whatever the status says. One whose entry is left out is not
// installed until a removal makes room (see ensureEntry). Caller holds p.mu.
func (p *statusPublisher) desiredLocked(ctx context.Context, assigned []artifactv1alpha1.NodeArtifactRef) []artifactv1alpha1.NodeArtifactStatus {
	desired := make([]artifactv1alpha1.NodeArtifactStatus, 0, len(p.entries)+len(p.baseline))
	for k, e := range p.baseline {
		if _, replaced := p.entries[k]; !replaced {
			desired = append(desired, e)
		}
	}
	for _, e := range p.entries {
		desired = append(desired, e)
	}
	sortStatuses(desired)

	if len(desired) > artifactv1alpha1.MaxNodeArtifacts {
		isAssigned := make(map[artifact.Ref]bool, len(assigned))
		for _, r := range assigned {
			isAssigned[artifact.RefOfAssignment(r)] = true
		}
		slices.SortStableFunc(desired, func(a, b artifactv1alpha1.NodeArtifactStatus) int {
			aOK, bOK := isAssigned[artifact.RefOfStatus(&a)], isAssigned[artifact.RefOfStatus(&b)]
			switch {
			case aOK == bOK:
				return 0
			case bOK:
				return -1
			default:
				return 1
			}
		})
		log.FromContext(ctx).Info("Node artifact status exceeds the schema cap, assigned artifacts wait for removals to make room",
			"limit", artifactv1alpha1.MaxNodeArtifacts, "entries", len(desired))
		desired = desired[:artifactv1alpha1.MaxNodeArtifacts]
		sortStatuses(desired)
	}
	return desired
}

func sortStatuses(s []artifactv1alpha1.NodeArtifactStatus) {
	slices.SortFunc(s, func(a, b artifactv1alpha1.NodeArtifactStatus) int {
		return artifact.RefOfStatus(&a).Compare(artifact.RefOfStatus(&b))
	})
}

// sleepContext waits for d and reports false if ctx ended first.
func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
