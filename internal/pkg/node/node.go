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
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
)

// removalBuffer is the capacity of a kind's removal channel: room for every artifact a node can be
// assigned, and as many stale entries.
const removalBuffer = 2 * artifactv1alpha1.MaxNodeArtifacts

// Node models the node that this sidecar and its Falco share: the artifacts installed on it, the
// dependency tree they form, the capabilities Falco reports, and the status published back to the
// node's ArtifactNode.
//
// It is the entry point for every operation on the node and is shared by all of the sidecar's
// controllers. It also owns the
// node's runnables (the warm sync, the Falco versions watcher, the status publisher, the directory
// watcher and the reload coordinator), which AddToManager registers with controller-runtime.
//
// Construct with New, which wires every collaborator; the zero value is not usable. A Node is safe
// for concurrent use by the reconcilers once New returns.
type Node struct {
	name      string
	namespace string
	cl        client.Client

	dirs         artifact.ArtifactDirs
	falcoBaseURL string

	// enforceRequirements is whether unmet requirements block an install or only annotate it. It
	// is a node-wide policy, set from the Falco instance's spec, not a per-artifact choice.
	enforceRequirements bool

	// recorder emits the Kubernetes Events that go with the conditions the node sets on an
	// artifact. The node decides what happened and says so in both places; only the wording of a
	// failure is the artifact kind's own.
	recorder events.EventRecorder

	// fetcher resolves an artifact's bytes: inline content from the spec, a ConfigMap through
	// the API, or an OCI blob from the artifact server. The node owns it because it owns the
	// decision of whether a source needs fetching at all.
	fetcher artifact.ArtifactFetcher

	// disk is the node's hand on the filesystem: it turns a (name, priority, medium, kind) tuple
	// into a path and moves bytes there. It holds no state of its own: what the node remembers
	// about those files is in artifacts, below the mutex.
	disk artifact.ArtifactStore
	// falcoFetcher reads the capabilities Falco reports.
	falcoFetcher compat.VersionsFetcher

	// mu guards everything below it, and nothing above. The installed files, the dependency
	// registry and the shared plugin configuration are one critical section, not three: every
	// write decision reads all of them, and the registry is published only once the disk write
	// has landed. Do not give them separate mutexes. mu may be held across a call into
	// statusPublisher; statusPublisher must never call back in. The removal bus below is an
	// independent leaf lock.
	mu sync.Mutex
	// artifacts is one record per artifact. Nothing else is keyed by artifact identity.
	artifacts map[artifact.Ref]*nodeArtifact
	// provides is who provides each capability name, and the version Falco reports for it.
	provides map[string]provided
	// pluginsConfig is the shared plugins-config file's content: the one artifact whose bytes
	// the node keeps, because it composes them from every Plugin's entry.
	pluginsConfig *pluginsConfig
	// pluginsConfigFile is where that file is installed, or nil when it is not. The node writes the file itself,
	// so it is no artifact's: it is kept here rather than among the artifacts.
	pluginsConfigFile *artifact.File
	// subscribers receive a notification when a provided version changes.
	subscribers []chan event.GenericEvent

	status *statusPublisher

	reload     *reloadCoordinator
	dirWatcher *artifactDirWatcher
	versions   *compat.VersionsWatcher
	// warmSync is the runnable of the warm sync, created by AddToManager. Nil for a Node that no manager runs.
	warmSync *WarmSyncRunnable
	// warmSynced is closed once the warm sync has run. It is nil until NewWarmSyncRunnable arms it: a Node
	// without the runnable has no warm sync to wait for, and is ready as soon as New returns.
	warmSynced   chan struct{}
	warmSyncDone sync.Once
	// falcoObserved is closed once Falco's capabilities have been observed. It is nil until AddToManager arms
	// it: a Node without the versions watcher has no observation to wait for, and is ready as soon as New returns.
	falcoObserved chan struct{}
	// falcoSeen records that OnFalcoVersionsObserved has run, so arming after a seeded observation is a no-op.
	falcoSeen bool

	// removals carries the ArtifactNode controller's requests to remove an artifact to the
	// reconciler of its kind. It is an independent leaf lock: it guards nothing the artifact
	// state guards.
	removalMu sync.Mutex
	removals  map[artifact.Kind]chan event.GenericEvent
}

// Config describes the node a Node models and the collaborators it is built from. Only the first
// group is required; the rest are defaulted, and exist so that tests can supply fakes.
type Config struct {
	// Client reaches the API server. Use the controller-runtime manager's cache-backed client.
	Client client.Client
	// NodeName is the name of the node this sidecar runs on, and of its ArtifactNode.
	NodeName string
	// Namespace is the namespace of the Falco instance this sidecar belongs to.
	Namespace string
	// FalcoBaseURL is the base URL of the Falco REST API on this node.
	FalcoBaseURL string
	// ReloadCooldown is how long the reload coordinator lets writes settle before it signals Falco.
	ReloadCooldown time.Duration

	// Dirs are the artifact directories shared with Falco. Zero means the production mount points.
	Dirs artifact.ArtifactDirs
	// Store performs the file I/O. Nil means a LocalStore over Dirs.
	Store artifact.ArtifactStore
	// Fetcher resolves artifact content. Required: Apply cannot resolve a source without it.
	Fetcher artifact.ArtifactFetcher
	// EnforceRequirements blocks installs whose requirements Falco does not satisfy, rather than
	// installing anyway and saying so.
	EnforceRequirements bool
	// Recorder emits Events on the artifact CRs. Nil records nothing, which is what a test that
	// does not assert events wants.
	Recorder events.EventRecorder
	// FalcoFetcher reads Falco's capabilities. Nil means an HTTP fetcher against FalcoBaseURL.
	FalcoFetcher compat.VersionsFetcher
	// WatchInterval is the Falco versions polling cadence. Zero means compat.DefaultWatchInterval.
	WatchInterval time.Duration
	// FalcoVersions seeds the capability registry with an observation already made, so that the
	// first reconciles do not have to wait for the first poll. Nil skips the seed.
	FalcoVersions *compat.Versions
	// StatusTimings replaces the status publisher's default delays; tests use it to shorten them. Nil keeps
	// the defaults.
	StatusTimings *StatusTimings
}

// New returns the Node for the node cfg describes, with every collaborator and runnable wired.
//
// It does not reach the network and does not block: the Falco handshake belongs to the caller,
// which passes its result as Config.FalcoVersions. It also does not touch the filesystem: the
// directory watcher is created by AddToManager, since registering its watches requires the Falco
// artifact directories to exist.
func New(cfg *Config) (*Node, error) {
	switch {
	case cfg.Client == nil:
		return nil, fmt.Errorf("node: Client is required")
	case cfg.NodeName == "":
		return nil, fmt.Errorf("node: NodeName is required")
	case cfg.Namespace == "":
		return nil, fmt.Errorf("node: Namespace is required")
	case cfg.FalcoBaseURL == "":
		return nil, fmt.Errorf("node: FalcoBaseURL is required")
	case cfg.ReloadCooldown <= 0:
		return nil, fmt.Errorf("node: ReloadCooldown must be positive, got %s", cfg.ReloadCooldown)
	case cfg.Fetcher == nil:
		return nil, fmt.Errorf("node: Fetcher is required")
	}

	if cfg.Dirs == (artifact.ArtifactDirs{}) {
		cfg.Dirs = artifact.DefaultArtifactDirs()
	}
	if cfg.Store == nil {
		cfg.Store = &artifact.LocalStore{FS: filesystem.NewOSFileSystem(), Dirs: cfg.Dirs}
	}
	if cfg.Recorder == nil {
		cfg.Recorder = nopRecorder{}
	}
	if cfg.FalcoFetcher == nil {
		cfg.FalcoFetcher = compat.NewHTTPVersionsFetcher(cfg.FalcoBaseURL)
	}
	if cfg.WatchInterval <= 0 {
		cfg.WatchInterval = compat.DefaultWatchInterval
	}

	n := &Node{
		name:         cfg.NodeName,
		namespace:    cfg.Namespace,
		cl:           cfg.Client,
		dirs:         cfg.Dirs,
		falcoBaseURL: cfg.FalcoBaseURL,
		fetcher:      cfg.Fetcher,
		recorder:     cfg.Recorder,

		enforceRequirements: cfg.EnforceRequirements,
		disk:                cfg.Store,
		falcoFetcher:        cfg.FalcoFetcher,
		artifacts:           make(map[artifact.Ref]*nodeArtifact),
		provides:            make(map[string]provided),
		pluginsConfig:       &pluginsConfig{},
		removals:            make(map[artifact.Kind]chan event.GenericEvent),
	}

	// The publisher is wired before anything can reach the Node, so a half-built Node in which
	// the reconcilers would silently not report their status cannot be observed.
	n.status = newStatusPublisher(cfg.Client, cfg.Namespace, cfg.NodeName, cfg.StatusTimings)

	n.reload = newReloadCoordinator(cfg.FalcoBaseURL).withCooldown(cfg.ReloadCooldown)

	// The sink is wired here rather than by the caller, so that the watcher cannot be started
	// without anything consuming what it observes.
	n.versions = compat.NewVersionsWatcher(cfg.FalcoFetcher, cfg.WatchInterval)
	n.versions.SetSink(n.OnFalcoVersionsObserved)

	if cfg.FalcoVersions != nil {
		n.OnFalcoVersionsObserved(cfg.FalcoVersions)
	}
	return n, nil
}

// Name is the name of the node, and of its ArtifactNode.
func (n *Node) Name() string { return n.name }

// EnforceRequirements reports whether unmet requirements block an install on this node, rather
// than installing anyway and saying so. It is a node-wide policy taken from the Falco instance's
// spec, which is why it is the node's and not each controller's. It is fixed at construction, from
// Config.EnforceRequirements: the sidecar gets it from its own arguments, which the instance operator
// sets, and a change to them is a new pod.
func (n *Node) EnforceRequirements() bool { return n.enforceRequirements }

// Namespace is the namespace of the Falco instance this sidecar belongs to.
func (n *Node) Namespace() string { return n.namespace }

// RunStatusPublisher runs the publisher of this node's per-artifact status until ctx ends. AddToManager registers
// it with a manager; this is for a Node used without one, as in tests.
func (n *Node) RunStatusPublisher(ctx context.Context) error { return n.status.Start(ctx) }

// AddToManager registers the node's runnables with mgr. Call it once, before mgr.Start.
//
// It also creates the directory watcher, which registers its fsnotify watches immediately and
// fails if the Falco artifact directories do not exist, so this runs where those directories are
// real. New deliberately leaves that out, so a Node can be built in a test without them.
//
// The runnables are registered in the order they are started in. Every one of them is per-node and
// declares that it needs no leader election: each Falco pod has its own, and a leader-only runnable
// would leave every other node unattended. It makes no difference while the sidecar runs with
// leader election disabled, but it is what makes turning it on safe.
//
// Registering the warm sync is also what makes the node's reconcilers wait for it: see WaitWarmSync. It
// also adds a readiness check that fails until the warm sync has run, so the pod is not reported Ready
// while the node does not yet know what it holds.
func (n *Node) AddToManager(mgr ctrl.Manager) error {
	dirWatcher, err := newArtifactDirWatcher(n.dirs, n.falcoBaseURL, n.reload.notifyWrite)
	if err != nil {
		return fmt.Errorf("create Falco dir watcher: %w", err)
	}
	n.dirWatcher = dirWatcher
	n.armFalcoVersions()
	n.warmSync = NewWarmSyncRunnable(n)

	for _, runnable := range []manager.Runnable{n.reload, n.dirWatcher, n.status, n.warmSync, n.versions} {
		if err := mgr.Add(runnable); err != nil {
			return fmt.Errorf("add %T to manager: %w", runnable, err)
		}
	}
	if err := mgr.AddReadyzCheck("warm-sync", n.checkWarmSynced); err != nil {
		return fmt.Errorf("add warm sync readiness check: %w", err)
	}
	if err := mgr.AddReadyzCheck("falco-versions", n.checkFalcoObserved); err != nil {
		return fmt.Errorf("add falco versions readiness check: %w", err)
	}
	return nil
}

// warmup observes the files already on disk and the artifacts currently assigned, and then lets the
// reconcilers go. See runWarmSync and WaitWarmSync.
func (n *Node) warmup(ctx context.Context) error {
	if err := n.runWarmSync(ctx); err != nil {
		return err
	}
	n.warmSyncDone.Do(func() {
		if n.warmSynced != nil {
			close(n.warmSynced)
		}
	})
	return nil
}

// armWarmSync makes WaitWarmSync wait until warmup has run. NewWarmSyncRunnable calls it: the runnable is
// the thing waited for, so a Node without one has nothing to wait for.
func (n *Node) armWarmSync() {
	if n.warmSynced == nil {
		n.warmSynced = make(chan struct{})
	}
}

// WaitWarmSync blocks until the node's warm sync has run, or ctx ends. Every reconciler of the sidecar calls
// it before anything else. Until the warm sync has observed the files on disk and the ArtifactNode, the node
// does not know what it holds: a reconcile ahead of it would find nothing to remove where there are orphans,
// or install a file that the scan then replaces in the node's record, hiding it from every later removal.
//
// controller-runtime does not put the warm sync first by itself. Its Warmup runnables are started before the
// controllers, but Warmup.Start returns as soon as they are running, not once they are done, so Warmup and
// the first reconciles overlap. This is what serializes them.
//
// A Node whose warm-sync runnable was never created, such as a test's, has nothing to wait for and is
// ready at once.
func (n *Node) WaitWarmSync(ctx context.Context) error {
	if n.warmSynced == nil {
		return nil
	}
	select {
	case <-n.warmSynced:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// armFalcoVersions makes WaitFalcoVersions wait until Falco's capabilities have been observed. AddToManager
// calls it when it registers the versions watcher, which makes that observation. A Node seeded through
// Config.FalcoVersions has already observed them, and stays ready.
func (n *Node) armFalcoVersions() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.falcoObserved == nil && !n.falcoSeen {
		n.falcoObserved = make(chan struct{})
	}
}

// WaitFalcoVersions blocks until Falco's capabilities have been observed once, or ctx ends. The install flow
// of an artifact that declares requirements on Falco calls it: those requirements are checked against the
// observed capabilities, so without an observation the check could only fail. Config does not wait, since a
// Config may carry what Falco needs to start at all, such as engine.kind.
//
// A Node whose versions watcher was never registered, such as a test's, has nothing to wait for and is
// ready at once.
func (n *Node) WaitFalcoVersions(ctx context.Context) error {
	n.mu.Lock()
	observed := n.falcoObserved
	n.mu.Unlock()
	if observed == nil {
		return nil
	}
	select {
	case <-observed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// checkFalcoObserved is a readiness check: it fails until Falco's capabilities have been observed, as the
// sidecar used to report Ready only once Falco answered /versions. Like WaitFalcoVersions, a Node without
// the versions watcher is ready at once.
func (n *Node) checkFalcoObserved(_ *http.Request) error {
	n.mu.Lock()
	observed := n.falcoObserved
	n.mu.Unlock()
	if observed == nil {
		return nil
	}
	select {
	case <-observed:
		return nil
	default:
		return errors.New("the node has not observed Falco's capabilities")
	}
}

// checkWarmSynced is a readiness check: it fails until the node's warm sync has run. Like WaitWarmSync, a
// Node without a warm-sync runnable has nothing to wait for and is ready at once.
func (n *Node) checkWarmSynced(_ *http.Request) error {
	if n.warmSynced == nil {
		return nil
	}
	select {
	case <-n.warmSynced:
		return nil
	default:
		return errors.New("the node's warm sync has not completed")
	}
}

// PublishStatus reports the status of obj, an artifact of kind on this node, as its reconciler computed it.
//
// The installed files in status are derived from what the node actually holds, for every medium of kind.
// A reconciler therefore never mirrors installed files itself: it computes conditions, and the files are
// the node's own record of them. That record is the source of every write decision, so deriving them here
// on every return path is also what keeps a published status from falling behind it when a previous
// reconcile's patch never landed.
//
// It is a no-op for kinds that are not artifacts assigned to the node (the shared plugin configuration and
// Falco's own capabilities).
func (n *Node) PublishStatus(kind artifact.Kind, obj metav1.Object, status *artifactv1alpha1.NodeArtifactStatus) {
	info, err := artifact.InfoForKind(kind)
	if err != nil {
		return
	}
	key := artifact.RefOf(kind, obj)
	// The mediums are the kind's registered sources: a property of the kind, not of any one
	// artifact, so a reconciler never has to say which ones its status covers.
	for _, medium := range info.Sources {
		n.syncInstalledStatus(key, medium, &status.InstalledArtifacts)
	}
	n.status.Set(kind, key.Name, string(obj.GetUID()), status.Conditions, status.InstalledArtifacts)
}

// StatusEntry returns the status the publisher holds for the artifact, so a reconciler starts from its
// previous conditions.
func (n *Node) StatusEntry(kind artifact.Kind, name string) (artifactv1alpha1.NodeArtifactStatus, bool) {
	return n.status.Entry(kind, name)
}

// StatusFor returns the last known status of obj on this node, for its reconciler to continue from. obj is a
// Rulesfile, Plugin or Config (as kind says) that is in the spec of this node's ArtifactNode.
//
// The status is the artifact's entry in status.artifacts of this node's ArtifactNode: its conditions and the
// files installed for it. The status publisher keeps a copy of it, the one this process last set or, after a
// restart, the one it found on the ArtifactNode, so a reconcile carries on from the previous result instead of
// from nothing. The copy can be a moment ahead of the ArtifactNode, which the publisher writes in batches.
// StatusFor only reads; nothing changes until the reconciler calls PublishStatus.
//
// Without an entry (the first install on this node) the returned status is empty.
//
// If the entry has another UID than obj, the artifact was deleted and recreated under the same name, and the
// entry belongs to the old one. It is not used: the returned status is empty and stale is true. The caller must
// then remove the files the old artifact installed before installing the new one.
func (n *Node) StatusFor(kind artifact.Kind, obj metav1.Object) (status *artifactv1alpha1.NodeArtifactStatus, stale bool) {
	status = &artifactv1alpha1.NodeArtifactStatus{Kind: kind, Name: obj.GetName(), UID: string(obj.GetUID())}
	entry, ok := n.StatusEntry(kind, obj.GetName())
	switch {
	case !ok:
	case entry.UID != string(obj.GetUID()):
		stale = true
	default:
		status.Conditions = entry.Conditions
		status.InstalledArtifacts = entry.InstalledArtifacts
	}
	return status, stale
}

// ensureStatusEntry persists a status entry for the artifact before returning, so that files never
// exist without an entry naming them: the cleanup and the parent's finalizer rely on that.
// ApplyArtifact calls it before running the kind's flow, and refuses to install if it fails.
func (n *Node) ensureStatusEntry(ctx context.Context, key artifact.Ref, uid string, conditions []metav1.Condition) error {
	return n.status.ensureEntry(ctx, key.Kind, key.Name, uid, conditions)
}

// WithdrawStatus drops the status entry of the artifact. Removing an artifact's last file already does
// so; this covers an artifact that never had a file.
func (n *Node) WithdrawStatus(key artifact.Ref) {
	n.status.Remove(key.Kind, key.Name)
}

// ObserveArtifactNode gives the publisher the entries already in status.artifacts of the node's ArtifactNode, which
// a previous process of this sidecar reported. After a restart the publisher starts empty, so without this it would
// not know those artifacts: HeldKeys would miss them and the ArtifactNode controller could never remove them,
// and StatusFor would start their reconciles from nothing instead of from their previous status.
//
// It also adds an empty entry (kind, name and uid, no conditions) for each artifact in the ArtifactNode's spec that has
// none yet. The next write then persists all of them together, where otherwise each artifact's reconciler would
// trigger a write of its own through ensureStatusEntry, which adds up when many artifacts are assigned at once.
//
// The existing entries are recorded only on the first call; later calls only add entries for newly listed
// artifacts, so calling it repeatedly is harmless. It is called by the warm sync at startup and at the start of every
// reconcile of the ArtifactNode controller, before that asks HeldKeys.
func (n *Node) ObserveArtifactNode(artifactNode *artifactv1alpha1.ArtifactNode) {
	n.status.Observe(artifactNode)
}

// HeldKeys returns every artifact that either has installed files on this node or has an entry in the status of the
// node's ArtifactNode. It is the union of the two, so an artifact is returned even when only one of them exists:
// files can have no entry, and an entry (one persisted before an install that never happened) can have no files.
// Only Rulesfiles, Plugins and Configs are returned.
//
// The installed files are the node's record of them, not a scan of the disk: warm sync fills it from disk at
// startup and every install and removal updates it. The entries are the publisher's: the ones this process has set,
// which may not be written to the ArtifactNode yet, plus the ones found on the ArtifactNode after a restart. Call
// ObserveArtifactNode first, or the latter are missing.
//
// The ArtifactNode controller compares the result with the spec to find what must be removed.
func (n *Node) HeldKeys() []artifact.Ref {
	seen := map[artifact.Ref]struct{}{}
	for _, key := range n.installedKeys() {
		seen[key] = struct{}{}
	}
	for _, key := range n.status.Keys() {
		seen[key] = struct{}{}
	}
	keys := make([]artifact.Ref, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	return keys
}

// RemovalRequests returns the channel on which the node controller asks for artifacts of kind to be
// removed. The reconciler of that kind consumes it as an event source, so that a removal is one more
// reconcile of the artifact, and never runs at the same time as another one of it.
func (n *Node) RemovalRequests(kind artifact.Kind) <-chan event.GenericEvent {
	return n.removalChannel(kind)
}

func (n *Node) removalChannel(kind artifact.Kind) chan event.GenericEvent {
	n.removalMu.Lock()
	defer n.removalMu.Unlock()
	ch, ok := n.removals[kind]
	if !ok {
		ch = make(chan event.GenericEvent, removalBuffer)
		n.removals[kind] = ch
	}
	return ch
}

// RequestRemoval asks the reconciler of key's kind to reconcile the artifact, which removes what the node
// holds for it once the spec of its ArtifactNode no longer lists it.
//
// Asking twice for the same artifact is free: the requests reach the reconciler through a workqueue, which
// coalesces the ones naming the same object. Callers are therefore expected to ask again rather than to
// remember what they have already asked for.
//
// It never blocks. A full channel means that kind's reconciler is far enough behind that it has not yet
// taken the requests already queued, and is reported as an error so that the caller retries on its own
// schedule instead of stalling its reconcile until there is room.
func (n *Node) RequestRemoval(ctx context.Context, key artifact.Ref) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	obj := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: n.namespace, Name: key.Name}}
	select {
	case n.removalChannel(key.Kind) <- event.GenericEvent{Object: obj}:
		return nil
	default:
		return fmt.Errorf("cannot ask for the removal of %s %q: the %s reconciler is behind, %d requests are queued",
			key.Kind, key.Name, key.Kind, removalBuffer)
	}
}

// Holds reports whether the node holds files or a status entry for the artifact.
func (n *Node) Holds(key artifact.Ref) bool {
	if n.hasInstalled(key) {
		return true
	}
	return n.status.Has(key.Kind, key.Name)
}
