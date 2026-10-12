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

// Package artifactnode implements the ArtifactNode assignment controller.
// It runs in the instance operator (singleton Deployment) and is the sole writer of an
// ArtifactNode's lifecycle and spec:
//   - Creating one ArtifactNode per namespace and node that runs a Falco pod.
//   - Keeping spec.artifacts equal to the Rulesfiles, Plugins and Configs whose selector selects
//     the node, within the schema's cap.
//   - Deleting the ArtifactNode when the node no longer runs a Falco pod, or when nothing is
//     assigned to it and its status is empty.
//
// The status is written by the artifact operator on the node and is never touched here.
package artifactnode

import (
	"context"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

// ControllerName identifies this controller in logs.
const ControllerName = "instance-artifactnode"

// falcoAbsentGrace is how long a node may run no Falco pod before its ArtifactNode is deleted. A
// Falco pod is replaced by an update, a restart or a reschedule, and there is a moment with none on the
// node. Deleting the ArtifactNode then would throw away what its sidecar reported and the assignment, only to
// recreate both seconds later, and every parent reading it would flap. The grace outlasts a normal
// replacement; a pod that stays away longer is treated as gone.
const falcoAbsentGrace = 2 * time.Minute

// ReasonMultipleSidecars is the Event reason for several Falco pods on one node in a namespace.
const ReasonMultipleSidecars = "MultipleSidecarsOnNode"

// legacyArtifactNodeFinalizers are the finalizers the artifact operators of the v0.5.0 release candidates put on
// their ArtifactNodes, which were one per artifact and node. No artifact operator of this version knows those
// objects, so nothing else would ever release them, and they, and their namespace, would stay Terminating.
var legacyArtifactNodeFinalizers = []string{
	"rulesfilenode.artifact.falcosecurity.dev/finalizer",
	"pluginnode.artifact.falcosecurity.dev/finalizer",
	"confignode.artifact.falcosecurity.dev/finalizer",
}

// ArtifactNodeReconciler assigns artifacts to nodes by maintaining ArtifactNodes.
type ArtifactNodeReconciler struct {
	client.Client

	// recorder emits the warning about several Falco pods on one node.
	recorder events.EventRecorder
	absences *absences
	// sidecars and sidecarsLogged remember the crowded nodes already warned about: with an Event, on the node's
	// ArtifactNode, and with a log line only, while the node has no ArtifactNode to put an Event on.
	sidecars       *sidecarCounts
	sidecarsLogged *sidecarCounts
}

// NewArtifactNodeReconciler returns a new ArtifactNodeReconciler.
func NewArtifactNodeReconciler(cl client.Client, recorder events.EventRecorder) *ArtifactNodeReconciler {
	return &ArtifactNodeReconciler{
		Client: cl, recorder: recorder, absences: newAbsences(falcoAbsentGrace),
		sidecars: newSidecarCounts(), sidecarsLogged: newSidecarCounts(),
	}
}

// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=artifactnodes,verbs=get;list;watch;create;patch;delete
// The controller never writes an ArtifactNode's status. The operator holds this permission because it can only
// grant a sidecar's Role permissions it has itself, and each sidecar patches its own node's status.
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=artifactnodes/status,verbs=get;patch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=rulesfiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=plugins,verbs=get;list;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=configs,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos,verbs=get;list;watch

// Reconcile reconciles the ArtifactNode of one node in one namespace. The request's name is the
// node name, which is also the name of the ArtifactNode. The ArtifactNode may not exist yet.
//
// Every decision is made from the informer cache, so a write may be based on stale state. Writes
// that could clobber a newer object therefore carry a precondition, and a rejected one is requeued
// instead of retried in place.
func (r *ArtifactNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log.FromContext(ctx).V(1).Info("Reconciling ArtifactNode")

	artifactNode, err := controllerhelper.GetArtifactNode(ctx, r.Client, req.Namespace, req.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	// An ArtifactNode being deleted is the artifact operator's to finish: it removes what it installed on
	// the node and then releases its own finalizer. The one thing it cannot act on is its own absence, so
	// that is handled here. Nothing else about a terminating ArtifactNode concerns this controller.
	if artifactNode != nil && !artifactNode.DeletionTimestamp.IsZero() {
		return r.releaseAbandonedArtifactNode(ctx, req.NamespacedName, artifactNode)
	}

	node := &corev1.Node{}
	if err := r.Get(ctx, client.ObjectKey{Name: req.Name}, node); err != nil {
		if !k8serrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		node = nil
	}

	// Only a node that runs a Falco pod has an artifact operator to act on the assignment.
	pods := 0
	if node != nil {
		pods, err = controllerhelper.CountFalcoRunningPodsOnNode(ctx, r.Client, req.Namespace, req.Name)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	switch {
	case pods <= 1:
		r.sidecars.forget(req.NamespacedName)
		r.sidecarsLogged.forget(req.NamespacedName)
	case artifactNode == nil:
		// There is no object to put the Event on yet: the warning is logged, once per change like the Event, and
		// the Event is given once the ArtifactNode exists.
		if r.sidecarsLogged.changed(req.NamespacedName, pods) {
			r.warnMultipleSidecars(ctx, nil, req.Name, pods)
		}
	case r.sidecars.changed(req.NamespacedName, pods):
		r.warnMultipleSidecars(ctx, artifactNode, req.Name, pods)
	}
	if pods == 0 {
		return r.reconcileWithoutFalco(ctx, req.NamespacedName, artifactNode, node == nil)
	}
	r.absences.forget(req.NamespacedName)
	return r.reconcileWithFalco(ctx, req.Namespace, node, artifactNode)
}

// releaseAbandonedArtifactNode removes the artifact operator's finalizer from a terminating ArtifactNode
// whose node runs no Falco pod. Without it the ArtifactNode would never go: the finalizer is the artifact
// operator's, the artifact operator went with its pod, and this controller is the only other actor that
// can remove it. A namespace holding such an ArtifactNode would never finish deleting either.
//
// Unlike reconcileWithoutFalco it waits out no grace. That grace keeps an assignment alive across a pod
// replacement; here the ArtifactNode is already being deleted, so there is no assignment left to protect,
// and waiting only holds the object, and its namespace, open. A pod merely restarting its containers is
// still Running, which leaves the artifact operator in charge of its own cleanup; a pod that is really
// gone took the emptyDir holding the installed files with it, so there is nothing left to remove. If
// files somehow outlive it, the next artifact operator on the node finds them with no ArtifactNode and
// removes them as orphans.
func (r *ArtifactNodeReconciler) releaseAbandonedArtifactNode(
	ctx context.Context, key types.NamespacedName, artifactNode *artifactv1alpha1.ArtifactNode,
) (ctrl.Result, error) {
	// An ArtifactNode left by a release candidate is named after an artifact and a node, so it is deleted like that
	// of a node that is gone, and gets here. The artifact operator that held it open no longer exists.
	for _, legacy := range legacyArtifactNodeFinalizers {
		if err := controllerhelper.RemoveFinalizer(ctx, r.Client, legacy, artifactNode); err != nil {
			return controllerhelper.ResultForWriteError(err)
		}
	}
	if !slices.Contains(artifactNode.Finalizers, controllerhelper.ArtifactNodeSidecarFinalizer) {
		return ctrl.Result{}, nil
	}
	running, err := controllerhelper.CountFalcoRunningPodsOnNode(ctx, r.Client, key.Namespace, key.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	if running > 0 {
		// The artifact operator is there to remove what it installed and release the finalizer itself.
		return ctrl.Result{}, nil
	}
	log.FromContext(ctx).Info("Releasing the artifact operator's finalizer: it is gone with its pod and the ArtifactNode is being deleted")
	return r.forgetOnSuccess(key)(controllerhelper.ResultForWriteError(
		controllerhelper.RemoveFinalizer(ctx, r.Client, controllerhelper.ArtifactNodeSidecarFinalizer, artifactNode)))
}

// forgetOnSuccess returns a function that passes a reconcile's outcome through and forgets the node's absence
// when that outcome is a completed write. A write that is requeued, a conflict with a stale cache for instance,
// keeps the absence as it is, so the retry does not restart the grace period.
func (r *ArtifactNodeReconciler) forgetOnSuccess(key types.NamespacedName) func(ctrl.Result, error) (ctrl.Result, error) {
	return func(result ctrl.Result, err error) (ctrl.Result, error) {
		if err == nil && result.IsZero() {
			r.absences.forget(key)
		}
		return result, err
	}
}

// reconcileWithoutFalco handles a node that runs no Falco pod: an ArtifactNode there, if any, is deleted, once
// the grace period for a pod being replaced has passed.
func (r *ArtifactNodeReconciler) reconcileWithoutFalco(
	ctx context.Context, key types.NamespacedName, artifactNode *artifactv1alpha1.ArtifactNode, nodeGone bool,
) (ctrl.Result, error) {
	if artifactNode != nil && !nodeGone {
		// A node that is gone cannot get its pod back. Otherwise a missing pod is usually a replacement in
		// progress.
		if wait := r.absences.observeAbsence(key); wait > 0 {
			log.FromContext(ctx).V(1).Info("No Falco pod runs on the node, keeping its ArtifactNode for now", "graceLeft", wait)
			return ctrl.Result{RequeueAfter: wait}, nil
		}
	}
	if artifactNode == nil {
		r.absences.forget(key)
		return ctrl.Result{}, nil
	}
	log.FromContext(ctx).Info("Deleting ArtifactNode: no Falco pod runs on the node")
	return r.forgetOnSuccess(key)(r.deleteArtifactNode(ctx, artifactNode, true))
}

// reconcileWithFalco brings the ArtifactNode of a node that runs a Falco pod in line with the artifacts that
// select the node. artifactNode is nil when there is none yet.
func (r *ArtifactNodeReconciler) reconcileWithFalco(
	ctx context.Context, namespace string, node *corev1.Node, artifactNode *artifactv1alpha1.ArtifactNode,
) (ctrl.Result, error) {
	var listed []artifactv1alpha1.NodeArtifactRef
	if artifactNode != nil {
		listed = artifactNode.Spec.Artifacts
	}
	selected, capped, err := r.desiredArtifacts(ctx, namespace, node, listed)
	if err != nil {
		return ctrl.Result{}, err
	}

	switch {
	case artifactNode == nil && len(selected) == 0:
		return ctrl.Result{}, nil
	case artifactNode == nil:
		return r.createArtifactNode(ctx, namespace, node.Name, selected)
	// The spec is emptied before the deletion, so a terminating ArtifactNode that still lists artifacts was
	// deleted by someone else.
	case len(selected) == 0 && len(artifactNode.Spec.Artifacts) == 0 && len(artifactNode.Status.Artifacts) == 0:
		log.FromContext(ctx).Info("Deleting ArtifactNode: nothing is assigned to the node")
		return r.deleteArtifactNode(ctx, artifactNode, false)
	default:
		return r.updateArtifactNode(ctx, artifactNode, selected, capped)
	}
}

// warnMultipleSidecars reports that several Falco pods run on one node in the namespace. Each pod has its own
// sidecar, and they would all write the node's one ArtifactNode status, each replacing the entries of the
// others. This is unsupported and only reported: the assignment carries on, and the ArtifactNode may misreport. The
// Event goes on the ArtifactNode, which may not exist yet, in which case the log is the only trace.
//
// A pod being replaced does not count (its old pod is being deleted, and a Running phase says nothing about
// that), so a rolling update of the DaemonSet does not raise this on every node. It is reported once per change
// of the number of pods (see sidecarCounts), not on every reconcile of the node.
func (r *ArtifactNodeReconciler) warnMultipleSidecars(
	ctx context.Context, artifactNode *artifactv1alpha1.ArtifactNode, nodeName string, pods int,
) {
	log.FromContext(ctx).Info("More than one Falco pod runs on the node in this namespace, which is not supported: "+
		"their sidecars share one ArtifactNode and overwrite each other's status",
		"node", nodeName, "pods", pods)
	if artifactNode != nil {
		artifact.RecordWarning(r.recorder, artifactNode, ReasonMultipleSidecars,
			"%d Falco pods run on node %q in this namespace; only one per node is supported, and artifact status may be wrong",
			pods, nodeName)
	}
}

// desiredArtifacts computes the artifacts to list in the spec of the node's ArtifactNode, given the ones
// currently listed. Artifacts that do not fit are logged, never silently assigned. capped reports that some did not
// fit: only then does the result depend on what is currently listed, which keeps its slots.
func (r *ArtifactNodeReconciler) desiredArtifacts(
	ctx context.Context, namespace string, node *corev1.Node, current []artifactv1alpha1.NodeArtifactRef,
) (selected []artifactv1alpha1.NodeArtifactRef, capped bool, err error) {
	logger := log.FromContext(ctx)
	inNamespace := client.InNamespace(namespace)

	rulesfiles := &artifactv1alpha1.RulesfileList{}
	plugins := &artifactv1alpha1.PluginList{}
	configs := &artifactv1alpha1.ConfigList{}
	// Only names, uids, timestamps and selectors are read, and an artifact can carry its whole content, so the
	// objects are not copied out of the informer cache: this runs for every node on every change of an artifact.
	for _, list := range []client.ObjectList{rulesfiles, plugins, configs} {
		if err := r.List(ctx, list, inNamespace, client.UnsafeDisableDeepCopy); err != nil {
			return nil, false, err
		}
	}

	cands, invalid := candidatesForNode(node.Labels, rulesfiles.Items, plugins.Items, configs.Items)
	if len(invalid) > 0 {
		logger.Info("Ignoring artifacts with an invalid node selector", "artifacts", invalid)
	}
	selected, dropped := selectArtifacts(current, cands, artifactv1alpha1.MaxNodeArtifacts)
	if len(dropped) > 0 {
		logger.Info("Node artifact capacity exceeded, artifacts left unassigned",
			"limit", artifactv1alpha1.MaxNodeArtifacts, "unassigned", dropped)
	}
	return selected, len(dropped) > 0, nil
}

func (r *ArtifactNodeReconciler) createArtifactNode(
	ctx context.Context, namespace, nodeName string, artifacts []artifactv1alpha1.NodeArtifactRef,
) (ctrl.Result, error) {
	artifactNode := &artifactv1alpha1.ArtifactNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nodeName,
			Namespace: namespace,
			Labels:    controllerhelper.ArtifactNodeLabels(nodeName),
		},
		Spec: artifactv1alpha1.ArtifactNodeSpec{NodeName: nodeName, Artifacts: artifacts},
	}
	if err := r.Create(ctx, artifactNode); err != nil {
		return controllerhelper.ResultForWriteError(err)
	}
	log.FromContext(ctx).Info("Created ArtifactNode", "artifacts", len(artifacts))
	return ctrl.Result{}, nil
}

// updateArtifactNode brings the ArtifactNode's spec and node label in line with the desired artifacts. It writes only
// on a difference. A merge patch replaces the list wholesale, which is what we want from the only writer of it.
//
// When every candidate fits (capped is false), the list follows from the artifacts alone, so a write based on a
// stale cache still writes the right list, and it carries no precondition: the artifact operator's status writes
// change the resourceVersion all the time, and a precondition would have this write conflict and retry with each
// of them. When some did not fit, which artifacts keep their slots depends on what is currently listed, so the
// write carries the resourceVersion the decision was based on, and a stale cache produces a conflict instead of
// handing a slot to the wrong artifact.
func (r *ArtifactNodeReconciler) updateArtifactNode(
	ctx context.Context, artifactNode *artifactv1alpha1.ArtifactNode, selected []artifactv1alpha1.NodeArtifactRef, capped bool,
) (ctrl.Result, error) {
	wantLabels := controllerhelper.ArtifactNodeLabels(artifactNode.Spec.NodeName)
	labelsOK := artifactNode.Labels[controllerhelper.LabelArtifactNode] == wantLabels[controllerhelper.LabelArtifactNode]
	if labelsOK && sameArtifacts(artifactNode.Spec.Artifacts, selected) {
		return ctrl.Result{}, nil
	}

	base := artifactNode.DeepCopy()
	artifactNode.Spec.Artifacts = selected
	artifactNode.Labels = labels.Merge(artifactNode.Labels, wantLabels)
	patch := client.MergeFrom(base)
	if capped {
		patch = client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})
	}
	if err := r.Patch(ctx, artifactNode, patch); err != nil {
		return controllerhelper.ResultForWriteError(err)
	}
	log.FromContext(ctx).Info("Updated ArtifactNode", "artifacts", len(selected))
	return ctrl.Result{}, nil
}

// deleteArtifactNode deletes artifactNode, guarded by its uid so an ArtifactNode recreated after the cache snapshot survives.
//
// releaseSidecar removes the artifact operator's finalizer first. It is for an ArtifactNode whose node no longer runs
// Falco: the artifact operator is gone with its pod, so nothing else would ever release the finalizer and
// the ArtifactNode could not be deleted. Otherwise the sidecar is alive and releases it itself, after removing what
// it installed.
func (r *ArtifactNodeReconciler) deleteArtifactNode(
	ctx context.Context, artifactNode *artifactv1alpha1.ArtifactNode, releaseSidecar bool,
) (ctrl.Result, error) {
	if releaseSidecar {
		if err := controllerhelper.RemoveFinalizer(ctx, r.Client, controllerhelper.ArtifactNodeSidecarFinalizer, artifactNode); err != nil {
			return controllerhelper.ResultForWriteError(err)
		}
	}
	uid := artifactNode.UID
	return controllerhelper.ResultForWriteError(r.Delete(ctx, artifactNode, client.Preconditions{UID: &uid}))
}

// artifactNodeChanged accepts the events of an ArtifactNode that can change what this controller does: a spec or
// label change, and the artifact operator withdrawing the last entry of the status. That last one matters because
// an ArtifactNode with nothing assigned is kept only while its status still reports something, and nothing else
// would tell the controller that it has since become deletable.
func artifactNodeChanged() predicate.Predicate {
	statusEmptied := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldNode, oldOK := e.ObjectOld.(*artifactv1alpha1.ArtifactNode)
			newNode, newOK := e.ObjectNew.(*artifactv1alpha1.ArtifactNode)
			return oldOK && newOK && len(oldNode.Status.Artifacts) > 0 && len(newNode.Status.Artifacts) == 0
		},
	}
	return predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}, statusEmptied)
}

// SetupWithManager registers the controller with the Manager.
func (r *ArtifactNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	parentChanged := builder.WithPredicates(controllerhelper.SpecChangedOrDeleting())
	inNamespace := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		return r.requestsForNamespace(ctx, obj.GetNamespace())
	})

	return ctrl.NewControllerManagedBy(mgr).
		// Repairs an ArtifactNode whose spec or node label was changed by someone else. Status-only updates
		// by the artifact operator do not concern this controller, except the one that empties the status.
		For(&artifactv1alpha1.ArtifactNode{}, builder.WithPredicates(artifactNodeChanged())).
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, node client.Object) []reconcile.Request {
				return r.requestsForNode(ctx, node.GetName())
			}),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{})),
		).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(falcoPodRequests),
			builder.WithPredicates(controllerhelper.FalcoPodChangePredicate())).
		// A pod counts as a Falco pod only while its Falco exists, and a Falco deleted with its pods orphaned, or
		// created over pods that are already there, changes that with no pod event.
		Watches(&instancev1alpha1.Falco{}, inNamespace, builder.WithPredicates(controllerhelper.CreatedOrDeleted())).
		Watches(&artifactv1alpha1.Rulesfile{}, inNamespace, parentChanged).
		Watches(&artifactv1alpha1.Plugin{}, inNamespace, parentChanged).
		Watches(&artifactv1alpha1.Config{}, inNamespace, parentChanged).
		Named(ControllerName).
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), ControllerName, &artifactv1alpha1.ArtifactNode{})).
		Complete(r)
}

// falcoPodRequests maps a pod to the ArtifactNode of the node it runs on.
func falcoPodRequests(_ context.Context, obj client.Object) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod.Spec.NodeName == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: pod.Namespace, Name: pod.Spec.NodeName}}}
}

// requestsForNamespace returns a request for every node that may need its ArtifactNode in namespace re-evaluated:
// those running a Falco pod there and those that already have an ArtifactNode. A change to an artifact can move
// it onto or off any of them, and the workqueue collapses duplicates.
func (r *ArtifactNodeReconciler) requestsForNamespace(ctx context.Context, namespace string) []reconcile.Request {
	logger := log.FromContext(ctx)
	keys := map[types.NamespacedName]struct{}{}

	running, err := controllerhelper.ListFalcoRunningNodeNames(ctx, r.Client, namespace)
	if err != nil {
		logger.Error(err, "unable to list nodes running Falco for re-enqueue", "namespace", namespace)
	}
	for name := range running {
		keys[types.NamespacedName{Namespace: namespace, Name: name}] = struct{}{}
	}
	artifactNodes := &artifactv1alpha1.ArtifactNodeList{}
	if err := r.List(ctx, artifactNodes, client.InNamespace(namespace), client.UnsafeDisableDeepCopy); err != nil {
		logger.Error(err, "unable to list ArtifactNodes for re-enqueue", "namespace", namespace)
	}
	for i := range artifactNodes.Items {
		keys[client.ObjectKeyFromObject(&artifactNodes.Items[i])] = struct{}{}
	}
	return toRequests(keys)
}

// requestsForNode returns a request for nodeName in every namespace that runs Falco or already has an ArtifactNode
// for it, since a node's labels decide which artifacts select it in each of them.
func (r *ArtifactNodeReconciler) requestsForNode(ctx context.Context, nodeName string) []reconcile.Request {
	logger := log.FromContext(ctx)
	keys := map[types.NamespacedName]struct{}{}

	falcos := &instancev1alpha1.FalcoList{}
	if err := r.List(ctx, falcos, client.UnsafeDisableDeepCopy); err != nil {
		logger.Error(err, "unable to list Falcos for re-enqueue", "node", nodeName)
	}
	for i := range falcos.Items {
		keys[types.NamespacedName{Namespace: falcos.Items[i].Namespace, Name: nodeName}] = struct{}{}
	}
	artifactNodes := &artifactv1alpha1.ArtifactNodeList{}
	onNode := client.MatchingLabels(controllerhelper.ArtifactNodeLabels(nodeName))
	if err := r.List(ctx, artifactNodes, onNode, client.UnsafeDisableDeepCopy); err != nil {
		logger.Error(err, "unable to list ArtifactNodes for re-enqueue", "node", nodeName)
	}
	for i := range artifactNodes.Items {
		keys[client.ObjectKeyFromObject(&artifactNodes.Items[i])] = struct{}{}
	}
	return toRequests(keys)
}

func toRequests(keys map[types.NamespacedName]struct{}) []reconcile.Request {
	reqs := make([]reconcile.Request, 0, len(keys))
	for key := range keys {
		reqs = append(reqs, reconcile.Request{NamespacedName: key})
	}
	return reqs
}
