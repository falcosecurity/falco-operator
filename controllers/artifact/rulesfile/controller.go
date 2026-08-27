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

package rulesfile

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

const (
	// rulesfileNodeFinalizer is the finalizer placed on RulesfileNode objects by this controller.
	// It blocks node-object deletion until local filesystem resources are cleaned up.
	rulesfileNodeFinalizer = "rulesfilenode.artifact.falcosecurity.dev/finalizer"
	// fieldManager is the name used to identify this controller's managed fields.
	fieldManager = "artifact-rulesfile"
)

// NewRulesfileReconciler returns a new RulesfileReconciler.
// fetcher is the shared artifact fetcher (built once in cmd/artifact/main.go, configured with
// the central artifact server's URL, TLS/mTLS, and retry policy) the sidecar uses to download
// OCI artifacts.
func NewRulesfileReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	nodeName, namespace string,
	enforceRequirements bool,
	fetcher artifact.ArtifactFetcher,
	nodeManager *nodeartifacts.Manager,
) *RulesfileReconciler {
	return &RulesfileReconciler{
		Client:              cl,
		Scheme:              scheme,
		recorder:            recorder,
		fetcher:             fetcher,
		store:               nodeManager,
		nodeName:            nodeName,
		namespace:           namespace,
		enforceRequirements: enforceRequirements,
	}
}

// RulesfileReconciler reconciles a RulesfileNode object assigned to this node.
type RulesfileReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	recorder            events.EventRecorder
	fetcher             artifact.ArtifactFetcher
	store               *nodeartifacts.Manager
	nodeName            string
	namespace           string
	enforceRequirements bool
}

// Reconcile reconciles the RulesfileNode assigned to this node.
// It reads the parent Rulesfile for spec, applies local filesystem changes,
// and writes resulting conditions to the RulesfileNode status only.
func (r *RulesfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := log.FromContext(ctx)

	nodeObj := &artifactv1alpha1.ArtifactNode{}
	if err := r.Get(ctx, req.NamespacedName, nodeObj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	oldStatus := nodeObj.Status.DeepCopy()

	// Handle deletion: clean up local FS resources then release the finalizer.
	if ok, err := r.handleDeletion(ctx, nodeObj); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure our finalizer is set on the node object.
	if ok, err := controllerhelper.EnsureFinalizer(ctx, r.Client, rulesfileNodeFinalizer, nodeObj); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Fetch the parent Rulesfile to get the spec.
	rulesfile, err := r.getParentRulesfile(ctx, nodeObj)
	if err != nil {
		return ctrl.Result{}, err
	}
	if rulesfile == nil {
		// Parent gone; node object will be GC'd via ownerRef shortly.
		logger.V(2).Info("Parent Rulesfile not found; waiting for GC")
		return ctrl.Result{}, nil
	}

	// Patch node object status via defer to ensure it's always called.
	// Programmed is derived here as a gateway: True only when all other conditions are True.
	// In advise mode DependenciesSatisfied is excluded from the gate; it's advisory only.
	defer func() {
		skipDependenciesSatisfied := func(condType string) bool {
			return !r.enforceRequirements && condType == commonv1alpha1.ConditionDependenciesSatisfied.String()
		}
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.ComputeProgrammedCondition(
			nodeObj.Status.Conditions, skipDependenciesSatisfied,
			artifact.ReasonProgrammed, artifact.MessageProgrammed, artifact.ReasonProgramFailed,
			rulesfile.GetGeneration(),
		))
		var patchErr error
		if !apiequality.Semantic.DeepEqual(*oldStatus, nodeObj.Status) {
			patchErr = controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, nodeObj, fieldManager)
			if patchErr != nil {
				logger.Error(patchErr, "unable to patch RulesfileNode status")
			}
		}
		reterr = kerrors.NewAggregate([]error{reterr, patchErr})
	}()

	// Enforce reference resolution before the generation gate below.
	if err := r.enforceReferenceResolution(ctx, rulesfile, nodeObj); err != nil {
		return ctrl.Result{}, err
	}

	// In enforce mode, defer remaining reconciliation (compatibility checks and filesystem
	// changes) until the instance operator has processed the current spec generation.
	// The guard runs after the defer so the ArtifactNode status is still patched on every
	// reconcile (skipping the patch would leave the parent Rulesfile status stale indefinitely).
	if r.enforceRequirements && rulesfile.Status.ObservedGeneration != rulesfile.Generation {
		logger.Info("instance operator has not yet processed current spec generation; deferring",
			"observedGeneration", rulesfile.Status.ObservedGeneration,
			"specGeneration", rulesfile.Generation)
		return ctrl.Result{}, nil
	} else {
		logger.Info("instance operator has processed current spec generation; proceeding",
			"observedGeneration", rulesfile.Status.ObservedGeneration,
			"specGeneration", rulesfile.Generation)
	}

	// Enforce rulesfile compatibility (OCI requirements and plugin dependencies). A blocked
	// reconcile does not touch disk, so any previously installed rulesfile stays in place.
	skip, compatErr := r.enforceRulesfileCompatibility(ctx, rulesfile, nodeObj)
	if compatErr != nil {
		return ctrl.Result{}, compatErr
	}
	if skip {
		// If the artifact was never installed on this node, explicitly mark source conditions as
		// False. Without this they are absent, which lets another node's True status win in
		// AggregateConditions and makes the Rulesfile-level status show e.g.
		// OCIArtifactProgrammed=True even when DependenciesSatisfied=False.
		if len(nodeObj.Status.InstalledArtifacts) == 0 {
			depCond := apimeta.FindStatusCondition(nodeObj.Status.Conditions,
				commonv1alpha1.ConditionDependenciesSatisfied.String())
			reason := artifact.ReasonDependenciesNotSatisfied
			msg := "dependency requirements not satisfied on this node"
			if depCond != nil {
				reason, msg = depCond.Reason, depCond.Message
			}
			gen := rulesfile.GetGeneration()
			if rulesfile.Spec.OCIArtifact != nil {
				apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewOCIArtifactProgrammedCondition(
					metav1.ConditionFalse, reason, msg, gen,
				))
			}
			if rulesfile.Spec.InlineRules != nil {
				apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewInlineArtifactProgrammedCondition(
					metav1.ConditionFalse, reason, msg, gen,
				))
			}
			if rulesfile.Spec.ConfigMapRef != nil {
				apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigMapArtifactProgrammedCondition(
					metav1.ConditionFalse, reason, msg, gen,
				))
			}
		}
		return ctrl.Result{}, nil
	}

	// Register this rulesfile's current dependencies with the shared node artifact manager
	// before writing anything, so a concurrent Plugin removal's blocked-by check can see them
	// (avoids a race with ensureRulesfile's own write).
	r.store.Sync(nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: rulesfile.Name},
		nodeartifacts.RequirementGroupsFromDependencies(dependenciesOf(rulesfile)))

	// Ensure the rulesfile artifacts are on the local filesystem. A transient OCI-fetch failure
	// (the artifact server hasn't cached this yet, or a network blip) requeues via RequeueAfter
	// instead of returning a reconcile error, avoiding tying up the worker for controller-runtime's
	// own retry backoff.
	if err := r.ensureRulesfile(ctx, rulesfile, nodeObj); err != nil {
		if delay, ok := artifact.RequeueDelay(err); ok {
			logger.Info("artifact server not ready, requeueing", "delay", delay)
			return ctrl.Result{RequeueAfter: delay}, nil
		}
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// handleDeletion cleans up local filesystem resources and removes the finalizer from the RulesfileNode.
func (r *RulesfileReconciler) handleDeletion(ctx context.Context, nodeObj *artifactv1alpha1.ArtifactNode) (bool, error) {
	if nodeObj.DeletionTimestamp.IsZero() {
		return false, nil
	}
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(nodeObj, rulesfileNodeFinalizer) {
		return true, nil
	}

	logger.Info("RulesfileNode marked for deletion, cleaning up")

	if err := r.store.Remove(ctx, nodeObj.Status.InstalledArtifacts); err != nil {
		logger.Error(err, "unable to remove installed rulesfile artifacts from disk")
		return false, err
	}

	// Forget this rulesfile's dependencies so a Plugin removal blocked on them can proceed.
	for _, ref := range nodeObj.OwnerReferences {
		if ref.Kind == controllerhelper.KindRulesfile {
			r.store.Sync(nodeartifacts.Key{Kind: nodeartifacts.KindRulesfile, Name: ref.Name}, nil)
			break
		}
	}

	patch := client.MergeFrom(nodeObj.DeepCopy())
	controllerutil.RemoveFinalizer(nodeObj, rulesfileNodeFinalizer)
	if err := r.Patch(ctx, nodeObj, patch); err != nil {
		logger.Error(err, "unable to remove finalizer from RulesfileNode")
		return false, err
	}
	return true, nil
}

// getParentRulesfile retrieves the parent Rulesfile via the node object's ownerRef, verifying
// by UID that it's still the generation nodeObj was created for (see GetVerifiedOwner's doc).
func (r *RulesfileReconciler) getParentRulesfile(ctx context.Context, nodeObj *artifactv1alpha1.ArtifactNode) (*artifactv1alpha1.Rulesfile, error) {
	rulesfile := &artifactv1alpha1.Rulesfile{}
	ok, err := controllerhelper.GetVerifiedOwner(ctx, r.Client, nodeObj, controllerhelper.KindRulesfile, rulesfile)
	if err != nil || !ok {
		return nil, err
	}
	return rulesfile, nil
}

// dependenciesOf returns rulesfile's declared plugin dependencies, or nil if ArtifactMeta
// hasn't been populated yet (instance operator hasn't fetched it).
func dependenciesOf(rulesfile *artifactv1alpha1.Rulesfile) []commonv1alpha1.ArtifactMetaDependency {
	if rulesfile.Status.ArtifactMeta == nil {
		return nil
	}
	return rulesfile.Status.ArtifactMeta.Dependencies
}

// SetupWithManager registers the controller with the Manager.
// versionEvents is the channel produced by compat.VersionsWatcher; a GenericEvent on this
// channel causes all RulesfileNodes on this node to be re-enqueued so they re-evaluate
// their plugin/engine dependencies against the updated Falco capability set.
func (r *RulesfileReconciler) SetupWithManager(mgr ctrl.Manager, versionEvents <-chan event.GenericEvent) error {
	// Only reconcile ArtifactNode objects assigned to this node that are owned by a Rulesfile.
	nodeFilter := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		n, ok := obj.(*artifactv1alpha1.ArtifactNode)
		if !ok || n.Spec.NodeName != r.nodeName {
			return false
		}
		for _, ref := range n.GetOwnerReferences() {
			if ref.Controller != nil && *ref.Controller && ref.Kind == controllerhelper.KindRulesfile {
				return true
			}
		}
		return false
	})

	// Re-enqueue all RulesfileNodes when a PluginNode on this node changes (e.g. a plugin
	// binary becomes available). A PluginNode transition to Programmed is the earliest signal
	// that Falco may now satisfy a plugin dependency, since the dep check calls Falco's
	// /versions endpoint.
	pluginNodeFilter := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		n, ok := obj.(*artifactv1alpha1.ArtifactNode)
		if !ok || n.Spec.NodeName != r.nodeName {
			return false
		}
		for _, ref := range n.GetOwnerReferences() {
			if ref.Controller != nil && *ref.Controller && ref.Kind == controllerhelper.KindPlugin {
				return true
			}
		}
		return false
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.ArtifactNode{}, builder.WithPredicates(nodeFilter)).
		// Re-trigger when the parent Rulesfile spec changes (e.g. new OCI tag).
		Watches(
			&artifactv1alpha1.Rulesfile{},
			handler.EnqueueRequestsFromMapFunc(r.findNodeObjectForRulesfile),
		).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findNodeObjectsForConfigMap),
		).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findNodeObjectsForSecret),
		).
		// Re-trigger all RulesfileNodes when any PluginNode on this node changes.
		Watches(
			&artifactv1alpha1.ArtifactNode{},
			handler.EnqueueRequestsFromMapFunc(r.findAllNodeObjectsOnVersionChange),
			builder.WithPredicates(pluginNodeFilter),
		).
		WatchesRawSource(source.Channel(versionEvents, handler.EnqueueRequestsFromMapFunc(r.findAllNodeObjectsOnVersionChange))).
		Named("artifact-rulesfile").
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), "artifact-rulesfile", &artifactv1alpha1.ArtifactNode{})).
		Complete(r)
}

// findNodeObjectForRulesfile maps a Rulesfile event to this node's RulesfileNode request.
func (r *RulesfileReconciler) findNodeObjectForRulesfile(_ context.Context, obj client.Object) []reconcile.Request {
	name := controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, obj.GetName(), r.nodeName)
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: obj.GetNamespace(), Name: name}},
	}
}

// findNodeObjectsForConfigMap maps a ConfigMap event to RulesfileNode requests on this node.
func (r *RulesfileReconciler) findNodeObjectsForConfigMap(ctx context.Context, configMap client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	rulesfileList := &artifactv1alpha1.RulesfileList{}
	indexKey := configMap.GetNamespace() + "/" + configMap.GetName()
	if err := r.List(ctx, rulesfileList, client.MatchingFields{index.ConfigMapOnRulesfile: indexKey}); err != nil {
		logger.Error(err, "unable to list Rulesfiles by ConfigMap index")
		return nil
	}
	reqs := make([]reconcile.Request, len(rulesfileList.Items))
	for i := range rulesfileList.Items {
		name := controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, rulesfileList.Items[i].Name, r.nodeName)
		reqs[i] = reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: rulesfileList.Items[i].Namespace, Name: name},
		}
	}
	return reqs
}

// findNodeObjectsForSecret maps a Secret event to RulesfileNode requests on this node.
func (r *RulesfileReconciler) findNodeObjectsForSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	rulesfileList := &artifactv1alpha1.RulesfileList{}
	indexKey := secret.GetNamespace() + "/" + secret.GetName()
	if err := r.List(ctx, rulesfileList, client.MatchingFields{index.SecretOnRulesfile: indexKey}); err != nil {
		logger.Error(err, "unable to list Rulesfiles by Secret index")
		return nil
	}
	reqs := make([]reconcile.Request, len(rulesfileList.Items))
	for i := range rulesfileList.Items {
		name := controllerhelper.NodeObjectName(controllerhelper.ArtifactKindRulesfile, rulesfileList.Items[i].Name, r.nodeName)
		reqs[i] = reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: rulesfileList.Items[i].Namespace, Name: name},
		}
	}
	return reqs
}

// findAllNodeObjectsOnVersionChange enqueues every RulesfileNode on this node when
// the VersionsWatcher detects a change in Falco's capability set.
func (r *RulesfileReconciler) findAllNodeObjectsOnVersionChange(ctx context.Context, _ client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	if err := r.List(ctx, nodeList,
		client.InNamespace(r.namespace),
		client.MatchingLabels{controllerhelper.LabelArtifactNode: r.nodeName},
		client.MatchingFields{index.ArtifactNodeOwnerKind: controllerhelper.KindRulesfile},
	); err != nil {
		logger.Error(err, "unable to list ArtifactNodes (rulesfile) on Falco versions change")
		return nil
	}
	reqs := make([]reconcile.Request, len(nodeList.Items))
	for i := range nodeList.Items {
		reqs[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&nodeList.Items[i])}
	}
	return reqs
}

// ensureRulesfile ensures the rulesfile artifacts are stored on the filesystem.
// For each source medium (oci, inline, configmap), stale files are cleaned up first
// if the medium is no longer active in the spec, then the active mediums are fetched/stored.
func (r *RulesfileReconciler) ensureRulesfile(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, nodeObj *artifactv1alpha1.ArtifactNode,
) error {
	if err := r.cleanupStaleMedium(ctx, rulesfile, nodeObj, rulesfile.Spec.OCIArtifact != nil,
		artifact.MediumOCI, commonv1alpha1.ConditionOCIArtifactProgrammed.String()); err != nil {
		return err
	}
	if err := r.cleanupStaleMedium(ctx, rulesfile, nodeObj, rulesfile.Spec.InlineRules != nil,
		artifact.MediumInline, commonv1alpha1.ConditionInlineArtifactProgrammed.String()); err != nil {
		return err
	}
	if err := r.cleanupStaleMedium(ctx, rulesfile, nodeObj, rulesfile.Spec.ConfigMapRef != nil,
		artifact.MediumConfigMap, commonv1alpha1.ConditionConfigMapArtifactProgrammed.String()); err != nil {
		return err
	}

	if rulesfile.Spec.OCIArtifact != nil {
		if err := r.ensureOCIRulesfile(ctx, rulesfile, nodeObj); err != nil {
			return err
		}
	}
	if rulesfile.Spec.InlineRules != nil {
		if err := r.ensureInlineRulesfile(ctx, rulesfile, nodeObj); err != nil {
			return err
		}
	}
	if rulesfile.Spec.ConfigMapRef != nil {
		if err := r.ensureConfigMapRulesfile(ctx, rulesfile, nodeObj); err != nil {
			return err
		}
	}

	return nil
}

// cleanupStaleMedium removes the tracked file and clears the Programmed condition for medium
// when it is no longer active in the spec (active is false). No-op when active is true or
// nothing is currently installed for medium.
func (r *RulesfileReconciler) cleanupStaleMedium(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, nodeObj *artifactv1alpha1.ArtifactNode,
	active bool, medium artifact.Medium, conditionType string,
) error {
	if active {
		return nil
	}
	logger := log.FromContext(ctx)
	apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, conditionType)
	existing := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, medium)
	if existing == nil {
		return nil
	}
	if err := r.store.Remove(ctx, []artifactv1alpha1.InstalledArtifact{{Path: existing.Path, Medium: string(medium)}}); err != nil {
		logger.Error(err, "unable to remove stale rulesfile", "medium", medium)
		return err
	}
	artifact.RecordStoreEvent(r.recorder, rulesfile, artifact.StoreActionRemoved, medium)
	artifact.ClearInstalled(&nodeObj.Status.InstalledArtifacts, medium)
	logger.Info("Removed stale rulesfile from disk", "medium", medium, "path", existing.Path)
	return nil
}

// ensureOCIRulesfile fetches and stores the OCI-sourced rulesfile when needed, then sets the
// OCIArtifactProgrammed condition. Skips the fetch when the disk copy is already known-good.
func (r *RulesfileReconciler) ensureOCIRulesfile(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, nodeObj *artifactv1alpha1.ArtifactNode,
) error {
	logger := log.FromContext(ctx)
	gen := rulesfile.GetGeneration()
	p := rulesfile.Spec.Priority

	parentSpecHash := ""
	if rulesfile.Status.ArtifactMeta != nil {
		parentSpecHash = rulesfile.Status.ArtifactMeta.SpecHash
	}
	current := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI)

	// Decide whether to hit the artifact server.
	// Skip only when the spec hash is unchanged AND the disk file is intact.
	needFetch := current == nil || current.SpecHash != parentSpecHash
	if !needFetch {
		if ok, err := r.store.Verify(ctx, current); err != nil {
			logger.V(3).Info("OCI artifact disk verify failed; re-fetching", "err", err)
			needFetch = true
		} else if !ok {
			logger.V(4).Info("OCI artifact missing or corrupted on disk; re-fetching")
			needFetch = true
		} else {
			logger.V(4).Info("OCI artifact verified on disk; skipping fetch")
		}
	}

	if needFetch {
		result, err := r.fetcher.FetchOCI(ctx, rulesfile.Namespace, rulesfile.Name, artifact.TypeRulesfile)
		if err != nil {
			logger.Error(err, "unable to fetch Rulesfile OCI artifact")
			artifact.RecordWarning(r.recorder, rulesfile, artifact.ReasonOCIArtifactStoreFailed, artifact.MessageFormatOCIArtifactStoreFailed, err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewOCIArtifactProgrammedCondition(
				metav1.ConditionFalse, artifact.ReasonOCIArtifactProgramFailed,
				fmt.Sprintf(artifact.MessageFormatOCIArtifactStoreFailed, err.Error()), gen,
			))
			return err
		}
		ociAction, newFile, err := r.store.Store(ctx, current, rulesfile.Name, p, artifact.TypeRulesfile, artifact.MediumOCI, result)
		if err != nil {
			logger.Error(err, "unable to store Rulesfile OCI artifact")
			artifact.RecordWarning(r.recorder, rulesfile, artifact.ReasonOCIArtifactStoreFailed, artifact.MessageFormatOCIArtifactStoreFailed, err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewOCIArtifactProgrammedCondition(
				metav1.ConditionFalse, artifact.ReasonOCIArtifactProgramFailed,
				fmt.Sprintf(artifact.MessageFormatOCIArtifactStoreFailed, err.Error()), gen,
			))
			return err
		}
		artifact.UpdateInstalledStatus(&nodeObj.Status.InstalledArtifacts, ociAction, artifact.MediumOCI, newFile)
		// Persist specHash even when StoreActionUnchanged (same content, different spec).
		artifact.UpdateInstalledSpecHash(&nodeObj.Status.InstalledArtifacts, artifact.MediumOCI, parentSpecHash)
		artifact.RecordStoreEvent(r.recorder, rulesfile, ociAction, artifact.MediumOCI)
		if ociAction == artifact.StoreActionAdded || ociAction == artifact.StoreActionUpdated || ociAction == artifact.StoreActionPriorityChanged {
			logger.Info("Rulesfile OCI artifact written to disk", "path", newFile.Path, "action", string(ociAction))
		}
	}
	apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewOCIArtifactProgrammedCondition(
		metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed, artifact.MessageOCIArtifactProgrammed, gen,
	))
	return nil
}

// ensureInlineRulesfile converts, fetches, and stores the inline-sourced rulesfile, then sets
// the InlineArtifactProgrammed condition.
func (r *RulesfileReconciler) ensureInlineRulesfile(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, nodeObj *artifactv1alpha1.ArtifactNode,
) error {
	logger := log.FromContext(ctx)
	gen := rulesfile.GetGeneration()
	p := rulesfile.Spec.Priority

	inlineRulesData, err := common.JSONRawToYAML(rulesfile.Spec.InlineRules)
	if err != nil {
		logger.Error(err, "unable to convert inline rules to YAML")
		artifact.RecordWarning(r.recorder, rulesfile, artifact.ReasonInlineRulesStoreFailed, artifact.MessageFormatInlineRulesStoreFailed, err.Error())
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewInlineArtifactProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonInlineArtifactProgramFailed,
			fmt.Sprintf(artifact.MessageFormatInlineRulesStoreFailed, err.Error()), gen,
		))
		return err
	}
	if inlineRulesData != nil {
		result, err := r.fetcher.FetchInline(ctx, []byte(*inlineRulesData))
		if err != nil {
			logger.Error(err, "unable to prepare inline rules content")
			artifact.RecordWarning(r.recorder, rulesfile, artifact.ReasonInlineRulesStoreFailed, artifact.MessageFormatInlineRulesStoreFailed, err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewInlineArtifactProgrammedCondition(
				metav1.ConditionFalse, artifact.ReasonInlineArtifactProgramFailed,
				fmt.Sprintf(artifact.MessageFormatInlineRulesStoreFailed, err.Error()), gen,
			))
			return err
		}
		current := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumInline)
		inlineAction, newFile, err := r.store.Store(ctx, current, rulesfile.Name, p, artifact.TypeRulesfile, artifact.MediumInline, result)
		if err != nil {
			logger.Error(err, "unable to store Rulesfile inline rules")
			artifact.RecordWarning(r.recorder, rulesfile, artifact.ReasonInlineRulesStoreFailed, artifact.MessageFormatInlineRulesStoreFailed, err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewInlineArtifactProgrammedCondition(
				metav1.ConditionFalse, artifact.ReasonInlineArtifactProgramFailed,
				fmt.Sprintf(artifact.MessageFormatInlineRulesStoreFailed, err.Error()), gen,
			))
			return err
		}
		artifact.UpdateInstalledStatus(&nodeObj.Status.InstalledArtifacts, inlineAction, artifact.MediumInline, newFile)
		artifact.RecordStoreEvent(r.recorder, rulesfile, inlineAction, artifact.MediumInline)
		if inlineAction == artifact.StoreActionAdded || inlineAction == artifact.StoreActionUpdated ||
			inlineAction == artifact.StoreActionPriorityChanged {
			logger.Info("Rulesfile inline artifact written to disk", "path", newFile.Path, "action", string(inlineAction))
		}
	}
	apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewInlineArtifactProgrammedCondition(
		metav1.ConditionTrue, artifact.ReasonInlineArtifactProgrammed, artifact.MessageInlineArtifactProgrammed, gen,
	))
	return nil
}

// ensureConfigMapRulesfile fetches and stores the ConfigMap-sourced rulesfile, then sets the
// ConfigMapArtifactProgrammed condition.
func (r *RulesfileReconciler) ensureConfigMapRulesfile(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, nodeObj *artifactv1alpha1.ArtifactNode,
) error {
	logger := log.FromContext(ctx)
	gen := rulesfile.GetGeneration()
	p := rulesfile.Spec.Priority

	result, err := r.fetcher.FetchConfigMap(ctx, rulesfile.Namespace, rulesfile.Spec.ConfigMapRef, artifact.TypeRulesfile)
	if err != nil {
		logger.Error(err, "unable to fetch Rulesfile from ConfigMap reference")
		artifact.RecordWarning(r.recorder, rulesfile,
			artifact.ReasonConfigMapRulesStoreFailed, artifact.MessageFormatConfigMapRulesStoreFailed, err.Error())
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigMapArtifactProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonConfigMapArtifactProgramFailed,
			fmt.Sprintf(artifact.MessageFormatConfigMapRulesStoreFailed, err.Error()), gen,
		))
		return err
	}
	current := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumConfigMap)
	cmAction, newFile, err := r.store.Store(ctx, current, rulesfile.Name, p, artifact.TypeRulesfile, artifact.MediumConfigMap, result)
	if err != nil {
		logger.Error(err, "unable to store Rulesfile from ConfigMap reference")
		artifact.RecordWarning(r.recorder, rulesfile,
			artifact.ReasonConfigMapRulesStoreFailed, artifact.MessageFormatConfigMapRulesStoreFailed, err.Error())
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigMapArtifactProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonConfigMapArtifactProgramFailed,
			fmt.Sprintf(artifact.MessageFormatConfigMapRulesStoreFailed, err.Error()), gen,
		))
		return err
	}
	artifact.UpdateInstalledStatus(&nodeObj.Status.InstalledArtifacts, cmAction, artifact.MediumConfigMap, newFile)
	artifact.RecordStoreEvent(r.recorder, rulesfile, cmAction, artifact.MediumConfigMap)
	if cmAction == artifact.StoreActionAdded || cmAction == artifact.StoreActionUpdated || cmAction == artifact.StoreActionPriorityChanged {
		logger.Info("Rulesfile ConfigMap artifact written to disk", "path", newFile.Path, "action", string(cmAction))
	}
	apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigMapArtifactProgrammedCondition(
		metav1.ConditionTrue, artifact.ReasonConfigMapArtifactProgrammed, artifact.MessageConfigMapArtifactProgrammed, gen,
	))
	return nil
}

func (r *RulesfileReconciler) enforceReferenceResolution(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, nodeObj *artifactv1alpha1.ArtifactNode,
) error {
	logger := log.FromContext(ctx)
	hasRefs := false

	if rulesfile.Spec.ConfigMapRef != nil {
		hasRefs = true
		err := r.Get(ctx, client.ObjectKey{Namespace: rulesfile.Namespace, Name: rulesfile.Spec.ConfigMapRef.Name}, &corev1.ConfigMap{})
		if err != nil {
			logger.Error(err, "ConfigMap reference resolution failed", "configMap", rulesfile.Spec.ConfigMapRef.Name)
			artifact.RecordWarning(r.recorder, rulesfile,
				artifact.ReasonReferenceResolutionFailed, artifact.MessageFormatReferenceResolutionFailed, err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewResolvedRefsCondition(
				metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
				fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, rulesfile.Spec.ConfigMapRef.Name), rulesfile.GetGeneration()))
			return err
		}
	}

	if ociArt := rulesfile.Spec.OCIArtifact; ociArt != nil && ociArt.Registry != nil {
		if reg := ociArt.Registry; reg.Auth != nil && reg.Auth.SecretRef != nil {
			hasRefs = true
			secretName := reg.Auth.SecretRef.Name
			err := r.Get(ctx, client.ObjectKey{Namespace: rulesfile.Namespace, Name: secretName}, &corev1.Secret{})
			if err != nil {
				logger.Error(err, "OCIArtifact auth secret reference resolution failed", "secret", secretName)
				artifact.RecordWarning(r.recorder, rulesfile,
					artifact.ReasonReferenceResolutionFailed, artifact.MessageFormatReferenceResolutionFailed, err.Error())
				apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewResolvedRefsCondition(
					metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
					fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, secretName), rulesfile.GetGeneration()))
				return err
			}
		}
	}

	if hasRefs {
		artifact.RecordNormal(r.recorder, rulesfile, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved)
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewResolvedRefsCondition(
			metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, rulesfile.GetGeneration(),
		))
	} else {
		apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, commonv1alpha1.ConditionResolvedRefs.String())
	}

	return nil
}

// enforceRulesfileCompatibility checks requirements and plugin dependencies against the running
// Falco instance before allowing any source to be installed.
//
// All requirements are collected by the instance operator and stored in parent.Status.ArtifactMeta
// (both OCI config layer and YAML content requirements). This controller only reads from that
// field and checks the union against the local Falco capabilities.
//
// In enforce mode (r.enforceRequirements=true): unreachable Falco versions block installation.
// In advise mode: nil ArtifactMeta is treated as no requirements; Falco version
// fetch failures result in DependenciesSatisfied=Unknown without blocking install.
func (r *RulesfileReconciler) enforceRulesfileCompatibility(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, nodeObj *artifactv1alpha1.ArtifactNode,
) (bool, error) {
	gen := rulesfile.GetGeneration()
	logger := log.FromContext(ctx)

	if rulesfile.Spec.OCIArtifact == nil && rulesfile.Spec.ConfigMapRef == nil && rulesfile.Spec.InlineRules == nil {
		// Returns skip=false so cleanupStaleMedium and store.Sync still run when no source is
		// configured, removing stale files, conditions, and dependency registrations (skip=true
		// here would leave them behind indefinitely).
		logger.Info("Skipping compatibility check: no artifact sources configured")
		apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
		return false, nil
	}

	// All requirements come from parent.Status.ArtifactMeta (populated by the instance operator).
	if rulesfile.Status.ArtifactMeta == nil {
		var msg string
		if rulesfile.Spec.OCIArtifact != nil {
			// OCI source present but meta is nil: instance operator has not fetched the config layer yet.
			msg = "OCI artifact metadata not yet available; instance operator has not fetched it"
		} else {
			// Inline or ConfigMap only: instance operator parsed the YAML content and found no requirements.
			msg = "artifact declares no requirements; installation blocked in enforce mode"
		}
		if r.enforceRequirements {
			logger.Info(msg)
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionUnknown, artifact.ReasonDependenciesUnknown, msg, gen,
			))
			return true, nil
		}
		logger.Info("ArtifactMeta not yet available; proceeding without compatibility check in advise mode")
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, gen,
		))
		return false, nil
	}

	if len(rulesfile.Status.ArtifactMeta.Requirements) == 0 && len(rulesfile.Status.ArtifactMeta.Dependencies) == 0 {
		if r.enforceRequirements {
			baseMsg := "artifact metadata declares no requirements; installation blocked in enforce mode"
			reason, msg := artifact.ReasonDependenciesUnknown, baseMsg
			if len(nodeObj.Status.InstalledArtifacts) > 0 {
				reason = artifact.ReasonDependenciesNotSatisfiedUpdateRejected
				msg = baseMsg + artifact.MessageSuffixUpdateRejected
			}
			logger.Info(msg)
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionUnknown, reason, msg, gen,
			))
			return true, nil
		}
		logger.Info("Artifact declares no requirements; proceeding in advise mode")
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, gen,
		))
		return false, nil
	}

	// anyUnsatisfied tracks whether any engine requirement failed, to avoid overwriting a False
	// condition with True at the end. In advise mode checkEngineRequirement returns skip=false
	// and the loop continues instead of returning early.
	anyUnsatisfied := false
	for _, req := range rulesfile.Status.ArtifactMeta.Requirements {
		skip, satisfied, err := r.checkEngineRequirement(ctx, rulesfile, nodeObj, req.Name, req.Version, gen)
		if err != nil || skip {
			return skip, err
		}
		if !satisfied {
			anyUnsatisfied = true
		}
	}

	var unsatisfied []string
	for _, dep := range rulesfile.Status.ArtifactMeta.Dependencies {
		satisfied, failMsg, err := r.checkDependency(ctx, dep)
		if err != nil {
			msg := fmt.Sprintf("Unable to compare plugin versions: %s", err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionUnknown, artifact.ReasonDependenciesUnknown, msg, gen,
			))
			return false, err
		}
		if !satisfied {
			unsatisfied = append(unsatisfied, failMsg)
		}
	}

	if len(unsatisfied) > 0 {
		baseMsg := strings.Join(unsatisfied, "; ")
		logger.Info("Rulesfile plugin dependencies not satisfied", "count", len(unsatisfied), "unsatisfied", unsatisfied)
		alreadyInstalled := len(nodeObj.Status.InstalledArtifacts) > 0
		skip, reason, msg := artifact.DependenciesNotSatisfiedOutcome(r.enforceRequirements, alreadyInstalled, baseMsg)
		artifact.RecordWarning(r.recorder, rulesfile, reason, msg)
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionFalse, reason, msg, gen,
		))
		return skip, nil
	}

	// Only mark satisfied when all requirements and dependencies passed. If anyUnsatisfied
	// is true an engine requirement already set the condition to False above; don't clobber it.
	if !anyUnsatisfied {
		logger.Info("All rulesfile requirements and dependencies satisfied")
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, gen,
		))
	}
	return false, nil
}

func (r *RulesfileReconciler) checkEngineRequirement(
	ctx context.Context,
	rulesfile *artifactv1alpha1.Rulesfile,
	nodeObj *artifactv1alpha1.ArtifactNode,
	name, requiredVersion string,
	gen int64,
) (skip, satisfied bool, err error) {
	logger := log.FromContext(ctx)
	alreadyInstalled := len(nodeObj.Status.InstalledArtifacts) > 0
	provided, found, ok, semverErr := r.store.CheckRequirement(name, requiredVersion)
	if semverErr != nil {
		msg := fmt.Sprintf("Unable to compare %s versions: %s", name, semverErr.Error())
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionUnknown, artifact.ReasonDependenciesUnknown, msg, gen,
		))
		return false, false, semverErr
	}
	if !found {
		// Covers both "Falco has never been observed yet" and "this requirement was never
		// reported". Treated as an expected, self-resolving state (the version-change watch
		// re-triggers once known), not a hard error.
		baseMsg := fmt.Sprintf(artifact.MessageFormatRequirementMissing, name, requiredVersion)
		logger.Info("Rulesfile requirement not found in Falco versions", "requirement", name, "required", requiredVersion)
		skip, reason, msg := artifact.DependenciesNotSatisfiedOutcome(r.enforceRequirements, alreadyInstalled, baseMsg)
		artifact.RecordWarning(r.recorder, rulesfile, reason, msg)
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionFalse, reason, msg, gen,
		))
		return skip, false, nil
	}
	if !ok {
		baseMsg := fmt.Sprintf(artifact.MessageFormatRequirementNotSatisfied, name, requiredVersion, provided)
		logger.Info("Rulesfile requirement not satisfied", "requirement", name, "provided", provided, "required", requiredVersion)
		skip, reason, msg := artifact.DependenciesNotSatisfiedOutcome(r.enforceRequirements, alreadyInstalled, baseMsg)
		artifact.RecordWarning(r.recorder, rulesfile, reason, msg)
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionFalse, reason, msg, gen,
		))
		return skip, false, nil
	}
	logger.Info("Rulesfile engine requirement satisfied", "requirement", name, "provided", provided, "required", requiredVersion)
	return false, true, nil
}

func (r *RulesfileReconciler) checkDependency(
	ctx context.Context,
	dep commonv1alpha1.ArtifactMetaDependency,
) (satisfied bool, failMsg string, err error) {
	logger := log.FromContext(ctx)

	primary := nodeartifacts.Requirement{Name: dep.Name, Version: dep.Version}
	alternatives := make([]nodeartifacts.Requirement, len(dep.Alternatives))
	for i, alt := range dep.Alternatives {
		alternatives[i] = nodeartifacts.Requirement{Name: alt.Name, Version: alt.Version}
	}

	matchedName, provided, ok, err := r.store.CheckDependency(primary, alternatives)
	if err != nil {
		return false, "", fmt.Errorf("compare %s: %w", dep.Name, err)
	}
	if ok {
		logger.V(4).Info("Rulesfile dependency satisfied", "plugin", matchedName, "version", provided)
		return true, "", nil
	}

	var msg string
	if len(dep.Alternatives) == 0 {
		msg = fmt.Sprintf(artifact.MessageFormatDependencyNotSatisfied, dep.Name, dep.Version)
	} else {
		altParts := make([]string, len(dep.Alternatives))
		for i, alt := range dep.Alternatives {
			altParts[i] = fmt.Sprintf("%s >= %s", alt.Name, alt.Version)
		}
		msg = fmt.Sprintf(artifact.MessageFormatDependencyNotSatisfiedWithAlternatives,
			dep.Name, dep.Version, strings.Join(altParts, ", "))
	}
	return false, msg, nil
}
