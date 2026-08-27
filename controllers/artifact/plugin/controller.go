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

// Package plugin implements the artifact operator's per-node plugin reconciler.
package plugin

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

const (
	// pluginNodeFinalizer is the finalizer placed on PluginNode objects by this controller.
	pluginNodeFinalizer = "pluginnode.artifact.falcosecurity.dev/finalizer"
	// fieldManager is the name used to identify the controller's managed fields.
	fieldManager = "artifact-plugin"
)

// NewPluginReconciler creates a new PluginReconciler instance.
// fetcher is the shared artifact fetcher, configured with the central artifact server's URL,
// TLS/mTLS, and retry policy, used to download OCI artifacts.
func NewPluginReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	nodeName, namespace string,
	enforceRequirements bool,
	fetcher artifact.ArtifactFetcher,
	nodeManager *nodeartifacts.Manager,
) *PluginReconciler {
	return &PluginReconciler{
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

// PluginReconciler reconciles a PluginNode object assigned to this node.
type PluginReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	recorder            events.EventRecorder
	fetcher             artifact.ArtifactFetcher
	store               *nodeartifacts.Manager
	nodeName            string
	namespace           string
	enforceRequirements bool
}

// Reconcile reconciles the PluginNode assigned to this node.
// It reads the parent Plugin for spec, applies local filesystem changes and plugin configuration,
// and writes resulting conditions to the PluginNode status only.
func (r *PluginReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := log.FromContext(ctx)

	nodeObj := &artifactv1alpha1.ArtifactNode{}
	if err := r.Get(ctx, req.NamespacedName, nodeObj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	oldStatus := nodeObj.Status.DeepCopy()

	// Handle deletion: clean up local resources then release the finalizer.
	if ok, err := r.handleDeletion(ctx, nodeObj); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure our finalizer is set on the node object.
	if ok, err := controllerhelper.EnsureFinalizer(ctx, r.Client, pluginNodeFinalizer, nodeObj); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Fetch the parent Plugin to get the spec.
	plugin, err := r.getParentPlugin(ctx, nodeObj)
	if err != nil {
		return ctrl.Result{}, err
	}
	if plugin == nil {
		logger.V(2).Info("Parent Plugin not found; waiting for GC")
		return ctrl.Result{}, nil
	}

	// Patches the node object status on return (deferred so it always runs).
	// Programmed is a gateway condition: True only when all other conditions are True. In advise
	// mode, DependenciesSatisfied is excluded from the gate since it's advisory only.
	defer func() {
		skipDependenciesSatisfied := func(condType string) bool {
			return !r.enforceRequirements && condType == commonv1alpha1.ConditionDependenciesSatisfied.String()
		}
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.ComputeProgrammedCondition(
			nodeObj.Status.Conditions, skipDependenciesSatisfied,
			artifact.ReasonProgrammed, artifact.MessageProgrammed, artifact.ReasonProgramFailed,
			plugin.GetGeneration(),
		))
		var patchErr error
		if !apiequality.Semantic.DeepEqual(*oldStatus, nodeObj.Status) {
			patchErr = controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, nodeObj, fieldManager)
			if patchErr != nil {
				logger.Error(patchErr, "unable to patch PluginNode status")
			}
		}
		reterr = kerrors.NewAggregate([]error{reterr, patchErr})
	}()

	// Enforce reference resolution before the generation gate below.
	if err := r.enforceReferenceResolution(ctx, plugin, nodeObj); err != nil {
		return ctrl.Result{}, err
	}

	// In enforce mode, waits until the instance operator has processed the current spec
	// generation before running compatibility checks or filesystem changes.
	if r.enforceRequirements && plugin.Status.ObservedGeneration != plugin.Generation {
		logger.Info("instance operator has not yet processed current spec generation; deferring",
			"observedGeneration", plugin.Status.ObservedGeneration,
			"specGeneration", plugin.Generation)
		return ctrl.Result{}, nil
	} else {
		logger.Info("instance operator has processed current spec generation; proceeding",
			"observedGeneration", plugin.Status.ObservedGeneration,
			"specGeneration", plugin.Generation)
	}

	// Check plugin compatibility with the running Falco instance.
	skip, compatErr := r.enforcePluginCompatibility(ctx, plugin, nodeObj)
	if compatErr != nil {
		return ctrl.Result{}, compatErr
	}
	if skip {
		// If the artifact was never installed on this node, explicitly mark installation
		// conditions as False so the aggregator sees them. Without this, absent conditions
		// let another node's True status win unopposed in AggregateConditions, making the
		// Plugin-level status show ConfigProgrammed=True even when DependenciesSatisfied=False.
		// When alreadyInstalled=true (update-rejected), the old version is still on disk and
		// ConfigProgrammed/OCIArtifactProgrammed correctly remain True; don't touch them.
		if artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI) == nil {
			depCond := apimeta.FindStatusCondition(nodeObj.Status.Conditions,
				commonv1alpha1.ConditionDependenciesSatisfied.String())
			reason := artifact.ReasonDependenciesNotSatisfied
			msg := "dependency requirements not satisfied on this node"
			if depCond != nil {
				reason, msg = depCond.Reason, depCond.Message
			}
			gen := plugin.GetGeneration()
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigProgrammedCondition(
				metav1.ConditionFalse, reason, msg, gen,
			))
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewOCIArtifactProgrammedCondition(
				metav1.ConditionFalse, reason, msg, gen,
			))
		}
		return ctrl.Result{}, nil
	}

	// ensurePlugin stores the Plugin artifact on disk. A transient fetch failure requeues via
	// RequeueAfter instead of returning an error, which would otherwise tie up this worker for
	// controller-runtime's retry backoff.
	if err := r.ensurePlugin(ctx, plugin, nodeObj); err != nil {
		if delay, ok := artifact.RequeueDelay(err); ok {
			logger.Info("artifact server not ready, requeueing", "delay", delay)
			return ctrl.Result{RequeueAfter: delay}, nil
		}
		return ctrl.Result{}, err
	}

	// Ensure the plugin configuration is written to the config file.
	if err := r.ensurePluginConfig(ctx, plugin, nodeObj); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// getParentPlugin retrieves the parent Plugin via the node object's ownerRef, verifying by UID
// that it's still the generation nodeObj was created for (see GetVerifiedOwner's doc).
func (r *PluginReconciler) getParentPlugin(ctx context.Context, nodeObj *artifactv1alpha1.ArtifactNode) (*artifactv1alpha1.Plugin, error) {
	plugin := &artifactv1alpha1.Plugin{}
	ok, err := controllerhelper.GetVerifiedOwner(ctx, r.Client, nodeObj, controllerhelper.KindPlugin, plugin)
	if err != nil || !ok {
		return nil, err
	}
	return plugin, nil
}

// handleDeletion cleans up local filesystem resources and the plugin config entry,
// then removes the finalizer from the PluginNode.
func (r *PluginReconciler) handleDeletion(ctx context.Context, nodeObj *artifactv1alpha1.ArtifactNode) (bool, error) {
	if nodeObj.DeletionTimestamp.IsZero() {
		return false, nil
	}
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(nodeObj, pluginNodeFinalizer) {
		return true, nil
	}

	logger.Info("PluginNode marked for deletion, cleaning up")

	// Resolves the config name: tries the parent Plugin for a Config.Name override, falling
	// back to the ownerRef name when the Plugin has already been deleted. Config cleanup does
	// not depend on the Plugin still existing.
	var pluginName string
	configName := ""
	plugin := &artifactv1alpha1.Plugin{}
	for _, ref := range nodeObj.OwnerReferences {
		if ref.Kind == controllerhelper.KindPlugin {
			pluginName = ref.Name
			configName = ref.Name // fallback: default config name == plugin name
			if err := r.Get(ctx, client.ObjectKey{Namespace: nodeObj.Namespace, Name: ref.Name}, plugin); err != nil {
				if !k8serrors.IsNotFound(err) {
					return false, err
				}
			} else {
				configName = nodeartifacts.ResolveConfigName(plugin)
			}
			break
		}
	}

	// Removes this plugin's entry from the shared config YAML before removing the binary.
	if pluginName != "" {
		if err := r.store.RemovePluginConfigByName(ctx, r.fetcher, pluginName, configName); err != nil {
			if blocked, ok := errors.AsType[*nodeartifacts.BlockedError](err); ok {
				logger.Info("PluginNode deletion blocked: plugin config still required by a Rulesfile on this node",
					"configName", configName, "blockedBy", blocked.BlockedBy)
				artifact.RecordWarning(r.recorder, nodeObj, artifact.ReasonDependenciesNotSatisfied, "%s", blocked.Error())
				// Sets a DeletionBlocked condition so the instance-level aggregator can propagate
				// the block onto the parent Plugin's status.
				apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDeletionBlockedCondition(
					metav1.ConditionTrue, artifact.ReasonPluginConfigStillRequired, blocked.Error(), plugin.Generation,
				))
				if patchErr := controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, nodeObj, fieldManager); patchErr != nil {
					logger.Error(patchErr, "unable to patch PluginNode status with DeletionBlocked condition")
				}
				return false, nil
			}
			logger.Error(err, "unable to remove plugin config on deletion")
			return false, err
		}
	}

	// Binary second: remove the plugin binary from disk.
	if err := r.store.Remove(ctx, nodeObj.Status.InstalledArtifacts); err != nil {
		logger.Error(err, "unable to remove installed plugin artifacts from disk")
		return false, err
	}

	patch := client.MergeFrom(nodeObj.DeepCopy())
	controllerutil.RemoveFinalizer(nodeObj, pluginNodeFinalizer)
	if err := r.Patch(ctx, nodeObj, patch); err != nil {
		logger.Error(err, "unable to remove finalizer from PluginNode")
		return false, err
	}
	return true, nil
}

// SetupWithManager registers the controller with the Manager.
// versionEvents is the channel produced by compat.VersionsWatcher; a GenericEvent on this
// channel re-enqueues all PluginNodes on this node to re-evaluate their compatibility
// requirements against the updated Falco capability set.
func (r *PluginReconciler) SetupWithManager(mgr ctrl.Manager, versionEvents <-chan event.GenericEvent) error {
	nodeFilter := predicate.NewPredicateFuncs(func(obj client.Object) bool {
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

	// Re-enqueues every PluginNode on this node when any RulesfileNode on this node changes, so
	// a Plugin config removal blocked by nodeartifacts.Manager.RemovePluginConfigByName is
	// re-evaluated once the blocking Rulesfile's requirement changes or the RulesfileNode is
	// removed.
	rulesfileNodeFilter := predicate.NewPredicateFuncs(func(obj client.Object) bool {
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

	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.ArtifactNode{}, builder.WithPredicates(nodeFilter)).
		Watches(
			&artifactv1alpha1.Plugin{},
			handler.EnqueueRequestsFromMapFunc(r.findNodeObjectForPlugin),
		).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findNodeObjectsForSecret),
		).
		Watches(
			&artifactv1alpha1.ArtifactNode{},
			handler.EnqueueRequestsFromMapFunc(r.findAllNodeObjectsOnVersionChange),
			builder.WithPredicates(rulesfileNodeFilter),
		).
		WatchesRawSource(source.Channel(versionEvents, handler.EnqueueRequestsFromMapFunc(r.findAllNodeObjectsOnVersionChange))).
		Named("artifact-plugin").
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), "artifact-plugin", &artifactv1alpha1.ArtifactNode{})).
		Complete(r)
}

// findAllNodeObjectsOnVersionChange re-enqueues every PluginNode on this node when Falco's
// reported capabilities change, so a blocked plugin can be re-evaluated and installed once its
// compatibility requirement is satisfied.
func (r *PluginReconciler) findAllNodeObjectsOnVersionChange(ctx context.Context, _ client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	nodeList := &artifactv1alpha1.ArtifactNodeList{}
	if err := r.List(ctx, nodeList,
		client.InNamespace(r.namespace),
		client.MatchingLabels{controllerhelper.LabelArtifactNode: r.nodeName},
		client.MatchingFields{index.ArtifactNodeOwnerKind: controllerhelper.KindPlugin},
	); err != nil {
		logger.Error(err, "unable to list ArtifactNodes (plugin) on Falco versions change")
		return nil
	}
	reqs := make([]reconcile.Request, len(nodeList.Items))
	for i := range nodeList.Items {
		reqs[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&nodeList.Items[i])}
	}
	return reqs
}

// findNodeObjectForPlugin maps a Plugin event to this node's PluginNode request.
func (r *PluginReconciler) findNodeObjectForPlugin(_ context.Context, obj client.Object) []reconcile.Request {
	name := controllerhelper.NodeObjectName(controllerhelper.ArtifactKindPlugin, obj.GetName(), r.nodeName)
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: obj.GetNamespace(), Name: name}},
	}
}

// findNodeObjectsForSecret maps a Secret event to PluginNode requests on this node.
func (r *PluginReconciler) findNodeObjectsForSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	pluginList := &artifactv1alpha1.PluginList{}
	indexKey := secret.GetNamespace() + "/" + secret.GetName()
	if err := r.List(ctx, pluginList, client.MatchingFields{index.SecretOnPlugin: indexKey}); err != nil {
		logger.Error(err, "unable to list Plugins by Secret index")
		return nil
	}
	reqs := make([]reconcile.Request, len(pluginList.Items))
	for i := range pluginList.Items {
		name := controllerhelper.NodeObjectName(controllerhelper.ArtifactKindPlugin, pluginList.Items[i].Name, r.nodeName)
		reqs[i] = reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: pluginList.Items[i].Namespace, Name: name},
		}
	}
	return reqs
}

// ensurePlugin ensures that the Plugin artifact is stored on the local filesystem.
func (r *PluginReconciler) ensurePlugin(ctx context.Context, plugin *artifactv1alpha1.Plugin, nodeObj *artifactv1alpha1.ArtifactNode) error {
	gen := plugin.GetGeneration()
	logger := log.FromContext(ctx)

	if plugin.Spec.OCIArtifact == nil {
		// OCI spec removed while the Plugin CR still exists: removes the config entry, then the
		// binary.
		if existing := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI); existing != nil {
			if err := r.store.RemovePluginConfig(ctx, r.fetcher, plugin); err != nil {
				logger.Error(err, "unable to remove plugin config during OCI spec removal")
				return err
			}
			if err := r.store.Remove(ctx, []artifactv1alpha1.InstalledArtifact{
				{Path: existing.Path, Medium: string(existing.Medium)},
			}); err != nil {
				logger.Error(err, "unable to remove stale plugin binary")
				return err
			}
			artifact.RecordStoreEvent(r.recorder, plugin, artifact.StoreActionRemoved, artifact.MediumOCI)
			artifact.ClearInstalled(&nodeObj.Status.InstalledArtifacts, artifact.MediumOCI)
		}
		// Removes the OCIArtifactProgrammed condition instead of leaving it stale. Mirrors
		// ensureRulesfile's per-medium stale-cleanup behavior.
		apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, commonv1alpha1.ConditionOCIArtifactProgrammed.String())
		return nil
	}

	parentSpecHash := ""
	if plugin.Status.ArtifactMeta != nil {
		parentSpecHash = plugin.Status.ArtifactMeta.SpecHash
	}
	current := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI)

	// Fetches from the artifact server unless the spec hash is unchanged and the disk file is
	// intact.
	needFetch := current == nil || current.SpecHash != parentSpecHash
	if !needFetch {
		if ok, err := r.store.Verify(ctx, current); err != nil {
			logger.V(3).Info("plugin artifact disk verify failed; re-fetching", "err", err)
		} else if !ok {
			logger.V(4).Info("plugin artifact missing or corrupted on disk; re-fetching")
		} else {
			logger.V(4).Info("plugin artifact verified on disk; skipping fetch")
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewOCIArtifactProgrammedCondition(
				metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed, artifact.MessageOCIArtifactProgrammed, gen,
			))
			return nil
		}
	}

	result, err := r.fetcher.FetchOCI(ctx, plugin.Namespace, plugin.Name, artifact.TypePlugin)
	if err != nil {
		logger.Error(err, "unable to fetch plugin artifact")
		artifact.RecordWarning(r.recorder, plugin, artifact.ReasonOCIArtifactStoreFailed, artifact.MessageFormatOCIArtifactStoreFailed, err.Error())
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewOCIArtifactProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonOCIArtifactProgramFailed,
			fmt.Sprintf(artifact.MessageFormatOCIArtifactStoreFailed, err.Error()), gen,
		))
		return err
	}
	ociAction, newFile, err := r.store.Store(ctx, current, plugin.Name, priority.DefaultPriority, artifact.TypePlugin, artifact.MediumOCI, result)
	if err != nil {
		logger.Error(err, "unable to store plugin artifact")
		artifact.RecordWarning(r.recorder, plugin, artifact.ReasonOCIArtifactStoreFailed, artifact.MessageFormatOCIArtifactStoreFailed, err.Error())
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewOCIArtifactProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonOCIArtifactProgramFailed,
			fmt.Sprintf(artifact.MessageFormatOCIArtifactStoreFailed, err.Error()), gen,
		))
		return err
	}
	artifact.UpdateInstalledStatus(&nodeObj.Status.InstalledArtifacts, ociAction, artifact.MediumOCI, newFile)
	// Persist specHash even when StoreActionUnchanged (same content, different spec).
	artifact.UpdateInstalledSpecHash(&nodeObj.Status.InstalledArtifacts, artifact.MediumOCI, parentSpecHash)
	artifact.RecordStoreEvent(r.recorder, plugin, ociAction, artifact.MediumOCI)
	apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewOCIArtifactProgrammedCondition(
		metav1.ConditionTrue, artifact.ReasonOCIArtifactProgrammed, artifact.MessageOCIArtifactProgrammed, gen,
	))
	return nil
}

func (r *PluginReconciler) enforceReferenceResolution(
	ctx context.Context, plugin *artifactv1alpha1.Plugin, nodeObj *artifactv1alpha1.ArtifactNode,
) error {
	logger := log.FromContext(ctx)
	hasRefs := false

	if ociArt := plugin.Spec.OCIArtifact; ociArt != nil && ociArt.Registry != nil {
		if reg := ociArt.Registry; reg.Auth != nil && reg.Auth.SecretRef != nil {
			hasRefs = true
			secretName := reg.Auth.SecretRef.Name
			err := r.Get(ctx, client.ObjectKey{Namespace: plugin.Namespace, Name: secretName}, &corev1.Secret{})
			if err != nil {
				logger.Error(err, "OCIArtifact auth secret reference resolution failed", "secret", secretName)
				artifact.RecordWarning(r.recorder, plugin, artifact.ReasonReferenceResolutionFailed, artifact.MessageFormatReferenceResolutionFailed, err.Error())
				apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewResolvedRefsCondition(
					metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
					fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, secretName), plugin.GetGeneration()))
				return err
			}
		}
	}

	if hasRefs {
		artifact.RecordNormal(r.recorder, plugin, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved)
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewResolvedRefsCondition(
			metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, plugin.GetGeneration(),
		))
	} else {
		apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, commonv1alpha1.ConditionResolvedRefs.String())
	}

	return nil
}

// enforcePluginCompatibility verifies that the plugin's declared requirements (from
// parent.Status.ArtifactMeta, populated by the instance operator) are satisfied by the
// running Falco instance.
//
// In enforce mode (r.enforceRequirements=true): a missing ArtifactMeta blocks installation.
// In advise mode: a missing ArtifactMeta is treated as no requirements, allowing install.
func (r *PluginReconciler) enforcePluginCompatibility(
	ctx context.Context, plugin *artifactv1alpha1.Plugin, nodeObj *artifactv1alpha1.ArtifactNode,
) (bool, error) {
	gen := plugin.GetGeneration()
	logger := log.FromContext(ctx)

	if plugin.Spec.OCIArtifact == nil {
		logger.Info("Skipping compatibility check: no OCI artifact configured")
		apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
		return false, nil
	}

	if plugin.Status.ArtifactMeta == nil {
		if r.enforceRequirements {
			msg := "OCI artifact metadata not yet available; instance operator has not fetched it"
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

	if len(plugin.Status.ArtifactMeta.Requirements) == 0 {
		if r.enforceRequirements {
			baseMsg := "artifact metadata declares no requirements; installation blocked in enforce mode"
			reason, msg := artifact.ReasonDependenciesUnknown, baseMsg
			if artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI) != nil {
				reason = artifact.ReasonDependenciesNotSatisfiedUpdateRejected
				msg = baseMsg + artifact.MessageSuffixUpdateRejected
			}
			logger.Info(msg)
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionUnknown, reason, msg, gen,
			))
			return true, nil
		}
		logger.Info("Plugin declares no requirements; proceeding in advise mode")
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, gen,
		))
		return false, nil
	}

	alreadyInstalled := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI) != nil
	for _, req := range plugin.Status.ArtifactMeta.Requirements {
		provided, found, ok, semverErr := r.store.CheckRequirement(req.Name, req.Version)
		if semverErr != nil {
			logger.Error(semverErr, "Unable to compare plugin requirement versions",
				"capability", req.Name, "provided", provided, "required", req.Version)
			msg := fmt.Sprintf("Unable to compare %s versions: %s", req.Name, semverErr.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionUnknown, artifact.ReasonDependenciesUnknown, msg, gen,
			))
			return false, semverErr
		}
		if !found {
			// Covers both "Falco not yet observed" and "capability never reported"; both are a
			// temporary state that resolves once the version-change watch re-triggers.
			baseMsg := fmt.Sprintf(artifact.MessageFormatDependenciesCapabilityMissing, req.Name, req.Version)
			logger.Info("Plugin dependency not advertised by Falco", "capability", req.Name, "required", req.Version)
			skip, reason, msg := artifact.DependenciesNotSatisfiedOutcome(r.enforceRequirements, alreadyInstalled, baseMsg)
			artifact.RecordWarning(r.recorder, plugin, reason, msg)
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionFalse, reason, msg, gen,
			))
			return skip, nil
		}

		if !ok {
			var baseMsg string
			if req.Name == compat.CapabilityPluginAPIVersion {
				baseMsg = fmt.Sprintf(artifact.MessageFormatPluginAPIMajorMismatch, req.Version, provided)
			} else {
				baseMsg = fmt.Sprintf(artifact.MessageFormatDependenciesNotSatisfied, req.Name, req.Version, provided)
			}
			logger.Info("Plugin dependency not satisfied", "capability", req.Name, "provided", provided, "required", req.Version)
			skip, reason, msg := artifact.DependenciesNotSatisfiedOutcome(r.enforceRequirements, alreadyInstalled, baseMsg)
			artifact.RecordWarning(r.recorder, plugin, reason, msg)
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionFalse, reason, msg, gen,
			))
			return skip, nil
		}
		logger.Info("Plugin requirement satisfied", "capability", req.Name, "provided", provided, "required", req.Version)
	}

	logger.Info("All plugin requirements satisfied")
	apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewDependenciesSatisfiedCondition(
		metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, gen,
	))
	return false, nil
}

// ensurePluginConfig writes the plugin configuration to the shared config file.
// A no-op when the plugin has no OCI artifact (see ensurePlugin's stale cleanup). The config
// file path and content hash are tracked in the OCI InstalledArtifact's Config sub-field, so
// StoreActionUnchanged fires when the YAML content is unchanged between reconciles.
//
// Aggregate-file bookkeeping (rename handling, serialization, the write, and registering the
// resulting name as provided) lives in nodeartifacts.Manager.AddPluginConfig.
func (r *PluginReconciler) ensurePluginConfig(ctx context.Context, plugin *artifactv1alpha1.Plugin, nodeObj *artifactv1alpha1.ArtifactNode) error {
	gen := plugin.GetGeneration()
	if plugin.Spec.OCIArtifact == nil {
		// ensurePlugin already removed this plugin's config entry (if any) during stale cleanup.
		// Removes the ConfigProgrammed condition instead of leaving it stale.
		apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, commonv1alpha1.ConditionConfigProgrammed.String())
		return nil
	}

	logger := log.FromContext(ctx)
	logger.Info("Ensuring plugin configuration")

	configCurrent := artifact.FindInstalledConfig(nodeObj.Status.InstalledArtifacts, artifact.MediumOCI)
	configAction, configFile, err := r.store.AddPluginConfig(ctx, plugin, configCurrent, r.fetcher)
	if err != nil {
		if blocked, ok := errors.AsType[*nodeartifacts.BlockedError](err); ok {
			logger.Info("Plugin config rename deferred: old name still required by a Rulesfile on this node",
				"blockedBy", blocked.BlockedBy)
			return err
		}
		logger.Error(err, "unable to store plugin config")
		artifact.RecordWarning(r.recorder, plugin,
			artifact.ReasonInlinePluginConfigStoreFailed, artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error())
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonConfigProgramFailed,
			fmt.Sprintf(artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error()), gen,
		))
		return err
	}

	// Both helpers below no-op when configFile is nil (StoreActionUnchanged/StoreActionNone).
	artifact.RecordStoreEvent(r.recorder, plugin, configAction, artifact.MediumInline)
	artifact.UpdateInstalledConfig(&nodeObj.Status.InstalledArtifacts, artifact.MediumOCI, configFile)
	apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigProgrammedCondition(
		metav1.ConditionTrue, artifact.ReasonConfigProgrammed, artifact.MessageConfigProgrammed, gen,
	))
	return nil
}
