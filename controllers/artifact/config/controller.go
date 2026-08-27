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

package config

import (
	"context"
	"fmt"
	"net/http"

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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
)

const (
	// configNodeFinalizer is the finalizer placed on ConfigNode objects by this controller.
	configNodeFinalizer = "confignode.artifact.falcosecurity.dev/finalizer"
	// fieldManager is the SSA field manager identifier for this controller.
	fieldManager = "artifact-config"
)

// NewConfigReconciler returns a new ConfigReconciler.
func NewConfigReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	nodeName, namespace string,
	nodeManager *nodeartifacts.Manager,
) *ConfigReconciler {
	return &ConfigReconciler{
		Client:   cl,
		Scheme:   scheme,
		recorder: recorder,
		fetcher: &artifact.Fetcher{
			HTTPClient: &http.Client{},
			K8sClient:  cl,
			NodeName:   nodeName,
		},
		store:     nodeManager,
		nodeName:  nodeName,
		namespace: namespace,
	}
}

// ConfigReconciler reconciles a ConfigNode object assigned to this node.
type ConfigReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	recorder  events.EventRecorder
	fetcher   artifact.ArtifactFetcher
	store     *nodeartifacts.Manager
	nodeName  string
	namespace string
}

// Reconcile reconciles the ConfigNode assigned to this node.
// It reads the parent Config for spec, applies local filesystem changes,
// and writes resulting conditions to the ConfigNode status only.
func (r *ConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
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
	if ok, err := controllerhelper.EnsureFinalizer(ctx, r.Client, configNodeFinalizer, nodeObj); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Fetch the parent Config to get the spec.
	config, err := r.getParentConfig(ctx, nodeObj)
	if err != nil {
		return ctrl.Result{}, err
	}
	if config == nil {
		logger.V(2).Info("Parent Config not found; waiting for GC")
		return ctrl.Result{}, nil
	}

	// Patch node object status via defer to ensure it's always called.
	// Programmed is derived here as a gateway: True only when all other conditions are True.
	defer func() {
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.ComputeProgrammedCondition(
			nodeObj.Status.Conditions, nil,
			artifact.ReasonProgrammed, artifact.MessageProgrammed, artifact.ReasonProgramFailed,
			config.GetGeneration(),
		))
		var patchErr error
		if !apiequality.Semantic.DeepEqual(*oldStatus, nodeObj.Status) {
			patchErr = controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, nodeObj, fieldManager)
			if patchErr != nil {
				logger.Error(patchErr, "unable to patch ConfigNode status")
			}
		}
		reterr = kerrors.NewAggregate([]error{reterr, patchErr})
	}()

	// Enforce reference resolution before the generation gate below.
	if err := r.enforceReferenceResolution(ctx, config, nodeObj); err != nil {
		return ctrl.Result{}, err
	}

	// Wait until the instance operator has processed the current spec generation before proceeding.
	// Placed after the status-patch defer above, so ArtifactNode status is still patched while waiting.
	if config.Status.ObservedGeneration != config.Generation {
		logger.Info("instance operator has not yet processed current spec generation; deferring",
			"observedGeneration", config.Status.ObservedGeneration,
			"specGeneration", config.Generation)
		return ctrl.Result{}, nil
	} else {
		logger.Info("instance operator has processed current spec generation; proceeding",
			"observedGeneration", config.Status.ObservedGeneration,
			"specGeneration", config.Generation)
	}

	// Ensure the configuration is written to the filesystem.
	if err := r.ensureConfig(ctx, config, nodeObj); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// getParentConfig retrieves the parent Config via the node object's ownerRef, verifying by UID
// that it's still the generation nodeObj was created for (see GetVerifiedOwner's doc).
func (r *ConfigReconciler) getParentConfig(ctx context.Context, nodeObj *artifactv1alpha1.ArtifactNode) (*artifactv1alpha1.Config, error) {
	cfg := &artifactv1alpha1.Config{}
	ok, err := controllerhelper.GetVerifiedOwner(ctx, r.Client, nodeObj, controllerhelper.KindConfig, cfg)
	if err != nil || !ok {
		return nil, err
	}
	return cfg, nil
}

// handleDeletion cleans up local filesystem resources, then removes the finalizer from the ConfigNode.
func (r *ConfigReconciler) handleDeletion(ctx context.Context, nodeObj *artifactv1alpha1.ArtifactNode) (bool, error) {
	if nodeObj.DeletionTimestamp.IsZero() {
		return false, nil
	}
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(nodeObj, configNodeFinalizer) {
		return true, nil
	}

	logger.Info("ConfigNode marked for deletion, cleaning up")

	if err := r.store.Remove(ctx, nodeObj.Status.InstalledArtifacts); err != nil {
		logger.Error(err, "unable to remove installed config artifacts from disk")
		return false, err
	}

	patch := client.MergeFrom(nodeObj.DeepCopy())
	controllerutil.RemoveFinalizer(nodeObj, configNodeFinalizer)
	if err := r.Patch(ctx, nodeObj, patch); err != nil {
		logger.Error(err, "unable to remove finalizer from ConfigNode")
		return false, err
	}
	return true, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	nodeFilter := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		n, ok := obj.(*artifactv1alpha1.ArtifactNode)
		if !ok || n.Spec.NodeName != r.nodeName {
			return false
		}
		for _, ref := range n.GetOwnerReferences() {
			if ref.Controller != nil && *ref.Controller && ref.Kind == controllerhelper.KindConfig {
				return true
			}
		}
		return false
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.ArtifactNode{}, builder.WithPredicates(nodeFilter)).
		Watches(
			&artifactv1alpha1.Config{},
			handler.EnqueueRequestsFromMapFunc(r.findNodeObjectForConfig),
		).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findNodeObjectsForConfigMap),
		).
		Named("artifact-config").
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), "artifact-config", &artifactv1alpha1.ArtifactNode{})).
		Complete(r)
}

// findNodeObjectForConfig maps a Config event to this node's ConfigNode request.
func (r *ConfigReconciler) findNodeObjectForConfig(_ context.Context, obj client.Object) []reconcile.Request {
	name := controllerhelper.NodeObjectName(controllerhelper.ArtifactKindConfig, obj.GetName(), r.nodeName)
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: obj.GetNamespace(), Name: name}},
	}
}

// findNodeObjectsForConfigMap maps a ConfigMap event to ConfigNode requests on this node.
func (r *ConfigReconciler) findNodeObjectsForConfigMap(ctx context.Context, configMap client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	configList := &artifactv1alpha1.ConfigList{}

	indexKey := configMap.GetNamespace() + "/" + configMap.GetName()
	if err := r.List(ctx, configList, client.MatchingFields{index.ConfigMapOnConfig: indexKey}); err != nil {
		logger.Error(err, "unable to list Configs by ConfigMap index")
		return nil
	}

	reqs := make([]reconcile.Request, len(configList.Items))
	for i := range configList.Items {
		name := controllerhelper.NodeObjectName(controllerhelper.ArtifactKindConfig, configList.Items[i].Name, r.nodeName)
		reqs[i] = reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: configList.Items[i].Namespace, Name: name},
		}
	}
	return reqs
}

// enforceReferenceResolution checks that all referenced resources exist.
func (r *ConfigReconciler) enforceReferenceResolution(
	ctx context.Context, config *artifactv1alpha1.Config, nodeObj *artifactv1alpha1.ArtifactNode,
) error {
	logger := log.FromContext(ctx)

	if config.Spec.ConfigMapRef != nil {
		err := r.Get(ctx, client.ObjectKey{Namespace: config.Namespace, Name: config.Spec.ConfigMapRef.Name}, &corev1.ConfigMap{})
		if err != nil {
			logger.Error(err, "ConfigMap reference resolution failed", "configMap", config.Spec.ConfigMapRef.Name)
			artifact.RecordWarning(r.recorder, config, artifact.ReasonReferenceResolutionFailed, artifact.MessageFormatReferenceResolutionFailed, err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewResolvedRefsCondition(
				metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
				fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, config.Spec.ConfigMapRef.Name), config.GetGeneration()))
			return err
		}

		artifact.RecordNormal(r.recorder, config, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved)
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewResolvedRefsCondition(
			metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, config.GetGeneration(),
		))
	} else {
		apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, commonv1alpha1.ConditionResolvedRefs.String())
	}

	return nil
}

// ensureConfig ensures the configuration is written to the filesystem.
// For each source medium (inline, configmap), if the source is no longer in spec
// but a tracked file exists, it is removed first (stale cleanup).
func (r *ConfigReconciler) ensureConfig(ctx context.Context, config *artifactv1alpha1.Config, nodeObj *artifactv1alpha1.ArtifactNode) error {
	gen := config.GetGeneration()
	logger := log.FromContext(ctx)
	p := config.Spec.Priority

	// Stale-entry cleanup: remove files and conditions for mediums no longer in spec.
	if config.Spec.Config == nil {
		apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, commonv1alpha1.ConditionInlineArtifactProgrammed.String())
		if existing := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumInline); existing != nil {
			if err := r.store.Remove(ctx, []artifactv1alpha1.InstalledArtifact{{Path: existing.Path, Medium: string(artifact.MediumInline)}}); err != nil {
				logger.Error(err, "unable to remove stale inline config")
				return err
			}
			artifact.ClearInstalled(&nodeObj.Status.InstalledArtifacts, artifact.MediumInline)
		}
	}
	if config.Spec.ConfigMapRef == nil {
		apimeta.RemoveStatusCondition(&nodeObj.Status.Conditions, commonv1alpha1.ConditionConfigMapArtifactProgrammed.String())
		if existing := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumConfigMap); existing != nil {
			if err := r.store.Remove(ctx, []artifactv1alpha1.InstalledArtifact{{Path: existing.Path, Medium: string(artifact.MediumConfigMap)}}); err != nil {
				logger.Error(err, "unable to remove stale configmap config")
				return err
			}
			artifact.ClearInstalled(&nodeObj.Status.InstalledArtifacts, artifact.MediumConfigMap)
		}
	}

	// Store inline config if specified.
	// spec.config is stored as JSON by the API server; convert to YAML before writing to disk.
	if config.Spec.Config != nil {
		configData, err := common.JSONRawToYAML(config.Spec.Config)
		if err != nil {
			logger.Error(err, "unable to convert inline config to YAML")
			artifact.RecordWarning(r.recorder, config, artifact.ReasonInlineConfigStoreFailed, artifact.MessageFormatConfigStoreFailed, err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewInlineArtifactProgrammedCondition(
				metav1.ConditionFalse, artifact.ReasonInlineArtifactProgramFailed,
				fmt.Sprintf(artifact.MessageFormatConfigStoreFailed, err.Error()), gen,
			))
			return err
		}
		if configData != nil {
			result, err := r.fetcher.FetchInline(ctx, []byte(*configData))
			if err != nil {
				logger.Error(err, "unable to prepare inline config content")
				artifact.RecordWarning(r.recorder, config, artifact.ReasonInlineConfigStoreFailed, artifact.MessageFormatConfigStoreFailed, err.Error())
				apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewInlineArtifactProgrammedCondition(
					metav1.ConditionFalse, artifact.ReasonInlineArtifactProgramFailed,
					fmt.Sprintf(artifact.MessageFormatConfigStoreFailed, err.Error()), gen,
				))
				return err
			}
			current := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumInline)
			inlineAction, newFile, err := r.store.Store(ctx, current, config.Name, p, artifact.TypeConfig, artifact.MediumInline, result)
			if err != nil {
				logger.Error(err, "unable to store inline config")
				artifact.RecordWarning(r.recorder, config, artifact.ReasonInlineConfigStoreFailed, artifact.MessageFormatConfigStoreFailed, err.Error())
				apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewInlineArtifactProgrammedCondition(
					metav1.ConditionFalse, artifact.ReasonInlineArtifactProgramFailed,
					fmt.Sprintf(artifact.MessageFormatConfigStoreFailed, err.Error()), gen,
				))
				return err
			}
			artifact.UpdateInstalledStatus(&nodeObj.Status.InstalledArtifacts, inlineAction, artifact.MediumInline, newFile)
			artifact.RecordStoreEvent(r.recorder, config, inlineAction, artifact.MediumInline)
		}
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewInlineArtifactProgrammedCondition(
			metav1.ConditionTrue, artifact.ReasonInlineArtifactProgrammed, artifact.MessageInlineArtifactProgrammed, gen,
		))
	}

	// Store ConfigMap config if specified.
	if config.Spec.ConfigMapRef != nil {
		result, err := r.fetcher.FetchConfigMap(ctx, config.Namespace, config.Spec.ConfigMapRef, artifact.TypeConfig)
		if err != nil {
			logger.Error(err, "unable to fetch config from ConfigMap reference")
			artifact.RecordWarning(r.recorder, config,
				artifact.ReasonConfigMapConfigStoreFailed, artifact.MessageFormatConfigMapConfigStoreFailed, err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigMapArtifactProgrammedCondition(
				metav1.ConditionFalse, artifact.ReasonConfigMapArtifactProgramFailed,
				fmt.Sprintf(artifact.MessageFormatConfigMapConfigStoreFailed, err.Error()), gen,
			))
			return err
		}
		current := artifact.FindInstalled(nodeObj.Status.InstalledArtifacts, artifact.MediumConfigMap)
		cmAction, newFile, err := r.store.Store(ctx, current, config.Name, p, artifact.TypeConfig, artifact.MediumConfigMap, result)
		if err != nil {
			logger.Error(err, "unable to store config from ConfigMap reference")
			artifact.RecordWarning(r.recorder, config,
				artifact.ReasonConfigMapConfigStoreFailed, artifact.MessageFormatConfigMapConfigStoreFailed, err.Error())
			apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigMapArtifactProgrammedCondition(
				metav1.ConditionFalse, artifact.ReasonConfigMapArtifactProgramFailed,
				fmt.Sprintf(artifact.MessageFormatConfigMapConfigStoreFailed, err.Error()), gen,
			))
			return err
		}
		artifact.UpdateInstalledStatus(&nodeObj.Status.InstalledArtifacts, cmAction, artifact.MediumConfigMap, newFile)
		artifact.RecordStoreEvent(r.recorder, config, cmAction, artifact.MediumConfigMap)
		apimeta.SetStatusCondition(&nodeObj.Status.Conditions, common.NewConfigMapArtifactProgrammedCondition(
			metav1.ConditionTrue, artifact.ReasonConfigMapArtifactProgrammed, artifact.MessageConfigMapArtifactProgrammed, gen,
		))
	}

	return nil
}
