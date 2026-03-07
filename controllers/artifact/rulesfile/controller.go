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

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

const (
	// rulesfileFinalizerPrefix is the prefix for the finalizer name.
	rulesfileFinalizerPrefix = "rulesfile.artifact.falcosecurity.dev/finalizer"
	// fieldManager is the name used to identify the controller's managed fields.
	fieldManager = "artifact-rulesfile"
)

// NewRulesfileReconciler returns a new RulesfileReconciler.
func NewRulesfileReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	nodeName, namespace string,
) *RulesfileReconciler {
	return &RulesfileReconciler{
		Client:          cl,
		Scheme:          scheme,
		recorder:        recorder,
		finalizer:       common.FormatFinalizerName(rulesfileFinalizerPrefix, nodeName),
		artifactManager: artifact.NewManager(cl, namespace),
		nodeName:        nodeName,
		namespace:       namespace,
	}
}

// RulesfileReconciler reconciles a Rulesfile object.
type RulesfileReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	recorder        events.EventRecorder
	finalizer       string
	artifactManager *artifact.Manager
	nodeName        string
	namespace       string
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *RulesfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := log.FromContext(ctx)
	rulesfile := &artifactv1alpha1.Rulesfile{}

	// Fetch the Rulesfile instance.
	logger.V(2).Info("Fetching Rulesfile instance")

	if err := r.Get(ctx, req.NamespacedName, rulesfile); err != nil && !k8serrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch Rulesfile")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	} else if k8serrors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the Rulesfile instance is for the current node.
	if ok, err := controllerhelper.NodeMatchesSelector(ctx, r.Client, r.nodeName, rulesfile.Spec.Selector); err != nil {
		return ctrl.Result{}, err
	} else if !ok {
		logger.Info("Rulesfile instance does not match node selector, will remove local resources if any")

		// Handle case where rulesfile selector no longer matches the node.
		if ok, err := controllerhelper.RemoveLocalResources(ctx, r.Client, r.artifactManager, r.finalizer, rulesfile); ok || err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Handle deletion.
	if ok, err := controllerhelper.HandleObjectDeletion(ctx, r.Client, r.artifactManager, r.finalizer, rulesfile); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the finalizer is set.
	if ok, err := r.ensureFinalizer(ctx, rulesfile); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Patch status via defer to ensure it's always called.
	defer func() {
		patchErr := r.patchStatus(ctx, rulesfile)
		if patchErr != nil {
			logger.Error(patchErr, "unable to patch status")
		}
		reterr = kerrors.NewAggregate([]error{reterr, patchErr})
	}()

	// Enforce reference resolution.
	if err := r.enforceReferenceResolution(ctx, rulesfile); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the rulesfile.
	if err := r.ensureRulesfile(ctx, rulesfile); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RulesfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Rulesfile{}).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findRulesfilesForConfigMap),
		).
		Named("artifact-rulesfile").
		Complete(r)
}

// findRulesfilesForConfigMap finds all Rulesfiles that reference a given ConfigMap using the index.
func (r *RulesfileReconciler) findRulesfilesForConfigMap(ctx context.Context, configMap client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	rulesfileList := &artifactv1alpha1.RulesfileList{}

	indexKey := configMap.GetNamespace() + "/" + configMap.GetName()
	if err := r.List(ctx, rulesfileList, client.MatchingFields{index.ConfigMapOnRulesfile: indexKey}); err != nil {
		logger.Error(err, "unable to list Rulesfiles by ConfigMap index")
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, len(rulesfileList.Items))
	for i := range rulesfileList.Items {
		requests[i] = reconcile.Request{
			NamespacedName: client.ObjectKey{
				Name:      rulesfileList.Items[i].Name,
				Namespace: rulesfileList.Items[i].Namespace,
			},
		}
	}

	return requests
}

// ensureFinalizer ensures the finalizer is set.
func (r *RulesfileReconciler) ensureFinalizer(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) (bool, error) {
	if !controllerutil.ContainsFinalizer(rulesfile, r.finalizer) {
		logger := log.FromContext(ctx)
		logger.V(3).Info("Setting finalizer", "finalizer", r.finalizer)

		patch := client.MergeFrom(rulesfile.DeepCopy())
		controllerutil.AddFinalizer(rulesfile, r.finalizer)
		if err := r.Patch(ctx, rulesfile, patch); err != nil {
			if k8serrors.IsConflict(err) {
				logger.V(3).Info("Conflict while setting finalizer, will retry")
				return false, err
			}
			logger.Error(err, "unable to set finalizer", "finalizer", r.finalizer)
			return false, err
		}

		logger.V(3).Info("Finalizer set", "finalizer", r.finalizer)
		return true, nil
	}

	return false, nil
}

// ensureRulesfile ensures the rulesfile artifacts are stored on the filesystem.
func (r *RulesfileReconciler) ensureRulesfile(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	gen := rulesfile.GetGeneration()
	var err error
	logger := log.FromContext(ctx)
	p := rulesfile.Spec.Priority

	// Clean up conditions before ensuring the rulesfile.
	apimeta.RemoveStatusCondition(&rulesfile.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())

	// Store OCI artifact if specified; passing nil removes any previously stored OCI artifact.
	if err = r.artifactManager.StoreFromOCI(ctx, rulesfile.Name, p, artifact.TypeRulesfile, rulesfile.Spec.OCIArtifact); err != nil {
		logger.Error(err, "unable to store Rulesfile OCI artifact")
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeWarning, artifact.ReasonOCIArtifactStoreFailed,
			artifact.ReasonOCIArtifactStoreFailed, artifact.MessageFormatOCIArtifactStoreFailed, err.Error())
		apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonOCIArtifactStoreFailed,
			fmt.Sprintf(artifact.MessageFormatOCIArtifactStoreFailed, err.Error()), gen,
		))
		return err
	}
	if rulesfile.Spec.OCIArtifact != nil {
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeNormal, artifact.ReasonOCIArtifactStored,
			artifact.ReasonOCIArtifactStored, artifact.MessageOCIArtifactStored)
	}

	// Store inline rules if specified.
	// spec.inlineRules is stored as JSON by the API server; convert to YAML before writing to disk.
	var inlineRulesData *string
	inlineRulesData, err = common.JSONRawToYAML(rulesfile.Spec.InlineRules)
	if err != nil {
		return fmt.Errorf("converting inline rules to YAML: %w", err)
	}

	if err = r.artifactManager.StoreFromInLineYaml(ctx, rulesfile.Name, p, inlineRulesData, artifact.TypeRulesfile); err != nil {
		logger.Error(err, "unable to store Rulesfile inline rules")
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeWarning, artifact.ReasonInlineRulesStoreFailed,
			artifact.ReasonInlineRulesStoreFailed, artifact.MessageFormatInlineRulesStoreFailed, err.Error())
		apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonInlineRulesStoreFailed,
			fmt.Sprintf(artifact.MessageFormatInlineRulesStoreFailed, err.Error()), gen,
		))
		return err
	}

	if inlineRulesData != nil {
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeNormal, artifact.ReasonInlineRulesStored,
			artifact.ReasonInlineRulesStored, artifact.MessageInlineRulesStored)
	}

	// Store or remove ConfigMap rules. Passing nil cleans up a previously stored file.
	if err = r.artifactManager.StoreFromConfigMap(
		ctx, rulesfile.Name, rulesfile.Namespace, p, rulesfile.Spec.ConfigMapRef, artifact.TypeRulesfile,
	); err != nil {
		logger.Error(err, "unable to store Rulesfile from ConfigMap reference")
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeWarning, artifact.ReasonConfigMapRulesStoreFailed,
			artifact.ReasonConfigMapRulesStoreFailed, artifact.MessageFormatConfigMapRulesStoreFailed, err.Error())
		apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonConfigMapRulesStoreFailed,
			fmt.Sprintf(artifact.MessageFormatConfigMapRulesStoreFailed, err.Error()), gen,
		))
		return err
	}
	if rulesfile.Spec.ConfigMapRef != nil {
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeNormal, artifact.ReasonConfigMapRulesStored,
			artifact.ReasonConfigMapRulesStored, artifact.MessageConfigMapRulesStored)
	}

	apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewProgrammedCondition(
		metav1.ConditionTrue, artifact.ReasonProgrammed, artifact.MessageProgrammed, gen,
	))

	return nil
}

func (r *RulesfileReconciler) enforceReferenceResolution(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	logger := log.FromContext(ctx)
	hasRefs := false

	if rulesfile.Spec.ConfigMapRef != nil {
		hasRefs = true
		err := r.artifactManager.CheckReferenceResolution(ctx, rulesfile.Namespace, rulesfile.Spec.ConfigMapRef.Name, &corev1.ConfigMap{})
		if err != nil {
			logger.Error(err, "ConfigMap reference resolution failed", "configMap", rulesfile.Spec.ConfigMapRef.Name)
			r.recorder.Eventf(rulesfile, nil, corev1.EventTypeWarning, artifact.ReasonReferenceResolutionFailed,
				artifact.ReasonReferenceResolutionFailed, artifact.MessageFormatReferenceResolutionFailed, err.Error())
			apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewResolvedRefsCondition(
				metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
				fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, rulesfile.Spec.ConfigMapRef.Name), rulesfile.GetGeneration()))
			apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewProgrammedCondition(
				metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
				fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, rulesfile.Spec.ConfigMapRef.Name), rulesfile.GetGeneration(),
			))
			return err
		}
	}

	if ociArt := rulesfile.Spec.OCIArtifact; ociArt != nil && ociArt.Registry != nil {
		reg := ociArt.Registry

		if reg.Auth != nil && reg.Auth.SecretRef != nil {
			hasRefs = true
			secretName := reg.Auth.SecretRef.Name
			err := r.artifactManager.CheckReferenceResolution(ctx, rulesfile.Namespace, secretName, &corev1.Secret{})
			if err != nil {
				logger.Error(err, "OCIArtifact auth secret reference resolution failed", "secret", secretName)
				r.recorder.Eventf(rulesfile, nil, corev1.EventTypeWarning, artifact.ReasonReferenceResolutionFailed,
					artifact.ReasonReferenceResolutionFailed, artifact.MessageFormatReferenceResolutionFailed, err.Error())
				apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewResolvedRefsCondition(
					metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
					fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, secretName), rulesfile.GetGeneration()))
				apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewProgrammedCondition(
					metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
					fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, secretName), rulesfile.GetGeneration(),
				))
				return err
			}
		}
	}

	if hasRefs {
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeNormal, artifact.ReasonReferenceResolved,
			artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved)
		apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewResolvedRefsCondition(
			metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, rulesfile.GetGeneration(),
		))
	} else {
		apimeta.RemoveStatusCondition(&rulesfile.Status.Conditions, commonv1alpha1.ConditionResolvedRefs.String())
	}

	return nil
}

// patchStatus patches the Rulesfile status using server-side apply.
func (r *RulesfileReconciler) patchStatus(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	return controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, rulesfile, fieldManager)
}
