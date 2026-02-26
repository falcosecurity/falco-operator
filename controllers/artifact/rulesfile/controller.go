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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
)

const (
	// rulesfileFinalizerPrefix is the prefix for the finalizer name.
	rulesfileFinalizerPrefix = "rulesfile.artifact.falcosecurity.dev/finalizer"
	// configMapRefIndexField is the field used for indexing Rulesfiles by ConfigMap reference.
	configMapRefIndexField = ".spec.configMapRef.name"
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

	if err := r.Get(ctx, req.NamespacedName, rulesfile); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch Rulesfile")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	} else if apierrors.IsNotFound(err) {
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

	// Snapshot status before any condition modifications.
	statusPatch := client.MergeFrom(rulesfile.DeepCopy())

	// Patch status via defer to ensure it's always called.
	defer func() {
		patchErr := r.patchStatus(ctx, rulesfile, statusPatch)
		if patchErr != nil {
			logger.Error(patchErr, "unable to patch status")
		}
		reterr = kerrors.NewAggregate([]error{reterr, patchErr})
	}()

	// Ensure the rulesfile.
	if err := r.ensureRulesfile(ctx, rulesfile); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RulesfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Create an index for Rulesfiles by ConfigMap reference for efficient lookups.
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&artifactv1alpha1.Rulesfile{},
		configMapRefIndexField,
		indexRulesfileByConfigMapRef,
	); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Rulesfile{}).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findRulesfilesForConfigMap),
		).
		Named("artifact-rulesfile").
		Complete(r)
}

func indexRulesfileByConfigMapRef(obj client.Object) []string {
	rulesfile := obj.(*artifactv1alpha1.Rulesfile)
	if rulesfile.Spec.ConfigMapRef == nil {
		return nil
	}
	return []string{rulesfile.Namespace + "/" + rulesfile.Spec.ConfigMapRef.Name}
}

// findRulesfilesForConfigMap finds all Rulesfiles that reference a given ConfigMap using the index.
func (r *RulesfileReconciler) findRulesfilesForConfigMap(ctx context.Context, configMap client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	rulesfileList := &artifactv1alpha1.RulesfileList{}

	// Use the index to find Rulesfiles that reference this ConfigMap
	indexKey := configMap.GetNamespace() + "/" + configMap.GetName()
	if err := r.List(ctx, rulesfileList, client.MatchingFields{configMapRefIndexField: indexKey}); err != nil {
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
			if apierrors.IsConflict(err) {
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

	// Remove conditions for source types no longer present in the spec.
	if rulesfile.Spec.OCIArtifact == nil {
		apimeta.RemoveStatusCondition(&rulesfile.Status.Conditions, commonv1alpha1.ConditionOCIArtifact.String())
	}
	if rulesfile.Spec.InlineRules == nil {
		apimeta.RemoveStatusCondition(&rulesfile.Status.Conditions, commonv1alpha1.ConditionInlineContent.String())
	}
	if rulesfile.Spec.ConfigMapRef == nil {
		apimeta.RemoveStatusCondition(&rulesfile.Status.Conditions, commonv1alpha1.ConditionConfigMapRef.String())
	}

	// Ensure Reconciled condition is stored even on early return.
	defer func() {
		if err != nil {
			apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewReconciledCondition(
				metav1.ConditionFalse, artifact.ReasonReconcileFailed, err.Error(), gen,
			))
		} else {
			r.recorder.Eventf(rulesfile, nil, corev1.EventTypeNormal, artifact.ReasonReconciled,
				artifact.ReasonReconciled, artifact.MessageRulesfileReconciled)
			apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewReconciledCondition(
				metav1.ConditionTrue, artifact.ReasonReconciled, artifact.MessageRulesfileReconciled, gen,
			))
		}
	}()

	// Store OCI artifact if specified.
	if rulesfile.Spec.OCIArtifact != nil {
		if err = r.artifactManager.StoreFromOCI(ctx, rulesfile.Name, p, artifact.TypeRulesfile, rulesfile.Spec.OCIArtifact); err != nil {
			logger.Error(err, "unable to store Rulesfile OCI artifact")
			r.recorder.Eventf(rulesfile, nil, corev1.EventTypeWarning, artifact.ReasonOCIArtifactStoreFailed,
				artifact.ReasonOCIArtifactStoreFailed, artifact.MessageFormatOCIArtifactStoreFailed, err.Error())
			apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewOCIArtifactCondition(
				metav1.ConditionFalse, artifact.ReasonOCIArtifactStoreFailed,
				fmt.Sprintf(artifact.MessageFormatOCIArtifactStoreFailed, err.Error()), gen,
			))
			return err
		}
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeNormal, artifact.ReasonOCIArtifactStored,
			artifact.ReasonOCIArtifactStored, artifact.MessageOCIArtifactStored)
		apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewOCIArtifactCondition(
			metav1.ConditionTrue, artifact.ReasonOCIArtifactStored, artifact.MessageOCIArtifactStored, gen,
		))
	}

	// Store inline rules if specified.
	if rulesfile.Spec.InlineRules != nil {
		if err = r.artifactManager.StoreFromInLineYaml(ctx, rulesfile.Name, p, rulesfile.Spec.InlineRules, artifact.TypeRulesfile); err != nil {
			logger.Error(err, "unable to store Rulesfile inline rules")
			r.recorder.Eventf(rulesfile, nil, corev1.EventTypeWarning, artifact.ReasonInlineRulesStoreFailed,
				artifact.ReasonInlineRulesStoreFailed, artifact.MessageFormatInlineRulesStoreFailed, err.Error())
			apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewInlineContentCondition(
				metav1.ConditionFalse, artifact.ReasonInlineRulesStoreFailed,
				fmt.Sprintf(artifact.MessageFormatInlineRulesStoreFailed, err.Error()), gen,
			))
			return err
		}
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeNormal, artifact.ReasonInlineRulesStored,
			artifact.ReasonInlineRulesStored, artifact.MessageInlineRulesStored)
		apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewInlineContentCondition(
			metav1.ConditionTrue, artifact.ReasonInlineRulesStored, artifact.MessageInlineRulesStored, gen,
		))
	}

	// Store ConfigMap rules if specified.
	if rulesfile.Spec.ConfigMapRef != nil {
		err = r.artifactManager.StoreFromConfigMap(
			ctx, rulesfile.Name, rulesfile.Namespace, p, rulesfile.Spec.ConfigMapRef, artifact.TypeRulesfile,
		)
		if err != nil {
			logger.Error(err, "unable to store Rulesfile from ConfigMap reference")
			r.recorder.Eventf(rulesfile, nil, corev1.EventTypeWarning, artifact.ReasonConfigMapResolutionFailed,
				artifact.ReasonConfigMapResolutionFailed, artifact.MessageFormatConfigMapResolutionFailed, err.Error())
			apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewConfigMapRefCondition(
				metav1.ConditionFalse, artifact.ReasonConfigMapResolutionFailed,
				fmt.Sprintf(artifact.MessageFormatConfigMapResolutionFailed, err.Error()), gen,
			))
			return err
		}
		r.recorder.Eventf(rulesfile, nil, corev1.EventTypeNormal, artifact.ReasonConfigMapResolved,
			artifact.ReasonConfigMapResolved, artifact.MessageFormatConfigMapResolved, rulesfile.Spec.ConfigMapRef.Name)
		apimeta.SetStatusCondition(&rulesfile.Status.Conditions, common.NewConfigMapRefCondition(
			metav1.ConditionTrue, artifact.ReasonConfigMapResolved,
			fmt.Sprintf(artifact.MessageFormatConfigMapResolved, rulesfile.Spec.ConfigMapRef.Name), gen,
		))
	}

	return nil
}

// patchStatus patches the Rulesfile status using the given pre-modification snapshot.
func (r *RulesfileReconciler) patchStatus(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, patch client.Patch) error {
	logger := log.FromContext(ctx)
	if err := r.Status().Patch(ctx, rulesfile, patch); err != nil {
		if apierrors.IsConflict(err) {
			logger.V(3).Info("Conflict while patching status, will retry")
			return err
		}
		logger.Error(err, "unable to patch status")
		return err
	}
	return nil
}
