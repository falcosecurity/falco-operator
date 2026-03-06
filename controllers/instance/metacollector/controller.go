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

package metacollector

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

const (
	containerName = "metacollector"
	finalizer     = "metacollector.falcosecurity.dev/finalizer"
	fieldManager  = "metacollector-controller"
)

// clusterScopedGVKs are the GVKs of cluster-scoped resources managed by the Metacollector controller.
var clusterScopedGVKs = []schema.GroupVersionKind{
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"},
}

// Reconciler reconciles a Metacollector object.
type Reconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	recorder events.EventRecorder
}

// NewReconciler creates a new Reconciler.
func NewReconciler(cl client.Client, scheme *runtime.Scheme, recorder events.EventRecorder) *Reconciler {
	return &Reconciler{
		Client:   cl,
		Scheme:   scheme,
		recorder: recorder,
	}
}

// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=metacollectors;metacollectors/status,verbs=create;delete;get;list;patch;update;watch

// Reconcile is part of the main kubernetes reconciliation loop.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := log.FromContext(ctx)
	mc := &instancev1alpha1.Metacollector{}

	logger.V(2).Info("Fetching metacollector instance")

	if err := r.Get(ctx, req.NamespacedName, mc); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch metacollector instance")
		return ctrl.Result{}, err
	} else if apierrors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion.
	if ok, err := r.handleDeletion(ctx, mc); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Patch status via defer to ensure it's always called.
	defer func() {
		computeErr := r.computeAvailableCondition(ctx, mc)
		if computeErr != nil {
			logger.Error(computeErr, "unable to compute available condition")
		}
		patchErr := r.patchStatus(ctx, mc)
		if patchErr != nil {
			logger.Error(patchErr, "unable to patch Metacollector status")
		}
		reterr = kerrors.NewAggregate([]error{reterr, computeErr, patchErr})
	}()

	// Ensure the service account is created.
	if err := r.ensureServiceAccount(ctx, mc); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the clusterrole is created.
	if err := r.ensureClusterRole(ctx, mc); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the clusterrolebinding is created.
	if err := r.ensureClusterRoleBinding(ctx, mc); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the service is created.
	if err := r.ensureService(ctx, mc); err != nil {
		return ctrl.Result{}, err
	}

	// Set the finalizer if needed.
	if ok, err := r.ensureFinalizer(ctx, mc); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the Metacollector version is set.
	if ok, err := r.ensureVersion(ctx, mc); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the deployment is created.
	if err := r.ensureDeployment(ctx, mc); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&instancev1alpha1.Metacollector{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.Service{}).
		Watches(&rbacv1.ClusterRole{}, handler.EnqueueRequestsFromMapFunc(instance.ClusterScopedResourceHandler)).
		Watches(&rbacv1.ClusterRoleBinding{}, handler.EnqueueRequestsFromMapFunc(instance.ClusterScopedResourceHandler)).
		Named(containerName).
		Complete(r)
}

// ensureFinalizer ensures the finalizer is set on the object and returns true if the object was updated.
func (r *Reconciler) ensureFinalizer(ctx context.Context, mc *instancev1alpha1.Metacollector) (bool, error) {
	return instance.EnsureFinalizer(ctx, r.Client, mc, finalizer)
}

// ensureVersion ensures the Metacollector version is set on the object and returns true if the object was updated.
func (r *Reconciler) ensureVersion(ctx context.Context, mc *instancev1alpha1.Metacollector) (bool, error) {
	version := instance.ResolveVersion(mc.Spec.Version, mc.Spec.PodTemplateSpec, containerName, image.VersionFromTag(image.MetacollectorTag))

	if version != mc.Spec.Version {
		log.FromContext(ctx).V(3).Info("Setting Metacollector version", "version", version)

		patch := client.MergeFrom(mc.DeepCopy())
		mc.Spec.Version = version
		if err := r.Patch(ctx, mc, patch); err != nil {
			log.FromContext(ctx).Error(err, "unable to set Metacollector version", "version", version)
			return false, err
		}
		return true, nil
	}

	return false, nil
}

// handleDeletion handles the deletion of the Metacollector instance.
func (r *Reconciler) handleDeletion(ctx context.Context, mc *instancev1alpha1.Metacollector) (bool, error) {
	return instance.HandleDeletion(ctx, r.Client, r.recorder, mc, finalizer, clusterScopedGVKs, instance.MessageMetacollectorInstanceDeleted)
}

// ensureDeployment ensures the Metacollector Deployment is created or updated.
func (r *Reconciler) ensureDeployment(ctx context.Context, mc *instancev1alpha1.Metacollector) error {
	logger := log.FromContext(ctx)

	conditionStatus := metav1.ConditionTrue
	conditionReason := ""
	conditionMessage := ""

	defer func() {
		apimeta.SetStatusCondition(&mc.Status.Conditions, common.NewReconciledCondition(
			conditionStatus,
			conditionReason,
			conditionMessage,
			mc.GetGeneration(),
		))
	}()

	logger.V(2).Info("Generating apply configuration from user input")
	applyConfig, err := generateApplyConfiguration(r.Client, mc)
	if err != nil {
		logger.Error(err, "unable to generate apply configuration")
		conditionStatus = metav1.ConditionFalse
		conditionReason = instance.ReasonApplyConfigurationError
		conditionMessage = fmt.Sprintf(instance.MessageFormatApplyConfigurationError, err.Error())
		return err
	}

	applyConfigYaml, err := yaml.Marshal(applyConfig.Object)
	if err != nil {
		logger.Error(err, "unable to marshal apply configuration")
		conditionStatus = metav1.ConditionFalse
		conditionReason = instance.ReasonMarshalConfigurationError
		conditionMessage = fmt.Sprintf(instance.MessageFormatMarshalConfigurationError, err.Error())
		return err
	}

	logger.V(4).Info("Generated apply configuration", "yaml", string(applyConfigYaml))

	if err = ctrl.SetControllerReference(mc, applyConfig, r.Scheme); err != nil {
		logger.Error(err, "unable to set owner reference")
		conditionStatus = metav1.ConditionFalse
		conditionReason = instance.ReasonOwnerReferenceError
		conditionMessage = fmt.Sprintf(instance.MessageFormatOwnerReferenceError, err.Error())
		return err
	}

	existingResource := &unstructured.Unstructured{}
	existingResource.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   appsv1.GroupName,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    instance.ResourceTypeDeployment,
	})
	resourceExists := true
	if err = r.Get(ctx, client.ObjectKeyFromObject(mc), existingResource); err != nil {
		if apierrors.IsNotFound(err) {
			resourceExists = false
		} else {
			logger.Error(err, "unable to fetch existing resource")
			conditionStatus = metav1.ConditionFalse
			conditionReason = instance.ReasonExistingResourceError
			conditionMessage = fmt.Sprintf(instance.MessageFormatExistingResourceError, err.Error())
			return err
		}
	}

	var changedFields string
	if resourceExists {
		comparison, err := instance.Diff(existingResource, applyConfig, fieldManager)
		if err != nil {
			if !errors.Is(err, instance.ErrNoManagedFields) {
				logger.Error(err, "unable to compare existing resource with desired state")
				conditionStatus = metav1.ConditionFalse
				conditionReason = instance.ReasonResourceComparisonError
				conditionMessage = fmt.Sprintf(instance.MessageFormatResourceComparisonError, err.Error())
				return err
			}
			logger.V(2).Info("No managed fields found, proceeding with apply to take ownership")
		} else {
			if comparison.IsSame() {
				logger.V(2).Info("Metacollector resource is up to date, skipping apply")
				conditionReason = instance.ReasonResourceUpToDate
				conditionMessage = instance.MessageResourceUpToDate
				return nil
			}
			changedFields = instance.FormatChangedFields(comparison)
		}
	}

	if !resourceExists {
		logger.Info("Creating Metacollector resource")
	}

	applyOpts := []client.ApplyOption{client.ForceOwnership, client.FieldOwner(fieldManager)}
	if err = r.Apply(ctx, client.ApplyConfigurationFromUnstructured(applyConfig), applyOpts...); err != nil {
		logger.Error(err, "unable to apply resource")
		if !resourceExists {
			conditionStatus = metav1.ConditionFalse
			conditionReason = instance.ReasonApplyPatchErrorOnCreate
			conditionMessage = fmt.Sprintf(instance.MessageFormatApplyPatchErrorOnCreate, err.Error())
			r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, instance.ReasonApplyPatchErrorOnCreate,
				instance.ReasonApplyPatchErrorOnCreate, instance.MessageFormatApplyPatchErrorOnCreate, err.Error())
		} else {
			conditionStatus = metav1.ConditionFalse
			conditionReason = instance.ReasonApplyPatchErrorOnUpdate
			conditionMessage = fmt.Sprintf(instance.MessageFormatApplyPatchErrorOnUpdate, err.Error())
			r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, instance.ReasonApplyPatchErrorOnUpdate,
				instance.ReasonApplyPatchErrorOnUpdate, instance.MessageFormatApplyPatchErrorOnUpdate, err.Error())
		}
		return err
	}

	if !resourceExists {
		logger.Info("Metacollector resource created")
		conditionReason = instance.ReasonResourceCreated
		conditionMessage = instance.MessageResourceCreated
		r.recorder.Eventf(mc, nil, corev1.EventTypeNormal, instance.ReasonResourceCreated,
			instance.ReasonResourceCreated, instance.MessageResourceCreated)
	} else {
		logger.Info("Metacollector resource updated", "changedFields", changedFields)
		conditionReason = instance.ReasonResourceUpdated
		conditionMessage = instance.MessageResourceUpdated
		r.recorder.Eventf(mc, nil, corev1.EventTypeNormal, instance.ReasonResourceUpdated,
			instance.ReasonResourceUpdated, instance.MessageResourceUpdated)
	}

	return nil
}

// patchStatus patches the Metacollector status using server-side apply.
func (r *Reconciler) patchStatus(ctx context.Context, mc *instancev1alpha1.Metacollector) error {
	return controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, mc, fieldManager)
}

// computeAvailableCondition queries the live Deployment state.
func (r *Reconciler) computeAvailableCondition(ctx context.Context, mc *instancev1alpha1.Metacollector) error {
	conditionStatus := metav1.ConditionUnknown
	conditionReason := ""
	conditionMessage := ""

	defer func() {
		apimeta.SetStatusCondition(&mc.Status.Conditions, common.NewAvailableCondition(
			conditionStatus, conditionReason, conditionMessage,
			mc.GetGeneration(),
		))
	}()

	desiredReplicas := int32(1)
	if mc.Spec.Replicas != nil {
		desiredReplicas = *mc.Spec.Replicas
	}
	mc.Status.DesiredReplicas = desiredReplicas

	deployment := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(mc), deployment); err != nil {
		if apierrors.IsNotFound(err) {
			conditionStatus = metav1.ConditionFalse
			conditionReason = instance.ReasonDeploymentNotFound
			conditionMessage = instance.MessageDeploymentNotFound
			return nil
		}
		conditionStatus = metav1.ConditionUnknown
		conditionReason = instance.ReasonDeploymentFetchError
		conditionMessage = fmt.Sprintf(instance.MessageFormatDeploymentFetchError, err.Error())
		log.FromContext(ctx).Error(err, "unable to fetch deployment for status")
		return fmt.Errorf("unable to fetch deployment: %w", err)
	}

	mc.Status.AvailableReplicas = deployment.Status.AvailableReplicas
	mc.Status.UnavailableReplicas = deployment.Status.UnavailableReplicas

	if desiredReplicas == deployment.Status.ReadyReplicas {
		conditionStatus = metav1.ConditionTrue
		conditionReason = instance.ReasonDeploymentAvailable
		conditionMessage = instance.MessageDeploymentAvailable
	} else {
		conditionStatus = metav1.ConditionFalse
		conditionReason = instance.ReasonDeploymentUnavailable
		conditionMessage = instance.MessageDeploymentUnavailable
		r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, instance.ReasonDeploymentUnavailable,
			instance.ReasonDeploymentUnavailable, instance.MessageDeploymentUnavailable)
	}

	return nil
}
