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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

const (
	finalizer = "metacollector.falcosecurity.dev/finalizer"
)

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
		Watches(&rbacv1.ClusterRole{}, handler.EnqueueRequestsFromMapFunc(clusterScopedResourceHandler)).
		Watches(&rbacv1.ClusterRoleBinding{}, handler.EnqueueRequestsFromMapFunc(clusterScopedResourceHandler)).
		Named("metacollector").
		Complete(r)
}

// ensureFinalizer ensures the finalizer is set on the object and returns true if the object was updated.
func (r *Reconciler) ensureFinalizer(ctx context.Context, mc *instancev1alpha1.Metacollector) (bool, error) {
	if !controllerutil.ContainsFinalizer(mc, finalizer) {
		log.FromContext(ctx).V(3).Info("Setting finalizer", "finalizer", finalizer)

		patch := client.MergeFrom(mc.DeepCopy())
		controllerutil.AddFinalizer(mc, finalizer)
		if err := r.Patch(ctx, mc, patch); err != nil {
			log.FromContext(ctx).Error(err, "unable to set finalizer", "finalizer", finalizer)
			return false, err
		}
		log.FromContext(ctx).V(3).Info("Finalizer set", "finalizer", finalizer)
		return true, nil
	}
	return false, nil
}

// handleDeletion handles the deletion of the Metacollector instance.
func (r *Reconciler) handleDeletion(ctx context.Context, mc *instancev1alpha1.Metacollector) (bool, error) {
	if mc.DeletionTimestamp == nil {
		return false, nil
	}

	if !controllerutil.ContainsFinalizer(mc, finalizer) {
		return true, nil
	}

	log.FromContext(ctx).Info("Metacollector instance marked for deletion, removing finalizer", "finalizer", finalizer)

	resourceName := GenerateUniqueName(mc.Name, mc.Namespace)

	crb := &unstructured.Unstructured{}
	crb.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "ClusterRoleBinding",
	})
	crb.SetName(resourceName)
	if err := r.Delete(ctx, crb); err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "unable to delete clusterrolebinding")
		r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, ReasonDeletionError,
			ReasonDeletionError, MessageFormatDeletionError, "ClusterRoleBinding", err.Error())
		return false, err
	}

	cr := &unstructured.Unstructured{}
	cr.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "ClusterRole",
	})
	cr.SetName(resourceName)
	if err := r.Delete(ctx, cr); err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "unable to delete clusterrole")
		r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, ReasonDeletionError,
			ReasonDeletionError, MessageFormatDeletionError, "ClusterRole", err.Error())
		return false, err
	}

	patch := client.MergeFrom(mc.DeepCopy())
	controllerutil.RemoveFinalizer(mc, finalizer)
	if err := r.Patch(ctx, mc, patch); err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "unable to remove finalizer from Metacollector instance")
		r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, ReasonDeletionError,
			ReasonDeletionError, MessageFormatDeletionError, "Finalizer", err.Error())
		return false, err
	}

	log.FromContext(ctx).Info("Metacollector instance deleted")
	r.recorder.Eventf(mc, nil, corev1.EventTypeNormal, ReasonInstanceDeleted,
		ReasonInstanceDeleted, MessageInstanceDeleted)

	return true, nil
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
		conditionReason = ReasonApplyConfigurationError
		conditionMessage = fmt.Sprintf(MessageFormatApplyConfigurationError, err.Error())
		return err
	}

	applyConfigYaml, err := yaml.Marshal(applyConfig.Object)
	if err != nil {
		logger.Error(err, "unable to marshal apply configuration")
		conditionStatus = metav1.ConditionFalse
		conditionReason = ReasonMarshalConfigurationError
		conditionMessage = fmt.Sprintf(MessageFormatMarshalConfigurationError, err.Error())
		return err
	}

	logger.V(4).Info("Generated apply configuration", "yaml", string(applyConfigYaml))

	if err = ctrl.SetControllerReference(mc, applyConfig, r.Scheme); err != nil {
		logger.Error(err, "unable to set owner reference")
		conditionStatus = metav1.ConditionFalse
		conditionReason = ReasonOwnerReferenceError
		conditionMessage = fmt.Sprintf(MessageFormatOwnerReferenceError, err.Error())
		return err
	}

	existingResource := &unstructured.Unstructured{}
	existingResource.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   appsv1.GroupName,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    "Deployment",
	})
	resourceExists := true
	if err = r.Get(ctx, client.ObjectKeyFromObject(mc), existingResource); err != nil {
		if apierrors.IsNotFound(err) {
			resourceExists = false
		} else {
			logger.Error(err, "unable to fetch existing resource")
			conditionStatus = metav1.ConditionFalse
			conditionReason = ReasonExistingResourceError
			conditionMessage = fmt.Sprintf(MessageFormatExistingResourceError, err.Error())
			return err
		}
	}

	var changedFields string
	if resourceExists {
		comparison, err := diff(existingResource, applyConfig)
		if err != nil {
			if !errors.Is(err, ErrNoManagedFields) {
				logger.Error(err, "unable to compare existing resource with desired state")
				conditionStatus = metav1.ConditionFalse
				conditionReason = ReasonResourceComparisonError
				conditionMessage = fmt.Sprintf(MessageFormatResourceComparisonError, err.Error())
				return err
			}
			logger.V(2).Info("No managed fields found, proceeding with apply to take ownership")
		} else {
			if comparison.IsSame() {
				logger.V(2).Info("Metacollector resource is up to date, skipping apply")
				conditionReason = ReasonResourceUpToDate
				conditionMessage = MessageResourceUpToDate
				return nil
			}
			changedFields = formatChangedFields(comparison)
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
			conditionReason = ReasonApplyPatchErrorOnCreate
			conditionMessage = fmt.Sprintf(MessageFormatApplyPatchErrorOnCreate, err.Error())
			r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, ReasonApplyPatchErrorOnCreate,
				ReasonApplyPatchErrorOnCreate, MessageFormatApplyPatchErrorOnCreate, err.Error())
		} else {
			conditionStatus = metav1.ConditionFalse
			conditionReason = ReasonApplyPatchErrorOnUpdate
			conditionMessage = fmt.Sprintf(MessageFormatApplyPatchErrorOnUpdate, err.Error())
			r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, ReasonApplyPatchErrorOnUpdate,
				ReasonApplyPatchErrorOnUpdate, MessageFormatApplyPatchErrorOnUpdate, err.Error())
		}
		return err
	}

	if !resourceExists {
		logger.Info("Metacollector resource created")
		conditionReason = ReasonResourceCreated
		conditionMessage = MessageResourceCreated
		r.recorder.Eventf(mc, nil, corev1.EventTypeNormal, ReasonResourceCreated,
			ReasonResourceCreated, MessageResourceCreated)
	} else {
		logger.Info("Metacollector resource updated", "changedFields", changedFields)
		conditionReason = ReasonResourceUpdated
		conditionMessage = MessageResourceUpdated
		r.recorder.Eventf(mc, nil, corev1.EventTypeNormal, ReasonResourceUpdated,
			ReasonResourceUpdated, MessageResourceUpdated)
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
			conditionReason = ReasonDeploymentNotFound
			conditionMessage = MessageDeploymentNotFound
			return nil
		}
		conditionStatus = metav1.ConditionUnknown
		conditionReason = ReasonDeploymentFetchError
		conditionMessage = fmt.Sprintf(MessageFormatDeploymentFetchError, err.Error())
		log.FromContext(ctx).Error(err, "unable to fetch deployment for status")
		return fmt.Errorf("unable to fetch deployment: %w", err)
	}

	mc.Status.AvailableReplicas = deployment.Status.AvailableReplicas
	mc.Status.UnavailableReplicas = deployment.Status.UnavailableReplicas

	if desiredReplicas == deployment.Status.ReadyReplicas {
		conditionStatus = metav1.ConditionTrue
		conditionReason = ReasonDeploymentAvailable
		conditionMessage = MessageDeploymentAvailable
	} else {
		conditionStatus = metav1.ConditionFalse
		conditionReason = ReasonDeploymentUnavailable
		conditionMessage = MessageDeploymentUnavailable
		r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, ReasonDeploymentUnavailable,
			ReasonDeploymentUnavailable, MessageDeploymentUnavailable)
	}

	return nil
}

// ensureResource is a generic function to ensure a resource exists and is up to date.
func (r *Reconciler) ensureResource(ctx context.Context, mc *instancev1alpha1.Metacollector,
	generateFunc func(cl client.Client, mc *instancev1alpha1.Metacollector) (*unstructured.Unstructured, error)) error {
	logger := log.FromContext(ctx)

	desiredResource, err := generateFunc(r.Client, mc)
	if err != nil {
		r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, ReasonResourceGenerateError,
			ReasonResourceGenerateError, MessageFormatResourceGenerateError, err.Error())
		return fmt.Errorf("unable to generate desired resource: %w", err)
	}

	resourceType := desiredResource.GetKind()

	logger.V(3).Info("Ensuring resource", "type", resourceType, "name", desiredResource.GetName())

	existingResource := &unstructured.Unstructured{}
	existingResource.SetGroupVersionKind(desiredResource.GetObjectKind().GroupVersionKind())
	resourceExists := true
	if err = r.Get(ctx, client.ObjectKeyFromObject(desiredResource), existingResource); err != nil {
		if apierrors.IsNotFound(err) {
			resourceExists = false
		} else {
			return fmt.Errorf("unable to fetch existing %s: %w", resourceType, err)
		}
	}

	var changedFields string
	if resourceExists {
		comparison, err := diff(existingResource, desiredResource)
		if err != nil {
			if !errors.Is(err, ErrNoManagedFields) {
				return fmt.Errorf("unable to compare existing %s with desired state: %w", resourceType, err)
			}
			logger.V(3).Info("No managed fields found, proceeding with apply to take ownership", "type", resourceType, "name", desiredResource.GetName())
		} else {
			if comparison.IsSame() {
				logger.V(3).Info(resourceType+" is up to date, skipping apply", "name", desiredResource.GetName())
				return nil
			}
			changedFields = formatChangedFields(comparison)
		}
	}

	applyOpts := []client.ApplyOption{client.ForceOwnership, client.FieldOwner(fieldManager)}
	if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(desiredResource), applyOpts...); err != nil {
		r.recorder.Eventf(mc, nil, corev1.EventTypeWarning, ReasonResourceApplyError,
			ReasonResourceApplyError, MessageFormatResourceApplyError, resourceType, err.Error())
		return fmt.Errorf("unable to apply %s: %w", resourceType, err)
	}

	if !resourceExists {
		logger.V(3).Info(resourceType+" created", "name", desiredResource.GetName())
		r.recorder.Eventf(mc, nil, corev1.EventTypeNormal, ReasonSubResourceCreated,
			ReasonSubResourceCreated, MessageFormatSubResourceCreated, resourceType, desiredResource.GetName())
	} else {
		logger.V(3).Info(resourceType+" updated", "name", desiredResource.GetName(), "changedFields", changedFields)
		r.recorder.Eventf(mc, nil, corev1.EventTypeNormal, ReasonSubResourceUpdated,
			ReasonSubResourceUpdated, MessageFormatSubResourceUpdated, resourceType, desiredResource.GetName())
	}

	return nil
}

// ensureServiceAccount ensures the Metacollector service account is created or updated.
func (r *Reconciler) ensureServiceAccount(ctx context.Context, mc *instancev1alpha1.Metacollector) error {
	return r.ensureResource(ctx, mc, generateServiceAccount)
}

// ensureClusterRole ensures the Metacollector cluster role is created or updated.
func (r *Reconciler) ensureClusterRole(ctx context.Context, mc *instancev1alpha1.Metacollector) error {
	return r.ensureResource(ctx, mc, generateClusterRole)
}

// ensureClusterRoleBinding ensures the Metacollector cluster role binding is created or updated.
func (r *Reconciler) ensureClusterRoleBinding(ctx context.Context, mc *instancev1alpha1.Metacollector) error {
	return r.ensureResource(ctx, mc, generateClusterRoleBinding)
}

// ensureService ensures the Metacollector service is created or updated.
func (r *Reconciler) ensureService(ctx context.Context, mc *instancev1alpha1.Metacollector) error {
	return r.ensureResource(ctx, mc, generateService)
}
