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

package falco

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
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
)

const (
	finalizer = "falco.falcosecurity.dev/finalizer"
)

// Reconciler reconciles a Falco object.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// recorder is the event recorder for creating Kubernetes events.
	recorder events.EventRecorder
	// NativeSidecar is a flag to enable the native sidecar.
	NativeSidecar bool
}

// NewReconciler creates a new Reconciler.
func NewReconciler(cl client.Client, scheme *runtime.Scheme, recorder events.EventRecorder, nativeSidecar bool) *Reconciler {
	return &Reconciler{
		Client:        cl,
		Scheme:        scheme,
		recorder:      recorder,
		NativeSidecar: nativeSidecar,
	}
}

// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos;falcos/status,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=rulesfiles;rulesfiles/status,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=configs;configs/status,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=plugins;plugins/status,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=pods;services;configmaps;secrets;serviceaccounts,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:urls=/metrics,verbs=get

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := log.FromContext(ctx)
	falco := &instancev1alpha1.Falco{}

	// Fetch the Falco instance
	logger.V(2).Info("Fetching falco instance")

	if err := r.Get(ctx, req.NamespacedName, falco); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch falco instance")
		return ctrl.Result{}, err
	} else if apierrors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion.
	if ok, err := r.handleDeletion(ctx, falco); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Patch status via defer to ensure it's always called.
	defer func() {
		computeErr := r.computeAvailableCondition(ctx, falco)
		if computeErr != nil {
			logger.Error(computeErr, "unable to compute available condition")
		}
		patchErr := r.patchStatus(ctx, falco)
		if patchErr != nil {
			logger.Error(patchErr, "unable to patch Falco status")
		}
		reterr = kerrors.NewAggregate([]error{reterr, computeErr, patchErr})
	}()

	// Ensure the service account is created.
	if err := r.ensureServiceAccount(ctx, falco); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the role is created.
	if err := r.ensureRole(ctx, falco); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the role binding is created.
	if err := r.ensureRoleBinding(ctx, falco); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the clusterrole is created.
	if err := r.ensureClusterRole(ctx, falco); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the clusterrolebinding is created.
	if err := r.ensureClusterRoleBinding(ctx, falco); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the service is created.
	if err := r.ensureService(ctx, falco); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the configmap is created
	if err := r.ensureConfigMap(ctx, falco); err != nil {
		return ctrl.Result{}, err
	}

	// Cleanup dual deployments.
	if err := r.cleanupDualDeployments(ctx, falco); err != nil {
		return ctrl.Result{}, err
	}

	// Set the finalizer if needed.
	if ok, err := r.ensureFinalizer(ctx, falco); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the Falco version is set.
	if ok, err := r.ensureVersion(ctx, falco); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the deployment/daemonset is created.
	if err := r.ensureDeployment(ctx, falco); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&instancev1alpha1.Falco{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.ConfigMap{}).
		Watches(&rbacv1.ClusterRoleBinding{}, handler.EnqueueRequestsFromMapFunc(clusterScopedResourceHandler)).
		Watches(&rbacv1.ClusterRole{}, handler.EnqueueRequestsFromMapFunc(clusterScopedResourceHandler)).
		Named("falco").
		Complete(r)
}

// ensureFinalizer ensures the finalizer is set on the object and returns true if the object was updated.
func (r *Reconciler) ensureFinalizer(ctx context.Context, falco *instancev1alpha1.Falco) (bool, error) {
	if !controllerutil.ContainsFinalizer(falco, finalizer) {
		log.FromContext(ctx).V(3).Info("Setting finalizer", "finalizer", finalizer)

		patch := client.MergeFrom(falco.DeepCopy())
		controllerutil.AddFinalizer(falco, finalizer)
		if err := r.Patch(ctx, falco, patch); err != nil {
			log.FromContext(ctx).Error(err, "unable to set finalizer", "finalizer", finalizer)
			return false, err
		}
		log.FromContext(ctx).V(3).Info("Finalizer set", "finalizer", finalizer)
		return true, nil
	}
	return false, nil
}

// ensureVersion ensures the Falco version is set on the object and returns true if the object was updated.
// Version can be provided by the user in three ways:
// 1. Extracted from the container image.
// 2. Specified in the Falco CRD.
// 3. Default Falco version.
// Priority is in the order mentioned above.
func (r *Reconciler) ensureVersion(ctx context.Context, falco *instancev1alpha1.Falco) (bool, error) {
	// Start with the default Falco version.
	version := image.FalcoVersion()

	// Check if the version is already set in the Falco CRD.
	if falco.Spec.Version != "" {
		version = falco.Spec.Version
	}

	// Check if the version can be extracted from the container image
	if falco.Spec.PodTemplateSpec != nil {
		for i := range falco.Spec.PodTemplateSpec.Spec.Containers {
			if falco.Spec.PodTemplateSpec.Spec.Containers[i].Name == "falco" {
				version = image.VersionFromImage(falco.Spec.PodTemplateSpec.Spec.Containers[i].Image)
				break
			}
		}
	}

	// Set the version in the Falco CRD if it differs from the desired version.
	if version != falco.Spec.Version {
		log.FromContext(ctx).V(3).Info("Setting Falco version", "version", version)

		patch := client.MergeFrom(falco.DeepCopy())
		falco.Spec.Version = version
		if err := r.Patch(ctx, falco, patch); err != nil {
			log.FromContext(ctx).Error(err, "unable to set default Falco version", "version", version)
			return false, err
		}
		return true, nil
	}

	return false, nil
}

// handleDeletion handles the deletion of the Falco instance.
func (r *Reconciler) handleDeletion(ctx context.Context, falco *instancev1alpha1.Falco) (bool, error) {
	if falco.DeletionTimestamp == nil {
		return false, nil
	}

	// Check if finalizer is already removed
	if !controllerutil.ContainsFinalizer(falco, finalizer) {
		// Finalizer already removed, nothing to do
		return true, nil
	}

	log.FromContext(ctx).Info("Falco instance marked for deletion, removing finalizer", "finalizer", finalizer)

	resourceName := GenerateUniqueName(falco.Name, falco.Namespace)

	crb := &unstructured.Unstructured{}
	crb.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "ClusterRoleBinding",
	})
	crb.SetName(resourceName)
	if err := r.Delete(ctx, crb); err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "unable to delete clusterrolebinding")
		r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, ReasonDeletionError,
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
		r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, ReasonDeletionError,
			ReasonDeletionError, MessageFormatDeletionError, "ClusterRole", err.Error())
		return false, err
	}

	patch := client.MergeFrom(falco.DeepCopy())
	controllerutil.RemoveFinalizer(falco, finalizer)
	if err := r.Patch(ctx, falco, patch); err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "unable to remove finalizer from Falco instance")
		r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, ReasonDeletionError,
			ReasonDeletionError, MessageFormatDeletionError, "Finalizer", err.Error())
		return false, err
	}

	log.FromContext(ctx).Info("Falco instance deleted")
	r.recorder.Eventf(falco, nil, corev1.EventTypeNormal, ReasonInstanceDeleted,
		ReasonInstanceDeleted, MessageInstanceDeleted)

	return true, nil
}

// ensureDeployment ensures the Falco deployment or daemonset is created or updated.
func (r *Reconciler) ensureDeployment(ctx context.Context, falco *instancev1alpha1.Falco) error {
	logger := log.FromContext(ctx)

	// Condition values to be set during reconciliation.
	conditionStatus := metav1.ConditionTrue
	conditionReason := ""
	conditionMessage := ""

	// Ensure the reconcile status is saved.
	defer func() {
		apimeta.SetStatusCondition(&falco.Status.Conditions, common.NewReconciledCondition(
			conditionStatus,
			conditionReason,
			conditionMessage,
			falco.GetGeneration(),
		))
	}()

	logger.V(2).Info("Generating apply configuration from user input")
	applyConfig, err := generateApplyConfiguration(r.Client, falco, r.NativeSidecar)
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

	// Set owner reference.
	if err = ctrl.SetControllerReference(falco, applyConfig, r.Scheme); err != nil {
		logger.Error(err, "unable to set owner reference")
		conditionStatus = metav1.ConditionFalse
		conditionReason = ReasonOwnerReferenceError
		conditionMessage = fmt.Sprintf(MessageFormatOwnerReferenceError, err.Error())
		return err
	}

	// Check if the resource already exists.
	existingResource := &unstructured.Unstructured{}
	existingResource.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   appsv1.GroupName,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    falco.Spec.Type,
	})
	resourceExists := true
	if err = r.Get(ctx, client.ObjectKeyFromObject(falco), existingResource); err != nil {
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

	// Check if update is needed to avoid unnecessary API writes.
	// This is important for K8s < 1.31 where SSA may cause spurious resourceVersion bumps.
	// See: https://github.com/kubernetes/kubernetes/issues/124605
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
			logger.V(2).Info("No managed fields found, proceeding with apply to take ownership", "kind", falco.Spec.Type)
		} else {
			if comparison.IsSame() {
				logger.V(2).Info("Falco resource is up to date, skipping apply", "kind", falco.Spec.Type)
				conditionReason = ReasonResourceUpToDate
				conditionMessage = MessageResourceUpToDate
				return nil
			}
			changedFields = formatChangedFields(comparison)
		}
	}

	if !resourceExists {
		logger.Info("Creating Falco resource", "kind", falco.Spec.Type)
	}

	applyOpts := []client.ApplyOption{client.ForceOwnership, client.FieldOwner(fieldManager)}
	if err = r.Apply(ctx, client.ApplyConfigurationFromUnstructured(applyConfig), applyOpts...); err != nil {
		logger.Error(err, "unable to apply resource", "kind", falco.Spec.Type)
		if !resourceExists {
			conditionStatus = metav1.ConditionFalse
			conditionReason = ReasonApplyPatchErrorOnCreate
			conditionMessage = fmt.Sprintf(MessageFormatApplyPatchErrorOnCreate, err.Error())
			r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, ReasonApplyPatchErrorOnCreate,
				ReasonApplyPatchErrorOnCreate, MessageFormatApplyPatchErrorOnCreate, err.Error())
		} else {
			conditionStatus = metav1.ConditionFalse
			conditionReason = ReasonApplyPatchErrorOnUpdate
			conditionMessage = fmt.Sprintf(MessageFormatApplyPatchErrorOnUpdate, err.Error())
			r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, ReasonApplyPatchErrorOnUpdate,
				ReasonApplyPatchErrorOnUpdate, MessageFormatApplyPatchErrorOnUpdate, err.Error())
		}
		return err
	}

	if !resourceExists {
		logger.Info("Falco resource created", "kind", falco.Spec.Type)
		conditionReason = ReasonResourceCreated
		conditionMessage = MessageResourceCreated
		r.recorder.Eventf(falco, nil, corev1.EventTypeNormal, ReasonResourceCreated,
			ReasonResourceCreated, MessageResourceCreated)
	} else {
		logger.Info("Falco resource updated", "kind", falco.Spec.Type, "changedFields", changedFields)
		conditionReason = ReasonResourceUpdated
		conditionMessage = MessageResourceUpdated
		r.recorder.Eventf(falco, nil, corev1.EventTypeNormal, ReasonResourceUpdated,
			ReasonResourceUpdated, MessageResourceUpdated)
	}

	return nil
}

// cleanupDualDeployments ensures there is no dual deployment for the given Falco instance.
func (r *Reconciler) cleanupDualDeployments(ctx context.Context, falco *instancev1alpha1.Falco) error {
	logger := log.FromContext(ctx)

	for _, t := range []string{resourceTypeDeployment, resourceTypeDaemonSet} {
		// Skip the current type of the Falco instance.
		if t == falco.Spec.Type {
			continue
		}

		// Create an unstructured object for the resource type.
		existingResource := &unstructured.Unstructured{}
		existingResource.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   appsv1.GroupName,
			Version: appsv1.SchemeGroupVersion.Version,
			Kind:    t,
		})

		// Try to get the existing resource.
		err := r.Get(ctx, client.ObjectKeyFromObject(falco), existingResource)
		if err != nil && !apierrors.IsNotFound(err) {
			logger.Error(err, "unable to fetch existing resource", "kind", t)
			return err
		}

		// If the resource exists, delete it.
		if err == nil {
			logger.Info("Deleting dual deployment resource", "kind", t)
			if err := r.Delete(ctx, existingResource); err != nil {
				logger.Error(err, "unable to delete dual deployment resource", "kind", t)
				return err
			}
		}
	}

	return nil
}

// patchStatus patches the Falco status using server-side apply.
func (r *Reconciler) patchStatus(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, falco, fieldManager)
}

// computeAvailableCondition queries live deployment/daemonset state.
func (r *Reconciler) computeAvailableCondition(ctx context.Context, falco *instancev1alpha1.Falco) error {
	conditionStatus := metav1.ConditionUnknown
	conditionReason := ""
	conditionMessage := ""

	defer func() {
		apimeta.SetStatusCondition(&falco.Status.Conditions, common.NewAvailableCondition(
			conditionStatus, conditionReason, conditionMessage,
			falco.GetGeneration(),
		))
	}()

	switch falco.Spec.Type {
	case resourceTypeDeployment:
		desiredReplicas := int32(1)
		if falco.Spec.Replicas != nil {
			desiredReplicas = *falco.Spec.Replicas
		}
		falco.Status.DesiredReplicas = desiredReplicas

		deployment := &appsv1.Deployment{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(falco), deployment); err != nil {
			if apierrors.IsNotFound(err) {
				conditionStatus = metav1.ConditionFalse
				conditionReason = ReasonDeploymentNotFound
				conditionMessage = MessageDeploymentNotFound
				break
			}
			conditionStatus = metav1.ConditionUnknown
			conditionReason = ReasonDeploymentFetchError
			conditionMessage = fmt.Sprintf(MessageFormatDeploymentFetchError, err.Error())
			log.FromContext(ctx).Error(err, "unable to fetch deployment for status")
			return fmt.Errorf("unable to fetch deployment: %w", err)
		}

		falco.Status.AvailableReplicas = deployment.Status.AvailableReplicas
		falco.Status.UnavailableReplicas = deployment.Status.UnavailableReplicas

		if desiredReplicas == deployment.Status.ReadyReplicas {
			conditionStatus = metav1.ConditionTrue
			conditionReason = ReasonDeploymentAvailable
			conditionMessage = MessageDeploymentAvailable
		} else {
			conditionStatus = metav1.ConditionFalse
			conditionReason = ReasonDeploymentUnavailable
			conditionMessage = MessageDeploymentUnavailable
			r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, ReasonDeploymentUnavailable,
				ReasonDeploymentUnavailable, MessageDeploymentUnavailable)
		}
	case resourceTypeDaemonSet:
		daemonset := &appsv1.DaemonSet{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(falco), daemonset); err != nil {
			if apierrors.IsNotFound(err) {
				conditionStatus = metav1.ConditionFalse
				conditionReason = ReasonDaemonSetNotFound
				conditionMessage = MessageDaemonSetNotFound
				break
			}
			conditionStatus = metav1.ConditionUnknown
			conditionReason = ReasonDaemonSetFetchError
			conditionMessage = fmt.Sprintf(MessageFormatDaemonSetFetchError, err.Error())
			log.FromContext(ctx).Error(err, "unable to fetch daemonset for status")
			return fmt.Errorf("unable to fetch daemonset: %w", err)
		}
		falco.Status.DesiredReplicas = daemonset.Status.DesiredNumberScheduled
		falco.Status.AvailableReplicas = daemonset.Status.NumberAvailable
		falco.Status.UnavailableReplicas = daemonset.Status.NumberUnavailable

		if daemonset.Status.DesiredNumberScheduled == daemonset.Status.NumberAvailable {
			conditionStatus = metav1.ConditionTrue
			conditionReason = ReasonDaemonSetAvailable
			conditionMessage = MessageDaemonSetAvailable
		} else {
			conditionStatus = metav1.ConditionFalse
			conditionReason = ReasonDaemonSetUnavailable
			conditionMessage = MessageDaemonSetUnavailable
			r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, ReasonDaemonSetUnavailable,
				ReasonDaemonSetUnavailable, MessageDaemonSetUnavailable)
		}
	}

	return nil
}

// ensureResource is a generic function to ensure a resource exists and is up to date.
func (r *Reconciler) ensureResource(ctx context.Context, falco *instancev1alpha1.Falco,
	generateFunc func(cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error)) error {
	logger := log.FromContext(ctx)

	// Generate the desired resource
	desiredResource, err := generateFunc(r.Client, falco)
	if err != nil {
		r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, ReasonResourceGenerateError,
			ReasonResourceGenerateError, MessageFormatResourceGenerateError, err.Error())
		return fmt.Errorf("unable to generate desired resource: %w", err)
	}

	resourceType := desiredResource.GetKind()

	logger.V(3).Info("Ensuring resource", "type", resourceType, "name", desiredResource.GetName())

	// Check if the resource already exists.
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

	// Check if update is needed to avoid unnecessary API writes.
	// This is important for K8s < 1.31 where SSA may cause spurious resourceVersion bumps.
	// See: https://github.com/kubernetes/kubernetes/issues/124605
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

	applyOpts := []client.ApplyOption{client.ForceOwnership, client.FieldOwner("falco-controller")}
	if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(desiredResource), applyOpts...); err != nil {
		r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, ReasonResourceApplyError,
			ReasonResourceApplyError, MessageFormatResourceApplyError, resourceType, err.Error())
		return fmt.Errorf("unable to apply %s: %w", resourceType, err)
	}

	if !resourceExists {
		logger.V(3).Info(resourceType+" created", "name", desiredResource.GetName())
		r.recorder.Eventf(falco, nil, corev1.EventTypeNormal, ReasonSubResourceCreated,
			ReasonSubResourceCreated, MessageFormatSubResourceCreated, resourceType, desiredResource.GetName())
	} else {
		logger.V(3).Info(resourceType+" updated", "name", desiredResource.GetName(), "changedFields", changedFields)
		r.recorder.Eventf(falco, nil, corev1.EventTypeNormal, ReasonSubResourceUpdated,
			ReasonSubResourceUpdated, MessageFormatSubResourceUpdated, resourceType, desiredResource.GetName())
	}

	return nil
}

// ensureServiceAccount ensures the Falco service account is created or updated.
func (r *Reconciler) ensureServiceAccount(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, generateServiceAccount)
}

// ensureRole ensures the Falco role is created or updated.
func (r *Reconciler) ensureRole(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, generateRole)
}

// ensureRoleBinding ensures the Falco role binding is created or updated.
func (r *Reconciler) ensureRoleBinding(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, generateRoleBinding)
}

// ensureClusterRole ensures the Falco cluster role is created or updated.
func (r *Reconciler) ensureClusterRole(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, generateClusterRole)
}

// ensureClusterRoleBinding ensures the Falco cluster role binding is created or updated.
func (r *Reconciler) ensureClusterRoleBinding(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, generateClusterRoleBinding)
}

// ensureService ensures the Falco service is created or updated.
func (r *Reconciler) ensureService(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, generateService)
}

// ensureConfigmap ensures the Falco configmap is created or updated.
func (r *Reconciler) ensureConfigMap(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, generateConfigmap)
}
