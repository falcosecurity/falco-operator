// Copyright (C) 2025 The Falco Authors
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
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
)

const (
	finalizer = "falco.falcosecurity.dev/finalizer"
)

// Reconciler reconciles a Falco object.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Last reconciled conditions for Falco instances.
	// This is used to update the status of the Falco instance in the defer function.
	ReconciledConditions map[string]metav1.Condition
	// NativeSidecar is a flag to enable the native sidecar.
	NativeSidecar bool
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var err error
	logger := log.FromContext(ctx)
	falco := &instancev1alpha1.Falco{}

	// Fetch the Falco instance
	logger.V(2).Info("Fetching falco instance")

	if err = r.Get(ctx, req.NamespacedName, falco); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch falco instance")
		return ctrl.Result{}, err
	} else if apierrors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion.
	if ok, err := r.handleDeletion(ctx, falco); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Update the status.
	defer func() {
		if err := r.updateStatus(ctx, falco); err != nil {
			logger.Error(err, "unable to update Falco status")
		}
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
		Named("falco").
		Complete(r)
}

// ensureFinalizer ensures the finalizer is set on the object and returns true if the object was updated.
func (r *Reconciler) ensureFinalizer(ctx context.Context, falco *instancev1alpha1.Falco) (bool, error) {
	if !controllerutil.ContainsFinalizer(falco, finalizer) {
		log.FromContext(ctx).V(3).Info("Setting finalizer", "finalizer", finalizer)
		controllerutil.AddFinalizer(falco, finalizer)

		if err := r.Update(ctx, falco); err != nil {
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
		falco.Spec.Version = version
		log.FromContext(ctx).V(3).Info("Setting Falco version", "version", version)
		if err := r.Update(ctx, falco); err != nil {
			log.FromContext(ctx).Error(err, "unable to set default Falco version", "version", image.FalcoVersion())
			return false, err
		}
		return true, nil
	}

	return false, nil
}

// handleDeletion handles the deletion of the Falco instance.
func (r *Reconciler) handleDeletion(ctx context.Context, falco *instancev1alpha1.Falco) (bool, error) {
	if falco.DeletionTimestamp != nil {
		log.FromContext(ctx).Info("Falco instance marked for deletion")
		if controllerutil.ContainsFinalizer(falco, finalizer) {
			log.FromContext(ctx).Info("Removing finalizer", "finalizer", finalizer)

			// Remove the finalizer.
			if controllerutil.RemoveFinalizer(falco, finalizer) {
				if err := r.Update(ctx, falco); err != nil {
					log.FromContext(ctx).Error(err, "unable to update Falco instance")
					return false, err
				}
			}
		}
		return true, nil
	}
	return false, nil
}

// ensureDeployment ensures the Falco deployment or daemonset is created or updated.
// It returns an error if the operation fails.
func (r *Reconciler) ensureDeployment(ctx context.Context, falco *instancev1alpha1.Falco) error {
	logger := log.FromContext(ctx)
	reconcileCondition := metav1.Condition{
		Type:               string(commonv1alpha1.Reconciled),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: falco.GetGeneration(),
		LastTransitionTime: metav1.Time{
			Time: time.Now().UTC(),
		},
	}

	// Ensure the reconcile status is saved.
	defer func() {
		r.ReconciledConditions[fmt.Sprintf("%s/%s", falco.Namespace, falco.Name)] = reconcileCondition
	}()

	logger.V(2).Info("Generating apply configuration from user input")
	applyConfig, err := generateApplyConfiguration(ctx, r.Client, falco, r.NativeSidecar)
	if err != nil {
		logger.Error(err, "unable to generate apply configuration")
		reconcileCondition.Status = metav1.ConditionFalse
		reconcileCondition.Reason = "ApplyConfigurationError"
		reconcileCondition.Message = "Unable to generate apply configuration: " + err.Error()
		return err
	}

	// transform the apply configuration to yaml.
	applyConfigYaml, err := yaml.Marshal(applyConfig.Object)
	if err != nil {
		logger.Error(err, "unable to marshal apply configuration")
		reconcileCondition.Status = metav1.ConditionFalse
		reconcileCondition.Reason = "MarshalConfigurationError"
		reconcileCondition.Message = "Unable to marshal apply configuration: " + err.Error()
		return err
	}

	logger.V(4).Info("Generated apply configuration", "yaml", string(applyConfigYaml))

	// Set owner reference.
	if err = ctrl.SetControllerReference(falco, applyConfig, r.Scheme); err != nil {
		logger.Error(err, "unable to set owner reference")
		reconcileCondition.Status = metav1.ConditionFalse
		reconcileCondition.Reason = "OwnerReferenceError"
		reconcileCondition.Message = "Unable to set owner reference: " + err.Error()
		return err
	}

	// Get existing Falco deployment/daemonset
	existingResource := &unstructured.Unstructured{}
	existingResource.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   appsv1.GroupName,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    falco.Spec.Type, // "Deployment" or "DaemonSet"
	})

	if err = r.Get(ctx, client.ObjectKeyFromObject(falco), existingResource); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch existing resource")
		reconcileCondition.Status = metav1.ConditionFalse
		reconcileCondition.Reason = "ExistingResourceError"
		reconcileCondition.Message = "Unable to fetch existing resource: " + err.Error()
		return err
	}

	// If the resource has not been found, create it.
	if apierrors.IsNotFound(err) {
		logger.Info("Creating Falco resource", "kind", falco.Spec.Type)
		err = r.Patch(ctx, applyConfig, client.Apply, client.ForceOwnership, client.FieldOwner("falco-controller"))
		if err != nil {
			logger.Error(err, "unable to apply patch")
			reconcileCondition.Status = metav1.ConditionFalse
			reconcileCondition.Reason = "ApplyPatchErrorOnCreate"
			reconcileCondition.Message = "Unable to create resource by patch: " + err.Error()
			return err
		}
		logger.Info("Falco resource created", "kind", falco.Spec.Type)
		reconcileCondition.Reason = "ResourceCreated"
		reconcileCondition.Message = "Resource created successfully"
		return nil
	}

	// If the resource has been found remove all the fields that are not needed.
	removeUnwantedFields(existingResource)

	cmp, err := diff(existingResource, applyConfig)
	if err != nil {
		logger.Error(err, "unable to compare existing and desired resources", "existing", existingResource, "desired", applyConfig)
		reconcileCondition.Status = metav1.ConditionFalse
		reconcileCondition.Reason = "ResourceComparisonError"
		reconcileCondition.Message = "Unable to compare existing and desired resources: " + err.Error()
		return err
	}

	if cmp.IsSame() {
		logger.V(2).Info("Falco resource is up to date", "kind", falco.Spec.Type)
		reconcileCondition.Reason = "ResourceUpToDate"
		reconcileCondition.Message = "Resource is up to date"
		return nil
	}

	logger.Info("Updating Falco resource", "kind", falco.Spec.Type, "diff", cmp.String())
	if err = r.Patch(ctx, applyConfig, client.Apply, client.ForceOwnership, client.FieldOwner("falco-controller")); err != nil {
		logger.Error(err, "unable to apply patch", "kind", falco.Spec.Type, "patch", applyConfig)
		reconcileCondition.Status = metav1.ConditionFalse
		reconcileCondition.Reason = "ApplyPatchErrorOnUpdate"
		reconcileCondition.Message = "Unable to update resource by patch: " + err.Error()
		return err
	}

	reconcileCondition.Reason = "ResourceUpdated"
	reconcileCondition.Message = "Resource updated successfully"

	logger.Info("Falco resource updated", "kind", falco.Spec.Type)
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

// updateStatus updates the status of the Falco instance.
func (r *Reconciler) updateStatus(ctx context.Context, falco *instancev1alpha1.Falco) error {
	var err error
	availableCondition := metav1.Condition{
		Type:               string(commonv1alpha1.Available),
		Status:             metav1.ConditionUnknown,
		ObservedGeneration: falco.GetGeneration(),
		LastTransitionTime: metav1.Time{
			Time: time.Now().UTC(),
		},
	}

	switch falco.Spec.Type {
	case resourceTypeDeployment:
		deployment := &appsv1.Deployment{}
		err = r.Get(ctx, client.ObjectKeyFromObject(falco), deployment)
		if err != nil {
			if apierrors.IsNotFound(err) {
				// Deployment has not been created or has been deleted.
				availableCondition.Status = metav1.ConditionFalse
				availableCondition.Reason = "DeploymentNotFound"
				availableCondition.Message = "Deployment has not been created or has been deleted"
			} else {
				return fmt.Errorf("unable to fetch deployment: %w", err)
			}
		}
		falco.Status.DesiredReplicas = *falco.Spec.Replicas
		falco.Status.AvailableReplicas = deployment.Status.AvailableReplicas
		falco.Status.UnavailableReplicas = deployment.Status.UnavailableReplicas

		if *falco.Spec.Replicas == deployment.Status.ReadyReplicas {
			availableCondition.Status = metav1.ConditionTrue
			availableCondition.Reason = "DeploymentAvailable"
			availableCondition.Message = "Deployment is available"
		} else {
			availableCondition.Status = metav1.ConditionFalse
			availableCondition.Reason = "DeploymentUnavailable"
			availableCondition.Message = "Deployment is unavailable"
		}
	case resourceTypeDaemonSet:
		daemonset := &appsv1.DaemonSet{}
		err = r.Get(ctx, client.ObjectKeyFromObject(falco), daemonset)
		if err != nil {
			if apierrors.IsNotFound(err) {
				// DaemonSet has not been created or has been deleted.
				availableCondition.Status = metav1.ConditionFalse
				availableCondition.Reason = "DaemonSetNotFound"
				availableCondition.Message = "DaemonSet has not been created or has been deleted"
			} else {
				return fmt.Errorf("unable to fetch daemonset: %w", err)
			}
		}
		falco.Status.DesiredReplicas = daemonset.Status.DesiredNumberScheduled
		falco.Status.AvailableReplicas = daemonset.Status.NumberAvailable
		falco.Status.UnavailableReplicas = daemonset.Status.NumberUnavailable

		if daemonset.Status.DesiredNumberScheduled == daemonset.Status.NumberAvailable {
			availableCondition.Status = metav1.ConditionTrue
			availableCondition.Reason = "DaemonSetAvailable"
			availableCondition.Message = "DaemonSet is available"
		} else {
			availableCondition.Status = metav1.ConditionFalse
			availableCondition.Reason = "DaemonSetUnavailable"
			availableCondition.Message = "DaemonSet is unavailable"
		}
	}

	// Get the reconciled condition.
	if reconciledCondition, ok := r.ReconciledConditions[fmt.Sprintf("%s/%s", falco.Namespace, falco.Name)]; ok {
		falco.Status.Conditions = updateConditions(falco.Status.Conditions, availableCondition, reconciledCondition)
	} else {
		// Update the status conditions.
		falco.Status.Conditions = updateConditions(falco.Status.Conditions, availableCondition)
	}

	if err := r.Status().Update(ctx, falco); err != nil && !apierrors.IsConflict(err) {
		return fmt.Errorf("unable to update status: %w", err)
	}

	return nil
}

// ensureResource is a generic function to ensure a resource exists and is up to date.
func (r *Reconciler) ensureResource(ctx context.Context, falco *instancev1alpha1.Falco,
	resourceType string,
	generateFunc func(ctx context.Context, cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error)) error {
	logger := log.FromContext(ctx)
	logger.V(3).Info("Ensuring resource", "type", resourceType, "name", falco.Name)

	// Generate the desired resource
	desiredResource, err := generateFunc(ctx, r.Client, falco)
	if err != nil {
		return fmt.Errorf("unable to generate desired %s: %w", resourceType, err)
	}

	// Get existing resource
	existingResource := &unstructured.Unstructured{}
	existingResource.SetGroupVersionKind(desiredResource.GetObjectKind().GroupVersionKind())
	existingResource.SetName(falco.Name)
	existingResource.SetNamespace(falco.Namespace)

	if err = r.Get(ctx, client.ObjectKeyFromObject(falco), existingResource); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("unable to fetch existing %s: %w", resourceType, err)
	}

	// Create if not found
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desiredResource); err != nil {
			return fmt.Errorf("unable to create %s: %w", resourceType, err)
		}
		logger.V(3).Info(resourceType+" created", "name", falco.Name)
		return nil
	}

	// Remove unwanted fields
	removeUnwantedFields(existingResource)

	// Compare and update if needed
	cmp, err := diff(existingResource, desiredResource)
	if err != nil {
		return fmt.Errorf("unable to compare existing and desired %s: %w", resourceType, err)
	}

	if cmp.IsSame() {
		logger.V(3).Info(resourceType+" is up to date", "name", falco.Name)
		return nil
	}

	logger.V(3).Info("Updating "+resourceType, "name", falco.Name, "diff", cmp.String())
	if err := r.Patch(ctx, desiredResource, client.Apply, client.ForceOwnership, client.FieldOwner("falco-controller")); err != nil {
		return fmt.Errorf("unable to apply patch to %s: %w", resourceType, err)
	}

	logger.V(3).Info(resourceType+" updated", "name", falco.Name)
	return nil
}

// ensureServiceAccount ensures the Falco service account is created or updated.
func (r *Reconciler) ensureServiceAccount(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, "ServiceAccount",
		func(ctx context.Context, cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
			return generateServiceAccount(ctx, r.Client, falco)
		})
}

// ensureRole ensures the Falco role is created or updated.
func (r *Reconciler) ensureRole(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, "ServiceAccount",
		func(ctx context.Context, cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
			return generateRole(ctx, r.Client, falco)
		})
}

// ensureRoleBinding ensures the Falco role binding is created or updated.
func (r *Reconciler) ensureRoleBinding(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, "RoleBinding",
		func(ctx context.Context, cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
			return generateRoleBinding(ctx, r.Client, falco)
		})
}

// ensureService ensures the Falco service is created or updated.
func (r *Reconciler) ensureService(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, "Service",
		func(ctx context.Context, cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
			return generateService(ctx, r.Client, falco)
		})
}

// ensureConfigmap ensures the Falco configmap is created or updated.
func (r *Reconciler) ensureConfigMap(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return r.ensureResource(ctx, falco, "ConfigMap",
		func(ctx context.Context, cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
			return generateConfigmap(ctx, r.Client, falco)
		})
}
