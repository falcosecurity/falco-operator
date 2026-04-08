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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

const (
	finalizer    = "falco.instance.falcosecurity.dev/finalizer"
	fieldManager = "falco-controller"
)

// clusterScopedGVKs are the GVKs of cluster-scoped resources managed by the Falco controller.
var clusterScopedGVKs = []schema.GroupVersionKind{
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"},
}

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
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=rulesfiles;rulesfiles/status,verbs=get;list;patch;update;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=configs;configs/status,verbs=get;list;patch;update;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=plugins;plugins/status,verbs=get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=pods;services;configmaps;serviceaccounts,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;patch;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch;update
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

	if err := r.Get(ctx, req.NamespacedName, falco); err != nil && !k8serrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch falco instance")
		return ctrl.Result{}, err
	} else if k8serrors.IsNotFound(err) {
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

	resolvedImage := instance.ResolveVersion(falco, resources.FalcoDefaults)
	resourceType := resolveResourceType(falco.Spec.Type)
	falco.Status.Version = resolvedImage
	falco.Status.ResourceType = resourceType

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
		Owns(&corev1.Service{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&corev1.ConfigMap{}).
		Watches(&rbacv1.ClusterRoleBinding{}, handler.EnqueueRequestsFromMapFunc(instance.ClusterScopedResourceHandler)).
		Watches(&rbacv1.ClusterRole{}, handler.EnqueueRequestsFromMapFunc(instance.ClusterScopedResourceHandler)).
		Named("falco").
		Complete(r)
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

	resourceType := resolveResourceType(falco.Spec.Type)

	logger.V(2).Info("Generating apply configuration from user input")
	applyConfig, err := generateApplyConfiguration(falco, resourceType, r.NativeSidecar)
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

	// Set owner reference.
	if err = ctrl.SetControllerReference(falco, applyConfig, r.Scheme); err != nil {
		logger.Error(err, "unable to set owner reference")
		conditionStatus = metav1.ConditionFalse
		conditionReason = instance.ReasonOwnerReferenceError
		conditionMessage = fmt.Sprintf(instance.MessageFormatOwnerReferenceError, err.Error())
		return err
	}

	// Check if the resource already exists.
	existingResource := &unstructured.Unstructured{}
	existingResource.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   appsv1.GroupName,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    resourceType,
	})
	resourceExists := true
	if err = r.Get(ctx, client.ObjectKeyFromObject(falco), existingResource); err != nil {
		if k8serrors.IsNotFound(err) {
			resourceExists = false
		} else {
			logger.Error(err, "unable to fetch existing resource")
			conditionStatus = metav1.ConditionFalse
			conditionReason = instance.ReasonExistingResourceError
			conditionMessage = fmt.Sprintf(instance.MessageFormatExistingResourceError, err.Error())
			return err
		}
	}

	// Check if update is needed to avoid unnecessary API writes.
	// This is important for K8s < 1.31 where SSA may cause spurious resourceVersion bumps.
	// See: https://github.com/kubernetes/kubernetes/issues/124605
	var changedFields string
	if resourceExists {
		comparison, err := controllerhelper.Diff(existingResource, applyConfig, fieldManager)
		if err != nil {
			if !errors.Is(err, controllerhelper.ErrNoManagedFields) {
				logger.Error(err, "unable to compare existing resource with desired state")
				conditionStatus = metav1.ConditionFalse
				conditionReason = instance.ReasonResourceComparisonError
				conditionMessage = fmt.Sprintf(instance.MessageFormatResourceComparisonError, err.Error())
				return err
			}
			logger.V(2).Info("No managed fields found, proceeding with apply to take ownership", "kind", falco.Spec.Type)
		} else {
			if comparison.IsSame() {
				logger.V(2).Info("Falco resource is up to date, skipping apply", "kind", falco.Spec.Type)
				conditionReason = instance.ReasonResourceUpToDate
				conditionMessage = instance.MessageResourceUpToDate
				return nil
			}
			changedFields = controllerhelper.FormatChangedFields(comparison)
		}
	}

	if !resourceExists {
		logger.Info("Creating Falco resource", "kind", falco.Spec.Type)
	}

	applyOpts := []client.ApplyOption{client.ForceOwnership, client.FieldOwner(fieldManager)}
	if err = r.Apply(ctx, client.ApplyConfigurationFromUnstructured(applyConfig), applyOpts...); err != nil {
		if !resourceExists {
			conditionStatus = metav1.ConditionFalse
			conditionReason = instance.ReasonApplyPatchErrorOnCreate
			conditionMessage = fmt.Sprintf(instance.MessageFormatApplyPatchErrorOnCreate, err.Error())
			r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, instance.ReasonApplyPatchErrorOnCreate,
				instance.ReasonApplyPatchErrorOnCreate, instance.MessageFormatApplyPatchErrorOnCreate, err.Error())
		} else {
			conditionStatus = metav1.ConditionFalse
			conditionReason = instance.ReasonApplyPatchErrorOnUpdate
			conditionMessage = fmt.Sprintf(instance.MessageFormatApplyPatchErrorOnUpdate, err.Error())
			r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, instance.ReasonApplyPatchErrorOnUpdate,
				instance.ReasonApplyPatchErrorOnUpdate, instance.MessageFormatApplyPatchErrorOnUpdate, err.Error())
		}
		// Validation errors are terminal — the user must fix the CR spec.
		// Don't requeue; the next reconciliation will be triggered by the CR update.
		if k8serrors.IsInvalid(err) {
			logger.Info("Apply rejected by API server due to invalid input", "kind", falco.Spec.Type, "error", err.Error())
			return nil
		}
		logger.Error(err, "unable to apply resource", "kind", falco.Spec.Type)
		return err
	}

	if !resourceExists {
		logger.Info("Falco resource created", "kind", falco.Spec.Type)
		conditionReason = instance.ReasonResourceCreated
		conditionMessage = instance.MessageResourceCreated
		r.recorder.Eventf(falco, nil, corev1.EventTypeNormal, instance.ReasonResourceCreated,
			instance.ReasonResourceCreated, instance.MessageResourceCreated)
	} else {
		logger.Info("Falco resource updated", "kind", falco.Spec.Type, "changedFields", changedFields)
		conditionReason = instance.ReasonResourceUpdated
		conditionMessage = fmt.Sprintf(instance.MessageFormatResourceUpdated, changedFields)
		r.recorder.Eventf(falco, nil, corev1.EventTypeNormal, instance.ReasonResourceUpdated,
			instance.ReasonResourceUpdated, instance.MessageFormatResourceUpdated, changedFields)
	}

	return nil
}

// cleanupDualDeployments ensures there is no dual deployment for the given Falco instance.
func (r *Reconciler) cleanupDualDeployments(ctx context.Context, falco *instancev1alpha1.Falco) error {
	logger := log.FromContext(ctx)

	resourceType := resolveResourceType(falco.Spec.Type)

	for _, t := range []string{resources.ResourceTypeDeployment, resources.ResourceTypeDaemonSet} {
		// Skip the current type of the Falco instance.
		if t == resourceType {
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
		if err != nil && !k8serrors.IsNotFound(err) {
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
			r.recorder.Eventf(falco, nil, corev1.EventTypeNormal, instance.ReasonDualDeploymentCleanup,
				instance.ReasonDualDeploymentCleanup, instance.MessageFormatDualDeploymentCleanup, t)
		}
	}

	return nil
}

// computeAvailableCondition queries live deployment/daemonset state.
func (r *Reconciler) computeAvailableCondition(ctx context.Context, falco *instancev1alpha1.Falco) error {
	var result instance.Availability
	var err error

	switch resolveResourceType(falco.Spec.Type) {
	case resources.ResourceTypeDeployment:
		result, err = instance.ComputeDeploymentAvailability(ctx, r.Client, client.ObjectKeyFromObject(falco), falco.Spec.Replicas)
	case resources.ResourceTypeDaemonSet:
		result, err = instance.ComputeDaemonSetAvailability(ctx, r.Client, client.ObjectKeyFromObject(falco))
	}

	falco.Status.DesiredReplicas = result.DesiredReplicas
	falco.Status.AvailableReplicas = result.AvailableReplicas
	falco.Status.UnavailableReplicas = result.UnavailableReplicas

	apimeta.SetStatusCondition(&falco.Status.Conditions, common.NewAvailableCondition(
		result.ConditionStatus, result.Reason, result.Message, falco.GetGeneration()))

	switch result.ConditionStatus {
	case metav1.ConditionTrue:
		r.recorder.Eventf(falco, nil, corev1.EventTypeNormal, result.Reason, result.Reason, result.Message)
	case metav1.ConditionFalse:
		r.recorder.Eventf(falco, nil, corev1.EventTypeWarning, result.Reason, result.Reason, result.Message)
	case metav1.ConditionUnknown:
		// No event on unknown status
	}

	return err
}

// patchStatus patches the Falco status using server-side apply.
func (r *Reconciler) patchStatus(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, falco, fieldManager)
}

// ensureFinalizer ensures the finalizer is set on the object and returns true if the object was updated.
func (r *Reconciler) ensureFinalizer(ctx context.Context, falco *instancev1alpha1.Falco) (bool, error) {
	return instance.EnsureFinalizer(ctx, r.Client, falco, finalizer)
}

// handleDeletion handles the deletion of the Falco instance.
func (r *Reconciler) handleDeletion(ctx context.Context, falco *instancev1alpha1.Falco) (bool, error) {
	return instance.HandleDeletion(ctx, r.Client, r.recorder, falco, finalizer, clusterScopedGVKs, instance.MessageFalcoInstanceDeleted)
}

// ensureServiceAccount ensures the ServiceAccount is created or updated.
func (r *Reconciler) ensureServiceAccount(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		resources.GenerateServiceAccount(falco),
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false})
}

// ensureRole ensures the Role is created or updated.
func (r *Reconciler) ensureRole(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		resources.GenerateRole(falco, resources.FalcoDefaults),
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false})
}

// ensureRoleBinding ensures the RoleBinding is created or updated.
func (r *Reconciler) ensureRoleBinding(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		resources.GenerateRoleBinding(falco),
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false})
}

// ensureClusterRole ensures the ClusterRole is created or updated.
func (r *Reconciler) ensureClusterRole(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		resources.GenerateClusterRole(falco, resources.FalcoDefaults),
		instance.GenerateOptions{SetControllerRef: false, IsClusterScoped: true})
}

// ensureClusterRoleBinding ensures the ClusterRoleBinding is created or updated.
func (r *Reconciler) ensureClusterRoleBinding(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		resources.GenerateClusterRoleBinding(falco),
		instance.GenerateOptions{SetControllerRef: false, IsClusterScoped: true})
}

// ensureService ensures the Service is created or updated.
func (r *Reconciler) ensureService(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		resources.GenerateService(falco, resources.FalcoDefaults),
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false})
}

// ensureConfigMap ensures the ConfigMap is created or updated.
func (r *Reconciler) ensureConfigMap(ctx context.Context, falco *instancev1alpha1.Falco) error {
	resourceType := resolveResourceType(falco.Spec.Type)
	configMapResource, err := resources.GenerateConfigMap(falco, resources.FalcoDefaults, resourceType)
	if err != nil {
		return fmt.Errorf("unsupported falco type: %s", resourceType)
	}
	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		configMapResource,
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false})
}

// resolveResourceType returns the resource type from the spec, falling back to the default.
func resolveResourceType(specType *string) string {
	if specType != nil {
		return *specType
	}
	return resources.FalcoDefaults.ResourceType
}
