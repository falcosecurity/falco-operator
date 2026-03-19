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

package component

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
	finalizer    = "component.instance.falcosecurity.dev/finalizer"
	fieldManager = "component-controller"
)

// clusterScopedGVKs are the GVKs of cluster-scoped resources managed by the Component controller.
var clusterScopedGVKs = []schema.GroupVersionKind{
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"},
}

// Reconciler reconciles a Component object.
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

// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=components;components/status,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=endpoints;namespaces;replicationcontrollers,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := log.FromContext(ctx)
	comp := &instancev1alpha1.Component{}

	logger.V(2).Info("Fetching component instance")

	if err := r.Get(ctx, req.NamespacedName, comp); err != nil && !k8serrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch component instance")
		return ctrl.Result{}, err
	} else if k8serrors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Resolve defaults for the component type.
	defs, err := resources.GetDefaults(string(comp.Spec.Component.Type))
	if err != nil {
		logger.Error(err, "unable to load defaults for component type", "type", comp.Spec.Component.Type)
		return ctrl.Result{}, err
	}

	// Handle deletion.
	if ok, err := r.handleDeletion(ctx, comp); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Patch status via defer to ensure it's always called.
	defer func() {
		computeErr := r.computeAvailableCondition(ctx, comp)
		if computeErr != nil {
			logger.Error(computeErr, "unable to compute available condition")
		}
		patchErr := r.patchStatus(ctx, comp)
		if patchErr != nil {
			logger.Error(patchErr, "unable to patch Component status")
		}
		reterr = kerrors.NewAggregate([]error{reterr, computeErr, patchErr})
	}()

	resolvedImage := instance.ResolveVersion(comp, defs)
	comp.Status.Version = resolvedImage
	comp.Status.ResourceType = defs.ResourceType

	// Ensure the service account is created.
	if err := r.ensureServiceAccount(ctx, comp); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the clusterrole is created.
	if err := r.ensureClusterRole(ctx, comp, defs); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the clusterrolebinding is created.
	if err := r.ensureClusterRoleBinding(ctx, comp); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the service is created.
	if err := r.ensureService(ctx, comp, defs); err != nil {
		return ctrl.Result{}, err
	}

	// Set the finalizer if needed.
	if ok, err := r.ensureFinalizer(ctx, comp); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the deployment is created.
	if err := r.ensureDeployment(ctx, comp, defs); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&instancev1alpha1.Component{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.Service{}).
		Watches(&rbacv1.ClusterRole{}, handler.EnqueueRequestsFromMapFunc(instance.ClusterScopedResourceHandler)).
		Watches(&rbacv1.ClusterRoleBinding{}, handler.EnqueueRequestsFromMapFunc(instance.ClusterScopedResourceHandler)).
		Named("component").
		Complete(r)
}

// ensureDeployment ensures the Component Deployment is created or updated.
func (r *Reconciler) ensureDeployment(ctx context.Context, comp *instancev1alpha1.Component, defs *resources.InstanceDefaults) error {
	logger := log.FromContext(ctx)

	conditionStatus := metav1.ConditionTrue
	conditionReason := ""
	conditionMessage := ""

	defer func() {
		apimeta.SetStatusCondition(&comp.Status.Conditions, common.NewReconciledCondition(
			conditionStatus,
			conditionReason,
			conditionMessage,
			comp.GetGeneration(),
		))
	}()

	logger.V(2).Info("Generating apply configuration from user input")
	applyConfig, err := generateApplyConfiguration(comp, defs)
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

	if err = ctrl.SetControllerReference(comp, applyConfig, r.Scheme); err != nil {
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
		Kind:    resources.ResourceTypeDeployment,
	})
	resourceExists := true
	if err = r.Get(ctx, client.ObjectKeyFromObject(comp), existingResource); err != nil {
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
			logger.V(2).Info("No managed fields found, proceeding with apply to take ownership")
		} else {
			if comparison.IsSame() {
				logger.V(2).Info("Component resource is up to date, skipping apply", "type", comp.Spec.Component.Type)
				conditionReason = instance.ReasonResourceUpToDate
				conditionMessage = instance.MessageResourceUpToDate
				return nil
			}
			changedFields = controllerhelper.FormatChangedFields(comparison)
		}
	}

	if !resourceExists {
		logger.Info("Creating Component resource", "type", comp.Spec.Component.Type)
	}

	applyOpts := []client.ApplyOption{client.ForceOwnership, client.FieldOwner(fieldManager)}
	if err = r.Apply(ctx, client.ApplyConfigurationFromUnstructured(applyConfig), applyOpts...); err != nil {
		if !resourceExists {
			conditionStatus = metav1.ConditionFalse
			conditionReason = instance.ReasonApplyPatchErrorOnCreate
			conditionMessage = fmt.Sprintf(instance.MessageFormatApplyPatchErrorOnCreate, err.Error())
			r.recorder.Eventf(comp, nil, corev1.EventTypeWarning, instance.ReasonApplyPatchErrorOnCreate,
				instance.ReasonApplyPatchErrorOnCreate, instance.MessageFormatApplyPatchErrorOnCreate, err.Error())
		} else {
			conditionStatus = metav1.ConditionFalse
			conditionReason = instance.ReasonApplyPatchErrorOnUpdate
			conditionMessage = fmt.Sprintf(instance.MessageFormatApplyPatchErrorOnUpdate, err.Error())
			r.recorder.Eventf(comp, nil, corev1.EventTypeWarning, instance.ReasonApplyPatchErrorOnUpdate,
				instance.ReasonApplyPatchErrorOnUpdate, instance.MessageFormatApplyPatchErrorOnUpdate, err.Error())
		}
		// Validation errors are terminal — the user must fix the CR spec.
		// Don't requeue; the next reconciliation will be triggered by the CR update.
		if k8serrors.IsInvalid(err) {
			logger.Info("Apply rejected by API server due to invalid input", "type", comp.Spec.Component.Type, "error", err.Error())
			return nil
		}
		logger.Error(err, "unable to apply resource", "type", comp.Spec.Component.Type)
		return err
	}

	if !resourceExists {
		logger.Info("Component resource created", "type", comp.Spec.Component.Type)
		conditionReason = instance.ReasonResourceCreated
		conditionMessage = instance.MessageResourceCreated
		r.recorder.Eventf(comp, nil, corev1.EventTypeNormal, instance.ReasonResourceCreated,
			instance.ReasonResourceCreated, instance.MessageResourceCreated)
	} else {
		logger.Info("Component resource updated", "type", comp.Spec.Component.Type, "changedFields", changedFields)
		conditionReason = instance.ReasonResourceUpdated
		conditionMessage = fmt.Sprintf(instance.MessageFormatResourceUpdated, changedFields)
		r.recorder.Eventf(comp, nil, corev1.EventTypeNormal, instance.ReasonResourceUpdated,
			instance.ReasonResourceUpdated, instance.MessageFormatResourceUpdated, changedFields)
	}

	return nil
}

// computeAvailableCondition queries the live Deployment state.
func (r *Reconciler) computeAvailableCondition(ctx context.Context, comp *instancev1alpha1.Component) error {
	result, err := instance.ComputeDeploymentAvailability(ctx, r.Client, client.ObjectKeyFromObject(comp), comp.Spec.Replicas)

	comp.Status.DesiredReplicas = result.DesiredReplicas
	comp.Status.AvailableReplicas = result.AvailableReplicas
	comp.Status.UnavailableReplicas = result.UnavailableReplicas

	apimeta.SetStatusCondition(&comp.Status.Conditions, common.NewAvailableCondition(
		result.ConditionStatus, result.Reason, result.Message, comp.GetGeneration()))

	switch result.ConditionStatus {
	case metav1.ConditionTrue:
		r.recorder.Eventf(comp, nil, corev1.EventTypeNormal, result.Reason, result.Reason, result.Message)
	case metav1.ConditionFalse:
		r.recorder.Eventf(comp, nil, corev1.EventTypeWarning, result.Reason, result.Reason, result.Message)
	case metav1.ConditionUnknown:
		// No event on unknown status
	}

	return err
}

// patchStatus patches the Component status using server-side apply.
func (r *Reconciler) patchStatus(ctx context.Context, comp *instancev1alpha1.Component) error {
	return controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, comp, fieldManager)
}

// ensureFinalizer ensures the finalizer is set on the object and returns true if the object was updated.
func (r *Reconciler) ensureFinalizer(ctx context.Context, comp *instancev1alpha1.Component) (bool, error) {
	return instance.EnsureFinalizer(ctx, r.Client, comp, finalizer)
}

// handleDeletion handles the deletion of the Component instance.
func (r *Reconciler) handleDeletion(ctx context.Context, comp *instancev1alpha1.Component) (bool, error) {
	return instance.HandleDeletion(ctx, r.Client, r.recorder, comp, finalizer, clusterScopedGVKs,
		fmt.Sprintf(instance.MessageFormatComponentInstanceDeleted, comp.Spec.Component.Type))
}

// ensureServiceAccount ensures the ServiceAccount is created or updated.
func (r *Reconciler) ensureServiceAccount(ctx context.Context, comp *instancev1alpha1.Component) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, comp, fieldManager,
		resources.GenerateServiceAccount(comp),
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false})
}

// ensureClusterRole ensures the ClusterRole is created or updated.
func (r *Reconciler) ensureClusterRole(ctx context.Context, comp *instancev1alpha1.Component, defs *resources.InstanceDefaults) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, comp, fieldManager,
		resources.GenerateClusterRole(comp, defs),
		instance.GenerateOptions{SetControllerRef: false, IsClusterScoped: true})
}

// ensureClusterRoleBinding ensures the ClusterRoleBinding is created or updated.
func (r *Reconciler) ensureClusterRoleBinding(ctx context.Context, comp *instancev1alpha1.Component) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, comp, fieldManager,
		resources.GenerateClusterRoleBinding(comp),
		instance.GenerateOptions{SetControllerRef: false, IsClusterScoped: true})
}

// ensureService ensures the Service is created or updated.
func (r *Reconciler) ensureService(ctx context.Context, comp *instancev1alpha1.Component, defs *resources.InstanceDefaults) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, comp, fieldManager,
		resources.GenerateService(comp, defs),
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false})
}
