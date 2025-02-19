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

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	instancev1alpha1 "github.com/alacuku/falco-operator/api/v1alpha1"
)

const (
	finalizer = "falco.falcosecurity.dev/finalizer"
)

// Reconciler reconciles a Falco object.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete

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

	logger.V(2).Info("Generating apply configuration from user input")
	applyConfig, err := generateApplyConfiguration(ctx, r.Client, falco)
	if err != nil {
		logger.Error(err, "unable to generate apply configuration")
		return err
	}

	// transform the apply configuration to yaml.
	applyConfigYaml, err := yaml.Marshal(applyConfig.Object)
	if err != nil {
		logger.Error(err, "unable to marshal apply configuration")
		return err
	}

	logger.V(4).Info("Generated apply configuration", "yaml", string(applyConfigYaml))

	// Set owner reference.
	if err = ctrl.SetControllerReference(falco, applyConfig, r.Scheme); err != nil {
		logger.Error(err, "unable to set owner reference")
		return err
	}

	// Get existing Falco deployment/daemonset
	existingResource := &unstructured.Unstructured{}
	existingResource.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "apps",
		Version: "v1",
		Kind:    falco.Spec.Type, // "Deployment" or "DaemonSet"
	})

	if err = r.Get(ctx, client.ObjectKeyFromObject(falco), existingResource); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch existing resource")
		return err
	}

	// If the resource has not been found, create it.
	if apierrors.IsNotFound(err) {
		logger.Info("Creating Falco resource", "kind", falco.Spec.Type)
		err = r.Patch(ctx, applyConfig, client.Apply, client.ForceOwnership, client.FieldOwner("falco-controller"))
		if err != nil {
			logger.Error(err, "unable to apply patch")
			return err
		}
		return nil
	}

	// If the resource has been found remove all the fields that are not needed.
	removeUnwantedFields(existingResource)

	cmp, err := diff(existingResource, applyConfig)
	if err != nil {
		logger.Error(err, "unable to compare existing and desired resources", "existing", existingResource, "desired", applyConfig)
		return err
	}

	if cmp.IsSame() {
		logger.V(2).Info("Falco resource is up to date", "kind", falco.Spec.Type)
		return nil
	}

	logger.Info("Updating Falco resource", "kind", falco.Spec.Type, "diff", cmp.String())
	if err = r.Patch(ctx, applyConfig, client.Apply, client.ForceOwnership, client.FieldOwner("falco-controller")); err != nil {
		logger.Error(err, "unable to apply patch", "kind", falco.Spec.Type, "patch", applyConfig)
		return err
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
			Group:   "apps",
			Version: "v1",
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
