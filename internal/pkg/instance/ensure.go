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

package instance

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

// EnsureFinalizer ensures the finalizer is set on the object and returns true if the object was updated.
func EnsureFinalizer(ctx context.Context, cl client.Client, obj client.Object, finalizerName string) (bool, error) {
	if !controllerutil.ContainsFinalizer(obj, finalizerName) {
		log.FromContext(ctx).V(3).Info("Setting finalizer", "finalizer", finalizerName)

		patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
		controllerutil.AddFinalizer(obj, finalizerName)
		if err := cl.Patch(ctx, obj, patch); err != nil {
			log.FromContext(ctx).Error(err, "unable to set finalizer", "finalizer", finalizerName)
			return false, err
		}
		log.FromContext(ctx).V(3).Info("Finalizer set", "finalizer", finalizerName)
		return true, nil
	}
	return false, nil
}

// HandleDeletion handles the deletion of an instance by cleaning up cluster-scoped resources
// and removing the finalizer.
func HandleDeletion(ctx context.Context, cl client.Client, recorder events.EventRecorder,
	obj client.Object, finalizerName string, clusterScopedGVKs []schema.GroupVersionKind,
	deletedMessage string) (bool, error) {
	if obj.GetDeletionTimestamp() == nil {
		return false, nil
	}

	// Check if finalizer is already removed
	if !controllerutil.ContainsFinalizer(obj, finalizerName) {
		// Finalizer already removed, nothing to do
		return true, nil
	}

	log.FromContext(ctx).Info("Instance marked for deletion, removing finalizer", "finalizer", finalizerName)

	resourceName := resources.GenerateUniqueName(obj.GetName(), obj.GetNamespace())

	for _, gvk := range clusterScopedGVKs {
		res := &unstructured.Unstructured{}
		res.SetGroupVersionKind(gvk)
		res.SetName(resourceName)
		if err := cl.Delete(ctx, res); err != nil && !k8serrors.IsNotFound(err) {
			log.FromContext(ctx).Error(err, "unable to delete cluster resource", "kind", gvk.Kind)
			recorder.Eventf(obj, nil, corev1.EventTypeWarning, ReasonDeletionError,
				ReasonDeletionError, MessageFormatDeletionError, gvk.Kind, err.Error())
			return false, err
		}
	}

	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	controllerutil.RemoveFinalizer(obj, finalizerName)
	if err := cl.Patch(ctx, obj, patch); err != nil && !k8serrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "unable to remove finalizer from instance")
		recorder.Eventf(obj, nil, corev1.EventTypeWarning, ReasonDeletionError,
			ReasonDeletionError, MessageFormatDeletionError, "Finalizer", err.Error())
		return false, err
	}

	log.FromContext(ctx).Info("Instance deleted")
	recorder.Eventf(obj, nil, corev1.EventTypeNormal, ReasonInstanceDeleted,
		ReasonInstanceDeleted, deletedMessage)

	return true, nil
}

// GenerateOptions defines options for resource generation.
type GenerateOptions struct {
	// SetControllerRef indicates whether to set the controller reference.
	SetControllerRef bool
	// IsClusterScoped indicates whether the resource is cluster-scoped.
	IsClusterScoped bool
}

// PrepareResource converts a runtime.Object into an unstructured resource ready for server-side apply.
// It optionally sets the controller reference and sets the name based on the resource scope.
func PrepareResource(
	cl client.Client,
	owner client.Object,
	resource runtime.Object,
	options GenerateOptions,
) (*unstructured.Unstructured, error) {
	if owner == nil || reflect.ValueOf(owner).IsNil() {
		return nil, fmt.Errorf("owner cannot be nil")
	}

	if cl == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}

	if resource == nil {
		return nil, fmt.Errorf("resource cannot be nil")
	}

	// Set controller reference if requested.
	if options.SetControllerRef {
		if err := controllerutil.SetControllerReference(owner, resource.(metav1.Object), cl.Scheme()); err != nil {
			return nil, fmt.Errorf("failed to set controller reference: %w", err)
		}
	}

	// Convert to unstructured.
	unstructuredObj, err := controllerhelper.ToUnstructured(resource)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to unstructured: %w", err)
	}

	// Set the name based on the resource scope.
	if options.IsClusterScoped {
		resourceName := resources.GenerateUniqueName(owner.GetName(), owner.GetNamespace())
		if err := unstructured.SetNestedField(unstructuredObj.Object, resourceName, "metadata", "name"); err != nil {
			return nil, fmt.Errorf("failed to set name field for cluster-scoped resource: %w", err)
		}
	} else {
		if err := unstructured.SetNestedField(unstructuredObj.Object, owner.GetName(), "metadata", "name"); err != nil {
			return nil, fmt.Errorf("failed to set name field for namespaced resource: %w", err)
		}
	}

	return unstructuredObj, nil
}

// EnsureResource prepares a runtime.Object for server-side apply, diffs it against
// the live object, and applies it when needed.
func EnsureResource(ctx context.Context, cl client.Client, recorder events.EventRecorder,
	owner client.Object, fieldManager string,
	resource runtime.Object, options GenerateOptions) error {
	logger := log.FromContext(ctx)

	desiredResource, err := PrepareResource(cl, owner, resource, options)
	if err != nil {
		recorder.Eventf(owner, nil, corev1.EventTypeWarning, ReasonResourceGenerateError,
			ReasonResourceGenerateError, MessageFormatResourceGenerateError, err.Error())
		return fmt.Errorf("unable to generate desired resource: %w", err)
	}

	resourceType := desiredResource.GetKind()

	logger.V(3).Info("Ensuring resource", "type", resourceType, "name", desiredResource.GetName())

	// Check if the resource already exists.
	existingResource := &unstructured.Unstructured{}
	existingResource.SetGroupVersionKind(desiredResource.GetObjectKind().GroupVersionKind())
	resourceExists := true
	if err = cl.Get(ctx, client.ObjectKeyFromObject(desiredResource), existingResource); err != nil {
		if k8serrors.IsNotFound(err) {
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
		comparison, err := controllerhelper.Diff(existingResource, desiredResource, fieldManager)
		if err != nil {
			if !errors.Is(err, controllerhelper.ErrNoManagedFields) {
				return fmt.Errorf("unable to compare existing %s with desired state: %w", resourceType, err)
			}
			logger.V(3).Info("No managed fields found, proceeding with apply to take ownership", "type", resourceType, "name", desiredResource.GetName())
		} else {
			if comparison.IsSame() {
				logger.V(3).Info(resourceType+" is up to date, skipping apply", "name", desiredResource.GetName())
				return nil
			}
			changedFields = controllerhelper.FormatChangedFields(comparison)
		}
	}

	applyOpts := []client.ApplyOption{client.ForceOwnership, client.FieldOwner(fieldManager)}
	if err := cl.Apply(ctx, client.ApplyConfigurationFromUnstructured(desiredResource), applyOpts...); err != nil {
		recorder.Eventf(owner, nil, corev1.EventTypeWarning, ReasonResourceApplyError,
			ReasonResourceApplyError, MessageFormatResourceApplyError, resourceType, err.Error())
		// Validation errors are terminal — the user must fix the CR spec.
		// Return nil so controller-runtime does not requeue with stack trace spam.
		if k8serrors.IsInvalid(err) {
			logger.Info("Apply rejected by API server due to invalid input", "type", resourceType, "name", desiredResource.GetName(), "error", err.Error())
			return nil
		}
		return fmt.Errorf("unable to apply %s: %w", resourceType, err)
	}

	if !resourceExists {
		logger.V(3).Info(resourceType+" created", "name", desiredResource.GetName())
		recorder.Eventf(owner, nil, corev1.EventTypeNormal, ReasonSubResourceCreated,
			ReasonSubResourceCreated, MessageFormatSubResourceCreated, resourceType, desiredResource.GetName())
	} else {
		logger.V(3).Info(resourceType+" updated", "name", desiredResource.GetName(), "changedFields", changedFields)
		recorder.Eventf(owner, nil, corev1.EventTypeNormal, ReasonSubResourceUpdated,
			ReasonSubResourceUpdated, MessageFormatSubResourceUpdated, resourceType, desiredResource.GetName(), changedFields)
	}

	return nil
}
