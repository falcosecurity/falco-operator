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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/internal/pkg/image"
)

// EnsureResource generates the desired sub-resource via GenerateResource, diffs it against
// the live object, and applies it via server-side apply when needed.
func EnsureResource[T client.Object](ctx context.Context, cl client.Client, recorder events.EventRecorder,
	obj T, fieldManager string,
	generator ResourceGenerator[T], options GenerateOptions) error {
	logger := log.FromContext(ctx)

	desiredResource, err := GenerateResource(cl, obj, generator, options)
	if err != nil {
		recorder.Eventf(obj, nil, corev1.EventTypeWarning, ReasonResourceGenerateError,
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
		comparison, err := Diff(existingResource, desiredResource, fieldManager)
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
			changedFields = FormatChangedFields(comparison)
		}
	}

	applyOpts := []client.ApplyOption{client.ForceOwnership, client.FieldOwner(fieldManager)}
	if err := cl.Apply(ctx, client.ApplyConfigurationFromUnstructured(desiredResource), applyOpts...); err != nil {
		recorder.Eventf(obj, nil, corev1.EventTypeWarning, ReasonResourceApplyError,
			ReasonResourceApplyError, MessageFormatResourceApplyError, resourceType, err.Error())
		return fmt.Errorf("unable to apply %s: %w", resourceType, err)
	}

	if !resourceExists {
		logger.V(3).Info(resourceType+" created", "name", desiredResource.GetName())
		recorder.Eventf(obj, nil, corev1.EventTypeNormal, ReasonSubResourceCreated,
			ReasonSubResourceCreated, MessageFormatSubResourceCreated, resourceType, desiredResource.GetName())
	} else {
		logger.V(3).Info(resourceType+" updated", "name", desiredResource.GetName(), "changedFields", changedFields)
		recorder.Eventf(obj, nil, corev1.EventTypeNormal, ReasonSubResourceUpdated,
			ReasonSubResourceUpdated, MessageFormatSubResourceUpdated, resourceType, desiredResource.GetName())
	}

	return nil
}

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

	resourceName := GenerateUniqueName(obj.GetName(), obj.GetNamespace())

	for _, gvk := range clusterScopedGVKs {
		res := &unstructured.Unstructured{}
		res.SetGroupVersionKind(gvk)
		res.SetName(resourceName)
		if err := cl.Delete(ctx, res); err != nil && !apierrors.IsNotFound(err) {
			log.FromContext(ctx).Error(err, "unable to delete cluster resource", "kind", gvk.Kind)
			recorder.Eventf(obj, nil, corev1.EventTypeWarning, ReasonDeletionError,
				ReasonDeletionError, MessageFormatDeletionError, gvk.Kind, err.Error())
			return false, err
		}
	}

	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	controllerutil.RemoveFinalizer(obj, finalizerName)
	if err := cl.Patch(ctx, obj, patch); err != nil && !apierrors.IsNotFound(err) {
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

// ResolveVersion determines the version to use for an instance controller, following this priority:
// 1. Version extracted from the container image tag (highest priority).
// 2. Version specified in the CR spec.
// 3. Default version from the image tag constant (lowest priority).
func ResolveVersion(currentVersion string, podTemplateSpec *corev1.PodTemplateSpec, containerName, defaultVersion string) string {
	version := defaultVersion

	if currentVersion != "" {
		version = currentVersion
	}

	if podTemplateSpec != nil {
		for i := range podTemplateSpec.Spec.Containers {
			if podTemplateSpec.Spec.Containers[i].Name == containerName {
				if v := image.VersionFromImage(podTemplateSpec.Spec.Containers[i].Image); v != "" {
					version = v
				}
				break
			}
		}
	}

	return version
}
