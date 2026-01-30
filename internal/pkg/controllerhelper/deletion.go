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

// Package controllerhelper contains common helper for controllers.
package controllerhelper

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// HandleObjectDeletion handles the deletion of an object.
// It removes the finalizer and cleans up the local resources associated with the object.
func HandleObjectDeletion(ctx context.Context, cl client.Client, am *artifact.Manager, finalizer string, obj client.Object) (bool, error) {
	logger := log.FromContext(ctx)

	if !obj.GetDeletionTimestamp().IsZero() {
		if controllerutil.ContainsFinalizer(obj, finalizer) {
			logger.Info("Config instance marked for deletion, cleaning up")
			if err := am.RemoveAll(ctx, obj.GetName()); err != nil {
				return false, err
			}

			// Remove the finalizer.
			patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
			controllerutil.RemoveFinalizer(obj, finalizer)
			if err := cl.Patch(ctx, obj, patch); err != nil {
				logger.Error(err, "unable to remove finalizer", "finalizer", finalizer)
				return false, err
			}
		}
		return true, nil
	}
	return false, nil
}

// RemoveLocalResources removes local resources associated with the object.
// Helps to clean up local resources when the object is not targeting the current node anymore.
// It also removes the finalizer from the object.
func RemoveLocalResources(ctx context.Context, cl client.Client, am *artifact.Manager, finalizer string, obj client.Object) (bool, error) {
	// If the object contains the finalizer it means that we processed it before.
	if controllerutil.ContainsFinalizer(obj, finalizer) {
		if err := am.RemoveAll(ctx, obj.GetName()); err != nil {
			return false, err
		}

		// Remove the finalizer.
		patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
		controllerutil.RemoveFinalizer(obj, finalizer)
		if err := cl.Patch(ctx, obj, patch); err != nil {
			return false, err
		}
	}
	return true, nil
}
