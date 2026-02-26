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

package controllerhelper

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// PatchStatusSSA patches the status subresource of the given object using server-side apply.
// It converts the object to extract its current status, builds a minimal unstructured
// apply-configuration containing only identity fields and the status.
func PatchStatusSSA(ctx context.Context, c client.Client, scheme *runtime.Scheme, obj client.Object, fieldManager string) error {
	logger := log.FromContext(ctx)

	gvk, err := apiutil.GVKForObject(obj, scheme)
	if err != nil {
		logger.Error(err, "unable to resolve GVK for object")
		return fmt.Errorf("resolving GVK for %T: %w", obj, err)
	}

	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		logger.Error(err, "unable to convert object to unstructured")
		return fmt.Errorf("converting %T to unstructured: %w", obj, err)
	}

	statusField, found, err := unstructured.NestedFieldCopy(raw, "status")
	if err != nil {
		logger.Error(err, "unable to extract status field from unstructured")
		return fmt.Errorf("extracting status from %T: %w", obj, err)
	}
	if !found {
		return nil
	}

	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gvk)
	u.SetName(obj.GetName())
	u.SetNamespace(obj.GetNamespace())

	if err := unstructured.SetNestedField(u.Object, statusField, "status"); err != nil {
		return fmt.Errorf("setting status on unstructured: %w", err)
	}

	if err := c.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(u), client.FieldOwner(fieldManager), client.ForceOwnership); err != nil {
		if apierrors.IsConflict(err) {
			logger.V(3).Info("Conflict while patching status, will retry")
			return err
		}
		logger.Error(err, "unable to patch status")
		return err
	}
	return nil
}
