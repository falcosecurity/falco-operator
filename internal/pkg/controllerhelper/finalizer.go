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

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// EnsureFinalizer adds the given finalizer to obj if not already present.
// Returns (true, nil) when the finalizer was just added, (false, nil) if already present,
// or (false, err) on patch failure.
func EnsureFinalizer(ctx context.Context, cl client.Client, finalizer string, obj client.Object) (bool, error) {
	if controllerutil.ContainsFinalizer(obj, finalizer) {
		return false, nil
	}

	logger := log.FromContext(ctx)
	logger.V(3).Info("Setting finalizer", "finalizer", finalizer)

	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	controllerutil.AddFinalizer(obj, finalizer)
	if err := cl.Patch(ctx, obj, patch); err != nil {
		if k8serrors.IsConflict(err) {
			logger.V(3).Info("Conflict while setting finalizer, will retry")
			return false, err
		}
		logger.Error(err, "unable to set finalizer", "finalizer", finalizer)
		return false, err
	}

	logger.V(3).Info("Finalizer set", "finalizer", finalizer)
	return true, nil
}
