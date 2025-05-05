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

// Package controller defines controllers' logic.

package artifact

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
)

const (
	configFinalizerPrefix = "config.artifact.falcosecurity.dev/finalizer"
)

// NewConfigReconciler returns a new ConfigReconciler.
func NewConfigReconciler(cl client.Client, scheme *runtime.Scheme, nodeName, namespace string) *ConfigReconciler {
	return &ConfigReconciler{
		Client:          cl,
		Scheme:          scheme,
		finalizer:       common.FormatFinalizerName(configFinalizerPrefix, nodeName),
		artifactManager: artifact.NewManager(cl, namespace),
	}
}

// ConfigReconciler reconciles a Config object.
type ConfigReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	finalizer       string
	artifactManager *artifact.Manager
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var err error
	logger := log.FromContext(ctx)
	config := &artifactv1alpha1.Config{}

	// Fetch the Config instance.
	logger.V(2).Info("Fetching Config instance")

	if err = r.Get(ctx, req.NamespacedName, config); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch Config instance")
		return ctrl.Result{}, err
	} else if apierrors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Handle deletion.
	if ok, err := r.handleDeletion(ctx, config); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the finalizer is set.
	if ok, err := r.ensureFinalizer(ctx, config); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the configuration is written to the filesystem.
	if err := r.ensureConfig(ctx, config); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Config{}).
		Named("artifact-config").
		Complete(r)
}

// ensureFinalizer ensures the finalizer is set.
func (r *ConfigReconciler) ensureFinalizer(ctx context.Context, config *artifactv1alpha1.Config) (bool, error) {
	if !controllerutil.ContainsFinalizer(config, r.finalizer) {
		logger := log.FromContext(ctx)
		logger.V(3).Info("Setting finalizer", "finalizer", r.finalizer)
		controllerutil.AddFinalizer(config, r.finalizer)

		if err := r.Update(ctx, config); err != nil && !apierrors.IsConflict(err) {
			logger.Error(err, "unable to set finalizer", "finalizer", r.finalizer)
			return false, err
		} else if apierrors.IsConflict(err) {
			logger.V(3).Info("Conflict while setting finalizer, retrying")
			// It has already been added to the queue, so we return nil.
			return false, nil
		}

		logger.V(3).Info("Finalizer set", "finalizer", r.finalizer)
		return true, nil
	}

	return false, nil
}

// ensureConfig ensures the configuration is written to the filesystem.
func (r *ConfigReconciler) ensureConfig(ctx context.Context, config *artifactv1alpha1.Config) error {
	return r.artifactManager.StoreFromInLineYaml(ctx, config.Name, config.Spec.Priority, &config.Spec.Config, artifact.TypeConfig)
}

// handleDeletion handles the deletion of the Config instance.
// It removes the configuration file and the finalizer.
func (r *ConfigReconciler) handleDeletion(ctx context.Context, config *artifactv1alpha1.Config) (bool, error) {
	logger := log.FromContext(ctx)

	if !config.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(config, r.finalizer) {
			logger.Info("Config instance marked for deletion, cleaning up")
			if err := r.artifactManager.RemoveAll(ctx, config.Name); err != nil {
				return false, err
			}

			// Remove the finalizer.
			controllerutil.RemoveFinalizer(config, r.finalizer)
			if err := r.Update(ctx, config); err != nil && !apierrors.IsConflict(err) {
				logger.Error(err, "unable to remove finalizer", "finalizer", r.finalizer)
				return false, err
			} else if apierrors.IsConflict(err) {
				logger.Info("Conflict while removing finalizer, retrying")
				// It has already been added to the queue, so we return nil.
				return true, nil
			}
		}
		return true, nil
	}
	return false, nil
}
