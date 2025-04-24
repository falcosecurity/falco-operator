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
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

const (
	// pluginFinalizerPrefix is the prefix for the finalizer name.
	pluginFinalizerPrefix = "plugin.artifact.falcosecurity.dev/finalizer"
)

// NewPluginReconciler creates a new PluginReconciler instance.
func NewPluginReconciler(cl client.Client, scheme *runtime.Scheme, nodeName, namespace string) *PluginReconciler {
	return &PluginReconciler{
		Client:          cl,
		Scheme:          scheme,
		finalizer:       common.FormatFinalizerName(pluginFinalizerPrefix, nodeName),
		artifactManager: artifact.NewManager(cl, namespace),
	}
}

// PluginReconciler reconciles a Plugin object.
type PluginReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	finalizer       string
	artifactManager *artifact.ArtifactManager
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PluginReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var err error
	logger := log.FromContext(ctx)
	plugin := &artifactv1alpha1.Plugin{}

	// Fetch the Plugin instance.
	logger.V(2).Info("Fetching Plugin instance")
	if err = r.Get(ctx, req.NamespacedName, plugin); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "Unable to fetch Plugin")
		return ctrl.Result{}, err
	} else if apierrors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion of the Plugin instance.
	if ok, err := r.handleDeletion(ctx, plugin); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the finalizer is set on the Plugin instance.
	if ok, err := r.ensureFinalizers(ctx, plugin); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the Plugin instance is created and configured correctly.
	if err := r.ensurePlugin(ctx, plugin); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PluginReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Plugin{}).
		Named("artifact-plugin").
		Complete(r)
}

// ensureFinalizers ensures that the finalizer is set on the Plugin instance.
func (r *PluginReconciler) ensureFinalizers(ctx context.Context, plugin *artifactv1alpha1.Plugin) (bool, error) {
	if !controllerutil.ContainsFinalizer(plugin, r.finalizer) {
		logger := log.FromContext(ctx)
		logger.V(3).Info("Setting finalizer", "finalizer", r.finalizer)
		controllerutil.AddFinalizer(plugin, r.finalizer)
		if err := r.Update(ctx, plugin); err != nil && !apierrors.IsConflict(err) {
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

// ensurePlugin ensures that the Plugin instance is created and configured correctly.
func (r *PluginReconciler) ensurePlugin(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	if err := r.artifactManager.StoreFromOCI(ctx, plugin.Name, priority.DefaultPriority, artifact.ArtifactTypePlugin, plugin.Spec.OCIArtifact); err != nil {
		return err
	}

	return nil
}

// handleDeletion handles the deletion of the Plugin instance.
func (r *PluginReconciler) handleDeletion(ctx context.Context, plugin *artifactv1alpha1.Plugin) (bool, error) {
	logger := log.FromContext(ctx)

	if !plugin.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(plugin, r.finalizer) {
			logger.Info("Plugin instance marked for deletion, cleaning up")
			if err := r.artifactManager.RemoveAll(ctx, plugin.Name); err != nil {
				return false, err
			}

			// Remove the finalizer.
			controllerutil.RemoveFinalizer(plugin, r.finalizer)
			if err := r.Update(ctx, plugin); err != nil && !apierrors.IsConflict(err) {
				logger.Error(err, "unable to remove finalizer", "finalizer", r.finalizer)
				return false, err
			} else if apierrors.IsConflict(err) {
				logger.Info("Conflict while removing finalizer, retrying")
				return true, nil
			}
		}

		return true, nil
	}

	return false, nil
}
