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
	"os"
	"path/filepath"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/mounts"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

const (
	configFinalizerPrefix = "config.artifact.falcosecurity.dev/finalizer"
)

// NewConfigReconciler returns a new ConfigReconciler.
func NewConfigReconciler(cl client.Client, scheme *runtime.Scheme, nodeName string) *ConfigReconciler {
	return &ConfigReconciler{
		Client:           cl,
		Scheme:           scheme,
		finalizer:        common.FormatFinalizerName(configFinalizerPrefix, nodeName),
		configPriorities: make(map[string]int32),
	}
}

// ConfigReconciler reconciles a Config object.
type ConfigReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	finalizer string
	// configPriorities is a map of configuration names and their priorities.
	configPriorities map[string]int32
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

	// Initialize the priority of the configuration.
	r.initConfigPriority(ctx, config)

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
	logger := log.FromContext(ctx)
	var err error

	// Cleanup old configuration file if the priority has changed.
	if err := r.cleanupOldConfigFile(ctx, config); err != nil {
		return err
	}

	// Get the priority of the configuration.
	p := config.Spec.Priority

	baseName := priority.NameFromPriority(p, config.Name+".yaml")
	configFile := filepath.Clean(filepath.Join(mounts.ConfigDirPath, baseName))

	// Check if the configuration file exists and is up to date.
	if _, err = os.Stat(configFile); err == nil {
		// Read the file.
		content, err := os.ReadFile(configFile)
		if err != nil {
			logger.Error(err, "unable to read config file", "file", configFile)
			return err
		}
		// Check if the content is the same.
		if string(content) == config.Spec.Config {
			logger.V(3).Info("Config file is up to date", "file", configFile)
			return nil
		}
		// The content is different, remove the file.
		// Overlayfs's support for inotify mechanisms is not complete yet.
		// Events like IN_CLOSE_WRITE cannot be notified to listening process.
		if err := os.Remove(configFile); err != nil {
			logger.Error(err, "unable to remove config file", "file", configFile)
			return err
		}
	} else if !os.IsNotExist(err) {
		logger.Error(err, "unable to check if file exists", "file", configFile)
		return err
	}

	// Write the configuration to the filesystem.
	if err := os.WriteFile(configFile, []byte(config.Spec.Config), 0o600); err != nil {
		logger.Error(err, "unable to write config file", "file", configFile)
		return err
	}

	logger.Info("Config file correctly written to filesystem", "file", configFile)
	return nil
}

// handleDeletion handles the deletion of the Config instance.
// It removes the configuration file and the finalizer.
func (r *ConfigReconciler) handleDeletion(ctx context.Context, config *artifactv1alpha1.Config) (bool, error) {
	logger := log.FromContext(ctx)
	if !config.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(config, r.finalizer) {
			logger.Info("Config instance marked for deletion, cleaning up")
			// Get name of the configuration file.
			configFile := r.getConfigFilePath(config, config.Spec.Priority)
			// Check if the file exists and remove it.
			if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
				logger.Error(err, "unable to remove config file", "file", configFile)
				return false, err
			} else if os.IsNotExist(err) {
				logger.Info("Config file does not exist, nothing to be done", "file", configFile)
			} else {
				logger.Info("Config file correctly removed", "file", configFile)
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
			return true, nil
		}
		return true, nil
	}
	return false, nil
}

// cleanupOldConfigFile removes the old configuration file if the priority has changed.
func (r *ConfigReconciler) cleanupOldConfigFile(ctx context.Context, config *artifactv1alpha1.Config) error {
	logger := log.FromContext(ctx)

	// Get the current priority.
	currentPriority := config.Spec.Priority

	// Get the old priority (if any).
	oldPriority, exists := r.configPriorities[config.Name]

	// If the priority hasn't changed or there was no old priority, nothing to do.
	if !exists || oldPriority == currentPriority {
		return nil
	}

	// The priority has changed, so we need to remove the old configuration file
	oldConfigFile := r.getConfigFilePath(config, oldPriority)

	// Check if the old file exists
	if _, err := os.Stat(oldConfigFile); err == nil {
		// File exists, remove it
		if err := os.Remove(oldConfigFile); err != nil {
			logger.Error(err, "unable to remove old config file", "file", oldConfigFile)
			return err
		}
		logger.Info("Old config file removed due to priority change",
			"file", oldConfigFile,
			"old priority", oldPriority,
			"new priority", currentPriority)
	} else if !os.IsNotExist(err) {
		logger.Error(err, "unable to check if old file exists", "file", oldConfigFile)
		return err
	}

	// Update the stored priority
	r.configPriorities[config.Name] = currentPriority

	return nil
}

// initConfigPriority checks if a priority exists for the config in the configPriorities map.
// If it doesn't exist, it extracts the priority from annotations and adds it to the map.
// If it already exists, it does nothing (even if the priority differs from the current one).
func (r *ConfigReconciler) initConfigPriority(ctx context.Context, config *artifactv1alpha1.Config) {
	logger := log.FromContext(ctx)

	// If there's already a priority for this config, do nothing
	if _, exists := r.configPriorities[config.Name]; exists {
		logger.V(3).Info("Priority already exists in the map, not changing it", "config", config.Name)
		return
	}

	// Store the priority in the map
	r.configPriorities[config.Name] = config.Spec.Priority
	logger.V(3).Info("Priority initialized for config", "config", config.Name, "priority", config.Spec.Priority)
}

// getConfigFilePath returns the full file path for a Config resource.
func (r *ConfigReconciler) getConfigFilePath(config *artifactv1alpha1.Config, configPriority int32) string {
	// Get the full file path and return it.
	return filepath.Clean(filepath.Join(mounts.ConfigDirPath, priority.NameFromPriority(configPriority, config.Name+".yaml")))
}
