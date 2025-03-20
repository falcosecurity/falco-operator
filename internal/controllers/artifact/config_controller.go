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
	"fmt"
	"os"
	"path/filepath"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/alacuku/falco-operator/api/artifact/v1alpha1"
	"github.com/alacuku/falco-operator/internal/pkg/mounts"
	"github.com/alacuku/falco-operator/internal/pkg/priority"
)

const (
	configFinalizerPrefix = "config.artifact.falcosecurity.dev/finalizer"
)

// ConfigReconciler reconciles a Config object.
type ConfigReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	NodeName string
	// ConfigPriorities is a map of configuration names and their priorities.
	ConfigPriorities map[string]string
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
	if err := r.initConfigPriority(ctx, config); err != nil {
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
	if !controllerutil.ContainsFinalizer(config, r.getFinalizer()) {
		logger := log.FromContext(ctx)
		logger.V(3).Info("Setting finalizer", "finalizer", r.getFinalizer())
		controllerutil.AddFinalizer(config, r.getFinalizer())

		if err := r.Update(ctx, config); err != nil && !apierrors.IsConflict(err) {
			logger.Error(err, "unable to set finalizer", "finalizer", r.getFinalizer())
			return false, err
		} else if apierrors.IsConflict(err) {
			logger.V(3).Info("Conflict while setting finalizer, retrying")
			// It has already been added to the queue, so we return nil.
			return false, nil
		}

		logger.V(3).Info("Finalizer set", "finalizer", r.getFinalizer())
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
	p, err := priority.ValidateAndExtract(config.Annotations)
	if err != nil {
		logger.Error(err, "unable to get the priority of the configuration")
		return err
	}

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
		if controllerutil.ContainsFinalizer(config, r.getFinalizer()) {
			logger.Info("Config instance marked for deletion, cleaning up")
			// Get name of the configuration file.
			configFile, err := r.getConfigFilePath(ctx, config, "")
			if err != nil {
				return false, err
			}
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
			controllerutil.RemoveFinalizer(config, r.getFinalizer())
			if err := r.Update(ctx, config); err != nil && !apierrors.IsConflict(err) {
				logger.Error(err, "unable to remove finalizer", "finalizer", r.getFinalizer())
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

// getFinalizer returns the finalizer name based on the NodeName.
func (r *ConfigReconciler) getFinalizer() string {
	return fmt.Sprintf("%s-%s", configFinalizerPrefix, r.NodeName)
}

// cleanupOldConfigFile removes the old configuration file if the priority has changed.
func (r *ConfigReconciler) cleanupOldConfigFile(ctx context.Context, config *artifactv1alpha1.Config) error {
	logger := log.FromContext(ctx)

	// Get the current priority.
	currentPriority, err := priority.ValidateAndExtract(config.Annotations)
	if err != nil {
		logger.Error(err, "unable to get the current priority of the configuration")
		return err
	}

	// Get the old priority (if any).
	oldPriority, exists := r.ConfigPriorities[config.Name]

	// If the priority hasn't changed or there was no old priority, nothing to do.
	if !exists || oldPriority == currentPriority {
		return nil
	}

	// The priority has changed, so we need to remove the old configuration file
	oldConfigFile, err := r.getConfigFilePath(ctx, config, oldPriority)
	if err != nil {
		return err
	}

	// Check if the old file exists
	if _, err = os.Stat(oldConfigFile); err == nil {
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
	r.ConfigPriorities[config.Name] = currentPriority

	return nil
}

// initConfigPriority checks if a priority exists for the config in the ConfigPriorities map.
// If it doesn't exist, it extracts the priority from annotations and adds it to the map.
// If it already exists, it does nothing (even if the priority differs from the current one).
func (r *ConfigReconciler) initConfigPriority(ctx context.Context, config *artifactv1alpha1.Config) error {
	logger := log.FromContext(ctx)

	// If there's already a priority for this config, do nothing
	if _, exists := r.ConfigPriorities[config.Name]; exists {
		logger.V(3).Info("Priority already exists in the map, not changing it", "config", config.Name)
		return nil
	}

	// Extract priority from annotations
	p, err := priority.ValidateAndExtract(config.Annotations)
	if err != nil {
		logger.Error(err, "unable to extract priority from config annotations")
		return err
	}

	// Store the priority in the map
	r.ConfigPriorities[config.Name] = p
	logger.V(3).Info("Priority initialized for config", "config", config.Name, "priority", p)
	return nil
}

// getConfigFilePath returns the full file path for a Config resource.
func (r *ConfigReconciler) getConfigFilePath(ctx context.Context, config *artifactv1alpha1.Config, configPriority string) (string, error) {
	var p string
	var err error
	logger := log.FromContext(ctx)

	if configPriority != "" {
		p = configPriority
	} else {
		// Extract priority from the config
		p, err = priority.ValidateAndExtract(config.Annotations)
		if err != nil {
			logger.Error(err, "unable to extract priority from config")
			return "", fmt.Errorf("unable to extract priority from config %s: %w", config.Name, err)
		}
	}

	// Get the full file path and return it.
	return filepath.Clean(filepath.Join(mounts.ConfigDirPath, priority.NameFromPriority(p, config.Name+".yaml"))), nil
}
