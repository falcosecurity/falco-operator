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

package plugin

import (
	"context"

	"gopkg.in/yaml.v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

const (
	// pluginFinalizerPrefix is the prefix for the finalizer name.
	pluginFinalizerPrefix = "plugin.artifact.falcosecurity.dev/finalizer"
	// pluginConfigFileName is the name of the plugin configuration file.
	pluginConfigFileName = "plugins-config"
)

// NewPluginReconciler creates a new PluginReconciler instance.
func NewPluginReconciler(cl client.Client, scheme *runtime.Scheme, nodeName, namespace string) *PluginReconciler {
	return &PluginReconciler{
		Client:          cl,
		Scheme:          scheme,
		finalizer:       common.FormatFinalizerName(pluginFinalizerPrefix, nodeName),
		artifactManager: artifact.NewManager(cl, namespace),
		PluginsConfig:   &PluginsConfig{},
		nodeName:        nodeName,
	}
}

// PluginReconciler reconciles a Plugin object.
type PluginReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	finalizer       string
	artifactManager *artifact.Manager
	PluginsConfig   *PluginsConfig
	nodeName        string
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

	// Check if the Plugin instance is for the current node.
	if ok, err := controllerhelper.NodeMatchesSelector(ctx, r.Client, r.nodeName, plugin.Spec.Selector); err != nil {
		return ctrl.Result{}, err
	} else if !ok {
		logger.Info("Plugin instance does not match node selector, will remove local resources if any")

		// Here we handle the case where the plugin was created with a selector that matched the node, but now it doesn't.
		if ok, err := controllerhelper.RemoveLocalResources(ctx, r.Client, r.artifactManager, r.finalizer, plugin); ok || err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
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

	// Ensure the plugin configuration is set correctly.
	if err := r.ensurePluginConfig(ctx, plugin); err != nil {
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
	if err := r.artifactManager.StoreFromOCI(ctx, plugin.Name, priority.DefaultPriority, artifact.TypePlugin, plugin.Spec.OCIArtifact); err != nil {
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

			// Remove the plugin configuration.
			r.PluginsConfig.removeConfig(plugin)

			// Write the updated configuration to the file.
			if err := r.removePluginConfig(ctx, plugin); err != nil {
				logger.Error(err, "unable to remove plugin config")
				return false, err
			}
			// Remove the finalizer.
			logger.V(3).Info("Removing finalizer", "finalizer", r.finalizer)
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

// Ensure plugin configuration is set correctly.
func (r *PluginReconciler) ensurePluginConfig(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	logger := log.FromContext(ctx)
	logger.Info("Ensuring plugin configuration")
	r.PluginsConfig.addConfig(plugin)
	// Convert the struct to string.
	pluginConfigString, err := r.PluginsConfig.toString()
	if err != nil {
		logger.Error(err, "unable to convert plugin config to string")
		return err
	}

	if err := r.artifactManager.StoreFromInLineYaml(ctx, pluginConfigFileName, priority.MaxPriority,
		&pluginConfigString, artifact.TypeConfig); err != nil {
		logger.Error(err, "unable to store plugin config", "filename", pluginConfigFileName)
		return err
	}

	return nil
}

// removePluginConfig removes the plugin configuration from the configuration file.
func (r *PluginReconciler) removePluginConfig(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	logger := log.FromContext(ctx)
	logger.Info("Removing plugin configuration")
	r.PluginsConfig.removeConfig(plugin)

	if r.PluginsConfig.isEmpty() {
		logger.Info("Plugin configuration is empty, removing file")
		if err := r.artifactManager.RemoveAll(ctx, pluginConfigFileName); err != nil {
			logger.Error(err, "unable to remove plugin config", "filename", pluginConfigFileName)
			return err
		}
		return nil
	}

	// Convert the struct to string.
	pluginConfigString, err := r.PluginsConfig.toString()
	if err != nil {
		logger.Error(err, "unable to convert plugin config to string")
		return err
	}

	if err := r.artifactManager.StoreFromInLineYaml(ctx, pluginConfigFileName, priority.MaxPriority,
		&pluginConfigString, artifact.TypeConfig); err != nil {
		logger.Error(err, "unable to store plugin config", "filename", pluginConfigFileName)
		return err
	}

	return nil
}

// PluginConfig is the configuration for a plugin.
type PluginConfig struct {
	InitConfig  map[string]string `yaml:"init_config,omitempty"`
	LibraryPath string            `yaml:"library_path"`
	Name        string            `yaml:"name"`
	OpenParams  string            `yaml:"open_params,omitempty"`
}

func (p *PluginConfig) isSame(other *PluginConfig) bool {
	if p.Name != other.Name {
		return false
	}
	// Check if the maps are equal.
	if len(p.InitConfig) != len(other.InitConfig) {
		return false
	}
	// Check if the keys and values are equal.
	for key, value := range p.InitConfig {
		if otherValue, ok := other.InitConfig[key]; !ok || value != otherValue {
			return false
		}
	}
	if p.LibraryPath != other.LibraryPath {
		return false
	}
	if p.OpenParams != other.OpenParams {
		return false
	}
	return true
}

// PluginsConfig is the configuration for the plugins.
type PluginsConfig struct {
	Configs     []PluginConfig `yaml:"plugins"`
	LoadPlugins []string       `yaml:"load_plugins,omitempty"`
}

func (pc *PluginsConfig) addConfig(plugin *artifactv1alpha1.Plugin) {
	var config = PluginConfig{
		LibraryPath: artifact.Path(plugin.Name, priority.DefaultPriority, artifact.MediumOCI, artifact.TypePlugin),
		Name:        plugin.Name,
	}

	// If not nil, set the values that are not empty.
	if plugin.Spec.Config != nil {
		if plugin.Spec.Config.InitConfig != nil {
			config.InitConfig = plugin.Spec.Config.InitConfig
		}
		if plugin.Spec.Config.LibraryPath != "" {
			config.LibraryPath = plugin.Spec.Config.LibraryPath
		}
		if plugin.Spec.Config.Name != "" {
			config.Name = plugin.Spec.Config.Name
		}
		if plugin.Spec.Config.OpenParams != "" {
			config.OpenParams = plugin.Spec.Config.OpenParams
		}
	}

	// Check if the pluginConfig already exists in the list.
	for i, c := range pc.Configs {
		if c.isSame(&config) {
			// Remove the plugin from the list and add the current plugin.
			pc.Configs = append(pc.Configs[:i], pc.Configs[i+1:]...)
			break
		}
	}

	// Add the plugin to the list if it doesn't exist.
	if len(pc.Configs) == 0 {
		pc.Configs = append(pc.Configs, config)
	} else {
		found := false
		for _, c := range pc.Configs {
			if c.Name == plugin.Name {
				found = true
				break
			}
		}
		if !found {
			pc.Configs = append(pc.Configs, config)
		}
	}

	// Check if the plugin is already in the list.
	for _, c := range pc.LoadPlugins {
		if c == plugin.Name {
			return
		}
	}
	pc.LoadPlugins = append(pc.LoadPlugins, plugin.Name)
}

func (pc *PluginsConfig) removeConfig(plugin *artifactv1alpha1.Plugin) {
	// Check if the pluginConfig already exists in the list.
	for i, c := range pc.Configs {
		if c.Name == plugin.Name {
			// Remove the plugin from the list.
			pc.Configs = append(pc.Configs[:i], pc.Configs[i+1:]...)
			break
		}
	}

	// Check if the plugin is already in the list.
	for i, c := range pc.LoadPlugins {
		if c == plugin.Name {
			// Remove the plugin from the list.
			pc.LoadPlugins = append(pc.LoadPlugins[:i], pc.LoadPlugins[i+1:]...)
			break
		}
	}
}

func (pc *PluginsConfig) toString() (string, error) {
	// Convert the struct to YAML.
	data, err := yaml.Marshal(pc)
	if err != nil {
		return "", err
	}

	// Convert the YAML to a string.
	yamlString := string(data)

	return yamlString, nil
}

func (pc *PluginsConfig) isEmpty() bool {
	if len(pc.Configs) == 0 && len(pc.LoadPlugins) == 0 {
		return true
	}
	return false
}
