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

// Package controller defines controllers' logic.

package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/events"
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
func NewPluginReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	nodeName, namespace string,
) *PluginReconciler {
	return &PluginReconciler{
		Client:          cl,
		Scheme:          scheme,
		recorder:        recorder,
		finalizer:       common.FormatFinalizerName(pluginFinalizerPrefix, nodeName),
		artifactManager: artifact.NewManager(cl, namespace),
		PluginsConfig:   &PluginsConfig{},
		nodeName:        nodeName,
		crToConfigName:  make(map[string]string),
	}
}

// PluginReconciler reconciles a Plugin object.
type PluginReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	recorder        events.EventRecorder
	finalizer       string
	artifactManager *artifact.Manager
	PluginsConfig   *PluginsConfig
	nodeName        string
	crToConfigName  map[string]string
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PluginReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := log.FromContext(ctx)
	plugin := &artifactv1alpha1.Plugin{}

	// Fetch the Plugin instance.
	logger.V(2).Info("Fetching Plugin instance")
	if err := r.Get(ctx, req.NamespacedName, plugin); err != nil && !apierrors.IsNotFound(err) {
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

	// Snapshot status before any condition modifications.
	statusPatch := client.MergeFrom(plugin.DeepCopy())

	// Patch status via defer to ensure it's always called.
	defer func() {
		patchErr := r.patchStatus(ctx, plugin, statusPatch)
		if patchErr != nil {
			logger.Error(patchErr, "unable to patch status")
		}
		reterr = kerrors.NewAggregate([]error{reterr, patchErr})
	}()

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

		patch := client.MergeFrom(plugin.DeepCopy())
		controllerutil.AddFinalizer(plugin, r.finalizer)
		if err := r.Patch(ctx, plugin, patch); err != nil {
			if apierrors.IsConflict(err) {
				logger.V(3).Info("Conflict while setting finalizer, will retry")
				return false, err
			}
			logger.Error(err, "unable to set finalizer", "finalizer", r.finalizer)
			return false, err
		}

		logger.V(3).Info("Finalizer set", "finalizer", r.finalizer)
		return true, nil
	}

	return false, nil
}

// ensurePlugin ensures that the Plugin artifact is stored correctly.
func (r *PluginReconciler) ensurePlugin(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	gen := plugin.GetGeneration()
	logger := log.FromContext(ctx)
	var err error

	// Ensure Reconciled condition is stored even on early return.
	defer func() {
		if err != nil {
			apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewReconciledCondition(
				metav1.ConditionFalse, artifact.ReasonReconcileFailed, err.Error(), gen,
			))
		}
	}()

	if err = r.artifactManager.StoreFromOCI(ctx, plugin.Name, priority.DefaultPriority, artifact.TypePlugin, plugin.Spec.OCIArtifact); err != nil {
		logger.Error(err, "unable to store plugin artifact")
		r.recorder.Eventf(plugin, nil, corev1.EventTypeWarning, artifact.ReasonOCIArtifactStoreFailed,
			artifact.ReasonOCIArtifactStoreFailed, artifact.MessageFormatOCIArtifactStoreFailed, err.Error())
		apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewOCIArtifactCondition(
			metav1.ConditionFalse, artifact.ReasonOCIArtifactStoreFailed,
			fmt.Sprintf(artifact.MessageFormatOCIArtifactStoreFailed, err.Error()), gen,
		))
		return err
	}

	r.recorder.Eventf(plugin, nil, corev1.EventTypeNormal, artifact.ReasonOCIArtifactStored,
		artifact.ReasonOCIArtifactStored, artifact.MessageOCIArtifactStored)
	apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewOCIArtifactCondition(
		metav1.ConditionTrue, artifact.ReasonOCIArtifactStored, artifact.MessageOCIArtifactStored, gen,
	))
	return nil
}

// handleDeletion handles the deletion of the Plugin instance.
func (r *PluginReconciler) handleDeletion(ctx context.Context, plugin *artifactv1alpha1.Plugin) (bool, error) {
	logger := log.FromContext(ctx)

	if !plugin.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(plugin, r.finalizer) {
			logger.Info("Plugin instance marked for deletion, cleaning up")
			if err := r.artifactManager.RemoveAll(ctx, plugin.Name); err != nil {
				r.recorder.Eventf(plugin, nil, corev1.EventTypeWarning, artifact.ReasonArtifactRemoveFailed,
					artifact.ReasonArtifactRemoveFailed, artifact.MessageFormatPluginArtifactsRemoveFailed, err.Error())
				return false, err
			}

			// Remove the plugin configuration.
			r.PluginsConfig.removeConfig(plugin)
			delete(r.crToConfigName, plugin.Name)

			// Write the updated configuration to the file.
			if err := r.removePluginConfig(ctx, plugin); err != nil {
				logger.Error(err, "unable to remove plugin config")
				return false, err
			}

			r.recorder.Eventf(plugin, nil, corev1.EventTypeNormal, artifact.ReasonArtifactRemoved,
				artifact.ReasonArtifactRemoved, artifact.MessagePluginArtifactsRemoved)

			// Remove the finalizer.
			logger.V(3).Info("Removing finalizer", "finalizer", r.finalizer)
			patch := client.MergeFrom(plugin.DeepCopy())
			controllerutil.RemoveFinalizer(plugin, r.finalizer)
			if err := r.Patch(ctx, plugin, patch); err != nil {
				logger.Error(err, "unable to remove finalizer", "finalizer", r.finalizer)
				return false, err
			}
		}

		return true, nil
	}

	return false, nil
}

// ensurePluginConfig ensures plugin configuration is set correctly.
func (r *PluginReconciler) ensurePluginConfig(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	gen := plugin.GetGeneration()
	var err error
	logger := log.FromContext(ctx)
	logger.Info("Ensuring plugin configuration")

	configName := resolveConfigName(plugin)
	if oldName, ok := r.crToConfigName[plugin.Name]; ok && oldName != configName {
		r.PluginsConfig.removeByName(oldName)
	}
	r.crToConfigName[plugin.Name] = configName

	r.PluginsConfig.addConfig(plugin)

	// Ensure Reconciled condition is stored even on early return.
	defer func() {
		if err != nil {
			apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewReconciledCondition(
				metav1.ConditionFalse, artifact.ReasonReconcileFailed, err.Error(), gen,
			))
		} else {
			r.recorder.Eventf(plugin, nil, corev1.EventTypeNormal, artifact.ReasonReconciled,
				artifact.ReasonReconciled, artifact.MessagePluginReconciled)
			apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewReconciledCondition(
				metav1.ConditionTrue, artifact.ReasonReconciled, artifact.MessagePluginReconciled, gen,
			))
		}
	}()

	pluginConfigString, err := r.PluginsConfig.toString()
	if err != nil {
		logger.Error(err, "unable to convert plugin config to string")
		r.recorder.Eventf(plugin, nil, corev1.EventTypeWarning, artifact.ReasonInlinePluginConfigStoreFailed,
			artifact.ReasonInlinePluginConfigStoreFailed, artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error())
		apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewInlineContentCondition(
			metav1.ConditionFalse, artifact.ReasonInlinePluginConfigStoreFailed,
			fmt.Sprintf(artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error()), gen,
		))
		return err
	}

	if err = r.artifactManager.StoreFromInLineYaml(ctx, pluginConfigFileName, priority.MaxPriority,
		&pluginConfigString, artifact.TypeConfig); err != nil {
		logger.Error(err, "unable to store plugin config", "filename", pluginConfigFileName)
		r.recorder.Eventf(plugin, nil, corev1.EventTypeWarning, artifact.ReasonInlinePluginConfigStoreFailed,
			artifact.ReasonInlinePluginConfigStoreFailed, artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error())
		apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewInlineContentCondition(
			metav1.ConditionFalse, artifact.ReasonInlinePluginConfigStoreFailed,
			fmt.Sprintf(artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error()), gen,
		))
		return err
	}

	r.recorder.Eventf(plugin, nil, corev1.EventTypeNormal, artifact.ReasonInlinePluginConfigStored,
		artifact.ReasonInlinePluginConfigStored, artifact.MessageInlinePluginConfigStored)
	apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewInlineContentCondition(
		metav1.ConditionTrue, artifact.ReasonInlinePluginConfigStored, artifact.MessageInlinePluginConfigStored, gen,
	))
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
	InitConfig  *InitConfig `yaml:"init_config,omitempty"`
	LibraryPath string      `yaml:"library_path"`
	Name        string      `yaml:"name"`
	OpenParams  string      `yaml:"open_params,omitempty"`
}

// InitConfig wraps apiextensionsv1.JSON to provide proper YAML marshaling.
type InitConfig struct {
	*apiextensionsv1.JSON
}

// MarshalYAML implements yaml.Marshaler to serialize the JSON content as nested YAML.
func (c *InitConfig) MarshalYAML() (interface{}, error) {
	if c == nil || c.JSON == nil || len(c.Raw) == 0 {
		return nil, nil
	}
	var data interface{}
	if err := json.Unmarshal(c.Raw, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func (p *PluginConfig) isSame(other *PluginConfig) bool {
	if p.LibraryPath != other.LibraryPath {
		return false
	}
	if p.OpenParams != other.OpenParams {
		return false
	}
	if p.InitConfig == nil && other.InitConfig == nil {
		return true
	}
	if p.InitConfig == nil || other.InitConfig == nil {
		return false
	}
	return reflect.DeepEqual(p.InitConfig.JSON, other.InitConfig.JSON)
}

// PluginsConfig is the configuration for the plugins.
type PluginsConfig struct {
	Configs     []PluginConfig `yaml:"plugins"`
	LoadPlugins []string       `yaml:"load_plugins,omitempty"`
}

func resolveConfigName(plugin *artifactv1alpha1.Plugin) string {
	if plugin.Spec.Config != nil && plugin.Spec.Config.Name != "" {
		return plugin.Spec.Config.Name
	}
	return plugin.Name
}

func (pc *PluginsConfig) addConfig(plugin *artifactv1alpha1.Plugin) {
	config := PluginConfig{
		LibraryPath: artifact.Path(plugin.Name, priority.DefaultPriority, artifact.MediumOCI, artifact.TypePlugin),
		Name:        plugin.Name,
	}

	if plugin.Spec.Config != nil {
		if plugin.Spec.Config.InitConfig != nil && len(plugin.Spec.Config.InitConfig.Raw) > 0 {
			config.InitConfig = &InitConfig{JSON: plugin.Spec.Config.InitConfig}
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

	// If an entry with the same name already exists and is identical, skip the update
	// to avoid unnecessary writes to the config file mounted in the pod.
	for i, c := range pc.Configs {
		if c.Name == config.Name {
			if c.isSame(&config) {
				return
			}
			pc.Configs = append(pc.Configs[:i], pc.Configs[i+1:]...)
			break
		}
	}
	pc.Configs = append(pc.Configs, config)

	// Add to LoadPlugins if not already present (use config.Name for consistency).
	for _, c := range pc.LoadPlugins {
		if c == config.Name {
			return
		}
	}
	pc.LoadPlugins = append(pc.LoadPlugins, config.Name)
}

func (pc *PluginsConfig) removeConfig(plugin *artifactv1alpha1.Plugin) {
	pc.removeByName(resolveConfigName(plugin))
}

func (pc *PluginsConfig) removeByName(name string) {
	for i, c := range pc.Configs {
		if c.Name == name {
			pc.Configs = append(pc.Configs[:i], pc.Configs[i+1:]...)
			break
		}
	}

	for i, c := range pc.LoadPlugins {
		if c == name {
			pc.LoadPlugins = append(pc.LoadPlugins[:i], pc.LoadPlugins[i+1:]...)
			break
		}
	}
}

func (pc *PluginsConfig) toString() (string, error) {
	data, err := yaml.Marshal(pc)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (pc *PluginsConfig) isEmpty() bool {
	return len(pc.Configs) == 0 && len(pc.LoadPlugins) == 0
}

// patchStatus patches the Plugin status using the given pre-modification snapshot.
func (r *PluginReconciler) patchStatus(ctx context.Context, plugin *artifactv1alpha1.Plugin, patch client.Patch) error {
	logger := log.FromContext(ctx)
	if err := r.Status().Patch(ctx, plugin, patch); err != nil {
		if apierrors.IsConflict(err) {
			logger.V(3).Info("Conflict while patching status, will retry")
			return err
		}
		logger.Error(err, "unable to patch status")
		return err
	}
	return nil
}
