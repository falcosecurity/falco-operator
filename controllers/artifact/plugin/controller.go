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
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
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
	// fieldManager is the name used to identify the controller's managed fields.
	fieldManager = "artifact-plugin"
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
	if err := r.Get(ctx, req.NamespacedName, plugin); err != nil && !k8serrors.IsNotFound(err) {
		logger.Error(err, "Unable to fetch Plugin")
		return ctrl.Result{}, err
	} else if k8serrors.IsNotFound(err) {
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

	// Patch status via defer to ensure it's always called.
	defer func() {
		patchErr := r.patchStatus(ctx, plugin)
		if patchErr != nil {
			logger.Error(patchErr, "unable to patch status")
		}
		reterr = kerrors.NewAggregate([]error{reterr, patchErr})
	}()

	// Enforce reference resolution.
	if err := r.enforceReferenceResolution(ctx, plugin); err != nil {
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
		Watches(
			&artifactv1alpha1.Plugin{},
			handler.EnqueueRequestsFromMapFunc(r.findPluginsForPluginChange),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("artifact-plugin").
		Complete(r)
}

// findPluginsForPluginChange enqueues all Plugins in the same namespace so
// dependency status is recomputed when a dependency Plugin changes.
func (r *PluginReconciler) findPluginsForPluginChange(ctx context.Context, obj client.Object) []reconcile.Request {
	plugin, ok := obj.(*artifactv1alpha1.Plugin)
	if !ok {
		return nil
	}

	pluginList := &artifactv1alpha1.PluginList{}
	if err := r.List(ctx, pluginList, client.InNamespace(plugin.Namespace)); err != nil {
		log.FromContext(ctx).Error(err, "unable to list Plugins for dependency fan-out reconcile", "namespace", plugin.Namespace)
		return nil
	}

	requests := make([]reconcile.Request, 0, len(pluginList.Items))
	for i := range pluginList.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Name:      pluginList.Items[i].Name,
				Namespace: pluginList.Items[i].Namespace,
			},
		})
	}

	return requests
}

// ensureFinalizers ensures that the finalizer is set on the Plugin instance.
func (r *PluginReconciler) ensureFinalizers(ctx context.Context, plugin *artifactv1alpha1.Plugin) (bool, error) {
	return controllerhelper.EnsureFinalizer(ctx, r.Client, r.finalizer, plugin)
}

// ensurePlugin ensures that the Plugin artifact is stored correctly.
func (r *PluginReconciler) ensurePlugin(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	gen := plugin.GetGeneration()
	logger := log.FromContext(ctx)
	var err error

	apimeta.RemoveStatusCondition(&plugin.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())

	ociAction, err := r.artifactManager.StoreFromOCI(ctx, plugin.Name, priority.DefaultPriority, artifact.TypePlugin, plugin.Spec.OCIArtifact)
	if err != nil {
		logger.Error(err, "unable to store plugin artifact")
		artifact.RecordWarning(r.recorder, plugin, artifact.ReasonOCIArtifactStoreFailed, artifact.MessageFormatOCIArtifactStoreFailed, err.Error())
		apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonOCIArtifactStoreFailed,
			fmt.Sprintf(artifact.MessageFormatOCIArtifactStoreFailed, err.Error()), gen,
		))
		return err
	}
	artifact.RecordStoreEvent(r.recorder, plugin, ociAction, artifact.MediumOCI)

	if err := r.validateDependencies(ctx, plugin); err != nil {
		return err
	}

	apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewProgrammedCondition(
		metav1.ConditionTrue, artifact.ReasonProgrammed, artifact.MessageProgrammed, gen,
	))
	return nil
}

func (r *PluginReconciler) enforceReferenceResolution(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	logger := log.FromContext(ctx)
	hasRefs := false

	if ociArt := plugin.Spec.OCIArtifact; ociArt != nil && ociArt.Registry != nil {
		reg := ociArt.Registry

		if reg.Auth != nil && reg.Auth.SecretRef != nil {
			hasRefs = true
			secretName := reg.Auth.SecretRef.Name
			err := r.artifactManager.CheckReferenceResolution(ctx, plugin.Namespace, secretName, &corev1.Secret{})
			if err != nil {
				logger.Error(err, "OCIArtifact auth secret reference resolution failed", "secret", secretName)
				artifact.RecordWarning(r.recorder, plugin, artifact.ReasonReferenceResolutionFailed, artifact.MessageFormatReferenceResolutionFailed, err.Error())
				apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewResolvedRefsCondition(
					metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
					fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, secretName), plugin.GetGeneration()))
				apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewProgrammedCondition(
					metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
					fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, secretName), plugin.GetGeneration(),
				))
				return err
			}
		}
	}

	if hasRefs {
		artifact.RecordNormal(r.recorder, plugin, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved)
		apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewResolvedRefsCondition(
			metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, plugin.GetGeneration(),
		))
	} else {
		apimeta.RemoveStatusCondition(&plugin.Status.Conditions, commonv1alpha1.ConditionResolvedRefs.String())
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
				artifact.RecordWarning(r.recorder, plugin, artifact.ReasonArtifactRemoveFailed, artifact.MessageFormatPluginArtifactsRemoveFailed, err.Error())
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

			artifact.RecordNormal(r.recorder, plugin, artifact.ReasonPluginArtifactsRemoved, artifact.MessagePluginArtifactsRemoved)

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

	r.PluginsConfig.addConfig(r.artifactManager, plugin)

	// Clean up conditions before ensuring the plugin config.
	apimeta.RemoveStatusCondition(&plugin.Status.Conditions, commonv1alpha1.ConditionProgrammed.String())

	pluginConfigString, err := r.PluginsConfig.toString()
	if err != nil {
		logger.Error(err, "unable to convert plugin config to string")
		artifact.RecordWarning(r.recorder, plugin,
			artifact.ReasonInlinePluginConfigStoreFailed, artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error())
		apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonInlinePluginConfigStoreFailed,
			fmt.Sprintf(artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error()), gen,
		))
		return err
	}

	configAction, err := r.artifactManager.StoreFromInLineYaml(ctx, pluginConfigFileName, priority.MaxPriority,
		&pluginConfigString, artifact.TypeConfig)
	if err != nil {
		logger.Error(err, "unable to store plugin config", "filename", pluginConfigFileName)
		artifact.RecordWarning(r.recorder, plugin,
			artifact.ReasonInlinePluginConfigStoreFailed, artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error())
		apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonInlinePluginConfigStoreFailed,
			fmt.Sprintf(artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error()), gen,
		))
		return err
	}
	artifact.RecordStoreEvent(r.recorder, plugin, configAction, artifact.MediumInline)
	apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewProgrammedCondition(
		metav1.ConditionTrue, artifact.ReasonProgrammed, artifact.MessageProgrammed, gen,
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

	if _, err := r.artifactManager.StoreFromInLineYaml(ctx, pluginConfigFileName, priority.MaxPriority,
		&pluginConfigString, artifact.TypeConfig); err != nil {
		logger.Error(err, "unable to store plugin config", "filename", pluginConfigFileName)
		return err
	}

	return nil
}

func (r *PluginReconciler) validateDependencies(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	logger := log.FromContext(ctx)
	logger.Info("Validating plugin dependencies")
	gen := plugin.GetGeneration()

	inspectResult, err := r.artifactManager.InspectOCI(ctx, plugin.Spec.OCIArtifact)
	if err != nil {
		logger.Error(err, "unable to get plugin dependencies")
		return err
	}
	if inspectResult == nil {
		apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionTrue,
			artifact.ReasonDependenciesSatisfied,
			artifact.MessageDependenciesSatisfied,
			gen,
		))
		return nil
	}

	seen := make(map[string]struct{})
	missingDeps := make([]string, 0, len(inspectResult.Config.Dependencies))

	pluginList := &artifactv1alpha1.PluginList{}
	if err := r.List(ctx, pluginList, client.InNamespace(plugin.Namespace)); err != nil {
		logger.Error(err, "unable to list plugins for dependency validation")
		return err
	}

	pluginsByConfigName := make(map[string][]*artifactv1alpha1.Plugin, len(pluginList.Items))
	for i := range pluginList.Items {
		p := &pluginList.Items[i]
		cfgName := resolveConfigName(p)
		pluginsByConfigName[cfgName] = append(pluginsByConfigName[cfgName], p)
	}

	for _, dep := range inspectResult.Config.Dependencies {
		if dep.Name == "" {
			continue
		}

		requiredVersion := dep.Version
		if requiredVersion == "" {
			requiredVersion = "latest"
		}
		reqKey := dep.Name + ":" + requiredVersion
		if _, ok := seen[reqKey]; ok {
			continue
		}
		seen[reqKey] = struct{}{}

		candidates, ok := pluginsByConfigName[dep.Name]
		if !ok || len(candidates) == 0 {
			missingDeps = append(missingDeps, dep.Name)
			continue
		}

		matched := false
		for _, depPlugin := range candidates {
			depPluginVersion := "latest"
			if depPlugin.Spec.OCIArtifact != nil && depPlugin.Spec.OCIArtifact.Image.Tag != "" {
				depPluginVersion = depPlugin.Spec.OCIArtifact.Image.Tag
			}

			if versionMatchesRequirement(requiredVersion, depPluginVersion) {
				matched = true
				break
			}
		}

		if !matched {
			missingDeps = append(missingDeps, dep.Name)
		}
	}

	if len(missingDeps) > 0 {
		sort.Strings(missingDeps)
		logger.V(1).Info("plugin has missing dependencies", "dependencies", missingDeps)
		apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionFalse,
			artifact.ReasonMissingDependencies,
			fmt.Sprintf(artifact.MessageFormatDependenciesNotFound, strings.Join(missingDeps, ", ")),
			gen,
		))
		return nil
	}

	apimeta.SetStatusCondition(&plugin.Status.Conditions, common.NewDependenciesSatisfiedCondition(
		metav1.ConditionTrue,
		artifact.ReasonDependenciesSatisfied,
		artifact.MessageDependenciesSatisfied,
		gen,
	))

	return nil
}

func versionMatchesRequirement(required, actual string) bool {
	if required == actual {
		return true
	}

	requiredParts, reqSemver := parseSemverPrefix(required)
	actualParts, actSemver := parseSemverPrefix(actual)
	if !reqSemver || !actSemver {
		return false
	}
	if len(requiredParts) > len(actualParts) {
		return false
	}

	for i := range requiredParts {
		if requiredParts[i] != actualParts[i] {
			return false
		}
	}

	return true
}

func parseSemverPrefix(version string) ([]int, bool) {
	if version == "" {
		return nil, false
	}

	trimmed := strings.TrimPrefix(version, "v")
	trimmed = stripSemverMetadata(trimmed)
	if trimmed == "" {
		return nil, false
	}

	rawParts := strings.Split(trimmed, ".")
	if len(rawParts) == 0 || len(rawParts) > 3 {
		return nil, false
	}

	parts := make([]int, 0, len(rawParts))
	for _, raw := range rawParts {
		if raw == "" {
			return nil, false
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, false
		}
		parts = append(parts, n)
	}

	return parts, true
}

func stripSemverMetadata(version string) string {
	if i := strings.Index(version, "+"); i >= 0 {
		version = version[:i]
	}
	if i := strings.Index(version, "-"); i >= 0 {
		version = version[:i]
	}
	return version
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
func (c *InitConfig) MarshalYAML() (any, error) {
	if c == nil || c.JSON == nil || len(c.Raw) == 0 {
		return nil, nil
	}
	var data any
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

func (pc *PluginsConfig) addConfig(am *artifact.Manager, plugin *artifactv1alpha1.Plugin) {
	config := PluginConfig{
		LibraryPath: am.Path(plugin.Name, priority.DefaultPriority, artifact.MediumOCI, artifact.TypePlugin),
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
	if slices.Contains(pc.LoadPlugins, config.Name) {
		return
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

// patchStatus patches the Plugin status using server-side apply.
func (r *PluginReconciler) patchStatus(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	return controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, plugin, fieldManager)
}
