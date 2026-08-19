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

// Package config implements the Config node-object aggregator controller.
// It runs in the instance operator (singleton Deployment) and is responsible for:
//   - Creating one ArtifactNode per cluster node that matches the Config selector.
//   - Deleting ArtifactNode objects when a node no longer matches.
//   - Aggregating per-node conditions into the parent Config status (sole writer).
//   - Managing the NodeObjectsInUseFinalizer on the parent Config.
package config

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

// ControllerName identifies this controller in logs and as the SSA field manager.
const ControllerName = "instance-artifact-config"

// NewConfigAggregatorReconciler returns a new ConfigAggregatorReconciler.
func NewConfigAggregatorReconciler(cl client.Client, scheme *runtime.Scheme) *ConfigAggregatorReconciler {
	return &ConfigAggregatorReconciler{Client: cl, Scheme: scheme}
}

// ConfigAggregatorReconciler manages ArtifactNode objects and aggregates their
// conditions into the parent Config status.
//
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=configs,verbs=get;list;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=configs/status,verbs=patch;update
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=configs/finalizers,verbs=patch;update
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=artifactnodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=artifactnodes/status,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos,verbs=get;list;watch
type ConfigAggregatorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile reconciles a Config: ensures ArtifactNode objects exist for matching nodes,
// removes stale ones, and writes the aggregate conditions back to the Config.
func (r *ConfigAggregatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.V(1).Info("Reconciling Config")

	config := &artifactv1alpha1.Config{}
	if err := r.Get(ctx, req.NamespacedName, config); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !config.DeletionTimestamp.IsZero() {
		logger.V(1).Info("Config marked for deletion, running cleanup")
		return ctrl.Result{}, r.handleDeletion(ctx, config)
	}

	matchingNodes, err := controllerhelper.ListMatchingFalcoNodes(ctx, r.Client, config.Spec.Selector, config.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(1).Info("Listed matching nodes", "count", len(matchingNodes))

	existingNodes, err := controllerhelper.ListOwnedNodes(ctx, r.Client, config.Namespace, config.Name, controllerhelper.KindConfig)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(1).Info("Listed existing ArtifactNode objects", "count", len(existingNodes.Items))

	desired := make(map[string]struct{}, len(matchingNodes))
	for i := range matchingNodes {
		desired[matchingNodes[i].Name] = struct{}{}
	}

	if err := controllerhelper.DeleteStaleNodeObjects(ctx, r.Client, existingNodes.Items, desired); err != nil {
		return ctrl.Result{}, err
	}

	// No network-bound work happens between here and node creation, so the DeletionTimestamp
	// check at the top of Reconcile is still valid.

	// Ensure an ArtifactNode exists for each matching node.
	configGVK := artifactv1alpha1.GroupVersion.WithKind(controllerhelper.KindConfig)
	for i := range matchingNodes {
		if err := controllerhelper.EnsureNodeObject(
			ctx, r.Client, config, configGVK, controllerhelper.ArtifactKindConfig, matchingNodes[i].Name,
		); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Ensure the in-use finalizer is present when node objects exist.
	// The SSA variant also strips any legacy per-node finalizers left by old operators.
	hasNodes := len(matchingNodes) > 0
	if err := controllerhelper.ReconcileInUseFinalizer(
		ctx, r.Client, config,
		controllerhelper.NodeObjectsInUseFinalizer,
		hasNodes,
	); err != nil {
		return ctrl.Result{}, err
	}

	// Re-fetch node objects (some may have just been created) to compute the aggregate.
	existingNodes, err = controllerhelper.ListOwnedNodes(ctx, r.Client, config.Namespace, config.Name, controllerhelper.KindConfig)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(1).Info("Re-listed ArtifactNode objects after sync", "count", len(existingNodes.Items))

	oldStatus := config.Status.DeepCopy()
	config.Status.ObservedGeneration = config.Generation
	controllerhelper.ComputeAggregateConditions(ctx, config, &config.Status.Conditions, existingNodes)
	if !apiequality.Semantic.DeepEqual(*oldStatus, config.Status) {
		return ctrl.Result{}, controllerhelper.PatchStatusSSA(ctx, r.Client, r.Scheme, config, ControllerName)
	}
	return ctrl.Result{}, nil
}

// handleDeletion deletes all ArtifactNode objects so each per-node artifact operator can clean up and
// remove its own finalizer (skipping this would deadlock: GC cascade only fires after the owner is
// deleted, but the in-use finalizer keeps the owner alive).
func (r *ConfigAggregatorReconciler) handleDeletion(ctx context.Context, config *artifactv1alpha1.Config) error {
	existing, err := controllerhelper.ListOwnedNodes(ctx, r.Client, config.Namespace, config.Name, controllerhelper.KindConfig)
	if err != nil {
		return err
	}

	nodesRemaining, err := controllerhelper.DeleteNodeObjectsForParentDeletion(ctx, r.Client, existing.Items)
	if err != nil {
		return err
	}
	if nodesRemaining {
		return nil
	}

	return controllerhelper.ReconcileInUseFinalizer(
		ctx, r.Client, config,
		controllerhelper.NodeObjectsInUseFinalizer,
		false,
	)
}

// SetupWithManager registers this controller with the manager.
func (r *ConfigAggregatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Config{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return !obj.GetDeletionTimestamp().IsZero()
			}),
		))).
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
				return controllerhelper.EnqueueAllOfType(ctx, r.Client, &artifactv1alpha1.ConfigList{})
			}),
		).
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, pod client.Object) []reconcile.Request {
				return controllerhelper.EnqueueAllOfType(ctx, r.Client, &artifactv1alpha1.ConfigList{}, client.InNamespace(pod.GetNamespace()))
			}),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				_, ok := obj.GetLabels()["app.kubernetes.io/instance"]
				return ok
			})),
		).
		Watches(&artifactv1alpha1.ArtifactNode{},
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &artifactv1alpha1.Config{}),
		).
		Named(ControllerName).
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), ControllerName, &artifactv1alpha1.Config{})).
		Complete(r)
}
