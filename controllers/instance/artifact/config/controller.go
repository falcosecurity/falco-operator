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

// Package config implements the Config aggregator controller.
// It runs in the instance operator (singleton Deployment) and is responsible for:
//   - Aggregating the per-node conditions that each node's artifact operator publishes on its
//     ArtifactNode into the parent Config status (sole writer).
//   - Managing the NodeObjectsInUseFinalizer on the parent Config.
//
// Which nodes get the Config is decided by the ArtifactNode assignment controller.
package config

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/instance/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// ControllerName identifies this controller in logs and as the SSA field manager.
const ControllerName = "instance-artifact-config"

// NewConfigAggregatorReconciler returns a new ConfigAggregatorReconciler.
func NewConfigAggregatorReconciler(cl client.Client, scheme *runtime.Scheme) *ConfigAggregatorReconciler {
	return &ConfigAggregatorReconciler{Client: cl, Scheme: scheme}
}

// ConfigAggregatorReconciler aggregates the per-node conditions published on ArtifactNodes into the
// parent Config status.
type ConfigAggregatorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=configs,verbs=get;list;watch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=configs/status,verbs=patch;update
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=configs/finalizers,verbs=patch;update
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=instance.falcosecurity.dev,resources=falcos,verbs=get;list;watch

// Reconcile reconciles a Config: manages its in-use finalizer and writes the aggregate of the conditions
// its nodes published back to the Config.
func (r *ConfigAggregatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return shared.Reconcile(ctx, req, r.aggregation())
}

// aggregation is what the aggregate reconcile needs of the Configs.
func (r *ConfigAggregatorReconciler) aggregation() shared.Aggregation[*artifactv1alpha1.Config] {
	return shared.Aggregation[*artifactv1alpha1.Config]{
		Client:       r.Client,
		Scheme:       r.Scheme,
		FieldManager: ControllerName,
		Kind:         artifact.KindConfig,
		Cache:        nil,
		New:          func() *artifactv1alpha1.Config { return &artifactv1alpha1.Config{} },
		StatusValue:  func(config *artifactv1alpha1.Config) any { return *config.Status.DeepCopy() },
	}
}

// SetupWithManager registers this controller with the manager.
func (r *ConfigAggregatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return shared.NewControllerManagedBy(mgr, r.Client, ControllerName, artifact.KindConfig, &artifactv1alpha1.Config{},
		func() client.ObjectList { return &artifactv1alpha1.ConfigList{} }, nil).
		Complete(r)
}
