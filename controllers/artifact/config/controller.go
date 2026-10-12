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

package config

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
)

// kind is the artifact kind this reconciler handles.
const kind = artifact.KindConfig

// NewConfigReconciler returns a new ConfigReconciler.
func NewConfigReconciler(cl client.Client, n *node.Node) *ConfigReconciler {
	return &ConfigReconciler{Client: cl, node: n}
}

// ConfigReconciler reconciles the Configs assigned to this node by its ArtifactNode.
type ConfigReconciler struct {
	client.Client
	node *node.Node
}

// Reconcile reconciles the Config named by req, on this node. When the spec of the node's ArtifactNode lists it,
// it is installed. When it does not, or the Config is gone, whatever this node holds for it is removed: the node
// controller asks for that whenever the spec stops listing an artifact, and a single reconcile per artifact at a
// time is what keeps an install and a removal from overlapping.
func (r *ConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return shared.ReconcileArtifact(ctx, r.Client, r.node, req, &artifactv1alpha1.Config{}, r.Cleanup)
}

// Cleanup removes everything installed for the Config named name. It is idempotent.
func (r *ConfigReconciler) Cleanup(ctx context.Context, name string) error {
	return shared.Remove(ctx, r.node, kind, name)
}

// SetupWithManager registers the controller: one reconcile per Config, woken by the Config itself, by its
// assignment on this node, by the ConfigMap it references, and by the node controller asking for its removal.
func (r *ConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Config{}, builder.WithPredicates(shared.ParentChanged())).
		Watches(&artifactv1alpha1.ArtifactNode{}, shared.AssignmentHandler(kind)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.findConfigsForConfigMap)).
		// The node controller asks for the removal of what the node holds for an artifact the spec of its ArtifactNode no
		// longer lists.
		WatchesRawSource(source.Channel(r.node.RemovalRequests(kind), &handler.EnqueueRequestForObject{})).
		Named("artifact-config").
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), "artifact-config", &artifactv1alpha1.Config{})).
		Complete(r)
}

// findConfigsForConfigMap maps a ConfigMap event to the Configs that reference it.
func (r *ConfigReconciler) findConfigsForConfigMap(ctx context.Context, configMap client.Object) []reconcile.Request {
	return controllerhelper.RequestsReferencing(ctx, r.Client, &artifactv1alpha1.ConfigList{}, index.ConfigMapOnConfig, configMap)
}
