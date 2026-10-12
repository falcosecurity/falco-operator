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

package rulesfile

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
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
const kind = artifact.KindRulesfile

// NewRulesfileReconciler returns a new RulesfileReconciler.
func NewRulesfileReconciler(cl client.Client, n *node.Node) *RulesfileReconciler {
	return &RulesfileReconciler{Client: cl, node: n}
}

// RulesfileReconciler reconciles the Rulesfiles assigned to this node by its ArtifactNode.
type RulesfileReconciler struct {
	client.Client
	node *node.Node
}

// Reconcile reconciles the Rulesfile named by req, on this node. When the spec of the node's ArtifactNode lists it,
// it is installed. When it does not, or the Rulesfile is gone, whatever this node holds for it is removed: the node
// controller asks for that whenever the spec stops listing an artifact, and a single reconcile per artifact at a
// time is what keeps an install and a removal from overlapping.
func (r *RulesfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return shared.ReconcileArtifact(ctx, r.Client, r.node, req, &artifactv1alpha1.Rulesfile{}, r.Cleanup)
}

// Cleanup removes everything installed for the Rulesfile named name, and releases its dependency
// registrations. It is idempotent.
func (r *RulesfileReconciler) Cleanup(ctx context.Context, name string) error {
	return shared.Remove(ctx, r.node, kind, name)
}

// SetupWithManager registers the controller: one reconcile per Rulesfile, woken by the
// Rulesfile itself, by its assignment on this node, by a ConfigMap it references, by a change of the
// plugins reported on this node (a rulesfile re-checks its plugin requirements), and by a change of Falco's
// reported capabilities (versionEvents).
func (r *RulesfileReconciler) SetupWithManager(mgr ctrl.Manager, versionEvents <-chan event.GenericEvent) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Rulesfile{}, builder.WithPredicates(shared.ParentChanged())).
		Watches(&artifactv1alpha1.ArtifactNode{},
			shared.AssignmentHandler(kind, artifact.KindPlugin)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.findRulesfilesForConfigMap)).
		WatchesRawSource(source.Channel(versionEvents, handler.EnqueueRequestsFromMapFunc(shared.AssignedRequests(r.Client, r.node, kind)))).
		// The node controller asks for the removal of what the node holds for an artifact the spec of its ArtifactNode no
		// longer lists.
		WatchesRawSource(source.Channel(r.node.RemovalRequests(kind), &handler.EnqueueRequestForObject{})).
		Named("artifact-rulesfile").
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), "artifact-rulesfile", &artifactv1alpha1.Rulesfile{})).
		Complete(r)
}

// findRulesfilesForConfigMap maps a ConfigMap event to the Rulesfiles that reference it.
func (r *RulesfileReconciler) findRulesfilesForConfigMap(ctx context.Context, configMap client.Object) []reconcile.Request {
	return controllerhelper.RequestsReferencing(ctx, r.Client, &artifactv1alpha1.RulesfileList{}, index.ConfigMapOnRulesfile, configMap)
}
