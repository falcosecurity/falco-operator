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

// Package plugin implements the artifact operator's per-node plugin reconciler.
package plugin

import (
	"context"
	"errors"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/shared"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/node"
)

// kind is the artifact kind this reconciler handles.
const kind = artifact.KindPlugin

// NewPluginReconciler creates a new PluginReconciler instance.
func NewPluginReconciler(cl client.Client, recorder events.EventRecorder, n *node.Node) *PluginReconciler {
	return &PluginReconciler{Client: cl, recorder: recorder, node: n}
}

// PluginReconciler reconciles the Plugins assigned to this node by its ArtifactNode.
type PluginReconciler struct {
	client.Client
	recorder events.EventRecorder
	node     *node.Node
}

// Reconcile reconciles the Plugin named by req, on this node. When the spec of the node's ArtifactNode lists it,
// it is installed. When it does not, or the Plugin is gone, whatever this node holds for it is removed: the node
// controller asks for that whenever the spec stops listing an artifact, and a single reconcile per artifact at a
// time is what keeps an install and a removal from overlapping.
func (r *PluginReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return shared.ReconcileArtifact(ctx, r.Client, r.node, req, &artifactv1alpha1.Plugin{}, r.Cleanup)
}

// Cleanup removes everything installed for the Plugin named name: its entry in the shared plugin
// config first, then its binary. It returns a *node.BlockedError while a Rulesfile on this node
// still requires the plugin's config, after publishing a DeletionBlocked condition so the parent shows why
// the plugin is still there. It is idempotent.
//
// Removal needs only what installation recorded, which the node holds under the plugin's key: the parent
// may be gone, or be another incarnation than the one that installed the files.
func (r *PluginReconciler) Cleanup(ctx context.Context, name string) error {
	logger := log.FromContext(ctx)
	err := r.node.Remove(ctx, artifact.Ref{Kind: kind, Name: name})
	if err == nil {
		return nil
	}
	blocked, ok := errors.AsType[*node.BlockedError](err)
	if !ok {
		logger.Error(err, "unable to remove installed plugin artifacts from disk", "plugin", name)
		return err
	}
	logger.Info("Plugin removal blocked: plugin config still required by a Rulesfile on this node",
		"plugin", name, "configName", blocked.Name, "blockedBy", blocked.BlockedBy)
	if publishErr := r.publishDeletionBlocked(ctx, name, blocked); publishErr != nil {
		return publishErr
	}
	return err
}

// publishDeletionBlocked puts a DeletionBlocked condition on the plugin's status entry, so that the parent
// shows why the plugin is still on the node. The entry is the one the node holds, which may be for an
// earlier incarnation of the plugin than the live one; the live one, when there is one, gets the Event and
// lends its generation.
func (r *PluginReconciler) publishDeletionBlocked(ctx context.Context, name string, blocked *node.BlockedError) error {
	blockedOn := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: r.node.Namespace(), Name: name}}
	parent := &artifactv1alpha1.Plugin{}
	switch err := r.Get(ctx, client.ObjectKeyFromObject(blockedOn), parent); {
	case err == nil:
		blockedOn.UID, blockedOn.Generation = parent.UID, parent.Generation
		artifact.RecordWarning(r.recorder, parent, artifact.ReasonDependenciesNotSatisfied, "%s", blocked.Error())
	case !k8serrors.IsNotFound(err):
		return err
	}
	if entry, ok := r.node.StatusEntry(kind, name); ok {
		blockedOn.UID = types.UID(entry.UID)
	}
	if blockedOn.UID == "" {
		// The plugin is gone and the node knows of it from its files alone. An entry needs a uid, and one
		// without would get every later write of the node's status rejected, so the block is only logged.
		log.FromContext(ctx).Info("Not reporting the blocked removal: the plugin is gone and the node has no status entry for it",
			"plugin", name)
		return nil
	}
	status, _ := r.node.StatusFor(kind, blockedOn)
	apimeta.SetStatusCondition(&status.Conditions, common.NewDeletionBlockedCondition(
		metav1.ConditionTrue, artifact.ReasonPluginConfigStillRequired, blocked.Error(), blockedOn.Generation,
	))
	r.node.PublishStatus(kind, blockedOn, status)
	return nil
}

// SetupWithManager registers the controller: one reconcile per Plugin, woken by the
// Plugin itself, by its assignment on this node, and by a change of Falco's
// reported capabilities (versionEvents), which can satisfy a requirement that blocked an install.
func (r *PluginReconciler) SetupWithManager(mgr ctrl.Manager, versionEvents <-chan event.GenericEvent) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Plugin{}, builder.WithPredicates(shared.ParentChanged())).
		Watches(&artifactv1alpha1.ArtifactNode{}, shared.AssignmentHandler(kind)).
		WatchesRawSource(source.Channel(versionEvents, handler.EnqueueRequestsFromMapFunc(shared.AssignedRequests(r.Client, r.node, kind)))).
		// The node controller asks for the removal of what the node holds for an artifact the spec of its ArtifactNode no
		// longer lists.
		WatchesRawSource(source.Channel(r.node.RemovalRequests(kind), &handler.EnqueueRequestForObject{})).
		Named("artifact-plugin").
		WithLogConstructor(controllerhelper.LogConstructorFor(mgr.GetLogger(), mgr.GetScheme(), "artifact-plugin", &artifactv1alpha1.Plugin{})).
		Complete(r)
}
