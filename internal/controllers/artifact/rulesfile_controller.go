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
)

const (
	// rulesfileFinalizerPrefix is the prefix for the finalizer name.
	rulesfileFinalizerPrefix = "rulesfile.artifact.falcosecurity.dev/finalizer"
)

// NewRulesfileReconciler returns a new RulesfileReconciler.
func NewRulesfileReconciler(cl client.Client, scheme *runtime.Scheme, nodeName, namespace string) *RulesfileReconciler {
	return &RulesfileReconciler{
		Client:          cl,
		Scheme:          scheme,
		finalizer:       common.FormatFinalizerName(rulesfileFinalizerPrefix, nodeName),
		artifactManager: artifact.NewManager(cl, namespace),
		nodeName:        nodeName,
	}
}

// RulesfileReconciler reconciles a Rulesfile object.
type RulesfileReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	finalizer       string
	artifactManager *artifact.Manager
	nodeName        string
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *RulesfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var err error
	logger := log.FromContext(ctx)
	rulesfile := &artifactv1alpha1.Rulesfile{}

	// Fetch the Rulesfile instance.
	logger.V(2).Info("Fetching Rulesfile instance")

	if err = r.Get(ctx, req.NamespacedName, rulesfile); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch Rulesfile")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	} else if apierrors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the Rulesfile instance is for the current node.
	if ok, err := controllerhelper.NodeMatchesSelector(ctx, r.Client, r.nodeName, rulesfile.Spec.Selector); err != nil {
		return ctrl.Result{}, err
	} else if !ok {
		logger.Info("Rulesfile instance does not match node selector, will remove local resources if any")

		// Here we handle the case where the rulesfile was created with a selector that matched the node, but now it doesn't.
		if ok, err := controllerhelper.RemoveLocalResources(ctx, r.Client, r.artifactManager, r.finalizer, rulesfile); ok || err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Handle deletion.
	if ok, err := controllerhelper.HandleObjectDeletion(ctx, r.Client, r.artifactManager, r.finalizer, rulesfile); ok || err != nil {
		return ctrl.Result{}, err
	}
	// Ensure the finalizer is set.
	if ok, err := r.ensureFinalizer(ctx, rulesfile); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the rulesfile.
	if err := r.ensureRulesfile(ctx, rulesfile); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RulesfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Rulesfile{}).
		Named("artifact-rulesfile").
		Complete(r)
}

// ensureFinalizer ensures the finalizer is set.
func (r *RulesfileReconciler) ensureFinalizer(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) (bool, error) {
	if !controllerutil.ContainsFinalizer(rulesfile, r.finalizer) {
		logger := log.FromContext(ctx)
		logger.V(3).Info("Setting finalizer", "finalizer", r.finalizer)
		controllerutil.AddFinalizer(rulesfile, r.finalizer)

		if err := r.Update(ctx, rulesfile); err != nil && !apierrors.IsConflict(err) {
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

func (r *RulesfileReconciler) ensureRulesfile(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	// Get the priority of the configuration.
	p := rulesfile.Spec.Priority

	if err := r.artifactManager.StoreFromOCI(ctx, rulesfile.Name, p, artifact.TypeRulesfile, rulesfile.Spec.OCIArtifact); err != nil {
		return err
	}

	if err := r.artifactManager.StoreFromInLineYaml(ctx, rulesfile.Name, p, rulesfile.Spec.InlineRules, artifact.TypeRulesfile); err != nil {
		return err
	}

	return nil
}
