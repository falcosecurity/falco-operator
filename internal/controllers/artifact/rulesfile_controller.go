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

	artifactv1alpha1 "github.com/alacuku/falco-operator/api/artifact/v1alpha1"
	"github.com/alacuku/falco-operator/internal/pkg/common"
	"github.com/alacuku/falco-operator/internal/pkg/priority"
)

const (
	// rulesfileFinalizerPrefix is the prefix for the finalizer name.
	rulesfileFinalizerPrefix = "rulesfile.artifact.falcosecurity.dev/finalizer"
)

// NewRulesfileReconciler returns a new RulesfileReconciler.
func NewRulesfileReconciler(cl client.Client, scheme *runtime.Scheme, nodeName string) *RulesfileReconciler {
	return &RulesfileReconciler{
		Client:              cl,
		Scheme:              scheme,
		finalizer:           common.FormatFinalizerName(rulesfileFinalizerPrefix, nodeName),
		rulesfilePriorities: make(map[string]string),
	}
}

// RulesfileReconciler reconciles a Rulesfile object.
type RulesfileReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	finalizer           string
	rulesfilePriorities map[string]string
}

// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=rulesfiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=rulesfiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=artifact.falcosecurity.dev,resources=rulesfiles/finalizers,verbs=update

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

	// Initialize the rulesfile priority.
	if err := r.initRulesfilesPriority(ctx, rulesfile); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the finalizer is set.
	if ok, err := r.ensureFinalizer(ctx, rulesfile); ok || err != nil {
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

// initRulesfilePriority checks if a priority exists for the rulesfile in the rulesfilePriority map.
// If it doesn't exist, it extracts the priority from annotations and adds it to the map.
// If it already exists, it does nothing (even if the priority differs from the current one).
func (r *RulesfileReconciler) initRulesfilesPriority(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile) error {
	logger := log.FromContext(ctx)

	// If there's already a priority for this config, do nothing
	if _, exists := r.rulesfilePriorities[rulesfile.Name]; exists {
		logger.V(3).Info("Priority already exists in the map, not changing it")
		return nil
	}

	// Extract priority from annotations
	p, err := priority.ValidateAndExtract(rulesfile.Annotations)
	if err != nil {
		logger.Error(err, "unable to extract priority from config annotations")
		return err
	}

	// Store the priority in the map
	r.rulesfilePriorities[rulesfile.Name] = p
	logger.V(3).Info("Priority initialized for config", "priority", p)
	return nil
}
