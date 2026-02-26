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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
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
	configFinalizerPrefix = "config.artifact.falcosecurity.dev/finalizer"
)

// NewConfigReconciler returns a new ConfigReconciler.
func NewConfigReconciler(
	cl client.Client,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	nodeName, namespace string,
) *ConfigReconciler {
	return &ConfigReconciler{
		Client:          cl,
		Scheme:          scheme,
		recorder:        recorder,
		finalizer:       common.FormatFinalizerName(configFinalizerPrefix, nodeName),
		artifactManager: artifact.NewManager(cl, namespace),
		nodeName:        nodeName,
		conditions:      make(map[string][]metav1.Condition),
	}
}

// ConfigReconciler reconciles a Config object.
type ConfigReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	recorder        events.EventRecorder
	finalizer       string
	artifactManager *artifact.Manager
	nodeName        string
	conditions      map[string][]metav1.Condition
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var err error
	logger := log.FromContext(ctx)
	config := &artifactv1alpha1.Config{}

	// Fetch the Config instance.
	logger.V(2).Info("Fetching Config instance")

	if err = r.Get(ctx, req.NamespacedName, config); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "unable to fetch Config instance")
		return ctrl.Result{}, err
	} else if apierrors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the Config instance is for the current node.
	if ok, err := controllerhelper.NodeMatchesSelector(ctx, r.Client, r.nodeName, config.Spec.Selector); err != nil {
		return ctrl.Result{}, err
	} else if !ok {
		logger.Info("Config instance does not match node selector, will remove local resources if any")

		// Handle case where config selector no longer matches the node.
		if ok, err := controllerhelper.RemoveLocalResources(ctx, r.Client, r.artifactManager, r.finalizer, config); ok || err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Handle deletion.
	if ok, err := controllerhelper.HandleObjectDeletion(ctx, r.Client, r.artifactManager, r.finalizer, config); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Ensure the finalizer is set.
	if ok, err := r.ensureFinalizer(ctx, config); ok || err != nil {
		return ctrl.Result{}, err
	}

	// Update status via defer to ensure it's always called.
	defer func() {
		if err := r.updateStatus(ctx, config); err != nil {
			logger.Error(err, "unable to update status")
		}
	}()

	// Ensure the configuration is written to the filesystem.
	if err := r.ensureConfig(ctx, config); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactv1alpha1.Config{}).
		Named("artifact-config").
		Complete(r)
}

// ensureFinalizer ensures the finalizer is set.
func (r *ConfigReconciler) ensureFinalizer(ctx context.Context, config *artifactv1alpha1.Config) (bool, error) {
	if !controllerutil.ContainsFinalizer(config, r.finalizer) {
		logger := log.FromContext(ctx)
		logger.V(3).Info("Setting finalizer", "finalizer", r.finalizer)

		patch := client.MergeFrom(config.DeepCopy())
		controllerutil.AddFinalizer(config, r.finalizer)
		if err := r.Patch(ctx, config, patch); err != nil {
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

// ensureConfig ensures the configuration is written to the filesystem.
func (r *ConfigReconciler) ensureConfig(ctx context.Context, config *artifactv1alpha1.Config) error {
	key := fmt.Sprintf("%s/%s", config.Namespace, config.Name)
	gen := config.GetGeneration()
	var conditions []metav1.Condition
	var err error

	// Ensure Reconciled condition is stored even on early return.
	defer func() {
		// Add overall Reconciled condition.
		if err != nil {
			conditions = append(conditions, common.NewReconciledCondition(
				metav1.ConditionFalse,
				artifact.ReasonReconcileFailed,
				err.Error(),
				gen,
			))
		} else {
			r.recorder.Eventf(config, nil, corev1.EventTypeNormal, artifact.ReasonReconciled, artifact.ReasonReconciled, artifact.MessageConfigReconciled)
			conditions = append(conditions, common.NewReconciledCondition(
				metav1.ConditionTrue,
				artifact.ReasonReconciled,
				artifact.MessageConfigReconciled,
				gen,
			))
		}
		r.conditions[key] = conditions
	}()

	if err := r.artifactManager.StoreFromInLineYaml(
		ctx, config.Name, config.Spec.Priority, &config.Spec.Config, artifact.TypeConfig,
	); err != nil {
		r.recorder.Eventf(config, nil, corev1.EventTypeWarning, artifact.ReasonInlineConfigStoreFailed,
			artifact.ReasonInlineConfigStoreFailed, artifact.MessageFormatConfigStoreFailed, err.Error())
		conditions = append(conditions, common.NewInlineContentCondition(
			metav1.ConditionFalse,
			artifact.ReasonInlineConfigStoreFailed,
			fmt.Sprintf(artifact.MessageFormatConfigStoreFailed, err.Error()),
			gen,
		))
		return err
	}

	r.recorder.Eventf(config, nil, corev1.EventTypeNormal, artifact.ReasonInlineConfigStored,
		artifact.ReasonInlineConfigStored, artifact.MessageInlineConfigStored)
	conditions = append(conditions, common.NewInlineContentCondition(
		metav1.ConditionTrue,
		artifact.ReasonInlineConfigStored,
		artifact.MessageInlineConfigStored,
		gen,
	))
	return nil
}

// updateStatus updates the Config status with conditions collected during reconciliation.
func (r *ConfigReconciler) updateStatus(ctx context.Context, config *artifactv1alpha1.Config) error {
	key := fmt.Sprintf("%s/%s", config.Namespace, config.Name)

	// Get conditions collected during reconciliation.
	conditions, ok := r.conditions[key]
	if !ok || len(conditions) == 0 {
		return nil
	}

	// Clean up conditions from map after use.
	defer delete(r.conditions, key)

	// Create patch from current state.
	patch := client.MergeFrom(config.DeepCopy())

	for _, c := range conditions {
		apimeta.SetStatusCondition(&config.Status.Conditions, c)
	}

	if err := r.Status().Patch(ctx, config, patch); err != nil {
		if apierrors.IsConflict(err) {
			log.FromContext(ctx).V(3).Info("Conflict while patching status, will retry")
			return nil
		}
		return fmt.Errorf("unable to patch status: %w", err)
	}

	return nil
}
