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

// Package configmap implements the ConfigMap in-use protection controller.
// It runs in the main falco operator (Deployment) and ensures that ConfigMaps
// referenced by Rulesfile or Config artifact resources cannot be deleted until
// all references are cleared.
package configmap

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
)

// ControllerName is the name of the ConfigMap in-use finalizer controller.
// It is used in log messages and as the field manager when updating finalizers.
const ControllerName = "configmap-in-use-finalizer"

// NewConfigMapReconciler returns a new ConfigMapReconciler.
func NewConfigMapReconciler(cl client.Client, scheme *runtime.Scheme) *ConfigMapReconciler {
	return &ConfigMapReconciler{
		Client: cl,
		Scheme: scheme,
	}
}

// ConfigMapReconciler protects ConfigMaps that are referenced by Rulesfile or Config resources.
type ConfigMapReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile ensures the in-use finalizer is present on referenced ConfigMaps and absent otherwise.
func (r *ConfigMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, req.NamespacedName, cm); err != nil {
		if k8serrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to fetch ConfigMap")
		return ctrl.Result{}, err
	}

	referenced, err := r.isReferenced(ctx, cm)
	if err != nil {
		return ctrl.Result{}, err
	}

	// If the ConfigMap is being deleted and still referenced, log a warning and do nothing.
	// The finalizer already blocks the deletion; waiting for references to be cleared.
	if !cm.DeletionTimestamp.IsZero() && referenced {
		logger.Info("ConfigMap marked for deletion but still referenced; blocking until references are cleared")
		return ctrl.Result{}, nil
	}

	if err := controllerhelper.EnsureInUseFinalizer(
		ctx, r.Client, r.Scheme, common.ConfigmapInUseFinalizer, ControllerName, cm, referenced); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller with the Manager.
func (r *ConfigMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Watches(
			&artifactv1alpha1.Rulesfile{},
			handler.EnqueueRequestsFromMapFunc(r.findConfigMapsForRulesfile),
		).
		Watches(
			&artifactv1alpha1.Config{},
			handler.EnqueueRequestsFromMapFunc(r.findConfigMapsForConfig),
		).
		Named(ControllerName).
		Complete(r)
}

// isReferenced returns true when at least one Rulesfile or Config references the given ConfigMap.
func (r *ConfigMapReconciler) isReferenced(ctx context.Context, cm client.Object) (bool, error) {
	indexKey := cm.GetNamespace() + "/" + cm.GetName()

	rfList := &artifactv1alpha1.RulesfileList{}
	if err := r.List(ctx, rfList, client.MatchingFields{index.ConfigMapOnRulesfile: indexKey}); err != nil {
		return false, err
	}
	if len(rfList.Items) > 0 {
		return true, nil
	}

	cfgList := &artifactv1alpha1.ConfigList{}
	if err := r.List(ctx, cfgList, client.MatchingFields{index.ConfigMapOnConfig: indexKey}); err != nil {
		return false, err
	}
	return len(cfgList.Items) > 0, nil
}

// findConfigMapsForRulesfile enqueues the ConfigMap named in a Rulesfile's spec.configMapRef.
func (r *ConfigMapReconciler) findConfigMapsForRulesfile(_ context.Context, obj client.Object) []reconcile.Request {
	rf, ok := obj.(*artifactv1alpha1.Rulesfile)
	if !ok || rf.Spec.ConfigMapRef == nil {
		return nil
	}
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: rf.Namespace, Name: rf.Spec.ConfigMapRef.Name}},
	}
}

// findConfigMapsForConfig enqueues the ConfigMap named in a Config's spec.configMapRef.
func (r *ConfigMapReconciler) findConfigMapsForConfig(_ context.Context, obj client.Object) []reconcile.Request {
	cfg, ok := obj.(*artifactv1alpha1.Config)
	if !ok || cfg.Spec.ConfigMapRef == nil {
		return nil
	}
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: cfg.Namespace, Name: cfg.Spec.ConfigMapRef.Name}},
	}
}
