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

package secret

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

// ControllerName is the name of the Secret controller. It is also used as the field manager name for finalizer updates.
const ControllerName = "secret-in-use-finalizer"

// NewSecretReconciler returns a new SecretReconciler.
func NewSecretReconciler(cl client.Client, scheme *runtime.Scheme) *SecretReconciler {
	return &SecretReconciler{
		Client: cl,
		Scheme: scheme,
	}
}

// SecretReconciler protects Secrets that are referenced by Rulesfile or Plugin resources
// via spec.ociArtifact.registry.auth.secretRef.
type SecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile ensures the in-use finalizer is present on referenced Secrets and absent otherwise.
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		if k8serrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to fetch Secret")
		return ctrl.Result{}, err
	}

	referenced, err := r.isReferenced(ctx, secret)
	if err != nil {
		return ctrl.Result{}, err
	}

	// If the Secret is being deleted and still referenced, log a warning and do nothing.
	// The finalizer already blocks the deletion; waiting for references to be cleared.
	if !secret.DeletionTimestamp.IsZero() && referenced {
		logger.Info("Secret marked for deletion but still referenced; blocking until references are cleared")
		return ctrl.Result{}, nil
	}

	if err := controllerhelper.EnsureInUseFinalizer(
		ctx, r.Client, r.Scheme, common.SecretInUseFinalizer, ControllerName, secret, referenced); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller with the Manager.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Watches(
			&artifactv1alpha1.Rulesfile{},
			handler.EnqueueRequestsFromMapFunc(r.findSecretsForRulesfile),
		).
		Watches(
			&artifactv1alpha1.Plugin{},
			handler.EnqueueRequestsFromMapFunc(r.findSecretsForPlugin),
		).
		Named(ControllerName).
		Complete(r)
}

// isReferenced returns true when at least one Rulesfile or Plugin references the given Secret.
func (r *SecretReconciler) isReferenced(ctx context.Context, secret client.Object) (bool, error) {
	indexKey := secret.GetNamespace() + "/" + secret.GetName()

	rfList := &artifactv1alpha1.RulesfileList{}
	if err := r.List(ctx, rfList, client.MatchingFields{index.SecretOnRulesfile: indexKey}); err != nil {
		return false, err
	}
	if len(rfList.Items) > 0 {
		return true, nil
	}

	plList := &artifactv1alpha1.PluginList{}
	if err := r.List(ctx, plList, client.MatchingFields{index.SecretOnPlugin: indexKey}); err != nil {
		return false, err
	}
	return len(plList.Items) > 0, nil
}

// findSecretsForRulesfile enqueues the Secret named in a Rulesfile's
// spec.ociArtifact.registry.auth.secretRef.
func (r *SecretReconciler) findSecretsForRulesfile(_ context.Context, obj client.Object) []reconcile.Request {
	rf, ok := obj.(*artifactv1alpha1.Rulesfile)
	if !ok {
		return nil
	}
	if rf.Spec.OCIArtifact == nil || rf.Spec.OCIArtifact.Registry == nil ||
		rf.Spec.OCIArtifact.Registry.Auth == nil || rf.Spec.OCIArtifact.Registry.Auth.SecretRef == nil {
		return nil
	}
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: rf.Namespace, Name: rf.Spec.OCIArtifact.Registry.Auth.SecretRef.Name}},
	}
}

// findSecretsForPlugin enqueues the Secret named in a Plugin's
// spec.ociArtifact.registry.auth.secretRef.
func (r *SecretReconciler) findSecretsForPlugin(_ context.Context, obj client.Object) []reconcile.Request {
	pl, ok := obj.(*artifactv1alpha1.Plugin)
	if !ok {
		return nil
	}
	if pl.Spec.OCIArtifact == nil || pl.Spec.OCIArtifact.Registry == nil ||
		pl.Spec.OCIArtifact.Registry.Auth == nil || pl.Spec.OCIArtifact.Registry.Auth.SecretRef == nil {
		return nil
	}
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: pl.Namespace, Name: pl.Spec.OCIArtifact.Registry.Auth.SecretRef.Name}},
	}
}
