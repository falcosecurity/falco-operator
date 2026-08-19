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

package controllerhelper

import (
	"context"
	"fmt"
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// patchFinalizer adds (add=true) or removes (add=false) finalizer on obj, then applies the
// change via a MergeFrom patch. obj is mutated in place. Callers classify/handle the returned
// error themselves.
func patchFinalizer(ctx context.Context, cl client.Client, obj client.Object, finalizer string, add bool) error {
	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object)) //nolint:forcetypeassert // client.Object always satisfies this

	if add {
		controllerutil.AddFinalizer(obj, finalizer)
	} else {
		controllerutil.RemoveFinalizer(obj, finalizer)
	}

	return cl.Patch(ctx, obj, patch)
}

// EnsureFinalizer adds the given finalizer to obj if not already present.
// Returns (true, nil) when the finalizer was just added, (false, nil) if already present,
// or (false, err) on patch failure.
func EnsureFinalizer(ctx context.Context, cl client.Client, finalizer string, obj client.Object) (bool, error) {
	if controllerutil.ContainsFinalizer(obj, finalizer) {
		return false, nil
	}

	logger := log.FromContext(ctx)
	logger.V(3).Info("Setting finalizer", "finalizer", finalizer)

	if err := patchFinalizer(ctx, cl, obj, finalizer, true); err != nil {
		if k8serrors.IsConflict(err) {
			logger.V(3).Info("Conflict while setting finalizer, will retry")
			return false, err
		}
		logger.Error(err, "unable to set finalizer", "finalizer", finalizer)
		return false, err
	}

	logger.V(3).Info("Finalizer set", "finalizer", finalizer)
	return true, nil
}

// EnsureInUseFinalizer adds or removes a single finalizer on obj based on whether the object is
// currently referenced (isReferenced): the finalizer is added when isReferenced is true, and
// removed when it's false. obj is re-fetched before the check so the decision is made against
// the object's current server state, not whatever the caller happened to be holding.
//
// A no-op guard avoids any API call when the current state already matches the desired state.
// A NotFound from the initial Get, and a NotFound or Conflict from the patch, are treated as
// nothing left to do rather than errors, since another actor already removed or changed the
// object.
func EnsureInUseFinalizer(ctx context.Context, c client.Client, finalizer string, obj client.Object, isReferenced bool) error {
	logger := log.FromContext(ctx)

	current := obj.DeepCopyObject().(client.Object) //nolint:forcetypeassert // client.Object always satisfies this
	if err := c.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("re-fetching %s/%s before updating finalizer: %w", obj.GetNamespace(), obj.GetName(), err)
	}

	// Nothing to do when state already matches.
	if isReferenced == controllerutil.ContainsFinalizer(current, finalizer) {
		return nil
	}

	if isReferenced {
		logger.Info("Adding in-use finalizer", "finalizer", finalizer)
	} else {
		logger.Info("Removing in-use finalizer", "finalizer", finalizer)
	}

	if err := patchFinalizer(ctx, c, current, finalizer, isReferenced); err != nil {
		if k8serrors.IsNotFound(err) || k8serrors.IsConflict(err) {
			logger.V(3).Info("Object gone or changed before finalizer update landed, skipping", "err", err)
			return nil
		}
		return fmt.Errorf("updating finalizer on %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
	}

	return nil
}

// legacyParentFinalizerPrefixes are the finalizer prefixes that pre node-object artifact
// operators placed directly on parent Plugin/Rulesfile/Config objects, one per node
// ("<kind>.artifact.falcosecurity.dev/finalizer-<nodeName>"). Nothing removes them anymore,
// so the instance-operator aggregators strip them on sight.
var legacyParentFinalizerPrefixes = []string{
	"rulesfile.artifact.falcosecurity.dev/finalizer-",
	"plugin.artifact.falcosecurity.dev/finalizer-",
	"config.artifact.falcosecurity.dev/finalizer-",
}

// ReconcileInUseFinalizer reconciles the full finalizer set of a parent artifact: it
// strips legacy per-node finalizers (legacyParentFinalizerPrefixes) and adds/removes the
// given in-use finalizer based on isReferenced. The object is re-fetched first so the
// decision is made against current server state; unknown (foreign) finalizers are
// preserved.
//
// Both additions and removals go through a single MergeFrom patch that replaces the whole
// finalizer list. That is deliberate, not incidental: SSA cannot remove elements of
// metadata.finalizers (a listType=set field) that are owned or co-owned by other managers,
// since applying the same value only adds the applier as a co-owner, it never strips the
// previous owner. A merge patch is the only form that can evict another manager's entries
// (e.g. a legacy per-node finalizer left by an old operator version), so this function uses
// it uniformly for both directions rather than switching mechanisms by direction.
//
// Use this only on objects whose finalizers are meant to be managed by the calling
// controller (the artifact CRDs). For shared core resources (Secrets, ConfigMaps) use
// EnsureInUseFinalizer instead, which only touches its own finalizer.
//
// A no-op guard avoids any API call when the current state already matches the desired
// state. A NotFound from the initial Get, and a NotFound or Conflict from the patch, are
// treated as nothing left to do rather than errors, mirroring EnsureInUseFinalizer.
func ReconcileInUseFinalizer(ctx context.Context, c client.Client,
	obj client.Object, finalizer string, isReferenced bool,
) error {
	logger := log.FromContext(ctx)

	current := obj.DeepCopyObject().(client.Object) //nolint:forcetypeassert // client.Object always satisfies this
	if err := c.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("re-fetching %s/%s before updating finalizer: %w", obj.GetNamespace(), obj.GetName(), err)
	}

	desired := make([]string, 0, len(current.GetFinalizers())+1)
	for _, f := range current.GetFinalizers() {
		if isLegacyParentFinalizer(f) {
			logger.Info("Removing legacy per-node finalizer", "finalizer", f)
			continue
		}
		if f != finalizer {
			desired = append(desired, f)
		}
	}
	if isReferenced {
		desired = append(desired, finalizer)
	}

	// Nothing to do when state already matches (finalizers are order-independent).
	if finalizerSetsEqual(desired, current.GetFinalizers()) {
		return nil
	}

	base := current.DeepCopyObject().(client.Object) //nolint:forcetypeassert // client.Object always satisfies this
	current.SetFinalizers(desired)
	if err := c.Patch(ctx, current, client.MergeFrom(base)); err != nil {
		return swallowGoneOrConflict(ctx, err, obj)
	}
	return nil
}

// swallowGoneOrConflict returns nil when err is NotFound or Conflict (the object is gone
// or changed underneath us; a later reconcile settles it), and a wrapped error otherwise.
func swallowGoneOrConflict(ctx context.Context, err error, obj client.Object) error {
	if k8serrors.IsNotFound(err) || k8serrors.IsConflict(err) {
		log.FromContext(ctx).V(3).Info("Object gone or changed before finalizer update landed, skipping", "err", err)
		return nil
	}
	return fmt.Errorf("updating finalizers on %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
}

// finalizerSetsEqual reports whether a and b contain the same finalizers, ignoring order.
func finalizerSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(b))
	for _, f := range b {
		set[f] = struct{}{}
	}
	for _, f := range a {
		if _, ok := set[f]; !ok {
			return false
		}
	}
	return true
}

// isLegacyParentFinalizer reports whether f carries one of the legacy per-node finalizer
// prefixes placed on parent artifacts by pre node-object artifact operators.
func isLegacyParentFinalizer(f string) bool {
	for _, prefix := range legacyParentFinalizerPrefixes {
		if strings.HasPrefix(f, prefix) {
			return true
		}
	}
	return false
}
