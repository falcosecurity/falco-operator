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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// SpecChangedOrDeleting accepts the events that can change what a controller does with an object: its creation,
// deletion and spec changes (generation), and any event on an object that is being deleted. Updates of the status
// or the metadata alone are ignored, so that a controller that is the only writer of them is not woken by its
// own writes.
func SpecChangedOrDeleting() predicate.Predicate {
	return predicate.Or(
		predicate.GenerationChangedPredicate{},
		predicate.NewPredicateFuncs(func(obj client.Object) bool { return !obj.GetDeletionTimestamp().IsZero() }),
	)
}

// CreatedOrDeleted accepts only the creation and the deletion of an object, for a controller that cares that the
// object exists and about nothing in it.
func CreatedOrDeleted() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc:  func(event.UpdateEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}
