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

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// EnqueueAllOfType lists every object of list's type and returns one reconcile.Request per item, for use in
// handler.EnqueueRequestsFromMapFunc watches that re-evaluate every parent artifact (Plugin/Rulesfile/Config)
// on an unrelated event (e.g. a Node's labels changing). list must be a pointer to an empty list (e.g.
// &artifactv1alpha1.PluginList{}); it is populated in place by the List call. Optional opts (e.g.
// client.InNamespace) narrow the listing.
func EnqueueAllOfType(ctx context.Context, cl client.Client, list client.ObjectList, opts ...client.ListOption) []reconcile.Request {
	if err := cl.List(ctx, list, opts...); err != nil {
		log.FromContext(ctx).Error(err, "unable to list for re-enqueue", "type", fmt.Sprintf("%T", list))
		return nil
	}
	items, err := apimeta.ExtractList(list)
	if err != nil {
		log.FromContext(ctx).Error(err, "unable to extract list items for re-enqueue", "type", fmt.Sprintf("%T", list))
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(items))
	for _, item := range items {
		obj, ok := item.(client.Object)
		if !ok {
			continue
		}
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
	}
	return reqs
}
