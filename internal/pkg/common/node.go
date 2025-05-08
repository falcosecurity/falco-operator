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

package common

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// NodeMatchesSelector checks if a selector matches the node labels.
func NodeMatchesSelector(ctx context.Context, cl client.Client, nodeName string, labelSelector *metav1.LabelSelector) (bool, error) {
	logger := log.FromContext(ctx)

	// If the labelSelector is nil, return true.
	if labelSelector == nil {
		logger.V(2).Info("LabelSelector is nil, returning true")
		return true, nil
	}

	// Fetch the partial object metadata for the node.
	node := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
	}
	logger.V(2).Info("Fetching node", "name", nodeName)
	if err := cl.Get(ctx, client.ObjectKey{Name: nodeName}, node); err != nil {
		logger.Error(err, "unable to fetch node")
		return false, err
	}

	// Convert the LabelSelector to a Selector.
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		logger.Error(err, "invalid label selector", "labelSelector", labelSelector)
		return false, err
	}

	// Check if the node matches the selector.
	logger.V(2).Info("Checking node labelSelector", "node", nodeName, "labelSelector", labelSelector)
	if selector.Matches(labels.Set(node.Labels)) {
		logger.V(2).Info("Node matches labelSelector", "node", nodeName)
		return true, nil
	} else {
		logger.V(2).Info("Node does not match labelSelector", "node", nodeName)
		return false, nil
	}
}
