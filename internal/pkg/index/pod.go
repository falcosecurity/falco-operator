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

package index

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PodNodeName is the index field name for Pods indexed by the node they are scheduled on.
const PodNodeName = "PodNodeName"

// PodByNodeName indexes Pods by their .spec.nodeName. A pod that is not scheduled yet is on no node.
func PodByNodeName(obj client.Object) []string {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod.Spec.NodeName == "" {
		return nil
	}
	return []string{pod.Spec.NodeName}
}

// PodIndexes holds the field indexes on Pods. Only the instance operator registers them: it reconciles one
// ArtifactNode per node and asks for that node's Falco pods, where the sidecar never lists pods at all.
var PodIndexes = []Entry{
	{
		Object:         &corev1.Pod{},
		Field:          PodNodeName,
		ExtractValueFn: PodByNodeName,
	},
}
