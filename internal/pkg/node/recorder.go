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

package node

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// recorderFor emits the Events that accompany the conditions the node sets.
type recorderFor struct{ node *Node }

func (r recorderFor) storeEvent(obj client.Object, action artifact.StoreAction, medium artifact.Medium) {
	artifact.RecordStoreEvent(r.node.recorder, obj, action, medium)
}

func (r recorderFor) warnf(obj client.Object, reason, format string, args ...any) {
	artifact.RecordWarning(r.node.recorder, obj, reason, format, args...)
}

// nopRecorder drops every Event. It stands in for a caller that did not supply a recorder, so
// that nothing downstream, including helpers the node hands its recorder to, has to check for
// nil before recording.
type nopRecorder struct{}

func (nopRecorder) Eventf(_, _ runtime.Object, _, _, _, _ string, _ ...any) {}
