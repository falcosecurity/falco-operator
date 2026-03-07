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

package artifact

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
)

// RecordWarning records a Warning event on obj with the given reason and formatted message.
func RecordWarning(r events.EventRecorder, obj runtime.Object, reason, messageFmt string, args ...any) {
	r.Eventf(obj, nil, corev1.EventTypeWarning, reason, reason, messageFmt, args...)
}

// RecordNormal records a Normal event on obj with the given reason and message.
func RecordNormal(r events.EventRecorder, obj runtime.Object, reason, message string) {
	r.Eventf(obj, nil, corev1.EventTypeNormal, reason, reason, message)
}

// RecordStoreEvent records a Normal event for a store operation based on the action and medium.
// No event is recorded for StoreActionNone or StoreActionUnchanged.
func RecordStoreEvent(r events.EventRecorder, obj runtime.Object, action StoreAction, medium Medium) {
	var reason, message string
	switch {
	case action == StoreActionRemoved && medium == MediumOCI:
		reason, message = ReasonOCIArtifactRemoved, MessageOCIArtifactRemoved
	case action == StoreActionRemoved && medium == MediumInline:
		reason, message = ReasonInlineArtifactRemoved, MessageInlineArtifactRemoved
	case action == StoreActionRemoved && medium == MediumConfigMap:
		reason, message = ReasonConfigMapArtifactRemoved, MessageConfigMapArtifactRemoved
	case action == StoreActionPriorityChanged && medium == MediumOCI:
		reason, message = ReasonOCIArtifactPriorityChanged, MessageOCIArtifactPriorityChanged
	case action == StoreActionPriorityChanged && medium == MediumInline:
		reason, message = ReasonInlineArtifactPriorityChanged, MessageInlineArtifactPriorityChanged
	case action == StoreActionPriorityChanged && medium == MediumConfigMap:
		reason, message = ReasonConfigMapArtifactPriorityChanged, MessageConfigMapArtifactPriorityChanged
	case action == StoreActionAdded && medium == MediumOCI:
		reason, message = ReasonOCIArtifactStored, MessageOCIArtifactStored
	case action == StoreActionUpdated && medium == MediumOCI:
		reason, message = ReasonOCIArtifactUpdated, MessageOCIArtifactUpdated
	case action == StoreActionAdded && medium == MediumInline:
		reason, message = ReasonInlineArtifactStored, MessageInlineArtifactStored
	case action == StoreActionUpdated && medium == MediumInline:
		reason, message = ReasonInlineArtifactUpdated, MessageInlineArtifactUpdated
	case action == StoreActionAdded && medium == MediumConfigMap:
		reason, message = ReasonConfigMapArtifactStored, MessageConfigMapArtifactStored
	case action == StoreActionUpdated && medium == MediumConfigMap:
		reason, message = ReasonConfigMapArtifactUpdated, MessageConfigMapArtifactUpdated
	default:
		return
	}
	RecordNormal(r, obj, reason, message)
}
