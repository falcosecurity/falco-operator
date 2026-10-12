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

package controllerhelper_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func TestSpecChangedOrDeleting(t *testing.T) {
	now := metav1.Now()
	pod := func(generation int64, deleting bool) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Generation: generation}}
		if deleting {
			p.DeletionTimestamp = &now
		}
		return p
	}

	tests := []struct {
		name string
		old  *corev1.Pod
		new  *corev1.Pod
		want bool
	}{
		{"nothing changed", pod(1, false), pod(1, false), false},
		{"the spec changed", pod(1, false), pod(2, false), true},
		{"deletion started", pod(1, false), pod(1, true), true},
		{"an object being deleted is not ignored", pod(1, true), pod(1, true), true},
	}
	p := controllerhelper.SpecChangedOrDeleting()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, p.Update(event.UpdateEvent{ObjectOld: tt.old, ObjectNew: tt.new}))
		})
	}

	t.Run("creation and deletion are accepted", func(t *testing.T) {
		assert.True(t, p.Create(event.CreateEvent{Object: pod(1, false)}))
		assert.True(t, p.Delete(event.DeleteEvent{Object: pod(1, false)}))
	})
}

func TestCreatedOrDeleted(t *testing.T) {
	p := controllerhelper.CreatedOrDeleted()
	pod := &corev1.Pod{}

	assert.True(t, p.Create(event.CreateEvent{Object: pod}))
	assert.True(t, p.Delete(event.DeleteEvent{Object: pod}))
	assert.False(t, p.Update(event.UpdateEvent{ObjectOld: pod, ObjectNew: pod}))
	assert.False(t, p.Generic(event.GenericEvent{Object: pod}))
}
