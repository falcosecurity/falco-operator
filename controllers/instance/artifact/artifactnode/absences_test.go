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

package artifactnode

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
)

func TestAbsences(t *testing.T) {
	const grace = time.Minute
	a, b := types.NamespacedName{Namespace: "ns", Name: "a"}, types.NamespacedName{Namespace: "ns", Name: "b"}

	type step struct {
		advance time.Duration
		forget  *types.NamespacedName // forgotten before the call
		key     types.NamespacedName
		want    time.Duration
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{"the first absence has the whole grace", []step{{key: a, want: grace}}},
		{"it counts down from the first absence", []step{
			{key: a, want: grace},
			{advance: 20 * time.Second, key: a, want: 40 * time.Second},
			{advance: 20 * time.Second, key: a, want: 20 * time.Second},
		}},
		{"it stops at zero once the grace has run out", []step{
			{key: a, want: grace},
			{advance: grace, key: a, want: 0},
			{advance: time.Hour, key: a, want: 0},
		}},
		{"forgetting starts the grace over", []step{
			{key: a, want: grace},
			{advance: 50 * time.Second, forget: &a, key: a, want: grace},
		}},
		{"a node has its own grace", []step{
			{key: a, want: grace},
			{advance: 30 * time.Second, key: b, want: grace},
			{advance: 10 * time.Second, key: a, want: 20 * time.Second},
		}},
		{"forgetting one node leaves the others", []step{
			{key: a, want: grace},
			{key: b, want: grace},
			{advance: 10 * time.Second, forget: &a, key: b, want: 50 * time.Second},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &fakeClock{t: baseTime}
			abs := newAbsences(grace)
			abs.now = clock.now

			for i, s := range tt.steps {
				clock.advance(s.advance)
				if s.forget != nil {
					abs.forget(*s.forget)
				}
				assert.Equal(t, s.want, abs.observeAbsence(s.key), "step %d", i)
			}
		})
	}

	t.Run("forgetting a node that was never absent is harmless", func(t *testing.T) {
		newAbsences(grace).forget(a)
	})
}
