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
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// absences remembers since when each node has run no Falco pod, to give it a grace period before its ArtifactNode
// is deleted. It is deliberately not persisted: the operator restarting only restarts the grace, which errs on
// keeping an ArtifactNode.
type absences struct {
	grace time.Duration
	now   func() time.Time

	mu    sync.Mutex
	since map[types.NamespacedName]time.Time
}

func newAbsences(grace time.Duration) *absences {
	return &absences{grace: grace, now: time.Now, since: make(map[types.NamespacedName]time.Time)}
}

// observeAbsence records that no Falco pod runs on the node, starting its grace period the first time it is told,
// and returns how much of the grace is left. Zero means the grace has run out.
func (a *absences) observeAbsence(key types.NamespacedName) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	since, seen := a.since[key]
	if !seen {
		since = a.now()
		a.since[key] = since
	}
	return max(0, a.grace-a.now().Sub(since))
}

// forget drops what was recorded about a node's missing Falco pod: it is back, or the ArtifactNode is gone.
func (a *absences) forget(key types.NamespacedName) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.since, key)
}

// sidecarCounts remembers, for each node running more than one Falco pod, how many were last reported, so that
// the warning about them is given once per change rather than on every reconcile of the node. A rolling update
// that surges a second pod onto each node is then one warning per node, not one per artifact event.
type sidecarCounts struct {
	mu   sync.Mutex
	last map[types.NamespacedName]int
}

func newSidecarCounts() *sidecarCounts {
	return &sidecarCounts{last: make(map[types.NamespacedName]int)}
}

// changed records that pods Falco pods run on the node and reports whether that is a different number than
// last recorded.
func (c *sidecarCounts) changed(key types.NamespacedName, pods int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last[key] == pods {
		return false
	}
	c.last[key] = pods
	return true
}

// forget drops the record of a node that runs one Falco pod or none, so that a later crowding is reported again.
func (c *sidecarCounts) forget(key types.NamespacedName) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.last, key)
}
