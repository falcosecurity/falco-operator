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

package logging

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// recordingSink wraps a real sink (testr, so failures still surface via t.Log) and counts Error
// calls received.
type recordingSink struct {
	logr.LogSink
	errorCalls *int
}

func (r *recordingSink) Error(err error, msg string, keysAndValues ...any) {
	*r.errorCalls++
	r.LogSink.Error(err, msg, keysAndValues...)
}

func (r *recordingSink) WithValues(keysAndValues ...any) logr.LogSink {
	return &recordingSink{LogSink: r.LogSink.WithValues(keysAndValues...), errorCalls: r.errorCalls}
}

func (r *recordingSink) WithName(name string) logr.LogSink {
	return &recordingSink{LogSink: r.LogSink.WithName(name), errorCalls: r.errorCalls}
}

func newRecordingLogger(t *testing.T) (logger logr.Logger, errorCallCount *int) {
	t.Helper()
	calls := 0
	return logr.New(&recordingSink{LogSink: testr.New(t).GetSink(), errorCalls: &calls}), &calls
}

func TestFilterEventRejectionOnTerminatingNamespace_SuppressesExactMatch(t *testing.T) {
	base, calls := newRecordingLogger(t)
	filtered := FilterEventRejectionOnTerminatingNamespace(base)

	err := errors.New(`events.events.k8s.io "x.18c4ff7dc8632896" is forbidden: unable to ` +
		`create new content in namespace chainsaw-pleasant-deer because it is being terminated`)
	filtered.Error(err, "Server rejected event (will not retry!)")

	assert.Equal(t, 0, *calls, "matching error must not reach the underlying sink")
}

func TestFilterEventRejectionOnTerminatingNamespace_PassesThroughDifferentMessage(t *testing.T) {
	base, calls := newRecordingLogger(t)
	filtered := FilterEventRejectionOnTerminatingNamespace(base)

	filtered.Error(errors.New("boom"), "Unable to write event (may retry after sleeping)")

	assert.Equal(t, 1, *calls, "a different message must not be suppressed")
}

func TestFilterEventRejectionOnTerminatingNamespace_SuppressesNamespaceNotFound(t *testing.T) {
	base, calls := newRecordingLogger(t)
	filtered := FilterEventRejectionOnTerminatingNamespace(base)

	err := k8serrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "chainsaw-legible-goose")
	filtered.Error(err, "Server rejected event (will not retry!)")

	assert.Equal(t, 0, *calls, "the namespace having fully deleted by the time the event write landed must not surface")
}

func TestFilterEventRejectionOnTerminatingNamespace_PassesThroughNotFoundForOtherResource(t *testing.T) {
	base, calls := newRecordingLogger(t)
	filtered := FilterEventRejectionOnTerminatingNamespace(base)

	// A NotFound for some other resource kind is a different, potentially real problem; must
	// not be swallowed just because it shares the NotFound reason with the namespace case.
	err := k8serrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "some-pod")
	filtered.Error(err, "Server rejected event (will not retry!)")

	assert.Equal(t, 1, *calls, "a NotFound for a non-namespace resource must not be suppressed")
}

func TestFilterEventRejectionOnTerminatingNamespace_PassesThroughDifferentRejectionReason(t *testing.T) {
	base, calls := newRecordingLogger(t)
	filtered := FilterEventRejectionOnTerminatingNamespace(base)

	// A rejection reason unrelated to namespace termination is not suppressed.
	filtered.Error(errors.New("events.events.k8s.io \"x\" is forbidden: user cannot create events"),
		"Server rejected event (will not retry!)")

	assert.Equal(t, 1, *calls, "a non-termination rejection reason must not be suppressed")
}

func TestFilterEventRejectionOnTerminatingNamespace_PassesThroughNilError(t *testing.T) {
	base, calls := newRecordingLogger(t)
	filtered := FilterEventRejectionOnTerminatingNamespace(base)

	require.NotPanics(t, func() {
		filtered.Error(nil, "Server rejected event (will not retry!)")
	})
	assert.Equal(t, 1, *calls, "a nil error must not be suppressed (and must not panic)")
}

func TestFilterEventRejectionOnTerminatingNamespace_InfoAndValuesStillWork(t *testing.T) {
	base, calls := newRecordingLogger(t)
	filtered := FilterEventRejectionOnTerminatingNamespace(base).WithValues("k", "v").WithName("test")

	filtered.Info("still logs")
	filtered.Error(errors.New("boom"), "still logs errors")

	assert.Equal(t, 1, *calls)
}
