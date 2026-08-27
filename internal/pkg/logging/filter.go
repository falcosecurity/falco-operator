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

// Package logging provides small logr.Logger wrappers shared by the instance and
// artifact operator entrypoints.
package logging

import (
	"errors"
	"strings"

	"github.com/go-logr/logr"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

// eventRejectionMsg is the exact message client-go's events.EventBroadcaster logs
// (k8s.io/client-go/tools/events, recordEvent) when the apiserver rejects an event write with a
// non-retriable *errors.StatusError.
const eventRejectionMsg = "Server rejected event (will not retry!)"

// terminatingNamespaceSubstr identifies one of the two rejection reasons this filter targets:
// the apiserver's message when a namespace has started terminating and refuses new content.
const terminatingNamespaceSubstr = "is being terminated"

// namespaceResourceKind is metav1.StatusDetails.Kind's value (actually the plural resource name,
// per NewNotFound's own construction) when a NotFound error is about a Namespace object itself,
// as opposed to some other resource living inside it.
const namespaceResourceKind = "namespaces"

// FilterEventRejectionOnTerminatingNamespace wraps logger to drop client-go's event-recorder
// error log for a Kubernetes Event write rejected because its namespace is terminating or gone.
// It matches two apiserver rejection reasons: a Forbidden error whose message contains "is being
// terminated", or a NotFound error for the "namespaces" resource itself. Any other message,
// rejection reason, or resource kind passes through unchanged.
func FilterEventRejectionOnTerminatingNamespace(logger logr.Logger) logr.Logger {
	return logr.New(&filteringSink{sink: logger.GetSink()})
}

// isNamespaceGoingAwayRejection reports whether err is one of the two expected apiserver
// rejection reasons described on FilterEventRejectionOnTerminatingNamespace's doc comment.
func isNamespaceGoingAwayRejection(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), terminatingNamespaceSubstr) {
		return true
	}
	if !k8serrors.IsNotFound(err) {
		return false
	}
	var apiStatus k8serrors.APIStatus
	if !errors.As(err, &apiStatus) {
		return false
	}
	details := apiStatus.Status().Details
	return details != nil && details.Kind == namespaceResourceKind
}

type filteringSink struct {
	sink logr.LogSink
}

func (f *filteringSink) Init(info logr.RuntimeInfo) {
	f.sink.Init(info)
}

func (f *filteringSink) Enabled(level int) bool {
	return f.sink.Enabled(level)
}

func (f *filteringSink) Info(level int, msg string, keysAndValues ...any) {
	f.sink.Info(level, msg, keysAndValues...)
}

func (f *filteringSink) Error(err error, msg string, keysAndValues ...any) {
	if msg == eventRejectionMsg && isNamespaceGoingAwayRejection(err) {
		return
	}
	f.sink.Error(err, msg, keysAndValues...)
}

func (f *filteringSink) WithValues(keysAndValues ...any) logr.LogSink {
	return &filteringSink{sink: f.sink.WithValues(keysAndValues...)}
}

func (f *filteringSink) WithName(name string) logr.LogSink {
	return &filteringSink{sink: f.sink.WithName(name)}
}

// WithCallDepth delegates to the underlying sink's WithCallDepth when it implements
// logr.CallDepthLogSink, otherwise returns f unchanged.
func (f *filteringSink) WithCallDepth(depth int) logr.LogSink {
	if cd, ok := f.sink.(logr.CallDepthLogSink); ok {
		return &filteringSink{sink: cd.WithCallDepth(depth)}
	}
	return f
}
