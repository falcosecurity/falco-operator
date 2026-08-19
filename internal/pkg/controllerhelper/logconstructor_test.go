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

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

// kvSink is a minimal logr.LogSink that accumulates WithValues key-value pairs and the
// hierarchical name built up via WithName (dot-joined, matching logr's own convention).
type kvSink struct {
	kvs  []any
	name string
}

func (s *kvSink) Init(_ logr.RuntimeInfo)           {}
func (s *kvSink) Enabled(_ int) bool                { return true }
func (s *kvSink) Info(_ int, _ string, _ ...any)    {}
func (s *kvSink) Error(_ error, _ string, _ ...any) {}
func (s *kvSink) WithName(name string) logr.LogSink {
	newName := name
	if s.name != "" {
		newName = s.name + "." + name
	}
	return &kvSink{kvs: s.kvs, name: newName}
}
func (s *kvSink) WithValues(kvs ...any) logr.LogSink {
	merged := make([]any, len(s.kvs)+len(kvs))
	copy(merged, s.kvs)
	copy(merged[len(s.kvs):], kvs)
	return &kvSink{kvs: merged, name: s.name}
}

// loggerKeys extracts the string keys from a logger's accumulated WithValues pairs.
func loggerKeys(logger logr.Logger) map[string]bool {
	sink, ok := logger.GetSink().(*kvSink)
	if !ok {
		return nil
	}
	m := make(map[string]bool, len(sink.kvs)/2)
	for i := 0; i+1 < len(sink.kvs); i += 2 {
		if k, ok := sink.kvs[i].(string); ok {
			m[k] = true
		}
	}
	return m
}

// loggerName returns the hierarchical name built up via WithName.
func loggerName(logger logr.Logger) string {
	sink, ok := logger.GetSink().(*kvSink)
	if !ok {
		return ""
	}
	return sink.name
}

func TestLogConstructorFor_withRequest(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))

	logger := logr.New(&kvSink{})
	fn := controllerhelper.LogConstructorFor(logger, scheme, "my-controller", &corev1.ConfigMap{})

	req := &reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cm", Namespace: "default"},
	}
	result := fn(req)
	k := loggerKeys(result)

	assert.Equal(t, "my-controller", loggerName(result), "logger must be named after the controller")
	assert.True(t, k["controller"], "expected 'controller' key")
	assert.True(t, k["controllerGroup"], "expected 'controllerGroup' key")
	assert.True(t, k["controllerKind"], "expected 'controllerKind' key")
	assert.True(t, k["ConfigMap"], "expected typed Kind key 'ConfigMap'")
	assert.False(t, k["name"], "must not emit flat 'name' key")
	assert.False(t, k["namespace"], "must not emit flat 'namespace' key")
}

func TestLogConstructorFor_nilRequest(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))

	logger := logr.New(&kvSink{})
	fn := controllerhelper.LogConstructorFor(logger, scheme, "my-controller", &corev1.ConfigMap{})

	result := fn(nil)
	k := loggerKeys(result)

	assert.Equal(t, "my-controller", loggerName(result), "logger must be named after the controller even for a nil request")
	assert.True(t, k["controller"])
	assert.False(t, k["ConfigMap"], "nil request must not add typed Kind key")
	assert.False(t, k["name"])
	assert.False(t, k["namespace"])
}
