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

package testutil

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// TestNamespace is the namespace used in tests.
	TestNamespace = "default"
	// TestNodeName is the node name used in tests.
	TestNodeName = "test-node"
)

// ConditionExpect describes an expected condition for declarative assertions.
type ConditionExpect struct {
	Type   string
	Status metav1.ConditionStatus
	Reason string
}

// Scheme creates a runtime.Scheme with common K8s types (core, apps, rbac) and any
// additional types registered via the provided adders.
func Scheme(t *testing.T, adders ...func(*runtime.Scheme) error) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, appsv1.AddToScheme(s))
	require.NoError(t, rbacv1.AddToScheme(s))
	for _, add := range adders {
		require.NoError(t, add(s))
	}
	return s
}

// Request creates a ctrl.Request for the given resource name in TestNamespace.
func Request(name string) ctrl.Request {
	return ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: TestNamespace,
		},
	}
}

// RequireCondition finds a condition by type and asserts its status and reason.
func RequireCondition(t *testing.T, conditions []metav1.Condition, condType string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	for _, c := range conditions {
		if c.Type == condType {
			assert.Equal(t, status, c.Status, "condition %s status", condType)
			assert.Equal(t, reason, c.Reason, "condition %s reason", condType)
			return
		}
	}
	t.Errorf("condition %s not found", condType)
}

// RequireConditions asserts that the given conditions match all expectations (count + each entry).
func RequireConditions(t *testing.T, actual []metav1.Condition, expected []ConditionExpect) {
	t.Helper()
	require.Len(t, actual, len(expected))
	for _, exp := range expected {
		RequireCondition(t, actual, exp.Type, exp.Status, exp.Reason)
	}
}

// CollectEvents drains all currently buffered events from the FakeRecorder channel and returns them.
// It reads until the channel is empty (non-blocking).
func CollectEvents(ch chan string) []string {
	var events []string
	for {
		select {
		case e := <-ch:
			events = append(events, e)
		default:
			return events
		}
	}
}

// DrainEvents discards all currently buffered events from the FakeRecorder channel.
func DrainEvents(ch chan string) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// RequireEvents asserts that the collected events from ch exactly match wantEvents (order-independent).
// If wantEvents is nil the check is skipped.
func RequireEvents(t *testing.T, ch chan string, wantEvents []string) {
	t.Helper()
	if wantEvents == nil {
		return
	}
	got := CollectEvents(ch)
	assert.ElementsMatch(t, wantEvents, got)
}

// repoRoot is the root of the repository, located from this file so that it does not depend on how deep the
// package running a test is.
func repoRoot() string {
	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		panic("testutil: cannot locate the repository root")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// CRDDirPath returns the directory holding the CRDs of the project.
func CRDDirPath() string {
	return filepath.Join(repoRoot(), "chart", "falco-operator", "crds")
}

// GetFirstFoundEnvTestBinaryDir returns the first found envtest binary directory, or empty string if not found.
func GetFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join(repoRoot(), "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}

// Finalizers of the finalizer tests: one the test sets, one another controller owns, and the legacy per-node
// finalizers that operators before node objects left on parents.
const (
	TestFinalizer                = "test.example.com/finalizer"
	TestForeignFinalizer         = "other.example.com/keep-me"
	TestLegacyRulesfileFinalizer = "rulesfile.artifact.falcosecurity.dev/finalizer-node-1"
	TestLegacyPluginFinalizer    = "plugin.artifact.falcosecurity.dev/finalizer-node-2"
	TestLegacyConfigFinalizer    = "config.artifact.falcosecurity.dev/finalizer-node-3"
)

// FailPatch returns interceptor funcs that fail every Patch with err.
func FailPatch(err error) interceptor.Funcs {
	return interceptor.Funcs{Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
		return err
	}}
}

// FailGet returns interceptor funcs that fail every Get with err.
func FailGet(err error) interceptor.Funcs {
	return interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
		return err
	}}
}

// FailCreate returns interceptor funcs that fail every Create with err.
func FailCreate(err error) interceptor.Funcs {
	return interceptor.Funcs{Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
		return err
	}}
}

// FailDelete returns interceptor funcs that fail every Delete with err.
func FailDelete(err error) interceptor.Funcs {
	return interceptor.Funcs{Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
		return err
	}}
}

// FailListOf returns interceptor funcs that fail every List of the type of list with err, and let every other List
// through.
func FailListOf(list client.ObjectList, err error) interceptor.Funcs {
	return interceptor.Funcs{List: func(ctx context.Context, cl client.WithWatch, l client.ObjectList, opts ...client.ListOption) error {
		if reflect.TypeOf(l) == reflect.TypeOf(list) {
			return err
		}
		return cl.List(ctx, l, opts...)
	}}
}

// NewQueue returns an empty queue of requests, for the event handlers under test to fill.
func NewQueue() workqueue.TypedRateLimitingInterface[reconcile.Request] {
	return workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
}

// DrainQueue empties q and returns the names of the requests it held, in order.
func DrainQueue(t *testing.T, q workqueue.TypedRateLimitingInterface[reconcile.Request]) []string {
	t.Helper()
	var names []string
	for q.Len() > 0 {
		item, _ := q.Get()
		names = append(names, item.Name)
		q.Done(item)
	}
	return names
}
