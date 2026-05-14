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

package startupgate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

const (
	testNodeName  = "node-1"
	testNamespace = "falco"
)

var testNodeLabels = map[string]string{"role": "worker"}

// artifactOpts builds an artifact CR. progStatus == "" leaves the status empty.
type artifactOpts struct {
	name       string
	generation int64
	progStatus metav1.ConditionStatus
	obsGen     int64
	selector   *metav1.LabelSelector
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, artifactv1alpha1.AddToScheme(s))
	return s
}

func newNode() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: testNodeName, Labels: testNodeLabels},
	}
}

func buildConditions(opts artifactOpts) []metav1.Condition {
	if opts.progStatus == "" {
		return nil
	}
	return []metav1.Condition{{
		Type:               commonv1alpha1.ConditionProgrammed.String(),
		Status:             opts.progStatus,
		Reason:             "TestReason",
		Message:            "test",
		ObservedGeneration: opts.obsGen,
		LastTransitionTime: metav1.Now(),
	}}
}

func newPlugin(opts artifactOpts) *artifactv1alpha1.Plugin {
	return &artifactv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: opts.name, Namespace: testNamespace, Generation: opts.generation},
		Spec:       artifactv1alpha1.PluginSpec{Selector: opts.selector},
		Status:     artifactv1alpha1.PluginStatus{Conditions: buildConditions(opts)},
	}
}

func newRulesfile(opts artifactOpts) *artifactv1alpha1.Rulesfile {
	return &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Name: opts.name, Namespace: testNamespace, Generation: opts.generation},
		Spec:       artifactv1alpha1.RulesfileSpec{Selector: opts.selector},
		Status:     artifactv1alpha1.RulesfileStatus{Conditions: buildConditions(opts)},
	}
}

func newConfig(opts artifactOpts) *artifactv1alpha1.Config {
	return &artifactv1alpha1.Config{
		ObjectMeta: metav1.ObjectMeta{Name: opts.name, Namespace: testNamespace, Generation: opts.generation},
		Spec:       artifactv1alpha1.ConfigSpec{Selector: opts.selector},
		Status:     artifactv1alpha1.ConfigStatus{Conditions: buildConditions(opts)},
	}
}

func newProbeRequest() *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", http.NoBody)
}

func newGateReady(t *testing.T, objects ...client.Object) *Gate {
	t.Helper()
	s := newScheme(t)
	all := append([]client.Object{newNode()}, objects...)
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(all...).Build()
	g := NewGate(cl, testNodeName, testNamespace)
	require.NoError(t, g.MarkCacheSynced(context.Background()))
	return g
}

func TestGate_MarkCacheSynced(t *testing.T) {
	workerSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"role": "worker"}}
	masterSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"role": "master"}}

	tests := []struct {
		name             string
		objects          []client.Object
		omitNode         bool
		wantErr          bool
		wantExpectedKeys []string
	}{
		{
			name:     "fails when node does not exist",
			omitNode: true,
			wantErr:  true,
		},
		{
			name:             "empty cluster yields empty snapshot",
			wantExpectedKeys: nil,
		},
		{
			name: "snapshots node-applicable CRs of every kind",
			objects: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 1}),
				newPlugin(artifactOpts{name: "p2", generation: 1, selector: workerSelector}),
				newRulesfile(artifactOpts{name: "r1", generation: 2}),
				newConfig(artifactOpts{name: "c1", generation: 3}),
			},
			wantExpectedKeys: []string{
				"Config/falco/c1",
				"Plugin/falco/p1",
				"Plugin/falco/p2",
				"Rulesfile/falco/r1",
			},
		},
		{
			name: "skips CRs whose selector does not match the node",
			objects: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 1, selector: masterSelector}),
				newRulesfile(artifactOpts{name: "r1", generation: 1, selector: workerSelector}),
			},
			wantExpectedKeys: []string{"Rulesfile/falco/r1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScheme(t)
			builder := fake.NewClientBuilder().WithScheme(s)
			if !tt.omitNode {
				builder = builder.WithObjects(newNode())
			}
			builder = builder.WithObjects(tt.objects...)
			cl := builder.Build()
			g := NewGate(cl, testNodeName, testNamespace)

			err := g.MarkCacheSynced(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
				assert.False(t, g.cacheSynced.Load())
				return
			}
			require.NoError(t, err)
			assert.True(t, g.cacheSynced.Load())
			assert.ElementsMatch(t, tt.wantExpectedKeys, keysOf(g.expected))
		})
	}
}

func TestGate_Check(t *testing.T) {
	tests := []struct {
		name            string
		skipMarkSynced  bool
		snapshot        []client.Object
		marks           []mark
		forgets         []forget
		wantErr         bool
		wantErrContains []string
	}{
		{
			name:            "cache not synced returns error",
			skipMarkSynced:  true,
			wantErr:         true,
			wantErrContains: []string{"cache not yet synced"},
		},
		{
			name: "empty snapshot is ready immediately",
		},
		{
			name: "snapshotted CR with no MarkReconciled is pending",
			snapshot: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 1}),
			},
			wantErr:         true,
			wantErrContains: []string{"Plugin/falco/p1"},
		},
		{
			name: "MarkReconciled with matching generation makes CR ready",
			snapshot: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 1}),
			},
			marks: []mark{{KindPlugin, testNamespace, "p1", 1}},
		},
		{
			name: "MarkReconciled with higher generation than snapshot makes CR ready",
			snapshot: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 1}),
			},
			marks: []mark{{KindPlugin, testNamespace, "p1", 2}},
		},
		{
			name: "MarkReconciled with lower generation than snapshot stays pending",
			snapshot: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 5}),
			},
			marks:           []mark{{KindPlugin, testNamespace, "p1", 4}},
			wantErr:         true,
			wantErrContains: []string{"Plugin/falco/p1"},
		},
		{
			name: "Forget drops a snapshotted CR from the expected set",
			snapshot: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 1}),
				newRulesfile(artifactOpts{name: "r1", generation: 1}),
			},
			marks:   []mark{{KindRulesfile, testNamespace, "r1", 1}},
			forgets: []forget{{KindPlugin, testNamespace, "p1"}},
		},
		{
			name: "CR with Programmed=True but no local MarkReconciled is still pending",
			snapshot: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 1, progStatus: metav1.ConditionTrue, obsGen: 1}),
			},
			wantErr:         true,
			wantErrContains: []string{"Plugin/falco/p1"},
		},
		{
			name: "mixed kinds: pending entries are reported sorted",
			snapshot: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 1}),
				newPlugin(artifactOpts{name: "p2", generation: 1}),
				newRulesfile(artifactOpts{name: "r1", generation: 1}),
				newConfig(artifactOpts{name: "c1", generation: 1}),
			},
			marks: []mark{
				{KindPlugin, testNamespace, "p1", 1},
				{KindRulesfile, testNamespace, "r1", 1},
			},
			wantErr: true,
			wantErrContains: []string{
				"Config/falco/c1",
				"Plugin/falco/p2",
			},
		},
		{
			name: "all snapshotted CRs reconciled returns nil",
			snapshot: []client.Object{
				newPlugin(artifactOpts{name: "p1", generation: 1}),
				newRulesfile(artifactOpts{name: "r1", generation: 2}),
				newConfig(artifactOpts{name: "c1", generation: 3}),
			},
			marks: []mark{
				{KindPlugin, testNamespace, "p1", 1},
				{KindRulesfile, testNamespace, "r1", 2},
				{KindConfig, testNamespace, "c1", 3},
			},
		},
		{
			name:  "MarkReconciled for a CR not in snapshot does not affect readiness",
			marks: []mark{{KindPlugin, testNamespace, "stray", 7}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScheme(t)
			objects := append([]client.Object{newNode()}, tt.snapshot...)
			cl := fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()
			g := NewGate(cl, testNodeName, testNamespace)

			if !tt.skipMarkSynced {
				require.NoError(t, g.MarkCacheSynced(context.Background()))
			}
			for _, m := range tt.marks {
				g.MarkReconciled(m.kind, m.namespace, m.name, m.generation)
			}
			for _, f := range tt.forgets {
				g.Forget(f.kind, f.namespace, f.name)
			}

			err := g.Check(newProbeRequest())
			if tt.wantErr {
				require.Error(t, err)
				for _, sub := range tt.wantErrContains {
					assert.Contains(t, err.Error(), sub)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestGate_MarkCacheSynced_ListErrors(t *testing.T) {
	tests := []struct {
		name        string
		failKind    string
		wantErrText string
	}{
		{name: "plugin list error surfaces", failKind: "Plugin", wantErrText: "listing plugins"},
		{name: "rulesfile list error surfaces", failKind: "Rulesfile", wantErrText: "listing rulesfiles"},
		{name: "config list error surfaces", failKind: "Config", wantErrText: "listing configs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injected := errors.New("injected list error")
			intercept := interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					switch tt.failKind {
					case "Plugin":
						if _, ok := list.(*artifactv1alpha1.PluginList); ok {
							return injected
						}
					case "Rulesfile":
						if _, ok := list.(*artifactv1alpha1.RulesfileList); ok {
							return injected
						}
					case "Config":
						if _, ok := list.(*artifactv1alpha1.ConfigList); ok {
							return injected
						}
					}
					return c.List(ctx, list, opts...)
				},
			}

			s := newScheme(t)
			cl := fake.NewClientBuilder().
				WithScheme(s).
				WithObjects(newNode()).
				WithInterceptorFuncs(intercept).
				Build()

			g := NewGate(cl, testNodeName, testNamespace)
			err := g.MarkCacheSynced(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrText)
			assert.False(t, g.cacheSynced.Load())
		})
	}
}

func TestGate_MarkReconciled_MonotonicOnGeneration(t *testing.T) {
	g := newGateReady(t, newPlugin(artifactOpts{name: "p1", generation: 5}))

	g.MarkReconciled(KindPlugin, testNamespace, "p1", 7)
	g.MarkReconciled(KindPlugin, testNamespace, "p1", 4)

	g.mu.Lock()
	defer g.mu.Unlock()
	assert.Equal(t, int64(7), g.processed[key(KindPlugin, testNamespace, "p1")])
}

type mark struct {
	kind, namespace, name string
	generation            int64
}

type forget struct {
	kind, namespace, name string
}

func keysOf(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
