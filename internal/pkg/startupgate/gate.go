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
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
)

const (
	KindPlugin    = "Plugin"
	KindRulesfile = "Rulesfile"
	KindConfig    = "Config"
)

// Recorder marks CRs as reconciled or forgotten.
type Recorder interface {
	MarkReconciled(kind, namespace, name string, generation int64)
	Forget(kind, namespace, name string)
}

// Gate tracks node-applicable artifact CRs and reports readiness when each has
// been locally reconciled at least once.
type Gate struct {
	client    client.Client
	nodeName  string
	namespace string

	cacheSynced atomic.Bool

	labelsMu   sync.RWMutex
	nodeLabels labels.Set

	mu        sync.Mutex
	expected  map[string]int64
	processed map[string]int64
}

func NewGate(cl client.Client, nodeName, namespace string) *Gate {
	return &Gate{
		client:    cl,
		nodeName:  nodeName,
		namespace: namespace,
		expected:  make(map[string]int64),
		processed: make(map[string]int64),
	}
}

// MarkCacheSynced caches the node labels and builds the startup snapshot.
func (g *Gate) MarkCacheSynced(ctx context.Context) error {
	node := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
	}
	if err := g.client.Get(ctx, client.ObjectKey{Name: g.nodeName}, node); err != nil {
		return fmt.Errorf("fetching node %q: %w", g.nodeName, err)
	}

	g.labelsMu.Lock()
	g.nodeLabels = labels.Set(node.Labels)
	g.labelsMu.Unlock()

	if err := g.snapshot(ctx); err != nil {
		return err
	}

	g.cacheSynced.Store(true)
	return nil
}

func (g *Gate) snapshot(ctx context.Context) error {
	pluginList := &artifactv1alpha1.PluginList{}
	if err := g.client.List(ctx, pluginList, client.InNamespace(g.namespace)); err != nil {
		return fmt.Errorf("listing plugins: %w", err)
	}
	rulesfileList := &artifactv1alpha1.RulesfileList{}
	if err := g.client.List(ctx, rulesfileList, client.InNamespace(g.namespace)); err != nil {
		return fmt.Errorf("listing rulesfiles: %w", err)
	}
	configList := &artifactv1alpha1.ConfigList{}
	if err := g.client.List(ctx, configList, client.InNamespace(g.namespace)); err != nil {
		return fmt.Errorf("listing configs: %w", err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range pluginList.Items {
		p := &pluginList.Items[i]
		if g.nodeMatches(p.Spec.Selector) {
			g.expected[key(KindPlugin, p.Namespace, p.Name)] = p.Generation
		}
	}
	for i := range rulesfileList.Items {
		r := &rulesfileList.Items[i]
		if g.nodeMatches(r.Spec.Selector) {
			g.expected[key(KindRulesfile, r.Namespace, r.Name)] = r.Generation
		}
	}
	for i := range configList.Items {
		c := &configList.Items[i]
		if g.nodeMatches(c.Spec.Selector) {
			g.expected[key(KindConfig, c.Namespace, c.Name)] = c.Generation
		}
	}
	return nil
}

// MarkReconciled records that the CR was reconciled at the given generation.
func (g *Gate) MarkReconciled(kind, namespace, name string, generation int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := key(kind, namespace, name)
	if cur, ok := g.processed[k]; ok && cur >= generation {
		return
	}
	g.processed[k] = generation
}

// Forget drops a CR from both the snapshot and the processed set.
func (g *Gate) Forget(kind, namespace, name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := key(kind, namespace, name)
	delete(g.expected, k)
	delete(g.processed, k)
}

// Check returns nil when every snapshotted CR has been processed.
func (g *Gate) Check(_ *http.Request) error {
	if !g.cacheSynced.Load() {
		return fmt.Errorf("artifact-operator cache not yet synced")
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	var pending []string
	for k, want := range g.expected {
		if got, ok := g.processed[k]; !ok || got < want {
			pending = append(pending, k)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	sort.Strings(pending)
	return fmt.Errorf("waiting for first reconcile of: %s", strings.Join(pending, ", "))
}

func (g *Gate) nodeMatches(labelSelector *metav1.LabelSelector) bool {
	if labelSelector == nil {
		return true
	}
	sel, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return false
	}
	g.labelsMu.RLock()
	defer g.labelsMu.RUnlock()
	return sel.Matches(g.nodeLabels)
}

func key(kind, namespace, name string) string {
	return kind + "/" + namespace + "/" + name
}
