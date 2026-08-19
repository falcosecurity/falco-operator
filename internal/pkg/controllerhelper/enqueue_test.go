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
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func TestEnqueueAllOfType_ReturnsOneRequestPerItem(t *testing.T) {
	s := newArtifactScheme(t)
	p1 := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: "default"}}
	p2 := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: "json", Namespace: "other"}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(p1, p2).Build()

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, &artifactv1alpha1.PluginList{})

	require.Len(t, reqs, 2)
	names := []string{reqs[0].Name, reqs[1].Name}
	assert.Contains(t, names, "container")
	assert.Contains(t, names, "json")
}

func TestEnqueueAllOfType_EmptyList(t *testing.T) {
	s := newArtifactScheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, &artifactv1alpha1.PluginList{})
	assert.Empty(t, reqs)
}

func TestEnqueueAllOfType_ListError(t *testing.T) {
	s := newArtifactScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return fmt.Errorf("list error")
			},
		}).
		Build()

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, &artifactv1alpha1.PluginList{})
	assert.Nil(t, reqs)
}

// stubListClient is a client.Client that only implements List; every other method panics via the
// embedded nil interface if called.
type stubListClient struct {
	client.Client
	listFunc func(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error
}

func (s *stubListClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return s.listFunc(ctx, list, opts...)
}

// plainItem implements runtime.Object (via *plainItem) but not metav1.Object, so it fails the
// client.Object type assertion inside EnqueueAllOfType.
type plainItem struct {
	metav1.TypeMeta
}

func (p *plainItem) DeepCopyObject() runtime.Object {
	return &plainItem{TypeMeta: p.TypeMeta}
}

// plainItemList is a minimal client.ObjectList whose Items are plainItem, not client.Object.
type plainItemList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []plainItem
}

func (l *plainItemList) DeepCopyObject() runtime.Object {
	items := make([]plainItem, len(l.Items))
	copy(items, l.Items)
	return &plainItemList{TypeMeta: l.TypeMeta, ListMeta: l.ListMeta, Items: items}
}

func TestEnqueueAllOfType_ExtractListError(t *testing.T) {
	// noItemsList has no Items field at all, so apimeta.ExtractList fails with "not a list".
	cl := &stubListClient{listFunc: func(context.Context, client.ObjectList, ...client.ListOption) error {
		return nil
	}}

	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, &noItemsList{})
	assert.Nil(t, reqs)
}

func TestEnqueueAllOfType_SkipsItemsThatAreNotClientObjects(t *testing.T) {
	cl := &stubListClient{listFunc: func(context.Context, client.ObjectList, ...client.ListOption) error {
		return nil // Items are pre-populated on the list passed below; nothing to do here.
	}}

	list := &plainItemList{Items: []plainItem{{}}}
	reqs := controllerhelper.EnqueueAllOfType(context.Background(), cl, list)
	assert.Empty(t, reqs)
}

// noItemsList is a client.ObjectList with no Items field, so apimeta.ExtractList fails.
type noItemsList struct {
	metav1.TypeMeta
	metav1.ListMeta
}

func (l *noItemsList) DeepCopyObject() runtime.Object {
	return &noItemsList{TypeMeta: l.TypeMeta, ListMeta: l.ListMeta}
}
