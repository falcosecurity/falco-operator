// Copyright (C) 2025 The Falco Authors
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

package falco

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// mockFailingClient implements client.Client and always returns errors.
type mockFailingClient struct {
	client.Client
	scheme *runtime.Scheme
}

func newMockFailingClient() *mockFailingClient {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = instancev1alpha1.AddToScheme(scheme)
	return &mockFailingClient{scheme: scheme}
}

func (m *mockFailingClient) Create(_ context.Context, _ client.Object, _ ...client.CreateOption) error {
	return fmt.Errorf("mock error")
}

func (m *mockFailingClient) Update(_ context.Context, _ client.Object, _ ...client.UpdateOption) error {
	return fmt.Errorf("mock error")
}

func (m *mockFailingClient) Scheme() *runtime.Scheme {
	return m.scheme
}
