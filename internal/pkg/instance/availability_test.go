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

package instance

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func availabilityScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(s))
	return s
}

//go:fix inline
func int32Ptr(n int32) *int32 { return new(n) }

func TestComputeDeploymentAvailability(t *testing.T) {
	scheme := availabilityScheme(t)

	tests := []struct {
		name            string
		deployment      *appsv1.Deployment
		specReplicas    *int32
		getErr          error
		wantErr         string
		wantStatus      metav1.ConditionStatus
		wantReason      string
		wantDesired     int32
		wantAvailable   int32
		wantUnavailable int32
	}{
		{
			name: "available",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 2, AvailableReplicas: 2, UnavailableReplicas: 0},
			},
			specReplicas:    int32Ptr(2),
			wantStatus:      metav1.ConditionTrue,
			wantReason:      ReasonDeploymentAvailable,
			wantDesired:     2,
			wantAvailable:   2,
			wantUnavailable: 0,
		},
		{
			name: "unavailable",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1, UnavailableReplicas: 2},
			},
			specReplicas:    int32Ptr(3),
			wantStatus:      metav1.ConditionFalse,
			wantReason:      ReasonDeploymentUnavailable,
			wantDesired:     3,
			wantAvailable:   1,
			wantUnavailable: 2,
		},
		{
			name:            "not found",
			specReplicas:    int32Ptr(1),
			wantStatus:      metav1.ConditionFalse,
			wantReason:      ReasonDeploymentNotFound,
			wantDesired:     1,
			wantAvailable:   0,
			wantUnavailable: 0,
		},
		{
			name: "defaults replicas to 1 when nil",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Status:     appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1},
			},
			specReplicas:    nil,
			wantStatus:      metav1.ConditionTrue,
			wantReason:      ReasonDeploymentAvailable,
			wantDesired:     1,
			wantAvailable:   1,
			wantUnavailable: 0,
		},
		{
			name:            "fetch error",
			specReplicas:    int32Ptr(1),
			getErr:          fmt.Errorf("injected get error"),
			wantErr:         "unable to fetch deployment",
			wantStatus:      metav1.ConditionUnknown,
			wantReason:      ReasonDeploymentFetchError,
			wantDesired:     1,
			wantAvailable:   0,
			wantUnavailable: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if tt.deployment != nil {
				objs = append(objs, tt.deployment)
			}
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...)
			if tt.getErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if _, ok := obj.(*appsv1.Deployment); ok {
							return tt.getErr
						}
						return cl.Get(ctx, key, obj, opts...)
					},
				})
			}
			cl := builder.Build()

			key := client.ObjectKey{Name: "test", Namespace: "default"}
			result, err := ComputeDeploymentAvailability(context.Background(), cl, key, tt.specReplicas)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantStatus, result.ConditionStatus)
			assert.Equal(t, tt.wantReason, result.Reason)
			assert.Equal(t, tt.wantDesired, result.DesiredReplicas)
			assert.Equal(t, tt.wantAvailable, result.AvailableReplicas)
			assert.Equal(t, tt.wantUnavailable, result.UnavailableReplicas)
		})
	}
}

func TestComputeDaemonSetAvailability(t *testing.T) {
	scheme := availabilityScheme(t)

	tests := []struct {
		name            string
		daemonset       *appsv1.DaemonSet
		getErr          error
		wantErr         string
		wantStatus      metav1.ConditionStatus
		wantReason      string
		wantDesired     int32
		wantAvailable   int32
		wantUnavailable int32
	}{
		{
			name: "available",
			daemonset: &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberAvailable: 3, NumberUnavailable: 0},
			},
			wantStatus:      metav1.ConditionTrue,
			wantReason:      ReasonDaemonSetAvailable,
			wantDesired:     3,
			wantAvailable:   3,
			wantUnavailable: 0,
		},
		{
			name: "unavailable",
			daemonset: &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 5, NumberAvailable: 3, NumberUnavailable: 2},
			},
			wantStatus:      metav1.ConditionFalse,
			wantReason:      ReasonDaemonSetUnavailable,
			wantDesired:     5,
			wantAvailable:   3,
			wantUnavailable: 2,
		},
		{
			name:            "not found",
			wantStatus:      metav1.ConditionFalse,
			wantReason:      ReasonDaemonSetNotFound,
			wantDesired:     0,
			wantAvailable:   0,
			wantUnavailable: 0,
		},
		{
			name:            "fetch error",
			getErr:          fmt.Errorf("injected get error"),
			wantErr:         "unable to fetch daemonset",
			wantStatus:      metav1.ConditionUnknown,
			wantReason:      ReasonDaemonSetFetchError,
			wantDesired:     0,
			wantAvailable:   0,
			wantUnavailable: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if tt.daemonset != nil {
				objs = append(objs, tt.daemonset)
			}
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...)
			if tt.getErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if _, ok := obj.(*appsv1.DaemonSet); ok {
							return tt.getErr
						}
						return cl.Get(ctx, key, obj, opts...)
					},
				})
			}
			cl := builder.Build()

			key := client.ObjectKey{Name: "test", Namespace: "default"}
			result, err := ComputeDaemonSetAvailability(context.Background(), cl, key)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantStatus, result.ConditionStatus)
			assert.Equal(t, tt.wantReason, result.Reason)
			assert.Equal(t, tt.wantDesired, result.DesiredReplicas)
			assert.Equal(t, tt.wantAvailable, result.AvailableReplicas)
			assert.Equal(t, tt.wantUnavailable, result.UnavailableReplicas)
		})
	}
}
