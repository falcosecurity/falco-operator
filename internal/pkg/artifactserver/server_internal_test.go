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

package artifactserver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// TestServer_httpServer_DefaultTimeouts asserts the constructed http.Server carries the
// baseline hardening timeouts unconditionally.
func TestServer_httpServer_DefaultTimeouts(t *testing.T) {
	s := &Server{}
	srv := s.httpServer(":0", func(net.Listener) context.Context { return context.Background() })

	assert.Equal(t, DefaultReadHeaderTimeout, srv.ReadHeaderTimeout)
	assert.Equal(t, DefaultReadTimeout, srv.ReadTimeout)
	assert.Equal(t, DefaultWriteTimeout, srv.WriteTimeout)
	assert.Equal(t, DefaultIdleTimeout, srv.IdleTimeout)
	assert.Equal(t, DefaultMaxHeaderBytes, srv.MaxHeaderBytes)
}

func routingPod(name, namespace, installation string, serving bool) *corev1.Pod {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: namespace, UID: types.UID(namespace + "/" + name),
		Labels: map[string]string{"app": installation, "unrelated": "preserve"},
	}}
	if serving {
		pod.Labels[ServingLabel] = servingValue
	}
	return pod
}

func routingService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "artifacts"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "operator", ServingLabel: servingValue}},
	}
}

func routingReference(pod *corev1.Pod) corev1.ObjectReference {
	return corev1.ObjectReference{Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
}

func TestPodRouting_Reconcile(t *testing.T) {
	for _, exclusive := range []bool{true, false} {
		name := "without leader election"
		if exclusive {
			name = "with leader election"
		}
		t.Run(name, func(t *testing.T) {
			own := routingPod("current", "operator", "operator", false)
			previous := routingPod("previous", "operator", "operator", true)
			previous.Labels["pod-template-hash"] = "old-replicaset"
			own.Labels["pod-template-hash"] = "new-replicaset"
			otherRelease := routingPod("other-release", "operator", "another-installation", true)
			otherNamespace := routingPod("other-namespace", "elsewhere", "operator", true)
			service := routingService()
			patches := 0
			cl := fake.NewClientBuilder().WithObjects(own, previous, otherRelease, otherNamespace, service).
				WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						patches++
						return cl.Patch(ctx, obj, patch, opts...)
					},
				}).Build()
			r := &podRouting{client: cl, pod: routingReference(own), service: service.Name, exclusive: exclusive}
			require.NoError(t, r.reconcile(t.Context()))
			for _, pod := range []*corev1.Pod{own, previous, otherRelease, otherNamespace} {
				require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
				assert.Equal(t, "preserve", pod.Labels["unrelated"])
				if pod.Name == previous.Name && exclusive {
					assert.NotContains(t, pod.Labels, ServingLabel)
				} else {
					assert.Equal(t, servingValue, pod.Labels[ServingLabel])
				}
			}
			before := patches
			require.NoError(t, r.reconcile(t.Context()))
			assert.Equal(t, before, patches, "steady state must not patch Pods")
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(service), service))
			assert.Equal(t, routingService().Spec.Selector, service.Spec.Selector)

			if exclusive {
				// A former leader's delayed publish can arrive after the first cleanup.
				previous.Labels[ServingLabel] = servingValue
				require.NoError(t, cl.Update(t.Context(), previous))
				require.NoError(t, r.reconcile(t.Context()))
				require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(previous), previous))
				assert.NotContains(t, previous.Labels, ServingLabel)
			}
		})
	}
}

func TestServer_ResetRouting(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		name := "same Pod after container restart"
		if replaced {
			name = "replacement Pod must not be modified"
		}
		t.Run(name, func(t *testing.T) {
			pod := routingPod("current", "operator", "operator", true)
			ref := routingReference(pod)
			if replaced {
				pod.UID = "new-uid"
			}
			cl := fake.NewClientBuilder().WithObjects(pod).Build()
			s := New(nil, WithPodRouting(cl, &ref, "artifacts", true))
			err := s.ResetRouting(t.Context())
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
			if replaced {
				require.ErrorContains(t, err, "has been replaced")
				assert.Equal(t, servingValue, pod.Labels[ServingLabel])
			} else {
				require.NoError(t, err)
				assert.NotContains(t, pod.Labels, ServingLabel)
			}
			assert.Equal(t, "preserve", pod.Labels["unrelated"])
		})
	}
	require.NoError(t, New(nil).ResetRouting(t.Context()))
	s := New(nil, WithPodRouting(nil, nil, "", true))
	require.ErrorContains(t, s.ResetRouting(t.Context()), "requires a client")
}

func TestPodRouting_InvalidService(t *testing.T) {
	for name, selector := range map[string]map[string]string{
		"missing serving selector":      {"app": "operator"},
		"missing installation selector": {ServingLabel: servingValue},
		"own Pod outside selector":      {"app": "different", ServingLabel: servingValue},
	} {
		t.Run(name, func(t *testing.T) {
			pod := routingPod("current", "operator", "operator", false)
			service := routingService()
			service.Spec.Selector = selector
			foreign := routingPod("foreign", "operator", "different", true)
			cl := fake.NewClientBuilder().WithObjects(pod, foreign, service).Build()
			r := &podRouting{client: cl, pod: routingReference(pod), service: service.Name, exclusive: true}
			require.Error(t, r.reconcile(t.Context()))
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
			assert.NotContains(t, pod.Labels, ServingLabel)
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(foreign), foreign))
			assert.Equal(t, servingValue, foreign.Labels[ServingLabel], "invalid routing must not disable another installation")
		})
	}
}

func TestPodRouting_APIFailureAndRecovery(t *testing.T) {
	for _, operation := range []string{"list", "withdraw", "publish"} {
		t.Run(operation, func(t *testing.T) {
			pod := routingPod("current", "operator", "operator", false)
			previous := routingPod("previous", "operator", "operator", true)
			failure := errors.New("API unavailable")
			cl := fake.NewClientBuilder().WithObjects(pod, previous, routingService()).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if operation == "list" && failure != nil {
							return failure
						}
						return cl.List(ctx, list, opts...)
					},
					Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						if failure != nil && ((operation == "withdraw" && obj.GetName() == previous.Name) ||
							(operation == "publish" && obj.GetName() == pod.Name)) {
							return failure
						}
						return cl.Patch(ctx, obj, patch, opts...)
					},
				}).Build()
			r := &podRouting{client: cl, pod: routingReference(pod), service: "artifacts", exclusive: true}
			require.ErrorIs(t, r.reconcile(t.Context()), failure)
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
			assert.NotContains(t, pod.Labels, ServingLabel)
			failure = nil
			require.NoError(t, r.reconcile(t.Context()))
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
			assert.Equal(t, servingValue, pod.Labels[ServingLabel])
			require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(previous), previous))
			assert.NotContains(t, previous.Labels, ServingLabel)
		})
	}
}

func TestPodRouting_ConflictPreservesConcurrentLabels(t *testing.T) {
	pod := routingPod("current", "operator", "operator", false)
	attempts := 0
	cl := fake.NewClientBuilder().WithObjects(pod, routingService()).WithInterceptorFuncs(interceptor.Funcs{
		Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			attempts++
			if attempts == 1 {
				var current corev1.Pod
				require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(obj), &current))
				current.Labels["concurrent"] = "preserve"
				require.NoError(t, cl.Update(ctx, &current))
				return k8serrors.NewConflict(schema.GroupResource{Resource: "pods"}, pod.Name, errors.New("concurrent edit"))
			}
			return cl.Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	r := &podRouting{client: cl, pod: routingReference(pod), service: "artifacts", exclusive: true}
	require.NoError(t, r.reconcile(t.Context()))
	assert.Equal(t, 2, attempts)
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
	assert.Equal(t, servingValue, pod.Labels[ServingLabel])
	assert.Equal(t, "preserve", pod.Labels["concurrent"])
}

func TestPodRouting_CancellationDuringAPIRead(t *testing.T) {
	pod := routingPod("current", "operator", "operator", false)
	reading := make(chan struct{})
	cl := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
			close(reading)
			<-ctx.Done()
			return ctx.Err()
		},
	}).Build()
	r := &podRouting{client: cl, pod: routingReference(pod), service: "artifacts", exclusive: true}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.run(ctx)
	}()
	select {
	case <-reading:
	case <-time.After(routingInterval + 2*time.Second):
		t.Fatal("routing did not start its API read")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("routing did not stop after its API read was canceled")
	}
}

func TestPodRouting_CopiesPodIdentity(t *testing.T) {
	pod := routingPod("current", "operator", "operator", false)
	ref := routingReference(pod)
	cl := fake.NewClientBuilder().WithObjects(pod).Build()
	s := New(nil, WithPodRouting(cl, &ref, "artifacts", true))
	ref.Name, ref.UID = "replacement", "replacement-uid"
	assert.Equal(t, routingReference(pod), s.routing.pod)
}
