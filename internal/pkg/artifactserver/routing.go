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
	"fmt"
	"maps"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// ServingLabel selects operator Pods whose artifact server is running.
	ServingLabel = "artifact.falcosecurity.dev/serving"

	servingValue    = "true"
	routingInterval = 5 * time.Second
)

type podRouting struct {
	client    client.Client
	pod       corev1.ObjectReference
	service   string
	exclusive bool
}

// WithPodRouting publishes this server through its Service. The client must read
// directly from the API server; exclusive is true when leader election is enabled.
func WithPodRouting(cl client.Client, pod *corev1.ObjectReference, service string, exclusive bool) Option {
	return func(s *Server) {
		s.routing = &podRouting{client: cl, service: service, exclusive: exclusive}
		if pod != nil {
			s.routing.pod = *pod
		}
	}
}

// ResetRouting removes a label retained across a container restart. Call it before
// starting the manager, including on replicas that may never become leader.
func (s *Server) ResetRouting(ctx context.Context) error {
	if s.routing == nil {
		return nil
	}
	r := s.routing
	if err := r.validate(); err != nil {
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		pod, err := r.ownPod(ctx)
		if err != nil {
			return client.IgnoreNotFound(err)
		}
		return r.setServing(ctx, pod, false)
	})
}

func (r *podRouting) validate() error {
	if r.client == nil || r.pod.Namespace == "" || r.pod.Name == "" || r.pod.UID == "" || r.service == "" {
		return fmt.Errorf("artifact server routing requires a client, Pod namespace/name/UID and Service name")
	}
	return nil
}

func (r *podRouting) reconcile(ctx context.Context) error {
	if err := r.validate(); err != nil {
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var service corev1.Service
		if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.pod.Namespace, Name: r.service}, &service); err != nil {
			return fmt.Errorf("read artifact Service: %w", err)
		}
		if service.Spec.Selector[ServingLabel] != servingValue {
			return fmt.Errorf("artifact Service must select %s=true", ServingLabel)
		}
		selector := maps.Clone(service.Spec.Selector)
		delete(selector, ServingLabel)
		if len(selector) == 0 {
			return fmt.Errorf("artifact Service must also select its operator installation")
		}
		peers := labels.SelectorFromSet(selector)
		own, err := r.ownPod(ctx)
		if err != nil {
			return err
		}
		if !peers.Matches(labels.Set(own.Labels)) {
			return fmt.Errorf("operator Pod %s/%s does not match the artifact Service", own.Namespace, own.Name)
		}
		if !own.DeletionTimestamp.IsZero() {
			return fmt.Errorf("operator Pod %s/%s is terminating", own.Namespace, own.Name)
		}
		if r.exclusive {
			var pods corev1.PodList
			if err := r.client.List(ctx, &pods, client.InNamespace(r.pod.Namespace), client.MatchingLabels(service.Spec.Selector)); err != nil {
				return fmt.Errorf("list serving operator Pods: %w", err)
			}
			for i := range pods.Items {
				pod := &pods.Items[i]
				if pod.UID == r.pod.UID {
					continue
				}
				if err := client.IgnoreNotFound(r.setServing(ctx, pod, false)); err != nil {
					return fmt.Errorf("withdraw previous artifact server %s: %w", pod.Name, err)
				}
			}
		}
		return r.setServing(ctx, own, true)
	})
}

func (r *podRouting) ownPod(ctx context.Context) (*corev1.Pod, error) {
	var pod corev1.Pod
	if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.pod.Namespace, Name: r.pod.Name}, &pod); err != nil {
		return nil, err
	}
	if pod.UID != r.pod.UID {
		return nil, fmt.Errorf("operator Pod %s/%s has been replaced", r.pod.Namespace, r.pod.Name)
	}
	return &pod, nil
}

func (r *podRouting) setServing(ctx context.Context, pod *corev1.Pod, serving bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	base := pod.DeepCopy()
	if serving {
		if pod.Labels[ServingLabel] == servingValue {
			return nil
		}
		if pod.Labels == nil {
			pod.Labels = make(map[string]string)
		}
		pod.Labels[ServingLabel] = servingValue
	} else {
		if _, exists := pod.Labels[ServingLabel]; !exists {
			return nil
		}
		delete(pod.Labels, ServingLabel)
	}
	return r.client.Patch(ctx, pod, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

func (r *podRouting) run(ctx context.Context) {
	ticker := time.NewTicker(routingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.reconcile(ctx); err != nil && ctx.Err() == nil {
				log.FromContext(ctx).Error(err, "Unable to reconcile artifact server routing")
			}
		}
	}
}
