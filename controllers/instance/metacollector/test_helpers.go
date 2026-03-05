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

package metacollector

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/testutil"
)

const defaultName = "test"

// newMetacollector creates a basic Metacollector instance for testing.
func newMetacollector(opts ...func(*instancev1alpha1.Metacollector)) *instancev1alpha1.Metacollector {
	mc := &instancev1alpha1.Metacollector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultName,
			Namespace: testutil.TestNamespace,
		},
	}
	for _, opt := range opts {
		opt(mc)
	}
	return mc
}

// withName overrides the resource name.
func withName(name string) func(*instancev1alpha1.Metacollector) {
	return func(mc *instancev1alpha1.Metacollector) {
		mc.Name = name
	}
}

// withNamespace overrides the namespace.
func withNamespace(ns string) func(*instancev1alpha1.Metacollector) {
	return func(mc *instancev1alpha1.Metacollector) {
		mc.Namespace = ns
	}
}

// withFinalizer adds the finalizer to the instance.
func withFinalizer() func(*instancev1alpha1.Metacollector) {
	return func(mc *instancev1alpha1.Metacollector) {
		mc.Finalizers = []string{finalizer}
	}
}

// withDeletionTimestamp sets the deletion timestamp.
func withDeletionTimestamp() func(*instancev1alpha1.Metacollector) {
	return func(mc *instancev1alpha1.Metacollector) {
		now := metav1.Now()
		mc.DeletionTimestamp = &now
	}
}

// withReplicas sets the number of replicas.
func withReplicas(r int32) func(*instancev1alpha1.Metacollector) {
	return func(mc *instancev1alpha1.Metacollector) {
		mc.Spec.Replicas = &r
	}
}

// withVersion sets the Metacollector version.
func withVersion(v string) func(*instancev1alpha1.Metacollector) {
	return func(mc *instancev1alpha1.Metacollector) {
		mc.Spec.Version = v
	}
}

// withLabels sets the labels.
func withLabels(labels map[string]string) func(*instancev1alpha1.Metacollector) {
	return func(mc *instancev1alpha1.Metacollector) {
		mc.Labels = labels
	}
}

// withImage sets the container image via PodTemplateSpec.
func withImage(img string) func(*instancev1alpha1.Metacollector) {
	return func(mc *instancev1alpha1.Metacollector) {
		mc.Spec.PodTemplateSpec = &corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: containerName, Image: img}},
			},
		}
	}
}

// withStrategy sets the Deployment strategy.
func withStrategy(s appsv1.DeploymentStrategy) func(*instancev1alpha1.Metacollector) {
	return func(mc *instancev1alpha1.Metacollector) {
		mc.Spec.Strategy = &s
	}
}
