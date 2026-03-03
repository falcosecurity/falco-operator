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

package resources

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// OverlayOption is a functional option for configuring a user overlay.
type OverlayOption func(*overlayConfig)

type overlayConfig struct {
	labels          map[string]string
	replicas        *int32
	strategy        *appsv1.DeploymentStrategy
	updateStrategy  *appsv1.DaemonSetUpdateStrategy
	podTemplateSpec *corev1.PodTemplateSpec
	version         *string
}

// WithOverlayLabels sets the labels on the overlay resource metadata.
func WithOverlayLabels(l map[string]string) OverlayOption {
	return func(c *overlayConfig) { c.labels = l }
}

// WithOverlayReplicas sets the replicas on the overlay resource.
func WithOverlayReplicas(replicas *int32) OverlayOption {
	return func(c *overlayConfig) { c.replicas = replicas }
}

// WithOverlayStrategy sets the deployment strategy on the overlay resource.
func WithOverlayStrategy(s *appsv1.DeploymentStrategy) OverlayOption {
	return func(c *overlayConfig) { c.strategy = s }
}

// WithOverlayUpdateStrategy sets the daemonset update strategy on the overlay resource.
func WithOverlayUpdateStrategy(s *appsv1.DaemonSetUpdateStrategy) OverlayOption {
	return func(c *overlayConfig) { c.updateStrategy = s }
}

// WithOverlayPodTemplateSpec sets the pod template spec on the overlay resource.
func WithOverlayPodTemplateSpec(pts *corev1.PodTemplateSpec) OverlayOption {
	return func(c *overlayConfig) { c.podTemplateSpec = pts }
}

// WithOverlayVersion sets the version override on the overlay resource.
func WithOverlayVersion(version *string) OverlayOption {
	return func(c *overlayConfig) { c.version = version }
}

func GenerateOverlayOptions(obj client.Object) []OverlayOption {
	opts := []OverlayOption{
		WithOverlayLabels(obj.GetLabels()),
	}

	switch o := obj.(type) {
	case *instancev1alpha1.Falco:
		if o.Spec.Replicas != nil {
			opts = append(opts, WithOverlayReplicas(o.Spec.Replicas))
		}
		if o.Spec.Strategy != nil {
			opts = append(opts, WithOverlayStrategy(o.Spec.Strategy))
		}
		if o.Spec.UpdateStrategy != nil {
			opts = append(opts, WithOverlayUpdateStrategy(o.Spec.UpdateStrategy))
		}
		if o.Spec.PodTemplateSpec != nil {
			opts = append(opts, WithOverlayPodTemplateSpec(o.Spec.PodTemplateSpec))
		}
		if o.Spec.Version != nil {
			opts = append(opts, WithOverlayVersion(o.Spec.Version))
		}
	case *instancev1alpha1.Component:
		if o.Spec.Replicas != nil {
			opts = append(opts, WithOverlayReplicas(o.Spec.Replicas))
		}
		if o.Spec.Strategy != nil {
			opts = append(opts, WithOverlayStrategy(o.Spec.Strategy))
		}
		if o.Spec.PodTemplateSpec != nil {
			opts = append(opts, WithOverlayPodTemplateSpec(o.Spec.PodTemplateSpec))
		}
		if o.Spec.Component.Version != nil {
			opts = append(opts, WithOverlayVersion(o.Spec.Component.Version))
		}
	}

	return opts
}

// GenerateUserOverlay builds a minimal overlay resource from user-defined fields.
func GenerateUserOverlay(resourceType, name string, defs *InstanceDefaults, opts ...OverlayOption) (*unstructured.Unstructured, error) {
	cfg := &overlayConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	selectorLabels := forgeSelectorLabels(name)

	var userResource any

	switch resourceType {
	case ResourceTypeDeployment:
		dep := &appsv1.Deployment{
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: selectorLabels},
			},
		}
		if cfg.labels != nil {
			dep.Labels = cfg.labels
		}
		if cfg.replicas != nil {
			dep.Spec.Replicas = cfg.replicas
		}
		if cfg.podTemplateSpec != nil {
			dep.Spec.Template = *cfg.podTemplateSpec
		} else {
			dep.Spec.Template = corev1.PodTemplateSpec{}
		}
		if cfg.labels != nil {
			dep.Spec.Template.Labels = labels.Merge(dep.Spec.Template.Labels, cfg.labels)
		}
		if cfg.strategy != nil {
			dep.Spec.Strategy = *cfg.strategy
		}
		applyVersionOverride(defs, cfg.version, &dep.Spec.Template)
		userResource = dep
	case ResourceTypeDaemonSet:
		ds := &appsv1.DaemonSet{
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: selectorLabels},
			},
		}
		if cfg.labels != nil {
			ds.Labels = cfg.labels
		}
		if cfg.podTemplateSpec != nil {
			ds.Spec.Template = *cfg.podTemplateSpec
		} else {
			ds.Spec.Template = corev1.PodTemplateSpec{}
		}
		if cfg.labels != nil {
			ds.Spec.Template.Labels = labels.Merge(ds.Spec.Template.Labels, cfg.labels)
		}
		if cfg.updateStrategy != nil {
			ds.Spec.UpdateStrategy = *cfg.updateStrategy
		}
		applyVersionOverride(defs, cfg.version, &ds.Spec.Template)
		userResource = ds
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	unResource, err := runtime.DefaultUnstructuredConverter.ToUnstructured(userResource)
	if err != nil {
		return nil, err
	}

	resource := &unstructured.Unstructured{Object: unResource}

	if err := removeEmptyContainers(resource); err != nil {
		return nil, err
	}

	return resource, nil
}

func applyVersionOverride(defs *InstanceDefaults, version *string, template *corev1.PodTemplateSpec) {
	for i := range template.Spec.Containers {
		if template.Spec.Containers[i].Name == defs.ContainerName {
			return
		}
	}

	if version != nil && *version != "" {
		template.Spec.Containers = append(template.Spec.Containers, corev1.Container{
			Name:  defs.ContainerName,
			Image: defs.ImageRepository + ":" + *version,
		})
	}
}
