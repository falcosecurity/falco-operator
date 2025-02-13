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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/alacuku/falco-operator/api/v1alpha1"
	"github.com/alacuku/falco-operator/internal/pkg/image"
	"github.com/alacuku/falco-operator/internal/pkg/scheme"
)

func GenerateDaemonsetApplyConfiguration(ctx context.Context, cl client.Client, falco *v1alpha1.Falco) (*unstructured.Unstructured, error) {
	// Build the default daemonset.
	baseDs := baseDaemonset(falco)

	// Create a parser to merge the base daemonset with the user defined one.
	parser := scheme.Parser()

	// Parse the base daemonset.
	baseTyped, err := parser.Type("io.k8s.api.apps.v1.DaemonSet").FromStructured(baseDs)
	if err != nil {
		return nil, err
	}

	// Generate the user defined daemonset.
	userUnstructured, err := generateUserDefinedDaemonset(falco)
	if err != nil {
		return nil, err
	}

	// Parse the user defined daemonset.
	userTyped, err := parser.Type("io.k8s.api.apps.v1.DaemonSet").FromUnstructured(userUnstructured.Object)
	if err != nil {
		return nil, err
	}

	// Merge the base and user defined daemonsets.
	desiredTyped, err := baseTyped.Merge(userTyped)
	if err != nil {
		return nil, err
	}

	mergedUnstructured := (desiredTyped.AsValue().Unstructured()).(map[string]interface{})

	desiredDsUnstructured := &unstructured.Unstructured{
		Object: mergedUnstructured,
	}

	if err := setDefaultValues(ctx, cl, desiredDsUnstructured, schema.GroupVersionKind{
		Group:   appsv1.GroupName,
		Version: "v1",
		Kind:    "DaemonSet",
	}); err != nil {
		return nil, err
	}

	// Set the name of the daemonset to the name of the falco CR.
	if err := unstructured.SetNestedField(desiredDsUnstructured.Object, falco.Name, "metadata", "name"); err != nil {
		return nil, fmt.Errorf("failed to set name field: %w", err)
	}

	// Remove unwanted fields.
	removeUnwantedFields(desiredDsUnstructured)

	return desiredDsUnstructured, nil
}

// baseDaemonset returns the base daemonset for Falco with default values + metadata coming from the Falco CR.
func baseDaemonset(falco *v1alpha1.Falco) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      falco.Name,
			Namespace: falco.Namespace,
			Labels:    falco.Labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":     falco.Name,
					"app.kubernetes.io/instance": falco.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: podTemplateSpecLabels(falco.Name, falco.Labels),
				},
				Spec: corev1.PodSpec{
					Tolerations: []corev1.Toleration{
						{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
						{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule},
					},
					Volumes: DefaultFalcoVolumes,
					Containers: []corev1.Container{
						{
							Name:            "falco",
							Image:           image.BuildFalcoImageStringFromVersion(falco.Spec.Version),
							ImagePullPolicy: DefaultFalcoImagePullPolicy,
							Resources:       DefaultFalcoResources,
							Ports:           DefaultFalcoPorts,
							Args:            DefaultFalcoArgs,
							Env:             DefaultFalcoEnv,
							VolumeMounts:    DefaultFalcoVolumeMounts,
							LivenessProbe:   DefaultFalcoLivenessProbe,
							ReadinessProbe:  DefaultFalcoReadinessProbe,
							SecurityContext: DefaultFalcoSecurityContext,
						},
					},
				},
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
			},
		},
	}
}

// generateUserDefinedDaemonset generates a user defined daemonset from the falco CR.
func generateUserDefinedDaemonset(falco *v1alpha1.Falco) (*unstructured.Unstructured, error) {
	// Build the default daemonset from the base one.
	// We use the base one as a starting point to have the same structure and, then we override the user defined fields.
	userDs := baseDaemonset(falco)

	// Set the PodTemplateSpec to the user define one if present, otherwise set it to an empty one.
	if falco.Spec.PodTemplateSpec != nil {
		userDs.Spec.Template = *falco.Spec.PodTemplateSpec
	} else {
		userDs.Spec.Template = corev1.PodTemplateSpec{}
	}

	// Convert to unstructured and remove the fields we don't want to compare.
	unUserDs, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&userDs)
	if err != nil {
		return nil, err
	}

	ds := &unstructured.Unstructured{
		Object: unUserDs,
	}

	// Remove the empty containers field if it exists.
	if removeEmptyContainers(ds) != nil {
		return nil, err
	}

	// Remove unwanted fields.
	removeUnwantedFields(ds)

	return ds, nil
}

// removeEmptyContainers removes the empty containers field from the unstructured DaemonSet if it exists.
func removeEmptyContainers(obj *unstructured.Unstructured) error {
	if templateSpec, found, err := unstructured.NestedMap(obj.Object, "spec", "template", "spec"); err != nil {
		return fmt.Errorf("failed to get podSpec from podTemplateSpec while generating user defined daemonset: %w", err)
	} else if !found {
		// should never happen
		return fmt.Errorf("podSpec not found in podTemplateSpec while generating user defined daemonset")
	} else {
		// Get the containers map and remove it if it's empty.
		// We can't leave an empty containers field since it will override the default one when merging with the base daemonset.
		if containers, ok := templateSpec["containers"]; ok {
			if containers == nil {
				unstructured.RemoveNestedField(obj.Object, "spec", "template", "spec", "containers")
			}
		}
	}
	return nil
}

// removeUnwantedFields removes unwanted fields from the unstructured object.
func removeUnwantedFields(obj *unstructured.Unstructured) {
	unstructured.RemoveNestedField(obj.Object, "metadata", "uid")
	unstructured.RemoveNestedField(obj.Object, "metadata", "resourceVersion")
	unstructured.RemoveNestedField(obj.Object, "metadata", "managedFields")
	unstructured.RemoveNestedField(obj.Object, "status")
	unstructured.RemoveNestedField(obj.Object, "metadata", "creationTimestamp")
	unstructured.RemoveNestedField(obj.Object, "spec", "template", "metadata", "creationTimestamp")
	unstructured.RemoveNestedField(obj.Object, "spec", "revisionHistoryLimit")
	unstructured.RemoveNestedField(obj.Object, "metadata", "generateName")
	unstructured.RemoveNestedField(obj.Object, "metadata", "generation")
}

// podTemplateSpecLabels returns the labels for the pod template spec.
func podTemplateSpecLabels(appName string, baseLabels map[string]string) map[string]string {
	return labels.Merge(baseLabels, map[string]string{
		"app.kubernetes.io/name":     appName,
		"app.kubernetes.io/instance": appName,
	})
}

// setDefaultValues sets the default values for the unstructured object by dry-run creating it.
func setDefaultValues(ctx context.Context, cl client.Client, obj *unstructured.Unstructured, gvk schema.GroupVersionKind) error {
	if err := unstructured.SetNestedField(obj.Object, "dry-run", "metadata", "generateName"); err != nil {
		return fmt.Errorf("failed to set generateName field: %w", err)
	}

	if err := unstructured.SetNestedField(obj.Object, "", "metadata", "name"); err != nil {
		return fmt.Errorf("failed to set name field: %w", err)
	}

	obj.SetKind(gvk.Kind)
	obj.SetAPIVersion(gvk.GroupVersion().String())

	err := cl.Create(ctx, obj, &client.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	if err != nil {
		return fmt.Errorf("failed to set default values by dry-run creating the object %s: %w", gvk.Kind, err)
	}

	return nil
}
