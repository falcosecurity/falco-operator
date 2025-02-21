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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// FalcoSpec defines the desired state of Falco.
type FalcoSpec struct {
	// Type specifies the type of Kubernetes resource to deploy Falco.
	// Allowed values: "DaemonSet" or "Deployment". Default value is DaemonSet.
	// +kubebuilder:default=DaemonSet
	// +kubebuilder:validation:Enum=DaemonSet;Deployment
	Type string `json:"type,omitempty"`

	// Replicas defines the number of replicas for the Deployment.
	// Required only when 'type' is "Deployment".
	// Default is 1.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// Version specifies the version of Falco to deploy.
	// - If specified, the operator will deploy the given version of Falco.
	//   Example: "0.39.2".
	// - If omitted, the operator will default to the latest upstream version of Falco
	//   available at the time the operator was released.
	// - The version string should match the format of Falco's official
	//   tags (https://github.com/falcosecurity/falco/releases), typically
	//   "major.minor.patch" (e.g., "0.39.2").
	// +optional
	Version string `json:"version,omitempty"`

	// PodTemplateSpec contains the pod template specification for the Falco instance.
	// Users can customize metadata, initContainers, containers, volumes, tolerations, etc.
	// +optional
	PodTemplateSpec *corev1.PodTemplateSpec `json:"podTemplateSpec,omitempty"`
}

// FalcoStatus defines the observed state of Falco.
type FalcoStatus struct {
	// Desired number of instances for the Falco deployment.
	// The total number of nodes that should be running the daemon pod (including nodes correctly running the daemon pod).
	// +optional
	DesiredReplicas int32 `json:"desiredReplicas,omitempty" protobuf:"varint,1,opt,name=desiredReplicas"`
	// Total number of available pods (ready for at least minReadySeconds) targeted by the deployment.
	// Or the number of nodes that should be running the  daemon pod and have one or more of the daemon pod running and
	// available (ready for at least spec.minReadySeconds)
	// +optional
	AvailableReplicas int32 `json:"availableReplicas" protobuf:"varint,11,opt,name=availableReplicas"`

	// Total number of unavailable pods targeted by falco deployment/daemonset. This is the total number of
	// pods that are still required for the deployment to have 100% available capacity or the number of nodes
	// that should be running the daemon pod and have none of the daemon pod running and available. They may
	// either be pods that are running but not yet available or pods that still have not been created.
	// +optional
	UnavailableReplicas int32 `json:"unavailableReplicas,omitempty" protobuf:"varint,5,opt,name=unavailableReplicas"`

	// The current status of the Falco instance
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ConditionType represents a Falco condition type.
// +kubebuilder:validation:MinLength=1
type ConditionType string

const (
	// Available indicates whether enough pods are ready to provide the
	// service.
	// The possible status values for this condition type are:
	// - True: all pods are running and ready, the service is fully available.
	// - Degraded: some pods aren't ready, the service is partially available.
	// - False: no pods are running, the service is totally unavailable.
	// - Unknown: the operator couldn't determine the condition status.
	Available ConditionType = "Available"
	// Reconciled indicates whether the operator has reconciled the state of
	// the underlying resources with the object's spec.
	// The possible status values for this condition type are:
	// - True: the reconciliation was successful.
	// - False: the reconciliation failed.
	// - Unknown: the operator couldn't determine the condition status.
	Reconciled ConditionType = "Reconciled"
)

// +kubebuilder:resource:categories="prometheus-operator",shortName="prom"
// +kubebuilder:printcolumn:name="Type",type="string",JSONPath=".spec.type",description="The type of Kubernetes resource to deploy Falco"
// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version",description="The version of Falco"
// +kubebuilder:printcolumn:name="Desired",type="integer",JSONPath=".status.desiredReplicas",description="The desired number of replicas"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.availableReplicas",description="The number of ready replicas"
// +kubebuilder:printcolumn:name="Reconciled",type="string",JSONPath=".status.conditions[?(@.type == 'Reconciled')].status"
// +kubebuilder:printcolumn:name="Available",type="string",JSONPath=".status.conditions[?(@.type == 'Available')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=falcos

// Falco is the Schema for the falcos API.
type Falco struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FalcoSpec   `json:"spec,omitempty"`
	Status FalcoStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FalcoList contains a list of Falco.
type FalcoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Falco `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Falco{}, &FalcoList{})
}
