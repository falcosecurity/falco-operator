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

	appsv1 "k8s.io/api/apps/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Availability holds the computed availability state of a workload.
type Availability struct {
	ConditionStatus     metav1.ConditionStatus
	Reason              string
	Message             string
	DesiredReplicas     int32
	AvailableReplicas   int32
	UnavailableReplicas int32
}

// ComputeDeploymentAvailability fetches the Deployment and computes availability.
func ComputeDeploymentAvailability(ctx context.Context, reader client.Reader,
	key client.ObjectKey, specReplicas *int32) (Availability, error) {
	result := Availability{
		ConditionStatus: metav1.ConditionUnknown,
	}

	desiredReplicas := int32(1)
	if specReplicas != nil {
		desiredReplicas = *specReplicas
	}
	result.DesiredReplicas = desiredReplicas

	deployment := &appsv1.Deployment{}
	if err := reader.Get(ctx, key, deployment); err != nil {
		if k8serrors.IsNotFound(err) {
			result.ConditionStatus = metav1.ConditionFalse
			result.Reason = ReasonDeploymentNotFound
			result.Message = MessageDeploymentNotFound
			return result, nil
		}
		result.Reason = ReasonDeploymentFetchError
		result.Message = fmt.Sprintf(MessageFormatDeploymentFetchError, err.Error())
		log.FromContext(ctx).Error(err, "unable to fetch deployment for status")
		return result, fmt.Errorf("unable to fetch deployment: %w", err)
	}

	result.AvailableReplicas = deployment.Status.AvailableReplicas
	result.UnavailableReplicas = deployment.Status.UnavailableReplicas

	if desiredReplicas == deployment.Status.ReadyReplicas {
		result.ConditionStatus = metav1.ConditionTrue
		result.Reason = ReasonDeploymentAvailable
		result.Message = MessageDeploymentAvailable
	} else {
		result.ConditionStatus = metav1.ConditionFalse
		result.Reason = ReasonDeploymentUnavailable
		result.Message = MessageDeploymentUnavailable
	}

	return result, nil
}

// ComputeDaemonSetAvailability fetches the DaemonSet and computes availability.
func ComputeDaemonSetAvailability(ctx context.Context, reader client.Reader,
	key client.ObjectKey) (Availability, error) {
	result := Availability{
		ConditionStatus: metav1.ConditionUnknown,
	}

	daemonset := &appsv1.DaemonSet{}
	if err := reader.Get(ctx, key, daemonset); err != nil {
		if k8serrors.IsNotFound(err) {
			result.ConditionStatus = metav1.ConditionFalse
			result.Reason = ReasonDaemonSetNotFound
			result.Message = MessageDaemonSetNotFound
			return result, nil
		}
		result.Reason = ReasonDaemonSetFetchError
		result.Message = fmt.Sprintf(MessageFormatDaemonSetFetchError, err.Error())
		log.FromContext(ctx).Error(err, "unable to fetch daemonset for status")
		return result, fmt.Errorf("unable to fetch daemonset: %w", err)
	}

	result.DesiredReplicas = daemonset.Status.DesiredNumberScheduled
	result.AvailableReplicas = daemonset.Status.NumberAvailable
	result.UnavailableReplicas = daemonset.Status.NumberUnavailable

	if daemonset.Status.DesiredNumberScheduled == daemonset.Status.NumberAvailable {
		result.ConditionStatus = metav1.ConditionTrue
		result.Reason = ReasonDaemonSetAvailable
		result.Message = MessageDaemonSetAvailable
	} else {
		result.ConditionStatus = metav1.ConditionFalse
		result.Reason = ReasonDaemonSetUnavailable
		result.Message = MessageDaemonSetUnavailable
	}

	return result, nil
}
