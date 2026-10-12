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

package node

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
)

// resolveReferences sets the ResolvedRefs condition of obj from the one reference a node resolves, its ConfigMap
// source (nil when it has none). The other references of an artifact, the registry auth Secret, are the instance
// operator's: it is the one that pulls from the registry.
//
// A ConfigMap that cannot be read is logged, recorded as a Warning event on obj and set as ResolvedRefs=False, and
// the error is returned. One that can sets ResolvedRefs=True, recording a Normal event when the condition was not True
// already. With no reference, the condition is removed.
func resolveReferences(ctx context.Context, cl client.Client, recorder events.EventRecorder,
	obj client.Object, conditions *[]metav1.Condition, configMapRef *commonv1alpha1.ConfigMapRef,
) error {
	if configMapRef == nil {
		apimeta.RemoveStatusCondition(conditions, commonv1alpha1.ConditionResolvedRefs.String())
		return nil
	}

	key := client.ObjectKey{Namespace: obj.GetNamespace(), Name: configMapRef.Name}
	if err := cl.Get(ctx, key, &corev1.ConfigMap{}); err != nil {
		log.FromContext(ctx).Error(err, "ConfigMap reference resolution failed", "configMap", configMapRef.Name)
		artifact.RecordWarning(recorder, obj, artifact.ReasonReferenceResolutionFailed, artifact.MessageFormatReferenceResolutionFailed, err.Error())
		apimeta.SetStatusCondition(conditions, common.NewResolvedRefsCondition(
			metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
			fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, configMapRef.Name), obj.GetGeneration()))
		return err
	}

	// Only the moment the references become resolved is an Event. Recording it on every reconcile would have every
	// node's artifact operator write Events about the same artifact each time it is reconciled.
	if !apimeta.IsStatusConditionTrue(*conditions, commonv1alpha1.ConditionResolvedRefs.String()) {
		artifact.RecordNormal(recorder, obj, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved)
	}
	apimeta.SetStatusCondition(conditions, common.NewResolvedRefsCondition(
		metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, obj.GetGeneration(),
	))
	return nil
}
