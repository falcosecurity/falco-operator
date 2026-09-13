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

package controllerhelper

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

// ReferenceCheck describes one referenced object a Config/Rulesfile/Plugin spec must resolve.
type ReferenceCheck struct {
	// Name is the referenced object's name: used in the ResolvedRefs condition message and as
	// the log field value on failure.
	Name string
	Key  client.ObjectKey
	// Into is the object Get populates; its type determines what's fetched (e.g. &corev1.ConfigMap{}).
	Into client.Object
	// LogMessage and LogField are the fixed text and field key used in the failure log line.
	LogMessage string
	LogField   string
}

// ConfigMapReferenceCheck builds the ReferenceCheck for a ConfigMapRef.
func ConfigMapReferenceCheck(namespace, name string) ReferenceCheck {
	return ReferenceCheck{
		Name:       name,
		Key:        client.ObjectKey{Namespace: namespace, Name: name},
		Into:       &corev1.ConfigMap{},
		LogMessage: "ConfigMap reference resolution failed",
		LogField:   "configMap",
	}
}

// SecretReferenceCheck builds the ReferenceCheck for an OCI-auth SecretRef.
func SecretReferenceCheck(namespace, name string) ReferenceCheck {
	return ReferenceCheck{
		Name:       name,
		Key:        client.ObjectKey{Namespace: namespace, Name: name},
		Into:       &corev1.Secret{},
		LogMessage: "OCIArtifact auth secret reference resolution failed",
		LogField:   "secret",
	}
}

// ResolveReferences resolves each check in order, stopping at the first failure: it logs, records
// a Warning event on obj, and sets ResolvedRefs=False using the failing check's Name. When every
// check succeeds, it records a Normal event and sets ResolvedRefs=True if len(checks) > 0, or
// removes the condition entirely when checks is empty (obj references nothing).
func ResolveReferences(ctx context.Context, cl client.Client, recorder events.EventRecorder,
	obj client.Object, conditions *[]metav1.Condition, checks ...ReferenceCheck,
) error {
	logger := log.FromContext(ctx)

	for _, c := range checks {
		if err := cl.Get(ctx, c.Key, c.Into); err != nil {
			logger.Error(err, c.LogMessage, c.LogField, c.Name)
			artifact.RecordWarning(recorder, obj, artifact.ReasonReferenceResolutionFailed, artifact.MessageFormatReferenceResolutionFailed, err.Error())
			apimeta.SetStatusCondition(conditions, common.NewResolvedRefsCondition(
				metav1.ConditionFalse, artifact.ReasonReferenceResolutionFailed,
				fmt.Sprintf(artifact.MessageFormatReferenceResolutionFailed, c.Name), obj.GetGeneration()))
			return err
		}
	}

	if len(checks) > 0 {
		artifact.RecordNormal(recorder, obj, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved)
		apimeta.SetStatusCondition(conditions, common.NewResolvedRefsCondition(
			metav1.ConditionTrue, artifact.ReasonReferenceResolved, artifact.MessageReferencesResolved, obj.GetGeneration(),
		))
	} else {
		apimeta.RemoveStatusCondition(conditions, commonv1alpha1.ConditionResolvedRefs.String())
	}

	return nil
}
