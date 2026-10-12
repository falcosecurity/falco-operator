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
	"fmt"
	"maps"
	"slices"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
)

// sourceCondition is the condition one source sets on an artifact's status, and the reasons that
// go with it. It follows from the medium alone: every artifact kind shares NodeArtifactStatus and
// the same condition types, so this is stated once rather than per kind.
type sourceCondition struct {
	conditionType commonv1alpha1.ConditionType
	newCondition  func(status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition
	failReason    string
	okReason      string
	okMessage     string
}

var sourceConditions = map[artifact.Medium]sourceCondition{
	artifact.MediumOCI: {
		conditionType: commonv1alpha1.ConditionOCIArtifactProgrammed,
		newCondition:  common.NewOCIArtifactProgrammedCondition,
		failReason:    artifact.ReasonOCIArtifactProgramFailed,
		okReason:      artifact.ReasonOCIArtifactProgrammed,
		okMessage:     artifact.MessageOCIArtifactProgrammed,
	},
	artifact.MediumInline: {
		conditionType: commonv1alpha1.ConditionInlineArtifactProgrammed,
		newCondition:  common.NewInlineArtifactProgrammedCondition,
		failReason:    artifact.ReasonInlineArtifactProgramFailed,
		okReason:      artifact.ReasonInlineArtifactProgrammed,
		okMessage:     artifact.MessageInlineArtifactProgrammed,
	},
	artifact.MediumConfigMap: {
		conditionType: commonv1alpha1.ConditionConfigMapArtifactProgrammed,
		newCondition:  common.NewConfigMapArtifactProgrammedCondition,
		failReason:    artifact.ReasonConfigMapArtifactProgramFailed,
		okReason:      artifact.ReasonConfigMapArtifactProgrammed,
		okMessage:     artifact.MessageConfigMapArtifactProgrammed,
	},
}

// storeFailure is what one kind of artifact calls a failed store of one source. It is the only
// part of source status that differs between kinds (a Config says "config" where a Rulesfile says
// "rules"), so it is the only part a kind's flow declares.
type storeFailure struct {
	reason string
	format string
}

// storeFailures is one kind's wording, keyed by the sources that kind has. Its keys also say which
// sources to report on at all.
type storeFailures map[artifact.Medium]storeFailure

// record writes the conditions and events for every source of one artifact.
//
// inPlay is the set of sources the artifact currently has, whether or not anything had to be done
// to them; a source outside it has been withdrawn and loses its condition rather than being marked
// failed. actions is what was done, keyed by medium, and an entry there earns an event; it is also
// what says the apply reached that source at all, since applySources stops at the first failure and
// leaves every later source untouched. failed is the source whose error is about to be reported by
// recordFailure, and is skipped here so it is not first marked programmed.
func (f storeFailures) record(recorder recorderFor, obj client.Object, conditions *[]metav1.Condition,
	generation int64, inPlay map[artifact.Medium]bool,
	actions map[artifact.Medium]artifact.StoreAction, failed artifact.Medium,
) {
	// In a fixed order, so that the conditions and events of an artifact's first report come out the same on
	// every node.
	for _, medium := range slices.Sorted(maps.Keys(f)) {
		source := sourceConditions[medium]
		action, reached := actions[medium]
		if !inPlay[medium] {
			if !reached {
				// The removal never got this far, so the file may still be on disk: keeping the
				// condition is what stops the aggregate status from hiding it.
				continue
			}
			// A withdrawn source loses its condition, but a file that was actually deleted is
			// still worth an event: it is a change to the node, not just to the CR's status.
			recorder.storeEvent(obj, action, medium)
			apimeta.RemoveStatusCondition(conditions, source.conditionType.String())
			continue
		}
		if medium == failed || !reached {
			// A source the apply never reached keeps whatever its last reconcile concluded, which is
			// still what is on disk. Marking it programmed here would claim a file that was never written.
			continue
		}
		recorder.storeEvent(obj, action, medium)
		apimeta.SetStatusCondition(conditions, source.newCondition(
			metav1.ConditionTrue, source.okReason, source.okMessage, generation,
		))
	}
}

// recordFailure records the warning and the False condition for the source that failed. It is a
// no-op for a medium this kind has no wording for, which is what an error belonging to no single
// source looks like.
func (f storeFailures) recordFailure(recorder recorderFor, obj client.Object,
	conditions *[]metav1.Condition, medium artifact.Medium, generation int64, err error,
) {
	failure, ok := f[medium]
	if !ok {
		return
	}
	source := sourceConditions[medium]
	recorder.warnf(obj, failure.reason, failure.format, err.Error())
	apimeta.SetStatusCondition(conditions, source.newCondition(
		metav1.ConditionFalse, source.failReason,
		fmt.Sprintf(failure.format, err.Error()), generation,
	))
}

// recordRemovalFailure records the warning and the False condition for a withdrawn source whose file could not
// be removed. The source is no longer in the spec, but its file is still on the node, so its condition stays
// until the removal succeeds: dropping it, as record does for a withdrawn source, would let the aggregate
// status hide a stale file. It is a no-op for a medium this kind has no wording for.
func (f storeFailures) recordRemovalFailure(recorder recorderFor, obj client.Object,
	conditions *[]metav1.Condition, medium artifact.Medium, generation int64, err error,
) {
	if _, ok := f[medium]; !ok {
		return
	}
	source := sourceConditions[medium]
	recorder.warnf(obj, artifact.ReasonArtifactRemoveFailed, "unable to remove withdrawn %s source: %s", medium, err.Error())
	apimeta.SetStatusCondition(conditions, source.newCondition(
		metav1.ConditionFalse, artifact.ReasonArtifactRemoveFailed, err.Error(), generation,
	))
}

// recordApplyFailure records the failure of the source applySources named in res.Failed: a removal failure
// when that source was withdrawn, a store failure otherwise.
func (f storeFailures) recordApplyFailure(recorder recorderFor, obj client.Object,
	conditions *[]metav1.Condition, inPlay map[artifact.Medium]bool, failed artifact.Medium, generation int64, err error,
) {
	if inPlay[failed] {
		f.recordFailure(recorder, obj, conditions, failed, generation, err)
		return
	}
	f.recordRemovalFailure(recorder, obj, conditions, failed, generation, err)
}

// setAllFalse marks every in-play source False with one shared reason, for a decision taken before
// any source was handled: an artifact blocked by unmet dependencies, whose per-source conditions
// would otherwise be absent and let another node's True status win when the parent aggregates them.
//

func (f storeFailures) setAllFalse(conditions *[]metav1.Condition, generation int64,
	inPlay map[artifact.Medium]bool, reason, message string,
) {
	for medium := range f {
		if !inPlay[medium] {
			continue
		}
		apimeta.SetStatusCondition(conditions, sourceConditions[medium].newCondition(
			metav1.ConditionFalse, reason, message, generation,
		))
	}
}
