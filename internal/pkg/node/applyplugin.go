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
	"errors"
	"fmt"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	pkgpriority "github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// applyPlugin installs one Plugin: its binary, and its entry in the shared plugins-config file
// that tells Falco to load it. The two are written in that order and withdrawn in the opposite
// one, because the entry names the binary.
func (n *Node) applyPlugin(ctx context.Context, plugin *artifactv1alpha1.Plugin, status *artifactv1alpha1.NodeArtifactStatus) error {
	if err := n.resolvePluginReferences(ctx, plugin, status); err != nil {
		return err
	}
	if n.enforceRequirements &&
		n.awaitObservedGeneration(ctx, plugin.Status.ObservedGeneration, plugin.Generation) {
		return nil
	}

	skip, err := n.reportPluginCompatibility(ctx, plugin, status)
	if err != nil {
		return err
	}
	if skip {
		// If the artifact was never installed on this node, explicitly mark installation
		// conditions as False so the aggregator sees them. Without this, absent conditions let
		// another node's True status win unopposed in AggregateConditions. When the old version
		// is still on disk its conditions correctly remain True; don't touch them.
		if n.FindInstalled(artifact.RefOf(artifact.KindPlugin, plugin), artifact.MediumOCI) == nil {
			reason, msg := artifact.DependenciesNotSatisfiedReasonFromCondition(status.Conditions)
			gen := plugin.GetGeneration()
			apimeta.SetStatusCondition(&status.Conditions, common.NewConfigProgrammedCondition(
				metav1.ConditionFalse, reason, msg, gen,
			))
			apimeta.SetStatusCondition(&status.Conditions, common.NewOCIArtifactProgrammedCondition(
				metav1.ConditionFalse, reason, msg, gen,
			))
		}
		return nil
	}

	if err := n.ensurePluginBinary(ctx, plugin, status); err != nil {
		return err
	}
	return n.ensurePluginConfig(ctx, plugin, status)
}

// pluginStoreFailures is what a Plugin calls a failed store of its one source. Everything else
// about the condition is shared with every other artifact kind (see conditions.go).
var pluginStoreFailures = storeFailures{
	artifact.MediumOCI: {
		reason: artifact.ReasonOCIArtifactStoreFailed,
		format: artifact.MessageFormatOCIArtifactStoreFailed,
	},
}

// ensurePluginBinary makes the node hold the plugin binary the spec describes, and reports what it did.
// The node fetches only when it cannot confirm that what it already holds is the requested
// revision, so a reconcile of an unchanged plugin reaches the artifact server not at all.
func (n *Node) ensurePluginBinary(ctx context.Context, plugin *artifactv1alpha1.Plugin, status *artifactv1alpha1.NodeArtifactStatus) error {
	gen := plugin.GetGeneration()
	logger := log.FromContext(ctx)
	key := artifact.RefOf(artifact.KindPlugin, plugin)

	want := desired{
		Priority: pkgpriority.DefaultPriority,
		Sources:  map[artifact.Medium]sourceInput{},
		claim:    pluginClaim(plugin),
	}
	inPlay := map[artifact.Medium]bool{}

	if plugin.Spec.OCIArtifact != nil {
		inPlay[artifact.MediumOCI] = true
		specHash, expectedDigest := "", ""
		if plugin.Status.ArtifactMeta != nil {
			specHash = plugin.Status.ArtifactMeta.SpecHash
			expectedDigest = plugin.Status.ArtifactMeta.Digest
		}
		want.Sources[artifact.MediumOCI] = sourceInput{
			SpecHash: specHash, ExpectedDigest: expectedDigest,
		}
	} else if err := n.RemovePluginConfig(ctx, plugin); err != nil {
		// OCI spec removed while the Plugin CR still exists. The config entry has to go before
		// the binary it points at, so this runs ahead of the removal the node does below.
		logger.Error(err, "unable to remove plugin config during OCI spec removal")
		return err
	}

	res, err := n.applySources(ctx, key, want)
	pluginStoreFailures.record(recorderFor{node: n}, plugin, &status.Conditions, gen, inPlay, res.Actions, res.Failed)
	if err != nil {
		if blocked, ok := errors.AsType[*BlockedError](err); ok {
			// The claim is checked before the binary is written: nothing failed to store.
			n.reportRenameBlocked(ctx, plugin, status, blocked)
			return err
		}
		logger.Error(err, "unable to store plugin artifact")
		pluginStoreFailures.recordApplyFailure(recorderFor{node: n}, plugin, &status.Conditions, inPlay, res.Failed, gen, err)
		return err
	}
	return nil
}

// reportPluginCompatibility asks the node whether Falco provides what this Plugin requires, and
// puts the answer into the Plugin's conditions and events. It returns whether to skip installation.
func (n *Node) reportPluginCompatibility(
	ctx context.Context, plugin *artifactv1alpha1.Plugin, status *artifactv1alpha1.NodeArtifactStatus,
) (bool, error) {
	gen := plugin.GetGeneration()
	logger := log.FromContext(ctx)

	if plugin.Spec.OCIArtifact == nil {
		logger.Info("Skipping compatibility check: no OCI artifact configured")
		apimeta.RemoveStatusCondition(&status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
		return false, nil
	}

	assessed, err := n.assess(artifact.RefOf(artifact.KindPlugin, plugin), plugin.Status.ArtifactMeta, n.enforceRequirements)
	if err != nil {
		requirement := "plugin"
		if compareErr, ok := errors.AsType[*compareError](err); ok && compareErr.Requirement != "" {
			requirement = compareErr.Requirement
		}
		logger.Error(err, "Unable to compare plugin requirement versions", "capability", requirement)
		apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionUnknown, artifact.ReasonDependenciesUnknown,
			fmt.Sprintf("Unable to compare %s versions: %s", requirement, err.Error()), gen,
		))
		return false, err
	}

	switch assessed.State {
	case metadataMissing:
		if !assessed.Blocked {
			logger.Info("ArtifactMeta not yet available; proceeding without compatibility check in advise mode")
			apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, gen,
			))
			break
		}
		msg := "OCI artifact metadata not yet available; instance operator has not fetched it"
		logger.Info(msg)
		apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionUnknown, artifact.ReasonDependenciesUnknown, msg, gen,
		))
	case metadataSilent:
		if !assessed.Blocked {
			logger.Info("Plugin declares no requirements; proceeding in advise mode")
			apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, gen,
			))
			break
		}
		baseMsg := artifact.MessageRequirementsUndeclared
		reason, msg := artifact.ReasonDependenciesUnknown, baseMsg
		if assessed.AlreadyInstalled {
			reason = artifact.ReasonDependenciesNotSatisfiedUpdateRejected
			msg = baseMsg + artifact.MessageSuffixUpdateRejected
		}
		logger.Info(msg)
		apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionUnknown, reason, msg, gen,
		))
	case metadataDeclared:
		if len(assessed.Unmet) == 0 {
			logger.V(1).Info("All plugin requirements satisfied")
			apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, gen,
			))
			break
		}
		// The first unsatisfied requirement is the answer: a plugin that cannot run is not made
		// more informative by listing everything else it would also have needed.
		unmet := assessed.Unmet[0]
		baseMsg := requirementMessage(unmet)
		if unmet.Found {
			logger.Info("Plugin dependency not satisfied", "capability", unmet.Name,
				"provided", unmet.Provided, "required", unmet.Required)
		} else {
			// Covers both "Falco not yet observed" and "capability never reported"; both are a
			// temporary state that resolves once the version-change watch re-triggers.
			logger.Info("Plugin dependency not advertised by Falco", "capability", unmet.Name, "required", unmet.Required)
		}
		_, reason, msg := artifact.DependenciesNotSatisfiedOutcome(n.enforceRequirements, assessed.AlreadyInstalled, baseMsg)
		artifact.RecordWarning(n.recorder, plugin, reason, "%s", msg)
		apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionFalse, reason, msg, gen,
		))
	}

	return assessed.Blocked, nil
}

// requirementMessage words one unmet requirement. A plugin API mismatch gets its own wording:
// it is a compatibility break rather than an out-of-date dependency, and reads as one.
func requirementMessage(unmet unmetRequirement) string {
	switch {
	case !unmet.Found:
		return fmt.Sprintf(artifact.MessageFormatDependenciesCapabilityMissing, unmet.Name, unmet.Required)
	case unmet.Name == compat.CapabilityPluginAPIVersion:
		return fmt.Sprintf(artifact.MessageFormatPluginAPIMajorMismatch, unmet.Required, unmet.Provided)
	default:
		return fmt.Sprintf(artifact.MessageFormatDependenciesNotSatisfied, unmet.Name, unmet.Required, unmet.Provided)
	}
}

// ensurePluginConfig writes the plugin configuration to the shared config file.
// A no-op when the plugin has no OCI artifact (see ensurePluginBinary's stale cleanup). The shared file's
// path and content hash are the node's own record of it, kept apart from any one Plugin, so
// StoreActionUnchanged fires when the rendered YAML is unchanged between reconciles.
//
// Aggregate-file bookkeeping (rename handling, serialization, the write, and registering the
// resulting name as provided) lives in Node.AddPluginConfig.
func (n *Node) ensurePluginConfig(
	ctx context.Context, plugin *artifactv1alpha1.Plugin, status *artifactv1alpha1.NodeArtifactStatus,
) error {
	gen := plugin.GetGeneration()
	if plugin.Spec.OCIArtifact == nil {
		// ensurePluginBinary already removed this plugin's config entry (if any) during stale cleanup.
		// Removes the ConfigProgrammed condition instead of leaving it stale.
		apimeta.RemoveStatusCondition(&status.Conditions, commonv1alpha1.ConditionConfigProgrammed.String())
		return nil
	}

	logger := log.FromContext(ctx)
	logger.V(1).Info("Ensuring plugin configuration")

	configAction, _, err := n.AddPluginConfig(ctx, plugin)
	if err != nil {
		if blocked, ok := errors.AsType[*BlockedError](err); ok {
			n.reportRenameBlocked(ctx, plugin, status, blocked)
			return err
		}
		logger.Error(err, "unable to store plugin config")
		artifact.RecordWarning(n.recorder, plugin,
			artifact.ReasonInlinePluginConfigStoreFailed, artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error())
		apimeta.SetStatusCondition(&status.Conditions, common.NewConfigProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonConfigProgramFailed,
			fmt.Sprintf(artifact.MessageFormatInlinePluginConfigStoreFailed, err.Error()), gen,
		))
		return err
	}

	artifact.RecordStoreEvent(n.recorder, plugin, configAction, artifact.MediumInline)
	// The condition is set whatever configAction was: an entry the node already holds unchanged is programmed
	// too, and an earlier reconcile's status may never have landed.
	apimeta.SetStatusCondition(&status.Conditions, common.NewConfigProgrammedCondition(
		metav1.ConditionTrue, artifact.ReasonConfigProgrammed, artifact.MessageConfigProgrammed, gen,
	))
	return nil
}

// reportRenameBlocked says, in the Plugin's conditions and events, that its entry in the shared plugin configuration
// cannot take its new name yet: a Rulesfile on this node still requires the name it has. The entry and the binary
// stay as they are, and the caller's *BlockedError has the reconcile tried again shortly, as a blocked removal is.
func (n *Node) reportRenameBlocked(
	ctx context.Context, plugin *artifactv1alpha1.Plugin, status *artifactv1alpha1.NodeArtifactStatus, blocked *BlockedError,
) {
	log.FromContext(ctx).Info("Plugin config rename deferred: old name still required by a Rulesfile on this node",
		"configName", blocked.Name, "blockedBy", blocked.BlockedBy)
	artifact.RecordWarning(n.recorder, plugin, artifact.ReasonPluginConfigStillRequired, "%s", blocked.Error())
	apimeta.SetStatusCondition(&status.Conditions, common.NewConfigProgrammedCondition(
		metav1.ConditionFalse, artifact.ReasonPluginConfigStillRequired, blocked.Error(), plugin.GetGeneration(),
	))
}

func (n *Node) resolvePluginReferences(
	ctx context.Context, plugin *artifactv1alpha1.Plugin, status *artifactv1alpha1.NodeArtifactStatus,
) error {
	// A Plugin's one reference, its registry auth Secret, is the instance operator's: it pulls from the registry
	// and reports a missing Secret on the Plugin. The node gets the binary from the artifact server and has no
	// reference to resolve, so it reports none.
	return resolveReferences(ctx, n.cl, n.recorder, plugin, &status.Conditions, nil)
}
