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
	"strings"

	"github.com/opencontainers/go-digest"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
)

// applyRulesfile installs one Rulesfile. It is the only kind that both judges its requirements
// against Falco and takes a snapshot before doing so: its ConfigMap bytes are an input to the hash
// that decides whether the parent's metadata describes these sources at all, so they are read
// first and the very same bytes are what gets written.
func (n *Node) applyRulesfile(ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, status *artifactv1alpha1.NodeArtifactStatus) error {
	if err := n.resolveRulesfileReferences(ctx, rulesfile, status); err != nil {
		return err
	}
	if n.enforceRequirements &&
		n.awaitObservedGeneration(ctx, rulesfile.Status.ObservedGeneration, rulesfile.Generation) {
		return nil
	}

	sources, err := n.resolveRulesfileSources(ctx, rulesfile, status)
	if err != nil {
		return err
	}
	metadata, err := verifiedRulesfileMetadata(rulesfile, sources)
	if err != nil {
		return err
	}

	blocked, err := n.reportRulesfileCompatibility(ctx, rulesfile, status, sources, metadata)
	if err != nil {
		return err
	}
	if blocked {
		// If the artifact was never installed on this node, explicitly mark source conditions as
		// False. Without this they are absent, which lets another node's True status win in
		// AggregateConditions and makes the Rulesfile-level status show e.g.
		// OCIArtifactProgrammed=True even when DependenciesSatisfied=False.
		key := artifact.RefOf(artifact.KindRulesfile, rulesfile)
		if len(n.GetInstalled(key)) == 0 {
			reason, msg := artifact.DependenciesNotSatisfiedReasonFromCondition(status.Conditions)
			rulesfileStoreFailures.setAllFalse(&status.Conditions, rulesfile.GetGeneration(),
				sourcesInPlay(sources), reason, msg)
		}
		return nil
	}

	return n.installRulesfile(ctx, rulesfile, status, sources, metadata)
}

// rulesfileStoreFailures is what a Rulesfile calls a failed store, per source. Everything else
// about a source's condition is shared with every other artifact kind (see conditions.go).
var rulesfileStoreFailures = storeFailures{
	artifact.MediumOCI: {
		reason: artifact.ReasonOCIArtifactStoreFailed,
		format: artifact.MessageFormatOCIArtifactStoreFailed,
	},
	artifact.MediumInline: {
		reason: artifact.ReasonInlineRulesStoreFailed,
		format: artifact.MessageFormatInlineRulesStoreFailed,
	},
	artifact.MediumConfigMap: {
		reason: artifact.ReasonConfigMapRulesStoreFailed,
		format: artifact.MessageFormatConfigMapRulesStoreFailed,
	},
}

// sourcesInPlay is the set of sources the Rulesfile currently declares, whatever the node has to
// do about them. A source outside it has been withdrawn.
func sourcesInPlay(sources *artifact.RulesfileSources) map[artifact.Medium]bool {
	inPlay := map[artifact.Medium]bool{}
	if sources.OCIArtifact != nil {
		inPlay[artifact.MediumOCI] = true
	}
	if sources.InlineRules != nil {
		inPlay[artifact.MediumInline] = true
	}
	if sources.ConfigMap != nil {
		inPlay[artifact.MediumConfigMap] = true
	}
	return inPlay
}

// desiredRulesfile turns the resolved sources into the intent the node acts on, and reports which
// sources the Rulesfile currently has at all. A source the spec no longer declares is left out of
// both, which is what makes the node remove its file and release what it registered.
func (n *Node) desiredRulesfile(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, status *artifactv1alpha1.NodeArtifactStatus,
	sources *artifact.RulesfileSources, metadata *commonv1alpha1.ArtifactMeta,
) (desired, map[artifact.Medium]bool, error) {
	logger := log.FromContext(ctx)
	want := desired{
		Priority: rulesfile.Spec.Priority,
		Metadata: metadata,
		Sources:  map[artifact.Medium]sourceInput{},
	}
	inPlay := sourcesInPlay(sources)

	if sources.OCIArtifact != nil {
		specHash, err := artifact.ComputeOCIArtifactSpecHash(sources.OCIArtifact)
		if err != nil {
			return want, inPlay, err
		}
		// Local source changes may leave aggregate metadata stale without changing the OCI pin,
		// so the digest is only trusted when the metadata still describes this spec.
		expectedDigest := ""
		if artifact.ArtifactMetaCacheHit(rulesfile.Status.ArtifactMeta, specHash) {
			expectedDigest = rulesfile.Status.ArtifactMeta.Digest
		}
		want.Sources[artifact.MediumOCI] = sourceInput{
			SpecHash: specHash, ExpectedDigest: expectedDigest,
		}
	}

	if sources.InlineRules != nil {
		inlineData, err := common.JSONRawToYAML(sources.InlineRules)
		if err != nil {
			logger.Error(err, "unable to convert inline rules to YAML")
			rulesfileStoreFailures.recordFailure(recorderFor{node: n}, rulesfile, &status.Conditions, artifact.MediumInline, rulesfile.GetGeneration(), err)
			return want, inPlay, err
		}
		if inlineData != nil {
			want.Sources[artifact.MediumInline] = sourceInput{Content: []byte(*inlineData)}
		} else {
			// Declared but carrying no rules: not content to write, and not a withdrawal either.
			want.Retain = append(want.Retain, artifact.MediumInline)
		}
	}

	if sources.ConfigMap != nil {
		// Already read, because its bytes are an input to the hash that decided whether the
		// parent's metadata describes these sources at all.
		want.Sources[artifact.MediumConfigMap] = sourceInput{Content: sources.ConfigMap.Content}
	}

	return want, inPlay, nil
}

// reportRulesfileCompatibility asks the node whether this Rulesfile can be installed and puts the answer into
// this CR's conditions and events. It returns whether installation is blocked.
func (n *Node) reportRulesfileCompatibility(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, status *artifactv1alpha1.NodeArtifactStatus,
	sources *artifact.RulesfileSources, metadata *commonv1alpha1.ArtifactMeta,
) (bool, error) {
	gen := rulesfile.GetGeneration()
	logger := log.FromContext(ctx)
	key := artifact.RefOf(artifact.KindRulesfile, rulesfile)
	inPlay := sourcesInPlay(sources)

	if len(inPlay) == 0 {
		// The node is still asked to apply: removing an installed file also releases its
		// dependencies, so skipping here would leave files and registrations behind.
		logger.Info("Skipping compatibility check: no artifact sources configured")
		apimeta.RemoveStatusCondition(&status.Conditions, commonv1alpha1.ConditionDependenciesSatisfied.String())
		return false, nil
	}

	assessed, err := n.assess(key, metadata, n.enforceRequirements)
	if err != nil {
		msg := fmt.Sprintf("Unable to compare plugin versions: %s", err.Error())
		if compareErr, ok := errors.AsType[*compareError](err); ok && compareErr.Requirement != "" {
			logger.Error(err, "Unable to compare rulesfile requirement versions", "requirement", compareErr.Requirement)
			msg = fmt.Sprintf("Unable to compare %s versions: %s", compareErr.Requirement, err.Error())
		}
		apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionUnknown, artifact.ReasonDependenciesUnknown, msg, gen,
		))
		return false, err
	}

	switch assessed.State {
	case metadataMissing:
		// Missing or stale metadata is unknown in both modes; advise only changes whether we wait.
		apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionUnknown, artifact.ReasonArtifactMetaNotReady,
			"Waiting for artifact metadata matching the current sources", gen,
		))
	case metadataSilent:
		if !assessed.Blocked {
			logger.Info("Artifact declares no requirements; proceeding in advise mode")
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
		n.reportDeclaredDependencies(ctx, rulesfile, status, assessed, gen)
	}

	return assessed.Blocked, nil
}

// reportDeclaredDependencies words the requirements and dependencies the node found wanting. Requirements come
// first and, in enforce mode, the first unsatisfied one is the answer; in advise mode every one is
// reported and the dependencies are checked as well.
func (n *Node) reportDeclaredDependencies(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, status *artifactv1alpha1.NodeArtifactStatus,
	assessed assessment, gen int64,
) {
	logger := log.FromContext(ctx)

	for _, unmet := range assessed.Unmet {
		baseMsg := fmt.Sprintf(artifact.MessageFormatRequirementNotSatisfied, unmet.Name, unmet.Required, unmet.Provided)
		if !unmet.Found {
			// Covers both "Falco has never been observed yet" and "this requirement was never
			// reported". Treated as an expected, self-resolving state, not a hard error.
			baseMsg = fmt.Sprintf(artifact.MessageFormatRequirementMissing, unmet.Name, unmet.Required)
			logger.Info("Rulesfile requirement not found in Falco versions", "requirement", unmet.Name, "required", unmet.Required)
		} else {
			logger.Info("Rulesfile requirement not satisfied", "requirement", unmet.Name,
				"provided", unmet.Provided, "required", unmet.Required)
		}
		skip, reason, msg := artifact.DependenciesNotSatisfiedOutcome(n.enforceRequirements, assessed.AlreadyInstalled, baseMsg)
		recorderFor{node: n}.warnf(rulesfile, reason, "%s", msg)
		apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionFalse, reason, msg, gen,
		))
		if skip {
			return
		}
	}

	if len(assessed.UnmetDependencies) > 0 {
		unsatisfied := make([]string, 0, len(assessed.UnmetDependencies))
		for _, unmet := range assessed.UnmetDependencies {
			unsatisfied = append(unsatisfied, dependencyMessage(unmet))
		}
		baseMsg := strings.Join(unsatisfied, "; ")
		logger.Info("Rulesfile plugin dependencies not satisfied", "count", len(unsatisfied), "unsatisfied", unsatisfied)
		_, reason, msg := artifact.DependenciesNotSatisfiedOutcome(n.enforceRequirements, assessed.AlreadyInstalled, baseMsg)
		recorderFor{node: n}.warnf(rulesfile, reason, "%s", msg)
		apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionFalse, reason, msg, gen,
		))
		return
	}

	// Only mark satisfied when all requirements and dependencies passed. If a requirement was
	// unsatisfied the condition is already False above; don't clobber it.
	if len(assessed.Unmet) == 0 {
		logger.V(1).Info("All rulesfile requirements and dependencies satisfied")
		apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
			metav1.ConditionTrue, artifact.ReasonDependenciesSatisfied, artifact.MessageDependenciesSatisfied, gen,
		))
	}
}

// dependencyMessage words one unsatisfied dependency, listing the alternatives that would also
// have done when there are any.
func dependencyMessage(dependency commonv1alpha1.ArtifactMetaDependency) string {
	if len(dependency.Alternatives) == 0 {
		return fmt.Sprintf(artifact.MessageFormatDependencyNotSatisfied, dependency.Name, dependency.Version)
	}
	alternatives := make([]string, len(dependency.Alternatives))
	for i, alternative := range dependency.Alternatives {
		alternatives[i] = fmt.Sprintf("%s >= %s", alternative.Name, alternative.Version)
	}
	return fmt.Sprintf(artifact.MessageFormatDependencyNotSatisfiedWithAlternatives,
		dependency.Name, dependency.Version, strings.Join(alternatives, ", "))
}

// verifiedRulesfileMetadata returns metadata only when it describes this source snapshot.
// A nil result means unknown, not a verified absence of dependencies.
func verifiedRulesfileMetadata(rulesfile *artifactv1alpha1.Rulesfile, sources *artifact.RulesfileSources) (*commonv1alpha1.ArtifactMeta, error) {
	metadata := rulesfile.Status.ArtifactMeta
	if metadata == nil {
		return nil, nil
	}
	sourcesHash, err := sources.Hash()
	if err != nil {
		return nil, err
	}
	if rulesfile.Status.ArtifactMetaSourcesHash != sourcesHash {
		return nil, nil
	}
	if sources.OCIArtifact != nil {
		specHash, err := sources.OCISpecHash()
		if err != nil {
			return nil, err
		}
		validDigest := digest.Digest(metadata.Digest).Validate() == nil
		if !artifact.ArtifactMetaCacheHit(metadata, specHash) || !validDigest {
			return nil, nil
		}
	}
	return metadata, nil
}

// installRulesfile makes the node hold what the Rulesfile's sources describe, and reports what it
// did in this CR's conditions and events, for all three mediums at once.
func (n *Node) installRulesfile(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, status *artifactv1alpha1.NodeArtifactStatus,
	sources *artifact.RulesfileSources, metadata *commonv1alpha1.ArtifactMeta,
) error {
	logger := log.FromContext(ctx)
	gen := rulesfile.GetGeneration()

	want, inPlay, err := n.desiredRulesfile(ctx, rulesfile, status, sources, metadata)
	if err != nil {
		return err
	}

	key := artifact.RefOf(artifact.KindRulesfile, rulesfile)
	res, err := n.applySources(ctx, key, want)
	rulesfileStoreFailures.record(recorderFor{node: n}, rulesfile, &status.Conditions, gen, inPlay, res.Actions, res.Failed)
	if err != nil {
		// A dependency that went away between the check and the write is not a failure to
		// report and retry: it says so in the status and waits. A provider changing is what
		// wakes this artifact again, so there is nothing to requeue for.
		if dependencyErr, ok := errors.AsType[*dependencyError](err); ok {
			_, reason, message := artifact.DependenciesNotSatisfiedOutcome(
				n.enforceRequirements, n.Holds(key), dependencyErr.Error())
			apimeta.SetStatusCondition(&status.Conditions, common.NewDependenciesSatisfiedCondition(
				metav1.ConditionFalse, reason, message, rulesfile.Generation,
			))
			return nil
		}
		logger.Error(err, "unable to store rulesfile", "medium", res.Failed)
		rulesfileStoreFailures.recordApplyFailure(recorderFor{node: n}, rulesfile, &status.Conditions, inPlay, res.Failed, gen, err)
		return err
	}
	return nil
}

// resolveRulesfileSources resolves source inputs before compatibility checks or writes.
func (n *Node) resolveRulesfileSources(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, status *artifactv1alpha1.NodeArtifactStatus,
) (*artifact.RulesfileSources, error) {
	logger := log.FromContext(ctx)
	gen := rulesfile.GetGeneration()

	result, err := artifact.ResolveRulesfileSources(ctx, n.fetcher, rulesfile)
	if err != nil {
		logger.Error(err, "unable to fetch Rulesfile from ConfigMap reference")
		recorderFor{node: n}.warnf(rulesfile,
			artifact.ReasonConfigMapRulesStoreFailed, artifact.MessageFormatConfigMapRulesStoreFailed, err.Error())
		apimeta.SetStatusCondition(&status.Conditions, common.NewConfigMapArtifactProgrammedCondition(
			metav1.ConditionFalse, artifact.ReasonConfigMapArtifactProgramFailed,
			fmt.Sprintf(artifact.MessageFormatConfigMapRulesStoreFailed, err.Error()), gen,
		))
		return nil, err
	}
	return result, nil
}

func (n *Node) resolveRulesfileReferences(
	ctx context.Context, rulesfile *artifactv1alpha1.Rulesfile, status *artifactv1alpha1.NodeArtifactStatus,
) error {
	return resolveReferences(ctx, n.cl, n.recorder, rulesfile, &status.Conditions, rulesfile.Spec.ConfigMapRef)
}
