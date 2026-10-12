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
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// metadataState is what the node could make of an artifact's declared requirements.
type metadataState int

const (
	// metadataMissing means no metadata describes this artifact yet. The instance operator has
	// not resolved it, or what it resolved does not describe the sources the node just saw. It
	// is not the same as declaring nothing: nothing is known either way.
	metadataMissing metadataState = iota
	// metadataSilent means metadata exists and declares neither requirements nor dependencies.
	// In enforce mode that is treated as unknown rather than satisfied, because an artifact that
	// should have declared something and did not is indistinguishable from one that genuinely
	// needs nothing.
	metadataSilent
	// metadataDeclared means there is something to check, and the assessment says how it went.
	metadataDeclared
)

// unmetRequirement is a capability Falco does not provide at the version an artifact asked for.
type unmetRequirement struct {
	// Name is the capability, e.g. engine_version_semver or a plugin name.
	Name string
	// Required is the minimum version asked for.
	Required string
	// Provided is what Falco reports, empty when Found is false.
	Provided string
	// Found distinguishes "Falco reports this capability at an incompatible version" from
	// "Falco has not reported it at all", which also covers Falco not having been observed yet.
	// Both resolve on their own once the next observation lands, so neither is an error.
	Found bool
}

// assessment is what the node makes of one artifact's requirements, in facts rather than words.
// The kind's flow turns it into conditions and events, because the wording belongs to the CR's API.
type assessment struct {
	// State is what could be made of the metadata at all.
	State metadataState
	// Unmet are the requirements Falco does not satisfy, in the order they were declared.
	Unmet []unmetRequirement
	// UnmetDependencies are the dependencies nothing on the node provides.
	UnmetDependencies []commonv1alpha1.ArtifactMetaDependency
	// AlreadyInstalled is whether the node holds this artifact right now. It is what decides
	// whether an unsatisfied requirement rejects an update or blocks a first install.
	AlreadyInstalled bool
	// Blocked is whether installation must not proceed. It follows from the mode: in advise
	// mode nothing blocks, and in enforce mode anything unresolved does.
	Blocked bool
}

// compareError means two declared versions could not be compared. It is a fault in the data an
// artifact declared, not an unmet requirement, and names what was being compared so the caller can
// say so: a capability the artifact requires, or, when Requirement is empty, a plugin dependency.
type compareError struct {
	Requirement string
	Err         error
}

func (e *compareError) Error() string { return e.Err.Error() }

func (e *compareError) Unwrap() error { return e.Err }

// assess decides whether the node can install key as metadata describes, from Falco's reported
// capabilities and the providers already on the node. It touches nothing: a blocked assessment
// leaves whatever is installed exactly as it was.
//
// An error means two versions could not be compared, which is a fault in the declared data rather
// than an unmet requirement, and is the one outcome a caller should retry.
func (n *Node) assess(key artifact.Ref, metadata *commonv1alpha1.ArtifactMeta, enforce bool) (assessment, error) {
	assessed := assessment{AlreadyInstalled: len(n.GetInstalled(key)) > 0}

	if metadata == nil {
		assessed.State = metadataMissing
		assessed.Blocked = enforce
		return assessed, nil
	}
	if len(metadata.Requirements) == 0 && len(metadata.Dependencies) == 0 {
		assessed.State = metadataSilent
		assessed.Blocked = enforce
		return assessed, nil
	}

	assessed.State = metadataDeclared
	for _, requirement := range metadata.Requirements {
		provided, found, satisfied, err := n.checkRequirement(requirement.Name, requirement.Version)
		if err != nil {
			return assessed, &compareError{Requirement: requirement.Name, Err: err}
		}
		if found && satisfied {
			continue
		}
		assessed.Unmet = append(assessed.Unmet, unmetRequirement{
			Name:     requirement.Name,
			Required: requirement.Version,
			Provided: provided,
			Found:    found,
		})
	}

	for _, dependency := range metadata.Dependencies {
		_, _, satisfied, err := n.checkDependency(dependency)
		if err != nil {
			return assessed, &compareError{Err: err}
		}
		if !satisfied {
			assessed.UnmetDependencies = append(assessed.UnmetDependencies, dependency)
		}
	}

	if len(assessed.Unmet) > 0 || len(assessed.UnmetDependencies) > 0 {
		assessed.Blocked, _, _ = artifact.DependenciesNotSatisfiedOutcome(enforce, assessed.AlreadyInstalled, "")
	}
	return assessed, nil
}
