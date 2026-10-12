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

	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
)

// configStoreFailures is what a Config calls a failed store of each of its sources.
var configStoreFailures = storeFailures{
	artifact.MediumInline: {
		reason: artifact.ReasonInlineConfigStoreFailed,
		format: artifact.MessageFormatConfigStoreFailed,
	},
	artifact.MediumConfigMap: {
		reason: artifact.ReasonConfigMapConfigStoreFailed,
		format: artifact.MessageFormatConfigMapConfigStoreFailed,
	},
}

// applyConfig installs one Config. It is the simplest of the three: a Config has no OCI source,
// so nothing is fetched from the artifact server, and it declares no requirements, so there is
// nothing to assess: its sources are written as soon as their references resolve.
func (n *Node) applyConfig(ctx context.Context, config *artifactv1alpha1.Config, status *artifactv1alpha1.NodeArtifactStatus) error {
	if err := n.resolveConfigReferences(ctx, config, status); err != nil {
		return err
	}
	if n.awaitObservedGeneration(ctx, config.Status.ObservedGeneration, config.Generation) {
		return nil
	}

	logger := log.FromContext(ctx)
	generation := config.GetGeneration()
	recorder := recorderFor{node: n}
	key := artifact.RefOf(artifact.KindConfig, config)

	want := desired{
		Priority: config.Spec.Priority,
		Sources:  map[artifact.Medium]sourceInput{},
	}
	inPlay := map[artifact.Medium]bool{}

	// spec.config is stored as JSON by the API server; it is written to disk as YAML. A
	// present-but-empty spec.config is neither content to write nor a withdrawal, so that source
	// is retained: its installed file stays, and it is still reported as programmed.
	if config.Spec.Config != nil {
		inPlay[artifact.MediumInline] = true
		configData, err := common.JSONRawToYAML(config.Spec.Config)
		if err != nil {
			logger.Error(err, "unable to convert inline config to YAML")
			configStoreFailures.recordFailure(recorder, config, &status.Conditions, artifact.MediumInline, generation, err)
			return err
		}
		if configData != nil {
			want.Sources[artifact.MediumInline] = sourceInput{Content: []byte(*configData)}
		} else {
			want.Retain = append(want.Retain, artifact.MediumInline)
		}
	}
	if config.Spec.ConfigMapRef != nil {
		inPlay[artifact.MediumConfigMap] = true
		fetched, err := n.fetcher.FetchConfigMap(ctx, config.Namespace, config.Spec.ConfigMapRef, artifact.KindConfig)
		if err != nil {
			logger.Error(err, "unable to read config ConfigMap", "configMap", config.Spec.ConfigMapRef.Name)
			configStoreFailures.recordFailure(recorder, config, &status.Conditions, artifact.MediumConfigMap, generation, err)
			return err
		}
		want.Sources[artifact.MediumConfigMap] = sourceInput{Content: fetched.Content}
	}

	res, err := n.applySources(ctx, key, want)
	configStoreFailures.record(recorder, config, &status.Conditions, generation, inPlay, res.Actions, res.Failed)
	if err != nil {
		logger.Error(err, "unable to store config", "medium", res.Failed)
		configStoreFailures.recordApplyFailure(recorder, config, &status.Conditions, inPlay, res.Failed, generation, err)
		return err
	}
	return nil
}

// resolveConfigReferences checks that everything the Config points at exists before anything is written.
func (n *Node) resolveConfigReferences(ctx context.Context, config *artifactv1alpha1.Config, status *artifactv1alpha1.NodeArtifactStatus) error {
	return resolveReferences(ctx, n.cl, n.recorder, config, &status.Conditions, config.Spec.ConfigMapRef)
}
