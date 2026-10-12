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

package shared

import (
	"context"

	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
)

// NewOCIManager returns the artifact Manager an aggregator pulls the OCI sources of namespace with. A nil
// ociPuller uses the default one.
func NewOCIManager(cl client.Client, namespace string, ociPuller puller.Puller) *artifact.Manager {
	var opts []artifact.ManagerOption
	if ociPuller != nil {
		opts = append(opts, artifact.WithOCIPuller(ociPuller))
	}
	return artifact.NewManagerWithOptions(cl, namespace, opts...)
}

// FetchConfigLayer fetches the config layer of obj's OCI source, at knownDigest when it is set, and records what it
// declares in meta: the digest the fetch resolved, and the requirements and dependencies. A failure is logged and
// recorded as a warning event on obj, and meta is left as it was.
func FetchConfigLayer(
	ctx context.Context, am *artifact.Manager, recorder events.EventRecorder, obj client.Object,
	source *commonv1alpha1.OCIArtifact, knownDigest string, meta *commonv1alpha1.ArtifactMeta,
) error {
	logger := log.FromContext(ctx)
	ref := artifact.ResolveReference(source)
	logger.Info("Fetching ArtifactMeta from OCI config layer", "ref", ref)
	fetched, digest, err := am.FetchConfig(ctx, source, knownDigest)
	if err != nil {
		logger.Error(err, "Unable to fetch OCI config; ArtifactMeta will remain stale", "ref", ref)
		artifact.RecordWarning(recorder, obj, artifact.ReasonOCIArtifactProgramFailed,
			"Failed to fetch OCI config layer: %s", err.Error())
		return err
	}
	meta.Digest = digest
	artifact.AppendConfigLayerRequirements(meta, fetched)
	logger.Info("ArtifactMeta parsed from OCI config layer",
		"ref", ref,
		"digest", digest,
		"requirements", len(meta.Requirements),
		"dependencies", len(meta.Dependencies),
	)
	return nil
}
