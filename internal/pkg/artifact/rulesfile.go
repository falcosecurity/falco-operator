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

package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// RulesfileSources is the snapshot shared by metadata collection, compatibility checks and
// installation. A nil source is absent; a non-nil source may contain empty content.
// OCI is captured as a spec: its content must still be fetched at the resolved metadata digest.
// Callers must not modify the snapshot after checking its hash.
type RulesfileSources struct {
	OCIArtifact   *commonv1alpha1.OCIArtifact
	InlineRules   *apiextensionsv1.JSON
	ConfigMapName string
	ConfigMap     *FetchResult
}

// ResolveRulesfileSources captures the spec and resolves the ConfigMap once, without fetching
// OCI or writing files. Both operators use the same ConfigMap key validation and source hash.
// Copies detach the snapshot from the parent's spec and the fetcher's content buffer.
func ResolveRulesfileSources(ctx context.Context, fetcher ConfigMapFetcher,
	rulesfile *artifactv1alpha1.Rulesfile,
) (*RulesfileSources, error) {
	sources := &RulesfileSources{
		OCIArtifact: rulesfile.Spec.OCIArtifact.DeepCopy(),
		InlineRules: rulesfile.Spec.InlineRules.DeepCopy(),
	}
	if rulesfile.Spec.ConfigMapRef != nil {
		sources.ConfigMapName = rulesfile.Spec.ConfigMapRef.Name
		result, err := fetcher.FetchConfigMap(ctx, rulesfile.Namespace, rulesfile.Spec.ConfigMapRef, TypeRulesfile)
		if err != nil {
			return nil, fmt.Errorf("fetch ConfigMap %q: %w", sources.ConfigMapName, err)
		}
		result.Content = bytes.Clone(result.Content)
		sources.ConfigMap = &result
	}
	return sources, nil
}

// OCISpecHash identifies only the OCI input; local source changes must not refresh its tag.
func (s *RulesfileSources) OCISpecHash() (string, error) {
	if s.OCIArtifact == nil {
		return "", nil
	}
	return ComputeOCIArtifactSpecHash(s.OCIArtifact)
}

// Hash identifies every input to ArtifactMeta. Keep this encoding compatible with the hash
// already persisted by the instance operator; transport fields such as Perm are not inputs.
func (s *RulesfileSources) Hash() (string, error) {
	specHash, err := s.OCISpecHash()
	if err != nil {
		return "", fmt.Errorf("compute OCI spec hash: %w", err)
	}
	var configMapRules, inlineRules []byte
	if s.ConfigMap != nil {
		configMapRules = s.ConfigMap.Content
	}
	if s.InlineRules != nil {
		inlineRules = s.InlineRules.Raw
	}
	data, err := json.Marshal(struct {
		OCIArtifactSpecHash string `json:"ociArtifactSpecHash"`
		ConfigMapName       string `json:"configMapName"`
		ConfigMapConfigured bool   `json:"configMapConfigured"`
		ConfigMapRules      []byte `json:"configMapRules"`
		InlineConfigured    bool   `json:"inlineConfigured"`
		InlineRules         []byte `json:"inlineRules"`
	}{specHash, s.ConfigMapName, s.ConfigMap != nil, configMapRules, s.InlineRules != nil, inlineRules})
	if err != nil {
		return "", fmt.Errorf("marshal Rulesfile artifact metadata sources: %w", err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}
