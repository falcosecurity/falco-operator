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
	"fmt"
	"runtime"

	"sigs.k8s.io/controller-runtime/pkg/log"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/credentials"
)

// EnsureBlob ensures the OCI binary for ociArt/platform is present in the blob cache.
// If the blob already exists (digest + platform match), the path is returned immediately.
// Otherwise the binary is pulled from the registry, extracted, and written atomically.
//
// Pass knownDigest when the caller already resolved the digest (e.g. from
// Status.ArtifactMeta.Digest set by fetchAndCacheArtifactMeta) to skip the
// redundant ResolveDigest registry call. Pass an empty string to resolve it here.
//
// For platform-specific artifacts (plugins) supply goos and goarch; for platform-agnostic
// artifacts (rulesfiles) pass empty strings. The pull still uses the server's own platform
// to satisfy the puller API, but the cached blob has no platform suffix.
func (am *Manager) EnsureBlob(ctx context.Context, ociArt *commonv1alpha1.OCIArtifact, artifactType Type,
	goos, goarch string, cache *artifactcache.Cache, knownDigest string,
) (string, error) {
	logger := log.FromContext(ctx)

	secretRef := authSecretRef(ociArt)
	authSecret, err := am.fetchOCIAuthSecret(ctx, secretRef)
	if err != nil {
		return "", fmt.Errorf("fetch auth secret: %w", err)
	}
	creds, err := credentials.FromSecret(ResolveRegistryHost(ociArt), authSecret)
	if err != nil {
		return "", fmt.Errorf("derive credentials: %w", err)
	}

	ref := ResolveReference(ociArt)
	opts := ResolveRegistryOptions(ociArt)

	digest := knownDigest
	if digest == "" {
		digest, err = am.ociPuller.ResolveDigest(ctx, ref, creds, opts)
		if err != nil {
			return "", fmt.Errorf("resolve digest for %q: %w", ref, err)
		}
	}

	blobPath := artifactcache.BlobPath(cache.Dir(), string(artifactType), ref, digest, goos, goarch)

	if cache.BlobExists(blobPath) {
		logger.V(2).Info("Blob already cached", "ref", ref, "digest", digest, "blob", blobPath)
		return blobPath, nil
	}

	pullGOOS, pullGOARCH := goos, goarch
	if pullGOOS == "" || pullGOARCH == "" {
		pullGOOS, pullGOARCH = runtime.GOOS, runtime.GOARCH
	}

	logger.Info("Pulling OCI blob", "ref", ref, "os", pullGOOS, "arch", pullGOARCH)

	var buf bytes.Buffer
	res, err := am.ociPuller.Pull(ctx, ref, pullGOOS, pullGOARCH, creds, opts, &buf)
	if err != nil {
		return "", fmt.Errorf("pull %q (%s/%s): %w", ref, pullGOOS, pullGOARCH, err)
	}
	if res == nil {
		return "", fmt.Errorf("puller returned nil result for %q", ref)
	}
	if !isExpectedOCIArtifactType(artifactType, res.Type) {
		return "", fmt.Errorf("pulled OCI artifact type %q does not match expected %q", res.Type, artifactType)
	}

	file, err := common.ExtractSingleFileFromTarGz(ctx, &buf, 0)
	if err != nil {
		return "", fmt.Errorf("extract from OCI layer %q: %w", ref, err)
	}

	if err := artifactcache.Store(blobPath, file.Content, file.Perm); err != nil {
		return "", err
	}

	logger.Info("OCI blob cached", "ref", ref, "digest", digest, "blob", blobPath)
	return blobPath, nil
}
