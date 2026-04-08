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

package puller

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/falcosecurity/falco-operator/internal/pkg/oci/client"
)

// Puller defines the interface for pulling OCI artifacts.
type Puller interface {
	Pull(ctx context.Context, ref, destDir, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions) (*RegistryResult, error)
	Inspect(ctx context.Context, ref, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions) (*RegistryResult, error)
}

// OciPuller implements the Puller interface for OCI artifacts.
// It holds optional default RegistryOptions that are used when no
// per-pull options are provided.
type OciPuller struct {
	defaults *RegistryOptions
}

// NewOciPuller creates a new puller with optional default registry options.
// Pass nil to use system defaults (HTTPS, system CAs).
func NewOciPuller(defaults *RegistryOptions) *OciPuller {
	return &OciPuller{defaults: defaults}
}

// Pull an artifact from a remote registry.
// Ref format follows: REGISTRY/REPO[:TAG|@DIGEST]. Ex. localhost:5000/hello:latest.
// When opts is non-nil it overrides the puller defaults entirely.
func (p *OciPuller) Pull(ctx context.Context, ref, destDir, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions) (*RegistryResult, error) {
	options := p.defaults
	if opts != nil {
		options = opts
	}

	fileStore, err := file.New(destDir)
	if err != nil {
		return nil, err
	}

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to create new repository with ref %s: %w", ref, err)
	}

	clientOpts := []client.Option{client.WithCredentialFunc(creds)}

	if options != nil {
		if options.InsecureSkipVerify {
			tlsConfig := &tls.Config{InsecureSkipVerify: options.InsecureSkipVerify} //nolint:gosec // user-configured
			httpTransport := &http.Transport{TLSClientConfig: tlsConfig}
			retryTransport := retry.NewTransport(httpTransport)
			clientOpts = append(clientOpts, client.WithTransport(retryTransport))
		}
		repo.PlainHTTP = options.PlainHTTP
	}

	repo.Client = client.NewClient(clientOpts...)

	// if no tag was specified, "latest" is used
	if repo.Reference.Reference == "" {
		ref += ":" + DefaultTag
		repo.Reference.Reference = DefaultTag
	}

	refDesc, _, err := repo.FetchReference(ctx, ref)
	if err != nil {
		return nil, err
	}

	copyOpts := oras.CopyOptions{}
	copyOpts.Concurrency = 1
	if refDesc.MediaType == v1.MediaTypeImageIndex {
		plt := &v1.Platform{
			OS:           os,
			Architecture: arch,
		}
		copyOpts.WithTargetPlatform(plt)
	}

	localTarget := oras.Target(fileStore)

	desc, err := oras.Copy(ctx, repo, ref, localTarget, ref, copyOpts)

	if err != nil {
		return nil, fmt.Errorf("unable to pull artifact %s with tag %s from repo %s: %w",
			repo.Reference.Repository, repo.Reference.Reference, repo.Reference.Repository, err)
	}

	manifest, err := manifestFromDesc(ctx, localTarget, &desc)
	if err != nil {
		return nil, err
	}

	artifactType, err := artifactTypeFromManifest(manifest)
	if err != nil {
		return nil, err
	}
	filename := artifactFilenameFromManifest(manifest)
	config, err := artifactConfigFromManifest(ctx, localTarget, manifest)
	if err != nil {
		return nil, err
	}

	return &RegistryResult{
		RootDigest: string(refDesc.Digest),
		Digest:     string(desc.Digest),
		Config:     config,
		Type:       artifactType,
		Filename:   filename,
	}, nil
}

// Inspect retrieves artifact metadata (type, config, filename, digests) without downloading layers.
func (p *OciPuller) Inspect(ctx context.Context, ref, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions) (*RegistryResult, error) {
	options := p.defaults
	if opts != nil {
		options = opts
	}

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to create new repository with ref %s: %w", ref, err)
	}

	clientOpts := []client.Option{client.WithCredentialFunc(creds)}

	if options != nil {
		if options.InsecureSkipVerify {
			tlsConfig := &tls.Config{InsecureSkipVerify: options.InsecureSkipVerify} //nolint:gosec // user-configured
			httpTransport := &http.Transport{TLSClientConfig: tlsConfig}
			retryTransport := retry.NewTransport(httpTransport)
			clientOpts = append(clientOpts, client.WithTransport(retryTransport))
		}
		repo.PlainHTTP = options.PlainHTTP
	}

	repo.Client = client.NewClient(clientOpts...)

	// if no tag was specified, "latest" is used
	if repo.Reference.Reference == "" {
		ref += ":" + DefaultTag
		repo.Reference.Reference = DefaultTag
	}

	rootDesc, _, err := repo.FetchReference(ctx, ref)
	if err != nil {
		return nil, err
	}

	manifestDesc, manifest, err := fetchManifestForPlatform(ctx, repo, ref, rootDesc, os, arch)
	if err != nil {
		return nil, err
	}

	artifactType, err := artifactTypeFromManifest(manifest)
	if err != nil {
		return nil, err
	}
	filename := artifactFilenameFromManifest(manifest)
	config, err := artifactConfigFromRepository(ctx, repo, manifest)
	if err != nil {
		return nil, err
	}

	return &RegistryResult{
		RootDigest: string(rootDesc.Digest),
		Digest:     string(manifestDesc.Digest),
		Config:     config,
		Type:       artifactType,
		Filename:   filename,
	}, nil
}

func manifestFromDesc(ctx context.Context, target oras.Target, desc *v1.Descriptor) (*v1.Manifest, error) {
	var manifest v1.Manifest

	descReader, err := target.Fetch(ctx, *desc)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch descriptor with digest %q: %w", desc.Digest, err)
	}
	defer descReader.Close()

	descBytes, err := io.ReadAll(descReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
	}

	if err = json.Unmarshal(descBytes, &manifest); err != nil {
		return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}

	if len(manifest.Layers) < 1 {
		return nil, fmt.Errorf("no layers in manifest")
	}

	return &manifest, nil
}

func manifestFromReader(reader io.Reader) (*v1.Manifest, error) {
	var manifest v1.Manifest

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read manifest bytes: %w", err)
	}

	if err = json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}

	if len(manifest.Layers) < 1 {
		return nil, fmt.Errorf("no layers in manifest")
	}

	return &manifest, nil
}

func artifactTypeFromManifest(manifest *v1.Manifest) (ArtifactType, error) {
	switch manifest.Layers[0].MediaType {
	case FalcoPluginLayerMediaType:
		return Plugin, nil
	case FalcoRulesfileLayerMediaType:
		return Rulesfile, nil
	case FalcoAssetLayerMediaType:
		return Asset, nil
	default:
		return "", fmt.Errorf("unknown media type: %q", manifest.Layers[0].MediaType)
	}
}

func artifactFilenameFromManifest(manifest *v1.Manifest) string {
	return manifest.Layers[0].Annotations[v1.AnnotationTitle]
}

func artifactConfigFromManifest(ctx context.Context, target oras.Target, manifest *v1.Manifest) (ArtifactConfig, error) {
	configReader, err := target.Fetch(ctx, manifest.Config)
	if err != nil {
		return ArtifactConfig{}, fmt.Errorf("unable to fetch config descriptor with digest %q: %w", manifest.Config.Digest, err)
	}
	defer configReader.Close()

	configBytes, err := io.ReadAll(configReader)
	if err != nil {
		return ArtifactConfig{}, fmt.Errorf("unable to read config bytes: %w", err)
	}

	var config ArtifactConfig
	if err = json.Unmarshal(configBytes, &config); err != nil {
		return ArtifactConfig{}, fmt.Errorf("unable to unmarshal artifact config: %w", err)
	}

	return config, nil
}

func artifactConfigFromRepository(ctx context.Context, repo *remote.Repository, manifest *v1.Manifest) (ArtifactConfig, error) {
	configReader, err := repo.Fetch(ctx, manifest.Config)
	if err != nil {
		return ArtifactConfig{}, fmt.Errorf("unable to fetch config descriptor with digest %q: %w", manifest.Config.Digest, err)
	}
	defer configReader.Close()

	configBytes, err := io.ReadAll(configReader)
	if err != nil {
		return ArtifactConfig{}, fmt.Errorf("unable to read config bytes: %w", err)
	}

	var config ArtifactConfig
	if err = json.Unmarshal(configBytes, &config); err != nil {
		return ArtifactConfig{}, fmt.Errorf("unable to unmarshal artifact config: %w", err)
	}

	return config, nil
}

func fetchManifestForPlatform(
	ctx context.Context,
	repo *remote.Repository,
	ref string,
	rootDesc v1.Descriptor,
	os, arch string,
) (v1.Descriptor, *v1.Manifest, error) {
	manifestDesc := rootDesc

	reader, err := repo.Fetch(ctx, rootDesc)
	if err != nil {
		return v1.Descriptor{}, nil, fmt.Errorf("unable to fetch descriptor with digest %q: %w", rootDesc.Digest, err)
	}
	defer reader.Close()

	if rootDesc.MediaType == v1.MediaTypeImageIndex {
		var index v1.Index
		indexBytes, err := io.ReadAll(reader)
		if err != nil {
			return v1.Descriptor{}, nil, fmt.Errorf("unable to read image index bytes: %w", err)
		}
		if err = json.Unmarshal(indexBytes, &index); err != nil {
			return v1.Descriptor{}, nil, fmt.Errorf("unable to unmarshal image index: %w", err)
		}

		found := false
		for _, candidate := range index.Manifests {
			if candidate.Platform == nil {
				continue
			}
			if candidate.Platform.OS == os && candidate.Platform.Architecture == arch {
				manifestDesc = candidate
				found = true
				break
			}
		}
		if !found {
			return v1.Descriptor{}, nil, fmt.Errorf("unable to find a manifest matching platform %s/%s for ref %q", os, arch, ref)
		}

		manifestReader, err := repo.Fetch(ctx, manifestDesc)
		if err != nil {
			return v1.Descriptor{}, nil, fmt.Errorf("unable to fetch platform-specific manifest with digest %q: %w", manifestDesc.Digest, err)
		}
		defer manifestReader.Close()

		manifest, err := manifestFromReader(manifestReader)
		if err != nil {
			return v1.Descriptor{}, nil, err
		}
		return manifestDesc, manifest, nil
	}

	manifest, err := manifestFromReader(reader)
	if err != nil {
		return v1.Descriptor{}, nil, err
	}
	return manifestDesc, manifest, nil
}
