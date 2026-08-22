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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/falcosecurity/falco-operator/internal/pkg/common"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/client"
)

// Puller defines the interface for pulling OCI artifacts.
type Puller interface {
	Pull(ctx context.Context, ref, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions, dst io.Writer) (*RegistryResult, error)
	// FetchConfig retrieves only the OCI config layer for the given reference without downloading the artifact
	// binary. It returns the parsed ArtifactConfig and the resolved root digest (suitable as a cache key).
	FetchConfig(ctx context.Context, ref string, creds auth.CredentialFunc, opts *RegistryOptions) (*ArtifactConfig, string, error)
	// ResolveDigest resolves the current OCI manifest digest for ref without downloading any content.
	// It is a cheap HEAD-equivalent call suitable for cache validation.
	ResolveDigest(ctx context.Context, ref string, creds auth.CredentialFunc, opts *RegistryOptions) (string, error)
	// FetchContent downloads the content layer for ref and returns the extracted file bytes without writing to disk.
	// For rulesfile artifacts this is the raw YAML.
	FetchContent(ctx context.Context, ref string, creds auth.CredentialFunc, opts *RegistryOptions) ([]byte, error)
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

// Pull resolves ref to its artifact layer and copies the compressed layer payload into dst.
//
// Ref format follows: REGISTRY/REPO[:TAG|@DIGEST]. Ex. localhost:5000/hello:latest.
// When opts is non-nil it overrides the puller defaults entirely.
func (p *OciPuller) Pull(ctx context.Context, ref, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions, dst io.Writer) (*RegistryResult, error) {
	if dst == nil {
		return nil, fmt.Errorf("nil destination writer")
	}

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

	if repo.Reference.Reference == "" {
		repo.Reference.Reference = DefaultTag
	}
	copyRef := repo.Reference.String()

	refDesc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return nil, err
	}

	copyOpts := oras.CopyOptions{
		CopyGraphOptions: oras.CopyGraphOptions{Concurrency: 1},
	}
	if refDesc.MediaType == v1.MediaTypeImageIndex {
		copyOpts.WithTargetPlatform(&v1.Platform{OS: os, Architecture: arch})
	}

	localTarget := oras.Target(memory.New())
	desc, err := oras.Copy(ctx, repo, copyRef, localTarget, copyRef, copyOpts)
	if err != nil {
		return nil, fmt.Errorf("unable to pull artifact %s with tag %s from repo %s: %w",
			repo.Reference.Repository, repo.Reference.Reference, repo.Reference.Repository, err)
	}

	manifest, err := manifestFromDesc(ctx, localTarget, &desc)
	if err != nil {
		return nil, err
	}

	layerDesc := manifest.Layers[0]
	var artifactType ArtifactType
	switch layerDesc.MediaType {
	case FalcoPluginLayerMediaType:
		artifactType = Plugin
	case FalcoRulesfileLayerMediaType:
		artifactType = Rulesfile
	case FalcoAssetLayerMediaType:
		artifactType = Asset
	default:
		return nil, fmt.Errorf("unknown media type: %q", layerDesc.MediaType)
	}

	layerReader, err := localTarget.Fetch(ctx, layerDesc)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch layer for %s: %w", ref, err)
	}
	if err := copyAndClose(dst, layerReader); err != nil {
		return nil, fmt.Errorf("unable to read layer for %s: %w", ref, err)
	}

	return &RegistryResult{
		RootDigest: string(refDesc.Digest),
		Digest:     string(desc.Digest),
		Type:       artifactType,
		Filename:   layerDesc.Annotations[v1.AnnotationTitle],
	}, nil
}

func manifestFromDesc(ctx context.Context, target oras.Target, desc *v1.Descriptor) (*v1.Manifest, error) {
	descReader, err := target.Fetch(ctx, *desc)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch descriptor with digest %q: %w", desc.Digest, err)
	}

	descBytes, err := readAndClose(descReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
	}

	var manifest v1.Manifest
	if err := json.Unmarshal(descBytes, &manifest); err != nil {
		return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}
	if len(manifest.Layers) < 1 {
		return nil, fmt.Errorf("no layers in manifest")
	}

	return &manifest, nil
}

func readAndClose(reader io.ReadCloser) ([]byte, error) {
	data, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return data, nil
}

func copyAndClose(dst io.Writer, reader io.ReadCloser) error {
	_, copyErr := io.Copy(dst, reader)
	closeErr := reader.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// FetchConfig retrieves only the OCI config layer (manifest.Config) for ref without
// downloading the artifact binary layers. It returns the parsed ArtifactConfig and
// the root manifest digest, which callers may use as a stable cache key.
func (p *OciPuller) FetchConfig(ctx context.Context, ref string, creds auth.CredentialFunc, opts *RegistryOptions) (*ArtifactConfig, string, error) {
	options := p.defaults
	if opts != nil {
		options = opts
	}

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, "", fmt.Errorf("unable to create repository for %q: %w", ref, err)
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

	if repo.Reference.Reference == "" {
		repo.Reference.Reference = DefaultTag
	}

	rootDesc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return nil, "", fmt.Errorf("unable to resolve %q: %w", ref, err)
	}

	manifestDesc := rootDesc
	if rootDesc.MediaType == v1.MediaTypeImageIndex {
		indexBytes, err := fetchBytes(ctx, repo, &rootDesc)
		if err != nil {
			return nil, "", fmt.Errorf("unable to fetch image index for %q: %w", ref, err)
		}
		var index v1.Index
		if err := json.Unmarshal(indexBytes, &index); err != nil {
			return nil, "", fmt.Errorf("unable to parse image index for %q: %w", ref, err)
		}
		if len(index.Manifests) == 0 {
			return nil, "", fmt.Errorf("image index for %q has no manifests", ref)
		}
		manifestDesc = index.Manifests[0]
	}

	manifestBytes, err := fetchBytes(ctx, repo, &manifestDesc)
	if err != nil {
		return nil, "", fmt.Errorf("unable to fetch manifest for %q: %w", ref, err)
	}
	var manifest v1.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, "", fmt.Errorf("unable to parse manifest for %q: %w", ref, err)
	}

	configBytes, err := fetchBytes(ctx, repo, &manifest.Config)
	if err != nil {
		return nil, "", fmt.Errorf("unable to fetch config for %q: %w", ref, err)
	}
	var config ArtifactConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return nil, "", fmt.Errorf("unable to parse config for %q: %w", ref, err)
	}

	return &config, string(rootDesc.Digest), nil
}

// ResolveDigest resolves the current OCI manifest digest for ref without downloading any content.
func (p *OciPuller) ResolveDigest(ctx context.Context, ref string, creds auth.CredentialFunc, opts *RegistryOptions) (string, error) {
	options := p.defaults
	if opts != nil {
		options = opts
	}

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return "", fmt.Errorf("unable to create repository for %q: %w", ref, err)
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

	if repo.Reference.Reference == "" {
		repo.Reference.Reference = DefaultTag
	}

	desc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return "", fmt.Errorf("unable to resolve %q: %w", ref, err)
	}

	return string(desc.Digest), nil
}

// FetchContent downloads the artifact content layer for ref and returns the extracted file bytes.
// For rulesfile artifacts the layer is a tar.gz archive containing a single YAML file.
func (p *OciPuller) FetchContent(ctx context.Context, ref string, creds auth.CredentialFunc, opts *RegistryOptions) ([]byte, error) {
	var compressed bytes.Buffer
	if _, err := p.Pull(ctx, ref, runtime.GOOS, runtime.GOARCH, creds, opts, &compressed); err != nil {
		return nil, fmt.Errorf("pull content for %q: %w", ref, err)
	}
	file, err := common.ExtractSingleFileFromTarGz(ctx, &compressed, 0)
	if err != nil {
		return nil, fmt.Errorf("extract content for %q: %w", ref, err)
	}
	return file.Content, nil
}

// fetchBytes fetches the content of desc from target and returns it as a byte slice.
func fetchBytes(ctx context.Context, target interface {
	Fetch(context.Context, v1.Descriptor) (io.ReadCloser, error)
}, desc *v1.Descriptor) ([]byte, error) {
	r, err := target.Fetch(ctx, *desc)
	if err != nil {
		return nil, err
	}
	return readAndClose(r)
}
