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
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/falcosecurity/falco-operator/internal/pkg/oci/client"
)

// Puller defines the interface for pulling OCI artifacts.
type Puller interface {
	Pull(ctx context.Context, ref, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions, dst io.Writer) (*RegistryResult, error)
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
