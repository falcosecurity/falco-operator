// Copyright (C) 2025 The Falco Authors
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
	"encoding/json"
	"fmt"
	"io"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falco-operator/internal/pkg/oci/client"
)

// Puller defines the interface for pulling OCI artifacts.
type Puller interface {
	Pull(ctx context.Context, ref, destDir, os, arch string, creds auth.CredentialFunc) (*RegistryResult, error)
}

// OciPuller implements the Puller interface for OCI artifacts.
type OciPuller struct {
	plainHTTP bool
}

// NewOciPuller create a new puller that can be used for pull operations.
// The client is used as a template and is never modified directly.
func NewOciPuller(plainHTTP bool) *OciPuller {
	return &OciPuller{
		plainHTTP: plainHTTP,
	}
}

// Pull an artifact from a remote registry.
// Ref format follows: REGISTRY/REPO[:TAG|@DIGEST]. Ex. localhost:5000/hello:latest.
func (p *OciPuller) Pull(ctx context.Context, ref, destDir, os, arch string, creds auth.CredentialFunc) (*RegistryResult, error) {
	c := client.NewClient(client.WithCredentialFunc(creds))

	fileStore, err := file.New(destDir)
	if err != nil {
		return nil, err
	}

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to create new repository with ref %s: %w", ref, err)
	}

	repo.Client = c
	repo.PlainHTTP = p.plainHTTP

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

	var artifactType ArtifactType
	switch manifest.Layers[0].MediaType {
	case FalcoPluginLayerMediaType:
		artifactType = Plugin
	case FalcoRulesfileLayerMediaType:
		artifactType = Rulesfile
	case FalcoAssetLayerMediaType:
		artifactType = Asset
	default:
		return nil, fmt.Errorf("unknown media type: %q", manifest.Layers[0].MediaType)
	}

	filename := manifest.Layers[0].Annotations[v1.AnnotationTitle]

	return &RegistryResult{
		RootDigest: string(refDesc.Digest),
		Digest:     string(desc.Digest),
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
