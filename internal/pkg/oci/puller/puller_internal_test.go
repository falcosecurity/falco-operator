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
	"encoding/json"
	"fmt"
	"io"
	"testing"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	orascontent "oras.land/oras-go/v2/content"
)

type memoryDescriptorFetcher map[string][]byte

//nolint:gocritic // descriptorFetcher mirrors ORAS's Fetcher interface, which passes descriptors by value.
func (f memoryDescriptorFetcher) Fetch(_ context.Context, desc v1.Descriptor) (io.ReadCloser, error) {
	content, ok := f[desc.Digest.String()]
	if !ok {
		return nil, fmt.Errorf("descriptor %q not found", desc.Digest)
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

func (f memoryDescriptorFetcher) addJSON(t *testing.T, mediaType string, value any) v1.Descriptor {
	t.Helper()
	content, err := json.Marshal(value)
	require.NoError(t, err)
	desc := descriptorForContent(mediaType, content)
	f[desc.Digest.String()] = content
	return desc
}

func descriptorForContent(mediaType string, content []byte) v1.Descriptor {
	return orascontent.NewDescriptorFromBytes(mediaType, content)
}

func TestResolveConfigDescriptor_DirectManifest(t *testing.T) {
	fetcher := memoryDescriptorFetcher{}
	configDesc := descriptorForContent(FalcoPluginConfigMediaType, []byte(`{"name":"plugin"}`))
	rootDesc := fetcher.addJSON(t, v1.MediaTypeImageManifest, v1.Manifest{Config: configDesc})

	got, err := resolveConfigDescriptor(context.Background(), fetcher, "registry.example/plugin:1", &rootDesc)

	require.NoError(t, err)
	assert.Equal(t, configDesc, *got)
}

func TestResolveConfigDescriptor_IndexUsesFirstPlatformManifest(t *testing.T) {
	fetcher := memoryDescriptorFetcher{}
	configDesc := descriptorForContent(FalcoPluginConfigMediaType, []byte(`{"name":"plugin"}`))
	arm64 := fetcher.addJSON(t, v1.MediaTypeImageManifest, v1.Manifest{Config: configDesc})
	arm64.Platform = &v1.Platform{OS: "linux", Architecture: "arm64"}
	amd64 := descriptorForContent(v1.MediaTypeImageManifest, []byte("not fetched"))
	amd64.Platform = &v1.Platform{OS: "linux", Architecture: "amd64"}
	auxiliary := descriptorForContent(v1.MediaTypeImageManifest, []byte("not fetched"))
	unknownPlatform := descriptorForContent(v1.MediaTypeImageManifest, []byte("also not fetched"))
	unknownPlatform.Platform = &v1.Platform{OS: "unknown", Architecture: "unknown"}
	rootDesc := fetcher.addJSON(t, v1.MediaTypeImageIndex, v1.Index{
		Manifests: []v1.Descriptor{auxiliary, unknownPlatform, arm64, amd64},
	})

	got, err := resolveConfigDescriptor(context.Background(), fetcher, "registry.example/plugin:1", &rootDesc)

	require.NoError(t, err)
	assert.Equal(t, configDesc, *got)
}

func TestResolveConfigDescriptor_IndexRequiresPlatformManifest(t *testing.T) {
	fetcher := memoryDescriptorFetcher{}
	rootDesc := fetcher.addJSON(t, v1.MediaTypeImageIndex, v1.Index{
		Manifests: []v1.Descriptor{descriptorForContent(v1.MediaTypeImageManifest, []byte("auxiliary"))},
	})

	_, err := resolveConfigDescriptor(context.Background(), fetcher, "registry.example/plugin:1", &rootDesc)

	require.EqualError(t, err, `image index for "registry.example/plugin:1" has no platform manifests`)
}
