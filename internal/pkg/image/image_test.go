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

package image

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNameRef(t *testing.T) {
	tests := []struct {
		name      string
		registry  string
		namespace string
		image     Name
		tag       string
		want      string
	}{
		{name: "default", image: Falco, tag: "0.44.1", want: "docker.io/falcosecurity/falco:0.44.1"},
		{name: "custom registry with port and prefix", registry: "registry.example.com:5000/team/cache", image: ArtifactOperator, tag: "main", want: "registry.example.com:5000/team/cache/falcosecurity/artifact-operator:main"},
		{name: "custom namespace", registry: "registry.example.com", namespace: "mirror", image: Falcosidekick, tag: "2.32.0", want: "registry.example.com/mirror/falcosidekick:2.32.0"},
		{name: "Redis keeps its namespace", registry: "registry.example.com", namespace: "mirror", image: Redis, tag: "7.2.0-v11", want: "registry.example.com/redis/redis-stack:7.2.0-v11"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			previousRegistry, previousNamespace := Registry, Namespace
			t.Cleanup(func() { Registry, Namespace = previousRegistry, previousNamespace })
			require.NoError(t, SetRegistry(tt.registry))
			if tt.namespace != "" {
				Namespace = tt.namespace
			}
			require.Equal(t, tt.want, tt.image.Ref(tt.tag))
		})
	}
}

func TestSetRegistry(t *testing.T) {
	for _, tt := range []struct {
		name      string
		value     string
		want      string
		wantError bool
	}{
		{name: "empty preserves central value", want: "previous.example.com"},
		{name: "explicit upstream registry", value: "docker.io", want: "docker.io"},
		{name: "custom", value: "registry.example.com/team", want: "registry.example.com/team"},
		{name: "invalid preserves previous", value: "https://registry.example.com", want: "previous.example.com", wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			previous := Registry
			t.Cleanup(func() { Registry = previous })
			Registry = "previous.example.com"
			err := SetRegistry(tt.value)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, Registry)
		})
	}
}

func TestValidateRegistry(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		valid    bool
	}{
		{name: "disabled", valid: true},
		{name: "default registry", registry: "docker.io", valid: true},
		{name: "hostname", registry: "registry.example.com", valid: true},
		{name: "port and path", registry: "registry.example.com:5000/dockerhub/cache", valid: true},
		{name: "localhost", registry: "localhost:5000", valid: true},
		{name: "IPv6", registry: "[::1]:5000/dockerhub", valid: true},
		{name: "scheme", registry: "https://registry.example.com"},
		{name: "trailing slash", registry: "registry.example.com/"},
		{name: "missing host", registry: "/dockerhub"},
		{name: "unqualified repository", registry: "dockerhub/cache"},
		{name: "tag", registry: "registry.example.com/cache:latest"},
		{name: "digest", registry: "registry.example.com/cache@sha256:" + strings.Repeat("a", 64)},
		{name: "whitespace", registry: " registry.example.com"},
		{name: "uppercase path", registry: "registry.example.com/DockerHub"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegistry(tt.registry)
			if tt.valid {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "invalid image registry")
			}
		})
	}
}

func TestVersionFromImage(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name  string
		image string
		want  string
	}{
		{
			name:  "valid image with tag",
			image: "docker.io/falcosecurity/falco:0.1.0",
			want:  "0.1.0",
		},
		{
			name:  "image without tag",
			image: "docker.io/falcosecurity/falco",
			want:  "",
		},
		{
			name:  "empty string",
			image: "",
			want:  "",
		},
		{name: "registry port and tag", image: "registry.example.com:5000/falco:0.43.0", want: "0.43.0"},
		{name: "registry port without tag", image: "registry.example.com:5000/falco"},
		{name: "IPv6 registry and tag", image: "[::1]:5000/falco:0.43.0", want: "0.43.0"},
		{name: "IPv6 registry without tag", image: "[::1]:5000/falco"},
		{name: "digest without tag", image: "falcosecurity/falco@" + digest},
		{name: "tag and digest", image: "falcosecurity/falco:0.43.0@" + digest, want: "0.43.0"},
		{name: "registry port tag and digest", image: "registry.example.com:5000/falco:0.43.0@" + digest, want: "0.43.0"},
		{name: "SHA512 digest", image: "falco:0.43.0@sha512:" + strings.Repeat("a", 128), want: "0.43.0"},
		{name: "short name with floating tag", image: "falco:latest", want: "latest"},
		{name: "short name without tag", image: "falco"},
		{name: "tag spelling preserved", image: "falco:v0.5.0-rc3", want: "v0.5.0-rc3"},
		{name: "missing repository", image: ":v1"},
		{name: "invalid digest", image: "falco:0.43.0@sha256:123"},
		{name: "URL instead of image", image: "https://registry.example.com/falco:0.43.0"},
		{name: "whitespace", image: " falco:0.43.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VersionFromImage(tt.image)
			if got != tt.want {
				t.Errorf("VersionFromImage() = %v, want %v", got, tt.want)
			}
		})
	}
}
