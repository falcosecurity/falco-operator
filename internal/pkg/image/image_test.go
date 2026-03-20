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
)

func TestBuildImageString(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		repo     string
		image    string
		tag      string
		want     string
	}{
		{
			name:     "basic image string",
			registry: "docker.io",
			repo:     "falcosecurity",
			image:    "falco",
			tag:      "latest",
			want:     "docker.io/falcosecurity/falco:latest",
		},
		{
			name:     "custom registry",
			registry: "custom.registry.io",
			repo:     "falcosecurity",
			image:    "falco",
			tag:      "0.1.0",
			want:     "custom.registry.io/falcosecurity/falco:0.1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildImageString(tt.registry, tt.repo, tt.image, tt.tag)
			if got != tt.want {
				t.Errorf("BuildImageString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildFalcoImageStringFromVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "empty version",
			version: "",
			want:    BuildImageString(Registry, Repository, FalcoImage, FalcoTag),
		},
		{
			name:    "specific version",
			version: "0.1.0",
			want:    BuildImageString(Registry, Repository, FalcoImage, "0.1.0"),
		},
		{
			name:    "version with prefix",
			version: "v0.1.0",
			want:    BuildImageString(Registry, Repository, FalcoImage, "v0.1.0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildFalcoImageStringFromVersion(tt.version)
			if got != tt.want {
				t.Errorf("BuildFalcoImageStringFromVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildMetacollectorImageStringFromVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "empty version uses default",
			version: "",
			want:    BuildImageString(Registry, Repository, MetacollectorImage, MetacollectorTag),
		},
		{
			name:    "specific version",
			version: "0.2.0",
			want:    BuildImageString(Registry, Repository, MetacollectorImage, "0.2.0"),
		},
		{
			name:    "version with prefix",
			version: "v0.2.0",
			want:    BuildImageString(Registry, Repository, MetacollectorImage, "v0.2.0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildMetacollectorImageStringFromVersion(tt.version)
			if got != tt.want {
				t.Errorf("BuildMetacollectorImageStringFromVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionFromTag(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		want string
	}{
		{
			name: "simple version",
			tag:  "0.43.0",
			want: "0.43.0",
		},
		{
			name: "version with suffix",
			tag:  "0.43.0-rc1",
			want: "0.43.0",
		},
		{
			name: "FalcoTag",
			tag:  FalcoTag,
			want: strings.Split(FalcoTag, "-")[0],
		},
		{
			name: "MetacollectorTag",
			tag:  MetacollectorTag,
			want: strings.Split(MetacollectorTag, "-")[0],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VersionFromTag(tt.tag)
			if got != tt.want {
				t.Errorf("VersionFromTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionFromImage(t *testing.T) {
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
