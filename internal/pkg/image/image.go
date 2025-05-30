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

package image

import (
	"fmt"
	"strings"
)

// BuildImageString constructs the image string from registry, repository, image, and tag.
func BuildImageString(registry, repository, image, tag string) string {
	return fmt.Sprintf("%s/%s/%s:%s", registry, repository, image, tag)
}

// BuildFalcoImageStringFromVersion constructs the image string for Falco.
func BuildFalcoImageStringFromVersion(version string) string {
	if version == "" {
		return BuildImageString(Registry, Repository, FalcoImage, FalcoTag)
	}

	return fmt.Sprintf("%s/%s/%s:%s", Registry, Repository, FalcoImage, version)
}

// FalcoVersion returns the version of Falco specified in the FalcoTag.
func FalcoVersion() string {
	return strings.Split(FalcoTag, "-")[0]
}

// VersionFromImage returns the version from the image string.
func VersionFromImage(image string) string {
	parts := strings.Split(image, ":")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}
