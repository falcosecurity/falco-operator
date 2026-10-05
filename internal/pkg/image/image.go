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
	_ "crypto/sha256" // Register digest algorithms used in image references.
	_ "crypto/sha512"
	"fmt"

	"github.com/distribution/reference"
)

// Ref composes the reference of the image with the given tag, using the registry and namespace
// configured at startup. An empty Name yields an empty reference.
func (n Name) Ref(tag string) string {
	if n == "" {
		return ""
	}
	namespace := Namespace
	if n == Redis {
		namespace = RedisNamespace
	}
	return Registry + "/" + namespace + "/" + string(n) + ":" + tag
}

// SetRegistry overrides the registry before starting controllers. Empty keeps the package default.
func SetRegistry(value string) error {
	if value == "" {
		return nil
	}
	if err := ValidateRegistry(value); err != nil {
		return err
	}
	Registry = value
	return nil
}

// ValidateRegistry checks a registry host with an optional port and repository prefix.
func ValidateRegistry(registry string) error {
	if registry == "" {
		return nil
	}
	if _, err := reference.ParseNamed(registry + "/library/image"); err != nil {
		return fmt.Errorf("invalid image registry %q: %w", registry, err)
	}
	return nil
}

// VersionFromImage returns the explicit image tag, or empty if absent or invalid.
func VersionFromImage(image string) string {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return ""
	}
	if tagged, ok := named.(reference.Tagged); ok {
		return tagged.Tag()
	}
	return ""
}
