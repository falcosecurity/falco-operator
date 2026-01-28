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

// Package version provides version information for the build.
package version

import (
	"fmt"
	"runtime"
)

var (
	// SemVersion indicates the semantic version of the build.
	SemVersion = "v0.0.0-master"

	// GitCommit indicates the git commit hash of the build.
	GitCommit = ""

	// BuildDate indicates the date when the build was created.
	BuildDate = "1970-01-01T00:00:00Z"

	// Compiler indicates the compiler used for the build.
	Compiler = runtime.Compiler

	// Platform indicates the operating system and architecture of the build.
	Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	// ArtifactOperatorImage indicates the artifact-operator container image.
	ArtifactOperatorImage = "docker.io/falcosecurity/artifact-operator:latest"
)
