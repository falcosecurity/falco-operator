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

// Registry and Namespace are read by Name.Ref when workloads are generated, so setting them at
// startup is enough to affect every default image. Do not change them concurrently.
var (
	Registry  = DefaultRegistry
	Namespace = DefaultNamespace
)

// DefaultRegistry is the upstream registry for generated images.
const DefaultRegistry = "docker.io"

// DefaultNamespace is the upstream namespace for generated images.
const DefaultNamespace = "falcosecurity"

// Name identifies an image the operators deploy by default.
type Name string

const (
	// Falco the image used for Falco.
	Falco Name = "falco"
	// ArtifactOperator the image used for the artifact-operator sidecar.
	ArtifactOperator Name = "artifact-operator"
	// Metacollector the image used for k8s-metacollector.
	Metacollector Name = "k8s-metacollector"
	// Falcosidekick the image used for Falcosidekick.
	Falcosidekick Name = "falcosidekick"
	// FalcosidekickUI the image used for Falcosidekick UI.
	FalcosidekickUI Name = "falcosidekick-ui"
	// Redis the image used for Redis. It is not published under Namespace.
	Redis Name = "redis-stack"
)

const (
	// FalcoTag the default tag used for Falco.
	FalcoTag = "0.44.1"
	// MetacollectorTag the default tag used for k8s-metacollector.
	MetacollectorTag = "0.1.2"
	// FalcosidekickTag the default tag used for Falcosidekick.
	FalcosidekickTag = "2.32.0"
	// FalcosidekickUITag the default tag used for Falcosidekick UI.
	FalcosidekickUITag = "2.2.0"

	// RedisNamespace the namespace used for Redis.
	RedisNamespace = "redis"
	// RedisTag the default tag used for Redis.
	RedisTag = "7.2.0-v11"
)
