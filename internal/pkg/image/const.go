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

const (
	// Registry the default registry used for images.
	Registry = "docker.io"
	// Repository the default repository used for images.
	Repository = "falcosecurity"

	// FalcoImage the default image name used for Falco.
	FalcoImage = "falco"
	// FalcoTag the default tag used for Falco.
	FalcoTag = "0.41.0"

	// MetacollectorImage the default image name used for k8s-metacollector.
	MetacollectorImage = "k8s-metacollector"
	// MetacollectorTag the default tag used for k8s-metacollector.
	MetacollectorTag = "0.1.1"

	// FalcosidekickImage the default image name used for Falcosidekick.
	FalcosidekickImage = "falcosidekick"
	// FalcosidekickTag the default tag used for Falcosidekick.
	FalcosidekickTag = "2.32.0"

	// FalcosidekickUIImage the default image name used for Falcosidekick UI.
	FalcosidekickUIImage = "falcosidekick-ui"
	// FalcosidekickUITag the default tag used for Falcosidekick UI.
	FalcosidekickUITag = "2.2.0"

	// RedisRegistry the default registry used for Redis.
	RedisRegistry = "docker.io"
	// RedisRepository the default repository used for Redis.
	RedisRepository = "redis"
	// RedisImage the default image name used for Redis.
	RedisImage = "redis-stack"
	// RedisTag the default tag used for Redis.
	RedisTag = "7.2.0-v11"
)
