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

package mounts

const (
	// ConfigDirPath mount path for empty dir where Falco's configuration files are store by
	// the artifact-operator.
	ConfigDirPath = "/etc/falco/config.d"
	// ConfigMountName is the name of the volume mount for Falco's configuration files.
	ConfigMountName = "falco-configs"
	// RulesfileDirPath mount path for empty dir where Falco's rules files are stored by the
	// artifact-operator.
	RulesfileDirPath = "/etc/falco/rules.d"
	// RulefileMountName is the name of the volume mount for Falco's rules files.
	RulesfileMountName = "falco-rulesfiles"
)
