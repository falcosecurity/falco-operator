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

package nodeartifacts

import (
	"context"
	"fmt"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// StoreConfig writes one Config source using the installed cache as the current state.
// The shared plugin configuration is managed separately by AddPluginConfig.
func (m *Manager) StoreConfig(ctx context.Context, namespace, name string, artifactPriority int32,
	medium artifact.Medium, result artifact.FetchResult) (artifact.StoreAction, *artifact.File, error) {
	if name == pluginConfigFileName && artifactPriority == priority.MaxPriority && medium == artifact.MediumInline {
		return artifact.StoreActionNone, nil, fmt.Errorf("config path is reserved for the shared plugin configuration")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.storeLocked(ctx, namespace, name, artifactPriority, artifact.TypeConfig, medium, result)
}
