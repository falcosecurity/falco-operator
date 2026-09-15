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
	"path/filepath"

	corev1 "k8s.io/api/core/v1"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// StorePlugin checks installed ownership before replacing a plugin's binary.
func (m *Manager) StorePlugin(ctx context.Context, plugin *artifactv1alpha1.Plugin,
	result artifact.FetchResult) (artifact.StoreAction, *artifact.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkPluginOwnershipLocked(plugin); err != nil {
		return artifact.StoreActionNone, nil, err
	}
	return m.storeLocked(ctx, plugin.Namespace, plugin.Name, priority.DefaultPriority, artifact.TypePlugin, artifact.MediumOCI, result)
}

// ResolveConfigName returns the canonical plugin name used by Falco and referenced in a
// Rulesfile's dependency list. Prefers spec.config.name (explicit override) over the CR's
// metadata.name, which may be an arbitrary Kubernetes identifier.
func ResolveConfigName(plugin *artifactv1alpha1.Plugin) string {
	if plugin.Spec.Config != nil && plugin.Spec.Config.Name != "" {
		return plugin.Spec.Config.Name
	}
	return plugin.Name
}

func (m *Manager) installedPluginNameLocked(plugin *artifactv1alpha1.Plugin) string {
	owner := pluginOwner(plugin)
	for _, config := range m.pluginsConfig.Configs {
		if m.pluginConfigOwners[config.Name] == owner {
			return config.Name
		}
	}
	return ""
}

func (m *Manager) checkPluginOwnershipLocked(plugin *artifactv1alpha1.Plugin) error {
	owner := pluginOwner(plugin)
	name := ResolveConfigName(plugin)
	for _, config := range m.pluginsConfig.Configs {
		existing := m.pluginConfigOwners[config.Name]
		if existing != owner && (config.Name == name || (existing.Namespace == owner.Namespace && existing.Name == owner.Name)) {
			return fmt.Errorf("installed plugin %q belongs to %s/%s (UID %s)", config.Name, existing.Namespace, existing.Name, existing.UID)
		}
		if existing == owner && config.Name != name {
			if blocked := m.blockedByOthersLocked(config.Name); blocked != nil {
				return blocked
			}
		}
	}
	return nil
}

func (m *Manager) pluginFilesReferencedLocked(files []artifactv1alpha1.InstalledArtifact) bool {
	for _, config := range m.pluginsConfig.Configs {
		for _, file := range files {
			if filepath.Clean(config.LibraryPath) == filepath.Clean(file.Path) {
				return true
			}
		}
	}
	return false
}

func pluginOwner(plugin *artifactv1alpha1.Plugin) corev1.ObjectReference {
	return corev1.ObjectReference{Namespace: plugin.Namespace, Name: plugin.Name, UID: plugin.UID}
}
