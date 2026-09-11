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

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// saveSidecarEnv returns a cleanup func that restores the sidecar env to its state at call time.
func saveSidecarEnv(t *testing.T) {
	t.Helper()
	original := make([]corev1.EnvVar, len(FalcoDefaults.SidecarContainers[0].Env))
	copy(original, FalcoDefaults.SidecarContainers[0].Env)
	t.Cleanup(func() {
		FalcoDefaults.SidecarContainers[0].Env = original
	})
}

func TestFalcoDefaults_ShareProcessNamespace(t *testing.T) {
	if assert.NotNil(t, FalcoDefaults.ShareProcessNamespace, "ShareProcessNamespace must be set") {
		assert.True(t, *FalcoDefaults.ShareProcessNamespace,
			"ShareProcessNamespace must be true so the sidecar can find Falco's PID via /proc")
	}
}

func TestFalcoDefaults_SidecarRunsAsRoot(t *testing.T) {
	containers := FalcoDefaults.SidecarContainers
	assert.NotEmpty(t, containers, "at least one sidecar container must be defined")

	sidecar := containers[0]
	if assert.NotNil(t, sidecar.SecurityContext, "sidecar SecurityContext must be set") {
		if assert.NotNil(t, sidecar.SecurityContext.RunAsUser,
			"sidecar RunAsUser must be set to 0 so SIGHUP to root-owned Falco is permitted") {
			assert.Equal(t, int64(0), *sidecar.SecurityContext.RunAsUser,
				"sidecar must run as UID 0; non-root→root kill(2) is blocked on K8s 1.27+ with SeccompDefault")
		}
	}
}

func TestSetArtifactOperatorEnforceRequirements(t *testing.T) {
	t.Run("true is a no-op", func(t *testing.T) {
		saveSidecarEnv(t)
		before := len(FalcoDefaults.SidecarContainers[0].Env)
		SetArtifactOperatorEnforceRequirements(true)
		assert.Len(t, FalcoDefaults.SidecarContainers[0].Env, before)
	})

	t.Run("false injects ENFORCE_REQUIREMENTS=false", func(t *testing.T) {
		saveSidecarEnv(t)
		SetArtifactOperatorEnforceRequirements(false)
		env := FalcoDefaults.SidecarContainers[0].Env
		var found *corev1.EnvVar
		for i := range env {
			if env[i].Name == "ENFORCE_REQUIREMENTS" {
				found = &env[i]
				break
			}
		}
		if assert.NotNil(t, found, "ENFORCE_REQUIREMENTS env var should be present") {
			assert.Equal(t, "false", found.Value)
		}
	})
}
