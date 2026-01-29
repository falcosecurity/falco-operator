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

package puller

import (
	"context"

	"oras.land/oras-go/v2/registry/remote/auth"
)

// MockOCIPuller implements Puller for testing.
type MockOCIPuller struct {
	Result    *RegistryResult
	PullErr   error
	PullCalls []pullCall
}

type pullCall struct {
	ref     string
	destDir string
	os      string
	arch    string
}

// Pull records the call and returns the preset result or error.
func (m *MockOCIPuller) Pull(ctx context.Context, ref, destDir, os, arch string, creds auth.CredentialFunc) (*RegistryResult, error) {
	m.PullCalls = append(m.PullCalls, pullCall{ref: ref, destDir: destDir, os: os, arch: arch})
	if m.PullErr != nil {
		return nil, m.PullErr
	}
	return m.Result, nil
}
