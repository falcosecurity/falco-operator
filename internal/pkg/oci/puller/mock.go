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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"path/filepath"

	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falco-operator/internal/pkg/filesystem"
)

// MockOCIPuller implements Puller for testing.
type MockOCIPuller struct {
	// Result is returned on a successful pull. Must be set when PullErr is nil.
	Result *RegistryResult
	// PullErr is returned instead of pulling when set.
	PullErr error
	// InspectResult is returned on a successful inspect. Falls back to Result when nil.
	InspectResult *RegistryResult
	// InspectErr is returned instead of inspecting when set.
	InspectErr error
	// FS is the filesystem used to write the archive on a successful pull.
	// When set, Pull writes a minimal valid tar.gz archive to destDir/Result.Filename
	// so that the caller (e.g. Manager.StoreFromOCI) can open and extract it.
	FS           filesystem.FileSystem
	PullCalls    []PullCall
	InspectCalls []InspectCall
}

// PullCall records the arguments of a Pull invocation.
type PullCall struct {
	Ref     string
	DestDir string
	OS      string
	Arch    string
	Opts    *RegistryOptions
}

// InspectCall records the arguments of an Inspect invocation.
type InspectCall struct {
	Ref  string
	OS   string
	Arch string
	Opts *RegistryOptions
}

// Pull records the call and returns the preset result or error.
// When FS is set and Result is non-nil, it writes a minimal tar.gz archive to
// destDir/Result.Filename before returning so the full StoreFromOCI path can proceed.
func (m *MockOCIPuller) Pull(ctx context.Context, ref, destDir, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions) (*RegistryResult, error) {
	m.PullCalls = append(m.PullCalls, PullCall{Ref: ref, DestDir: destDir, OS: os, Arch: arch, Opts: opts})
	if m.PullErr != nil {
		return nil, m.PullErr
	}
	if m.Result == nil {
		return nil, fmt.Errorf("MockOCIPuller: Result is not set for ref %q", ref)
	}
	if m.FS != nil {
		archivePath := filepath.Join(destDir, m.Result.Filename)
		// Use "rules.yaml" as the inner file name so it differs from the archive
		// file name; the manager removes the archive after extraction, and having
		// the same name for both would cause the extracted file to be deleted too.
		data, err := MakeTarGz("rules.yaml", []byte("fake-rules-content"))
		if err != nil {
			return nil, fmt.Errorf("MockOCIPuller: failed to create fake archive: %w", err)
		}
		if err := m.FS.WriteFile(archivePath, data, 0o644); err != nil {
			return nil, fmt.Errorf("MockOCIPuller: failed to write archive to FS: %w", err)
		}
	}
	return m.Result, nil
}

// Inspect records the call and returns the preset inspect result or error.
func (m *MockOCIPuller) Inspect(ctx context.Context, ref, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions) (*RegistryResult, error) {
	m.InspectCalls = append(m.InspectCalls, InspectCall{Ref: ref, OS: os, Arch: arch, Opts: opts})
	if m.InspectErr != nil {
		return nil, m.InspectErr
	}
	if m.InspectResult != nil {
		return m.InspectResult, nil
	}
	if m.Result != nil {
		return m.Result, nil
	}
	return nil, fmt.Errorf("MockOCIPuller: InspectResult/Result is not set for ref %q", ref)
}

// MakeTarGz creates a minimal valid tar.gz archive containing a single file
// with the given name and content. Useful for seeding mock filesystems in tests.
func MakeTarGz(filename string, content []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Name: filename,
		Mode: 0o644,
		Size: int64(len(content)),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
