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
	"io"

	"oras.land/oras-go/v2/registry/remote/auth"
)

// MockOCIPuller implements Puller for testing.
type MockOCIPuller struct {
	// Result is returned on a successful pull. Must be set when PullErr is nil.
	Result *RegistryResult
	// PullErr is returned instead of pulling when set.
	PullErr error
	// AllowNilResult makes Pull return (nil, nil) when Result is nil.
	AllowNilResult bool
	// LayerContent is the raw layer payload (typically a tar.gz archive) copied to the
	// destination writer when PullErr is nil. If nil, the payload is empty.
	LayerContent []byte
	PullCalls    []PullCall
}

// PullCall records the arguments of a Pull invocation.
type PullCall struct {
	Ref  string
	OS   string
	Arch string
	Opts *RegistryOptions
}

// Pull records the call, writes LayerContent to dst, and returns the preset result.
func (m *MockOCIPuller) Pull(ctx context.Context, ref, os, arch string, creds auth.CredentialFunc, opts *RegistryOptions, dst io.Writer) (*RegistryResult, error) {
	m.PullCalls = append(m.PullCalls, PullCall{Ref: ref, OS: os, Arch: arch, Opts: opts})
	if m.PullErr != nil {
		return nil, m.PullErr
	}
	if m.Result == nil {
		if m.AllowNilResult {
			return nil, nil
		}
		return nil, fmt.Errorf("MockOCIPuller: Result is not set for ref %q", ref)
	}
	if _, err := dst.Write(m.LayerContent); err != nil {
		return nil, err
	}
	return m.Result, nil
}

// MakeTarGz creates a minimal valid tar.gz archive containing a single file
// with the given name and content. Useful for seeding mock pullers in tests.
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
