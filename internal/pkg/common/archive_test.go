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

package common

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io/fs"
	"strings"
	"testing"
)

func TestExtractSingleFileFromTarGz(t *testing.T) {
	tests := []struct {
		name     string
		entries  []tarGzEntry
		strip    int
		wantData string
		wantMode fs.FileMode
		wantErr  string
	}{
		{
			name: "extracts the only regular file",
			entries: []tarGzEntry{
				{name: "rules.yaml", mode: 0o640, body: "rules-content"},
			},
			wantData: "rules-content",
			wantMode: 0o640,
		},
		{
			name: "allows directory packaging around the single regular file",
			entries: []tarGzEntry{
				{name: "rules", typ: tar.TypeDir, mode: 0o755},
				{name: "rules/falco_rules.yaml", mode: 0o600, body: "packaged-rules"},
			},
			wantData: "packaged-rules",
			wantMode: 0o600,
		},
		{
			name: "applies strip path components",
			entries: []tarGzEntry{
				{name: "pkg/rules.yaml", mode: 0o644, body: "stripped-rules"},
			},
			strip:    1,
			wantData: "stripped-rules",
			wantMode: 0o644,
		},
		{
			name: "rejects archives without regular files",
			entries: []tarGzEntry{
				{name: "rules", typ: tar.TypeDir, mode: 0o755},
			},
			wantErr: "no regular file found",
		},
		{
			name: "rejects archives with multiple regular files",
			entries: []tarGzEntry{
				{name: "rules.yaml", mode: 0o644, body: "first"},
				{name: "extra.yaml", mode: 0o644, body: "second"},
			},
			wantErr: "multiple regular files",
		},
		{
			name: "rejects symbolic links",
			entries: []tarGzEntry{
				{name: "rules.yaml", typ: tar.TypeSymlink, linkname: "target.yaml"},
			},
			wantErr: "symbolic links are not allowed",
		},
		{
			name: "rejects hard links",
			entries: []tarGzEntry{
				{name: "rules.yaml", typ: tar.TypeLink, linkname: "target.yaml"},
			},
			wantErr: "hard links are not allowed",
		},
		{
			name: "rejects relative path escapes",
			entries: []tarGzEntry{
				{name: "../rules.yaml", mode: 0o644, body: "bad"},
			},
			wantErr: "not allowed relative path",
		},
		{
			name: "rejects absolute paths",
			entries: []tarGzEntry{
				{name: "/rules.yaml", mode: 0o644, body: "bad"},
			},
			wantErr: "absolute path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := ExtractSingleFileFromTarGz(context.Background(), newTarGz(t, tt.entries...), tt.strip)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if file.Perm != tt.wantMode {
				t.Fatalf("got file mode %o, want %o", file.Perm, tt.wantMode)
			}
			if string(file.Content) != tt.wantData {
				t.Fatalf("got data %q, want %q", string(file.Content), tt.wantData)
			}
		})
	}
}

type tarGzEntry struct {
	name     string
	typ      byte
	mode     int64
	body     string
	linkname string
}

func newTarGz(t *testing.T, entries ...tarGzEntry) *bytes.Reader {
	t.Helper()

	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, entry := range entries {
		typ := entry.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}

		header := &tar.Header{
			Name:     entry.name,
			Typeflag: typ,
			Mode:     mode,
			Linkname: entry.linkname,
		}
		if typ == tar.TypeReg {
			header.Size = int64(len(entry.body))
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if typ == tar.TypeReg {
			if _, err := tarWriter.Write([]byte(entry.body)); err != nil {
				t.Fatalf("write tar body: %v", err)
			}
		}
	}

	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}
