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

package filesystem

import (
	"errors"
	"io"
	"io/fs"
)

// mockFileSystem implements FileSystem for testing.
type mockFileSystem struct {
	Files       map[string][]byte
	StatErr     error
	ReadErr     error
	WriteErr    error
	RemoveErr   error
	RenameErr   error
	OpenErr     error
	statCalls   []string
	readCalls   []string
	WriteCalls  []writeCall
	RemoveCalls []string
	RenameCalls []renameCall
	openCalls   []string
}

type renameCall struct {
	oldpath string
	newpath string
}

type writeCall struct {
	name string
	data []byte
	perm fs.FileMode
}

// NewMockFileSystem creates a new mock filesystem.
func NewMockFileSystem() *mockFileSystem {
	return &mockFileSystem{
		Files: make(map[string][]byte),
	}
}

func (m *mockFileSystem) Stat(name string) (fs.FileInfo, error) {
	m.statCalls = append(m.statCalls, name)
	if m.StatErr != nil {
		return nil, m.StatErr
	}
	if _, ok := m.Files[name]; !ok {
		return nil, fs.ErrNotExist
	}
	return nil, nil
}

func (m *mockFileSystem) ReadFile(name string) ([]byte, error) {
	m.readCalls = append(m.readCalls, name)
	if m.ReadErr != nil {
		return nil, m.ReadErr
	}
	data, ok := m.Files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return data, nil
}

func (m *mockFileSystem) WriteFile(name string, data []byte, perm fs.FileMode) error {
	m.WriteCalls = append(m.WriteCalls, writeCall{name: name, data: data, perm: perm})
	if m.WriteErr != nil {
		return m.WriteErr
	}
	m.Files[name] = data
	return nil
}

func (m *mockFileSystem) Remove(name string) error {
	m.RemoveCalls = append(m.RemoveCalls, name)
	if m.RemoveErr != nil {
		return m.RemoveErr
	}
	delete(m.Files, name)
	return nil
}

func (m *mockFileSystem) Rename(oldpath, newpath string) error {
	m.RenameCalls = append(m.RenameCalls, renameCall{oldpath: oldpath, newpath: newpath})
	if m.RenameErr != nil {
		return m.RenameErr
	}
	if data, ok := m.Files[oldpath]; ok {
		m.Files[newpath] = data
		delete(m.Files, oldpath)
		return nil
	}
	return fs.ErrNotExist
}

func (m *mockFileSystem) Open(name string) (io.ReadCloser, error) {
	m.openCalls = append(m.openCalls, name)
	if m.OpenErr != nil {
		return nil, m.OpenErr
	}
	data, ok := m.Files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &mockReadCloser{data: data}, nil
}

// mockReadCloser implements io.ReadCloser for testing.
type mockReadCloser struct {
	data   []byte
	offset int
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	if m.offset >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.offset:])
	m.offset += n
	return n, nil
}

func (m *mockReadCloser) Close() error {
	return nil
}

// Exists checks if a file exists in the mock filesystem.
func (m *mockFileSystem) Exists(path string) (bool, error) {
	if m.StatErr != nil && !errors.Is(m.StatErr, fs.ErrNotExist) {
		return false, m.StatErr
	}
	_, ok := m.Files[path]
	return ok, nil
}
