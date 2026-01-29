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
	"io"
	"io/fs"
	"os"
)

// OS implements FileSystem using the real os package.
type OS struct{}

// NewOSFileSystem creates a new OS filesystem.
func NewOSFileSystem() *OS {
	return &OS{}
}

// Stat returns file info for the given path.
func (OS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(name)
}

// ReadFile reads the file at the given path.
func (OS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name) //nolint:gosec // This is intentional - the filesystem abstraction needs to accept variable paths
}

// WriteFile writes data to the file at the given path.
func (OS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(name, data, perm)
}

// Remove removes the file at the given path.
func (OS) Remove(name string) error {
	return os.Remove(name)
}

// Rename renames (moves) oldpath to newpath.
func (OS) Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

// Open opens the file at the given path.
func (OS) Open(name string) (io.ReadCloser, error) {
	return os.Open(name) //nolint:gosec // This is intentional - the filesystem abstraction needs to accept variable paths
}

// Exists checks if the file exists.
func (OS) Exists(f *File) (bool, error) {
	if _, err := os.Stat(f.Path); err != nil && !os.IsNotExist(err) {
		return false, err
	} else if os.IsNotExist(err) {
		return false, nil
	}
	return true, nil
}
