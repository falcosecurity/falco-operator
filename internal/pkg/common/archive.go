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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
)

// ExtractedFile is a regular file read from an archive.
type ExtractedFile struct {
	Content []byte
	Perm    fs.FileMode
}

// ExtractSingleFileFromTarGz reads a gzipped tar archive and returns its only
// regular file. Directory entries are accepted as packaging metadata;
// links, unknown entry types, empty archives, and multi-file archives are rejected.
func ExtractSingleFileFromTarGz(ctx context.Context, gzipStream io.Reader, stripPathComponents int) (ExtractedFile, error) {
	var content bytes.Buffer
	var fileMode fs.FileMode
	var found bool

	uncompressed, err := gzip.NewReader(gzipStream)
	if err != nil {
		return ExtractedFile{}, err
	}
	defer uncompressed.Close()

	tarReader := tar.NewReader(uncompressed)
	for {
		select {
		case <-ctx.Done():
			return ExtractedFile{}, errors.New("interrupted")
		default:
		}

		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			if !found {
				return ExtractedFile{}, fmt.Errorf("no regular file found in tar archive")
			}
			return ExtractedFile{Content: content.Bytes(), Perm: fileMode}, nil
		}
		if err != nil {
			return ExtractedFile{}, err
		}

		_, ok, err := archivePath(header.Name, stripPathComponents)
		if err != nil {
			return ExtractedFile{}, err
		}
		if !ok {
			continue
		}

		info := header.FileInfo()
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			if found {
				return ExtractedFile{}, fmt.Errorf("multiple regular files found in tar archive")
			}
			if written, err := io.CopyN(&content, tarReader, header.Size); err != nil {
				return ExtractedFile{}, err
			} else if written != header.Size {
				return ExtractedFile{}, io.ErrShortWrite
			}
			fileMode = info.Mode().Perm()
			found = true
		case tar.TypeLink:
			return ExtractedFile{}, fmt.Errorf("hard links are not allowed in OCI artifact tar archive")
		case tar.TypeSymlink:
			return ExtractedFile{}, fmt.Errorf("symbolic links are not allowed in OCI artifact tar archive")
		default:
			return ExtractedFile{}, fmt.Errorf("extractTarGz: uknown type: %b in %s", header.Typeflag, header.Name)
		}
	}
}

func archivePath(headerName string, stripPathComponents int) (path string, ok bool, err error) {
	if strings.Contains(headerName, "..") {
		return "", false, fmt.Errorf("not allowed relative path in tar archive")
	}

	name, ok := strippedPath(headerName, stripPathComponents)
	if !ok {
		return "", false, nil
	}
	clean := filepath.Clean(name)
	if clean == "." {
		return "", false, nil
	}
	if filepath.IsAbs(clean) {
		return "", false, fmt.Errorf("absolute path %q is not allowed in tar archive", headerName)
	}
	return clean, true, nil
}

func strippedPath(headerName string, stripPathComponents int) (string, bool) {
	name := headerName
	if stripPathComponents > 0 {
		name = stripComponents(name, stripPathComponents)
	}
	return name, name != ""
}

func stripComponents(headerName string, stripComponents int) string {
	if stripComponents == 0 {
		return headerName
	}
	names := strings.Split(headerName, string(filepath.Separator))
	if len(names) < stripComponents {
		return headerName
	}
	return filepath.Clean(strings.Join(names[stripComponents:], string(filepath.Separator)))
}
