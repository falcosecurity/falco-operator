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

package metacollector

import (
	"fmt"
	"strings"
)

const (
	delimiter        = "--"
	escapedDelimiter = "__DASH__"
)

// GenerateUniqueName creates a unique name from the name and namespace of a Metacollector instance.
func GenerateUniqueName(name, namespace string) string {
	escapedName := strings.ReplaceAll(name, delimiter, escapedDelimiter)
	escapedNamespace := strings.ReplaceAll(namespace, delimiter, escapedDelimiter)
	return fmt.Sprintf("%s%s%s", escapedName, delimiter, escapedNamespace)
}

// ParseUniqueName reverses the unique name back into the original name and namespace.
func ParseUniqueName(uniqueName string) (name, namespace string, err error) {
	if count := strings.Count(uniqueName, delimiter); count != 1 {
		return "", "", fmt.Errorf("invalid unique name format, was expecting only one %q: %s", delimiter, uniqueName)
	}

	if uniqueName == delimiter {
		return "", "", fmt.Errorf("invalid unique name format, was expecting a name: %s", uniqueName)
	}

	parts := strings.SplitN(uniqueName, delimiter, 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid unique name format: %s", uniqueName)
	}

	originalName := strings.ReplaceAll(parts[0], escapedDelimiter, delimiter)
	originalNamespace := strings.ReplaceAll(parts[1], escapedDelimiter, delimiter)
	return originalName, originalNamespace, nil
}
