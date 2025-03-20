// Copyright (C) 2025 The Falco Authors
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

package priority

import (
	"fmt"
	"strconv"
)

const (
	// AnnotationKey is the key for the priority annotation.
	// The value of the annotation is the priority of the artifact expressed as an integer.
	// The higher the value, the higher the priority meaning that Falco will use the values of the
	// artifact with the highest priority.
	AnnotationKey   = "artifact.falcosecurity.dev/priority"
	DefaultPriority = "0"
)

// validate validates the priority annotation.
// It takes a map of annotations and returns an error if the priority annotation is invalid.
// If the priority annotation is not present in the map, it returns nil. In that case,
// a default priority will be used.
func validate(priority string) error {
	if _, err := strconv.Atoi(priority); err != nil {
		return fmt.Errorf("invalid priority annotation %q, value %q: %w", AnnotationKey, priority, err)
	}

	return nil
}

// Extract returns the priority of the artifact.
// It takes a map of annotations and returns the priority of the artifact as string
// if valid priority is present otherwise it returns the default priority.
func Extract(annotations map[string]string) string {
	// Check if the priority annotation exists.
	priority, ok := annotations[AnnotationKey]
	if !ok {
		// The priority annotation is not present in the map.
		// In this case, a default priority will be used.
		return DefaultPriority
	}
	return priority
}

// ValidateAndExtract validates the priority annotation and returns the priority of the artifact.
// It takes a map of annotations and returns the priority of the artifact as string if valid priority is present.
// If the priority annotation is not present in the map, it returns the default priority.
func ValidateAndExtract(annotations map[string]string) (string, error) {
	priority := Extract(annotations)
	if err := validate(priority); err != nil {
		return "", err
	} else {
		return priority, nil
	}
}

func NameFromPriority(priority, originalName string) string {
	return fmt.Sprintf("%s-%s", priority, originalName)
}
