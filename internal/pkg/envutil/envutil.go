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

// Package envutil provides helpers for sourcing configuration from environment
// variables, primarily as flag.StringVar/etc. default values.
package envutil

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// StringOr returns the value of the environment variable named by key, or
// fallback if the variable is unset or empty.
func StringOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// FlagNameToEnvName translates a flag name (e.g. "artifact-cache-dir") into
// the name of the environment variable BindFlagEnv checks for it (e.g.
// "ARTIFACT_CACHE_DIR"): upper-cased, with '-' replaced by '_'.
func FlagNameToEnvName(flagName string) string {
	return strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// BindFlagEnv gives every flag registered on fs an implicit environment
// variable override, named per FlagNameToEnvName. Call it after fs.Parse.
//
// Precedence: an explicit command-line flag always wins; otherwise, if the
// corresponding environment variable is set, it overrides the flag's
// registered default.
func BindFlagEnv(fs *flag.FlagSet) error {
	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		explicit[f.Name] = true
	})

	var errs []error
	fs.VisitAll(func(f *flag.Flag) {
		if explicit[f.Name] {
			return
		}
		envName := FlagNameToEnvName(f.Name)
		envValue, ok := os.LookupEnv(envName)
		if !ok {
			return
		}
		if err := fs.Set(f.Name, envValue); err != nil {
			errs = append(errs, fmt.Errorf("environment variable %s: invalid value for flag -%s: %w", envName, f.Name, err))
		}
	})

	return errors.Join(errs...)
}
