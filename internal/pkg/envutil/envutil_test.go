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

package envutil

import (
	"flag"
	"strings"
	"testing"
)

func TestStringOr(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envValue string
		setEnv   bool
		fallback string
		want     string
	}{
		{
			name:     "returns env var value when set",
			key:      "ENVUTIL_TEST_VAR",
			envValue: "from-env",
			setEnv:   true,
			fallback: "fallback",
			want:     "from-env",
		},
		{
			name:     "returns fallback when env var unset",
			key:      "ENVUTIL_TEST_VAR",
			setEnv:   false,
			fallback: "fallback",
			want:     "fallback",
		},
		{
			name:     "returns fallback when env var set to empty string",
			key:      "ENVUTIL_TEST_VAR",
			envValue: "",
			setEnv:   true,
			fallback: "fallback",
			want:     "fallback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			}

			got := StringOr(tt.key, tt.fallback)

			if got != tt.want {
				t.Errorf("StringOr(%q, %q) = %q, want %q", tt.key, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestFlagNameToEnvName(t *testing.T) {
	tests := []struct {
		flagName string
		want     string
	}{
		{"artifact-cache-dir", "ARTIFACT_CACHE_DIR"},
		{"leader-elect", "LEADER_ELECT"},
		{"a", "A"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			if got := FlagNameToEnvName(tt.flagName); got != tt.want {
				t.Errorf("FlagNameToEnvName(%q) = %q, want %q", tt.flagName, got, tt.want)
			}
		})
	}
}

func TestBindFlagEnv(t *testing.T) {
	t.Run("overrides unset flag from env var", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		var val string
		fs.StringVar(&val, "artifact-cache-dir", "default-dir", "usage")
		if err := fs.Parse(nil); err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		t.Setenv("ARTIFACT_CACHE_DIR", "/env/dir")

		if err := BindFlagEnv(fs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != "/env/dir" {
			t.Errorf("val = %q, want %q", val, "/env/dir")
		}
	})

	t.Run("explicit flag wins over env var", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		var val string
		fs.StringVar(&val, "artifact-cache-dir", "default-dir", "usage")
		if err := fs.Parse([]string{"-artifact-cache-dir=/cli/dir"}); err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		t.Setenv("ARTIFACT_CACHE_DIR", "/env/dir")

		if err := BindFlagEnv(fs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != "/cli/dir" {
			t.Errorf("val = %q, want %q (CLI flag should win over env var)", val, "/cli/dir")
		}
	})

	t.Run("keeps default when no env var and no CLI flag", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		var val string
		fs.StringVar(&val, "artifact-cache-dir", "default-dir", "usage")
		if err := fs.Parse(nil); err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}

		if err := BindFlagEnv(fs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != "default-dir" {
			t.Errorf("val = %q, want %q", val, "default-dir")
		}
	})

	t.Run("returns error for env value invalid for the flag's type", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		var val bool
		fs.BoolVar(&val, "leader-elect", false, "usage")
		if err := fs.Parse(nil); err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		t.Setenv("LEADER_ELECT", "not-a-bool")

		err := BindFlagEnv(fs)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "LEADER_ELECT") || !strings.Contains(err.Error(), "leader-elect") {
			t.Errorf("error %q should mention both env var and flag name", err.Error())
		}
	})
}
