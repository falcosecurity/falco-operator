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
	"time"
)

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

func TestBindFlagEnv_Duration(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		args    []string
		want    time.Duration
		wantErr bool
	}{
		{name: "environment override", env: "7s", want: 7 * time.Second},
		{name: "fractional duration", env: "500ms", want: 500 * time.Millisecond},
		{name: "explicit flag wins", env: "7s", args: []string{"--falco-reload-cooldown=4s"}, want: 4 * time.Second},
		{name: "explicit flag ignores invalid environment", env: "invalid", args: []string{"--falco-reload-cooldown=4s"}, want: 4 * time.Second},
		{name: "invalid environment duration", env: "invalid", wantErr: true},
		{name: "empty environment duration", env: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			val := fs.Duration("falco-reload-cooldown", 5*time.Second, "usage")
			if err := fs.Parse(tt.args); err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			t.Setenv("FALCO_RELOAD_COOLDOWN", tt.env)
			err := BindFlagEnv(fs)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "FALCO_RELOAD_COOLDOWN") {
					t.Fatalf("expected duration error mentioning the environment variable, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if *val != tt.want {
				t.Errorf("duration = %s, want %s", *val, tt.want)
			}
		})
	}
}
