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

package node

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchFalcoMetrics_RepeatedDefinitions(t *testing.T) {
	const timestamp = "# HELP falcosecurity_falco_reload_timestamp_nanoseconds https://falco.org/docs/metrics/\n" +
		"# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\n" +
		"falcosecurity_falco_reload_timestamp_nanoseconds 1789460410000000000\n"
	const rulesHeader = "# HELP falcosecurity_falco_sha256_rules_files_info https://falco.org/docs/metrics/\n" +
		"# TYPE falcosecurity_falco_sha256_rules_files_info gauge\n"
	const firstRule = "falcosecurity_falco_sha256_rules_files_info{file_name=\"managed.yaml\",sha256=\"abc\"} 1\n"
	const secondRule = "falcosecurity_falco_sha256_rules_files_info{file_name=\"external.yaml\",sha256=\"def\"} 1\n"
	tests := []struct {
		name      string
		body      string
		wantRules int
		wantErr   bool
		noEpoch   bool
	}{
		{
			// Falco 0.44.1 emits each file's sample with its own HELP/TYPE lines.
			name:      "repeated rules definitions retain every file",
			body:      rulesHeader + firstRule + rulesHeader + secondRule + timestamp,
			wantRules: 2,
		},
		{
			name: "unrelated duplicate definitions do not hide the epoch",
			body: "# HELP falcosecurity_scap_n_drops_buffer_total https://falco.org/docs/metrics/\n" +
				"# TYPE falcosecurity_scap_n_drops_buffer_total counter\n" +
				"falcosecurity_scap_n_drops_buffer_total 0\n" +
				"# HELP falcosecurity_scap_n_drops_buffer_total https://falco.org/docs/metrics/\n" +
				"# TYPE falcosecurity_scap_n_drops_buffer_total counter\n" +
				"falcosecurity_scap_n_drops_buffer_total 0\n" + timestamp,
		},
		{
			name: "conflicting target type is rejected",
			body: rulesHeader + firstRule + "# TYPE falcosecurity_falco_sha256_rules_files_info counter\n" +
				secondRule + timestamp,
			wantErr: true,
		},
		{
			name: "conflicting target help is rejected",
			body: rulesHeader + firstRule + "# HELP falcosecurity_falco_sha256_rules_files_info conflicting\n" +
				secondRule + timestamp,
			wantErr: true,
		},
		{
			name:    "malformed target sample is rejected",
			body:    rulesHeader + firstRule + rulesHeader + "falcosecurity_falco_sha256_rules_files_info{file_name=\"unclosed} 1\n" + timestamp,
			wantErr: true,
		},
		{
			name:    "malformed target value is rejected",
			body:    strings.Replace(timestamp, "1789460410000000000", "invalid", 1),
			wantErr: true,
		},
		{
			name:    "missing target type value is rejected",
			body:    "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds\n",
			wantErr: true,
		},
		{
			name:    "duplicate epoch samples are not coalesced",
			body:    timestamp + timestamp,
			noEpoch: true,
		},
		{
			name:    "definitions without samples do not prove a runtime",
			body:    rulesHeader,
			noEpoch: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			metrics, err := fetchFalcoMetrics(t.Context(), srv.Client(), srv.URL)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, metrics["falcosecurity_falco_sha256_rules_files_info"].GetMetric(), tc.wantRules)
			assert.NotContains(t, metrics, "falcosecurity_scap_n_drops_buffer_total")
			if tc.wantRules == 0 {
				assert.NotContains(t, metrics, "falcosecurity_falco_sha256_rules_files_info")
			}
			epoch, err := reloadTimestamp(metrics)
			if tc.noEpoch {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, float64(1789460410000000000), epoch) //nolint:testifylint // exact reload epoch
			if tc.wantRules == 2 {
				rules := metrics["falcosecurity_falco_sha256_rules_files_info"].GetMetric()
				assert.Equal(t, "managed.yaml", rules[0].GetLabel()[0].GetValue())
				assert.Equal(t, "external.yaml", rules[1].GetLabel()[0].GetValue())
			}
		})
	}
}

func TestReloadTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    float64
		wantErr bool
	}{
		{name: "nanosecond epoch", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds 1789460410000000000\n", want: 1789460410000000000},
		{name: "missing metric", body: "other_metric 1\n", wantErr: true},
		{name: "missing type", body: "falcosecurity_falco_reload_timestamp_nanoseconds 1000\n", wantErr: true},
		{name: "counter is not timestamp gauge", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds counter\nfalcosecurity_falco_reload_timestamp_nanoseconds 1000\n", wantErr: true},
		{name: "zero", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds 0\n", wantErr: true},
		{name: "negative", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds -1\n", wantErr: true},
		{name: "not a number", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds NaN\n", wantErr: true},
		{name: "infinity", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds +Inf\n", wantErr: true},
		{name: "ambiguous epochs", body: "# TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\nfalcosecurity_falco_reload_timestamp_nanoseconds{instance=\"a\"} 1000\nfalcosecurity_falco_reload_timestamp_nanoseconds{instance=\"b\"} 2000\n", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			metrics, err := fetchFalcoMetrics(t.Context(), srv.Client(), srv.URL)
			require.NoError(t, err)
			got, err := reloadTimestamp(metrics)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got) //nolint:testifylint // reload epochs require exact comparison
		})
	}
}
