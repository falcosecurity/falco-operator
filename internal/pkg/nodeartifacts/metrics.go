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

package nodeartifacts

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// fetchFalcoMetrics reads and parses the metrics used by periodic verification.
func fetchFalcoMetrics(ctx context.Context, client *http.Client, baseURL string) (map[string]*dto.MetricFamily, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/metrics", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", req.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Falco 0.44 repeats HELP/TYPE for each labeled sample. Keep every sample,
	// deduplicating only identical definitions for the two families we consume.
	var selected strings.Builder
	definitions := make(map[string]string)
	const typeDefinition = "TYPE"
	for raw := range strings.SplitSeq(string(body), "\n") {
		line := strings.TrimSpace(raw)
		name, definition := line, ""
		if after, ok := strings.CutPrefix(line, "#"); ok {
			fields := strings.Fields(after)
			if len(fields) < 2 || (fields[0] != "HELP" && fields[0] != typeDefinition) {
				continue
			}
			name = fields[1]
			definition = fields[0]
		} else if end := strings.IndexAny(line, "{ \t"); end >= 0 {
			name = line[:end]
		}
		if name != "falcosecurity_falco_sha256_rules_files_info" && name != "falcosecurity_falco_reload_timestamp_nanoseconds" {
			continue
		}
		if definition != "" {
			if definition == typeDefinition && len(strings.Fields(strings.TrimPrefix(line, "#"))) != 3 {
				return nil, fmt.Errorf("invalid TYPE definition for Falco metric %q", name)
			}
			key := definition + " " + name
			if previous, ok := definitions[key]; ok {
				if previous != line {
					return nil, fmt.Errorf("conflicting %s definitions for Falco metric %q", definition, name)
				}
				continue
			}
			definitions[key] = line
		}
		_, _ = selected.WriteString(line)
		_ = selected.WriteByte('\n')
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	metrics, err := parser.TextToMetricFamilies(strings.NewReader(selected.String()))
	if err != nil {
		return nil, err
	}
	for name, family := range metrics {
		if len(family.GetMetric()) == 0 {
			delete(metrics, name)
		}
	}
	return metrics, nil
}

func reloadTimestamp(metrics map[string]*dto.MetricFamily) (float64, error) {
	family := metrics["falcosecurity_falco_reload_timestamp_nanoseconds"]
	if len(family.GetMetric()) != 1 || family.GetMetric()[0].Gauge == nil {
		return 0, fmt.Errorf("falco reload timestamp is unavailable")
	}
	value := family.GetMetric()[0].GetGauge().GetValue()
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("invalid Falco reload timestamp %v", value)
	}
	return value, nil
}
