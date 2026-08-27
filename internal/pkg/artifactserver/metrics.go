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

package artifactserver

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Metrics are registered against controller-runtime's shared metrics registry and exposed on
// the operator's existing metrics HTTP endpoint.
var (
	requestsTotal = promauto.With(ctrlmetrics.Registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "artifactserver_requests_total",
			Help: "Total artifact server HTTP requests, by artifact type and response status code.",
		},
		[]string{"type", "status"},
	)

	requestDuration = promauto.With(ctrlmetrics.Registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "artifactserver_request_duration_seconds",
			Help:    "Artifact server request handling latency, by artifact type.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"type"},
	)

	cacheLookupsTotal = promauto.With(ctrlmetrics.Registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "artifactserver_cache_lookups_total",
			Help: "Artifact cache lookups performed by the artifact server, by artifact type and result (hit|miss).",
		},
		[]string{"type", "result"},
	)
)
