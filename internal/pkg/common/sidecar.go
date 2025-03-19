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

package common

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// IsSidecarContainersFeatureEnabled checks if the SidecarContainers feature is enabled in the cluster.
// It returns true if the feature is enabled, false otherwise.
func IsSidecarContainersFeatureEnabled(cfg *rest.Config) (bool, error) {
	clSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("unable to create a client set: %w", err)
	}

	req := clSet.RESTClient().Get().AbsPath("/metrics").RequestURI("/metrics").Do(context.Background())
	rawMetrics, err := req.Raw()
	if err != nil {
		return false, fmt.Errorf("unable to get metrics: %w", err)
	}

	if strings.Contains(string(rawMetrics), "kubernetes_feature_enabled") && strings.Contains(string(rawMetrics), "SidecarContainers") {
		return true, nil
	}
	return false, nil
}
