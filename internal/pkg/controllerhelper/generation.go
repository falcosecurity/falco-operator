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

package controllerhelper

import "github.com/go-logr/logr"

// WaitForObservedGeneration reports whether a reconcile should defer the rest of its work until
// the instance operator has processed the parent artifact's current spec generation. It logs one
// Info line either way.
func WaitForObservedGeneration(logger logr.Logger, observedGeneration, generation int64) (wait bool) {
	if observedGeneration != generation {
		logger.Info("instance operator has not yet processed current spec generation; deferring",
			"observedGeneration", observedGeneration,
			"specGeneration", generation)
		return true
	}
	logger.Info("instance operator has processed current spec generation; proceeding",
		"observedGeneration", observedGeneration,
		"specGeneration", generation)
	return false
}
