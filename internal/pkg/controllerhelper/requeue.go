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

import (
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// ResultForEnsureError translates an ensureX error into a reconcile Result, requeueing after
// RequeueDelay's backoff for a transient artifact-server error instead of returning it as-is.
func ResultForEnsureError(logger logr.Logger, err error) (ctrl.Result, error) {
	if delay, ok := artifact.RequeueDelay(err); ok {
		logger.Info("artifact server not ready, requeueing", "delay", delay)
		return ctrl.Result{RequeueAfter: delay}, nil
	}
	return ctrl.Result{}, err
}
