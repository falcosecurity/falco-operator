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
	"time"

	"github.com/go-logr/logr"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

// StaleCacheRetryDelay is how long to wait before retrying a write rejected because the informer cache lagged
// behind the API server. The cache catches up within milliseconds, and the rejection is expected rather than an
// error.
const StaleCacheRetryDelay = 250 * time.Millisecond

// ResultForWriteError turns the outcome of a write based on an object read from an informer cache. A conflict,
// or a create that finds the object already there, means the cache lagged behind the API server: it is retried
// after StaleCacheRetryDelay and is not an error. An object that is gone leaves nothing to do. Any other error is
// returned.
func ResultForWriteError(err error) (ctrl.Result, error) {
	if k8serrors.IsConflict(err) || k8serrors.IsAlreadyExists(err) {
		return ctrl.Result{RequeueAfter: StaleCacheRetryDelay}, nil
	}
	return ctrl.Result{}, client.IgnoreNotFound(err)
}
