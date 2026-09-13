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

package controllerhelper_test

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func TestResultForEnsureError_RetryableRequeuesWithoutError(t *testing.T) {
	retryable := &artifact.RetryableError{Err: errors.New("artifact server not ready"), RetryAfter: 2 * time.Second}

	result, err := controllerhelper.ResultForEnsureError(logr.Discard(), retryable)

	require.NoError(t, err)
	assert.Positive(t, result.RequeueAfter, "a retryable error must set RequeueAfter")
}

func TestResultForEnsureError_NonRetryablePropagatesError(t *testing.T) {
	plain := errors.New("boom")

	result, err := controllerhelper.ResultForEnsureError(logr.Discard(), plain)

	assert.Equal(t, plain, err)
	assert.Zero(t, result.RequeueAfter)
}
