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

package shared

import (
	"context"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

// reconcileInUseFinalizer keeps parent alive while its nodes or its cache entry require cleanup. The cache entry
// outlives the node assignments: removing the OCI source releases it, and only then may the finalizer go.
func (a Aggregation[T]) reconcileInUseFinalizer(ctx context.Context, parent T, nodesInUse bool) error {
	info, err := artifact.InfoForKind(a.Kind)
	if err != nil {
		return err
	}
	if a.Cache != nil && info.Accepts(artifact.MediumOCI) {
		if parent.GetOCIArtifact() != nil {
			nodesInUse = true
		} else if err := a.evict(parent.GetNamespace(), parent.GetName()); err != nil {
			return err
		}
	}
	return controllerhelper.ReconcileInUseFinalizer(ctx, a.Client, parent, controllerhelper.NodeObjectsInUseFinalizer, nodesInUse)
}
