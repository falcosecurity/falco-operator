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
	"time"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// DefaultPluginConfigRetryInterval is the polling cadence used by PluginConfigRetrier when none
// is specified.
const DefaultPluginConfigRetryInterval = 15 * time.Second

// DefaultPluginConfigMismatchGracePeriod is how long a desired-vs-actual plugin load mismatch
// must persist before PluginConfigRetrier forces a rewrite, when none is specified. Gives
// Falco's own restart cycle time to finish before concluding a write was missed; a
// freshly-installed (or freshly-removed) plugin that Falco simply hasn't gotten to yet looks
// identical to a genuinely lost write until this window elapses.
const DefaultPluginConfigMismatchGracePeriod = 45 * time.Second

// PluginConfigRetrier is a background correction for the race Falco's own reload mechanism
// creates: it reloads by doing a full process restart on SIGHUP, and a write to the shared
// plugins-config file that lands during that restart's teardown/re-init window is never
// observed; Falco comes back up having read the file's earlier state and never restarts again
// for the missed write. PluginConfigRetrier periodically compares what this node intends loaded
// against what Falco currently reports loaded (Manager.PluginLoadMismatch); if that mismatch
// persists past a grace period, it forces a fresh write (Manager.ForceRewritePluginConfig) to
// give Falco's file-watch another chance; in either direction, a configured-but-never-loaded
// plugin or a removed-but-still-loaded one.
//
// mismatchSince is owned by the retrier itself, not the Manager: it's purely "how long has some
// mismatch persisted," not per-plugin state, so a single timestamp is enough; bundling a
// newly-arrived mismatch into an already-due forced rewrite is efficient, not premature, since
// the rewrite was already about to happen anyway.
type PluginConfigRetrier struct {
	manager     *Manager
	fetcher     artifact.ArtifactFetcher
	interval    time.Duration
	gracePeriod time.Duration

	mismatchSince time.Time
}

// NewPluginConfigRetrier creates a PluginConfigRetrier that checks manager every interval, and
// forces a rewrite once a mismatch has persisted for gracePeriod.
func NewPluginConfigRetrier(manager *Manager, fetcher artifact.ArtifactFetcher, interval, gracePeriod time.Duration) *PluginConfigRetrier {
	return &PluginConfigRetrier{manager: manager, fetcher: fetcher, interval: interval, gracePeriod: gracePeriod}
}

// Start implements manager.Runnable. It checks for a plugin-load mismatch until ctx is canceled.
func (r *PluginConfigRetrier) Start(ctx context.Context) error {
	logger := ctrllog.FromContext(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if !r.manager.PluginLoadMismatch() {
				r.mismatchSince = time.Time{}
				continue
			}
			if r.mismatchSince.IsZero() {
				r.mismatchSince = time.Now()
				continue
			}
			if time.Since(r.mismatchSince) < r.gracePeriod {
				continue
			}
			if err := r.manager.ForceRewritePluginConfig(ctx, r.fetcher); err != nil {
				logger.V(4).Info("plugin config confirmation retry failed, will retry", "err", err)
				continue
			}
			logger.V(2).Info("forced plugins-config rewrite: desired/loaded plugin set mismatch persisted past grace period")
			r.mismatchSince = time.Now()
		}
	}
}
