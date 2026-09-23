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
	"context"
	"fmt"
	"net/http"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// WithStartup delays added runnables until initialize succeeds using the manager's synced cache.
// Finish controller setup before calling Start, so their watches are installed before workers run.
func WithStartup(mgr manager.Manager, initialize func(context.Context) error) (manager.Manager, error) {
	s := &startupManager{Manager: mgr, initialize: initialize, ready: make(chan struct{})}
	if err := mgr.AddReadyzCheck("startup", s.checkReady); err != nil {
		return nil, err
	}
	// Do not register s itself: its embedded GetCache would place it in the cache startup group.
	if err := mgr.Add(startupRunnable(s.start)); err != nil {
		return nil, err
	}
	return s, nil
}

type startupManager struct {
	manager.Manager
	initialize func(context.Context) error
	ready      chan struct{}
	mu         sync.Mutex
	pending    []manager.Runnable
	started    bool
}

func (s *startupManager) Add(r manager.Runnable) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return s.Manager.Add(r)
	}
	s.pending = append(s.pending, r)
	return nil
}

func (s *startupManager) start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.initialize(ctx); err != nil {
		return fmt.Errorf("initialize controller manager: %w", err)
	}
	if err := s.activate(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func (s *startupManager) activate(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, r := range s.pending {
		if err := s.Manager.Add(r); err != nil {
			return fmt.Errorf("register runnable after initialization: %w", err)
		}
	}
	s.pending = nil
	s.started = true
	close(s.ready)
	return nil
}

func (s *startupManager) checkReady(_ *http.Request) error {
	select {
	case <-s.ready:
		return nil
	default:
		return fmt.Errorf("controller initialization is not complete")
	}
}

type startupRunnable func(context.Context) error

func (s startupRunnable) Start(ctx context.Context) error { return s(ctx) }

func (startupRunnable) NeedLeaderElection() bool { return false }
