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
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/falcosecurity/falco-operator/internal/pkg/controllerhelper"
)

func TestWithStartup_DelaysRunnablesUntilInitializationSucceeds(t *testing.T) {
	for _, tc := range []struct {
		name           string
		leaderElection []bool
	}{
		{name: "no queued runnables"},
		{name: "leader runnable", leaderElection: []bool{true}},
		{name: "nonleader runnable", leaderElection: []bool{false}},
		{name: "mixed runnables", leaderElection: []bool{true, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realManager := &startupRecordingManager{}
			entered, release := make(chan struct{}), make(chan struct{})
			mgr, err := controllerhelper.WithStartup(realManager, func(ctx context.Context) error {
				close(entered)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			require.NoError(t, err)
			require.Equal(t, "startup", realManager.readyName)
			require.Error(t, realManager.readyCheck(nil))

			queued := make([]*startupTestRunnable, len(tc.leaderElection))
			for i, leader := range tc.leaderElection {
				queued[i] = &startupTestRunnable{leader: leader}
				require.NoError(t, mgr.Add(queued[i]))
			}
			registered := realManager.registered()
			require.Len(t, registered, 1, "only initialization may be registered before recovery")
			bootstrap := registered[0]
			election, ok := bootstrap.(manager.LeaderElectionRunnable)
			require.True(t, ok)
			assert.False(t, election.NeedLeaderElection())
			_, isCache := bootstrap.(interface{ GetCache() cache.Cache })
			assert.False(t, isCache, "initialization must not join the manager's cache startup group")

			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- bootstrap.Start(ctx) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					assert.NoError(t, err)
				case <-time.After(5 * time.Second):
					t.Error("initialization runnable did not stop")
				}
			})
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("initialization did not start")
			}
			assert.Len(t, realManager.registered(), 1)
			assert.Error(t, realManager.readyCheck(nil))

			close(release)
			require.Eventually(t, func() bool { return realManager.readyCheck(nil) == nil }, 5*time.Second, time.Millisecond)
			registered = realManager.registered()
			require.Len(t, registered, len(queued)+1)
			for i, runnable := range queued {
				assert.Same(t, runnable, registered[i+1])
				election, ok := registered[i+1].(manager.LeaderElectionRunnable)
				require.True(t, ok)
				assert.Equal(t, tc.leaderElection[i], election.NeedLeaderElection())
				_, hasWarmup := registered[i+1].(interface{ Warmup(context.Context) error })
				assert.True(t, hasWarmup, "registration must retain the runnable's warmup contract")
			}

			later := &startupTestRunnable{}
			require.NoError(t, mgr.Add(later))
			registered = realManager.registered()
			require.Len(t, registered, len(queued)+2)
			assert.Same(t, later, registered[len(queued)+1])
			realManager.mu.Lock()
			realManager.addErr = assert.AnError
			realManager.mu.Unlock()
			assert.ErrorIs(t, mgr.Add(&startupTestRunnable{}), assert.AnError)
			assert.Len(t, realManager.registered(), len(queued)+2)
		})
	}
}

func TestWithStartup_FailedOrCanceledInitializationDoesNotRegisterRunnables(t *testing.T) {
	for _, tc := range []struct {
		name             string
		cancelBefore     bool
		cancelDuring     bool
		initializeErr    error
		wantErr          error
		wantInitialCalls int
	}{
		{name: "initialization error", initializeErr: assert.AnError, wantErr: assert.AnError, wantInitialCalls: 1},
		{name: "canceled before initialization", cancelBefore: true, wantErr: context.Canceled},
		{name: "canceled during initialization", cancelDuring: true, wantErr: context.Canceled, wantInitialCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realManager := &startupRecordingManager{}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			mgr, err := controllerhelper.WithStartup(realManager, func(context.Context) error {
				calls++
				if tc.cancelDuring {
					cancel()
				}
				return tc.initializeErr
			})
			require.NoError(t, err)
			require.NoError(t, mgr.Add(&startupTestRunnable{}))
			if tc.cancelBefore {
				cancel()
			}
			done := make(chan error, 1)
			go func() { done <- realManager.registered()[0].Start(ctx) }()
			select {
			case err := <-done:
				assert.ErrorIs(t, err, tc.wantErr)
			case <-time.After(5 * time.Second):
				t.Fatal("failed initialization did not return")
			}
			assert.Equal(t, tc.wantInitialCalls, calls)
			assert.Len(t, realManager.registered(), 1)
			assert.Error(t, realManager.readyCheck(nil))
		})
	}
}

func TestWithStartup_RegistrationFailureDoesNotBecomeReady(t *testing.T) {
	for _, tc := range []struct {
		name   string
		failAt int
	}{
		{name: "first runnable", failAt: 1},
		{name: "middle runnable", failAt: 2},
		{name: "last runnable", failAt: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realManager := &startupRecordingManager{failAddAt: tc.failAt + 1}
			mgr, err := controllerhelper.WithStartup(realManager, func(context.Context) error { return nil })
			require.NoError(t, err)
			queued := []*startupTestRunnable{{leader: true}, {}, {leader: true}}
			for _, runnable := range queued {
				require.NoError(t, mgr.Add(runnable))
			}

			done := make(chan error, 1)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			go func() { done <- realManager.registered()[0].Start(ctx) }()
			select {
			case err := <-done:
				assert.ErrorIs(t, err, assert.AnError)
			case <-time.After(5 * time.Second):
				t.Fatal("registration failure did not return")
			}
			registered := realManager.registered()
			require.Len(t, registered, tc.failAt)
			for i, runnable := range queued[:tc.failAt-1] {
				assert.Same(t, runnable, registered[i+1], "earlier successful registration cannot be rolled back")
			}
			assert.Error(t, realManager.readyCheck(nil))
		})
	}
}

func TestWithStartup_ConstructionErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readyErr error
		addErr   error
	}{
		{name: "readiness check", readyErr: assert.AnError},
		{name: "initialization runnable", addErr: assert.AnError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realManager := &startupRecordingManager{readyErr: tc.readyErr, addErr: tc.addErr}
			mgr, err := controllerhelper.WithStartup(realManager, func(context.Context) error {
				t.Error("construction must not run initialization")
				return nil
			})
			assert.Nil(t, mgr)
			assert.ErrorIs(t, err, assert.AnError)
			assert.Empty(t, realManager.registered())
		})
	}
}

type startupRecordingManager struct {
	manager.Manager
	mu         sync.Mutex
	runnables  []manager.Runnable
	readyName  string
	readyCheck healthz.Checker
	readyErr   error
	addErr     error
	failAddAt  int
}

func (m *startupRecordingManager) Add(r manager.Runnable) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addErr != nil {
		return m.addErr
	}
	if m.failAddAt > 0 && len(m.runnables)+1 == m.failAddAt {
		return assert.AnError
	}
	m.runnables = append(m.runnables, r)
	return nil
}

func (m *startupRecordingManager) AddReadyzCheck(name string, check healthz.Checker) error {
	if m.readyErr != nil {
		return m.readyErr
	}
	m.readyName, m.readyCheck = name, check
	return nil
}

func (m *startupRecordingManager) registered() []manager.Runnable {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]manager.Runnable(nil), m.runnables...)
}

type startupTestRunnable struct{ leader bool }

func (*startupTestRunnable) Start(context.Context) error  { return nil }
func (*startupTestRunnable) Warmup(context.Context) error { return nil }
func (r *startupTestRunnable) NeedLeaderElection() bool   { return r.leader }
