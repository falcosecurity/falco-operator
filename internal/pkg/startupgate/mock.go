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

package startupgate

// NoopGateRecorder is a Recorder that ignores every call.
type NoopGateRecorder struct{}

func (NoopGateRecorder) MarkReconciled(string, string, string, int64) {}
func (NoopGateRecorder) Forget(string, string, string)                {}

// FakeGateRecorder captures Recorder calls.
type FakeGateRecorder struct {
	Reconciled []FakeGateCall
	Forgotten  []FakeGateCall
}

type FakeGateCall struct {
	Kind, Namespace, Name string
	Generation            int64
}

func (r *FakeGateRecorder) MarkReconciled(kind, namespace, name string, generation int64) {
	r.Reconciled = append(r.Reconciled, FakeGateCall{Kind: kind, Namespace: namespace, Name: name, Generation: generation})
}

func (r *FakeGateRecorder) Forget(kind, namespace, name string) {
	r.Forgotten = append(r.Forgotten, FakeGateCall{Kind: kind, Namespace: namespace, Name: name})
}
