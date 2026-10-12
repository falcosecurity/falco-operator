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

// Package node models the node that the artifact-operator sidecar and its Falco share: the
// artifacts installed on it, the dependency tree they form, the capabilities Falco reports, and
// the status published back to the node's ArtifactNode.
//
// It coordinates on-disk writes across the sidecar's three per-node reconcilers (Plugin,
// Rulesfile, Config), which write into the same Falco config directories. This package controls
// what combination of files can be on disk; Falco reloads are triggered explicitly by
// reloadCoordinator (reloadcoordinator.go) after writes settle, not by Falco's own file-watch.
package node
