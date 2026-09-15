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

import "fmt"

// DependencyError means a dependency stopped being available before a rulesfile write.
type DependencyError struct {
	Name string
}

func (e *DependencyError) Error() string {
	return fmt.Sprintf("plugin dependency %q is no longer available at a compatible version", e.Name)
}

// BlockedError reports a plugin removal blocked by installed rules.
type BlockedError struct {
	Name      string
	BlockedBy []Key
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("%q is still required by %v", e.Name, e.BlockedBy)
}
