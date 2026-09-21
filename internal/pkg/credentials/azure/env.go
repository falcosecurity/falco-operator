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

package azure

import (
	"os"
	"strings"
)

// Environment variable names deliberately match the wider Azure SDK ecosystem's own
// EnvironmentCredential/DefaultAzureCredential conventions (az CLI, other language SDKs), not
// project-specific names, so operators already familiar with Azure tooling don't have to learn
// new ones. Read from this process's own environment -- the falco-operator Deployment's -- so
// they act as a cluster-wide default identity for any AzureAuth that leaves a field unset, not
// as a per-resource mechanism.
const (
	envTenantID              = "AZURE_TENANT_ID"
	envClientID              = "AZURE_CLIENT_ID"
	envClientCertificatePath = "AZURE_CLIENT_CERTIFICATE_PATH"
	//nolint:gosec // G101: variable NAME, not a credential value
	envClientSecret = "AZURE_CLIENT_SECRET"
	//nolint:gosec // G101: variable NAME, not a credential value
	envClientCertificatePassword  = "AZURE_CLIENT_CERTIFICATE_PASSWORD"
	envClientSendCertificateChain = "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN"
)

// resolveString returns configValue if non-empty, otherwise the named environment variable
// (empty if unset). Config always wins when both are set.
func resolveString(configValue, envVar string) string {
	if configValue != "" {
		return configValue
	}
	return os.Getenv(envVar)
}

// resolveBool returns *configValue when configValue is non-nil (an explicit true or false in
// the CR), otherwise the named environment variable's truthiness ("1" or a case-insensitive
// "true"). A pointer, not a bare bool: a zero-value "false" CR field would otherwise be
// indistinguishable from "not set, check the environment.".
func resolveBool(configValue *bool, envVar string) bool {
	if configValue != nil {
		return *configValue
	}
	v := os.Getenv(envVar)
	return v == "1" || strings.EqualFold(v, "true")
}
