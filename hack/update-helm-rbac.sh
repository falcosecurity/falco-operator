#!/usr/bin/env bash
# Copyright (C) 2026 The Falco Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Generate Helm RBAC template from config/rbac/role.yaml

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ROLE_YAML="${REPO_ROOT}/config/rbac/role.yaml"
HELM_RBAC_TEMPLATE="${REPO_ROOT}/chart/falco-operator/templates/rbac.yaml"

if [[ ! -f "${ROLE_YAML}" ]]; then
    echo "Error: ${ROLE_YAML} not found. Run 'make manifests' first." >&2
    exit 1
fi

cat > "${HELM_RBAC_TEMPLATE}" << 'EOF'
{{- if .Values.rbac.create }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "falco-operator.fullname" . }}-role
  labels:
    {{- include "falco-operator.labels" . | nindent 4 }}
    app.kubernetes.io/part-of: falco
EOF

# Extract rules section from role.yaml (everything from 'rules:' to end of file)
awk '/^rules:/ {found=1} found {print}' "${ROLE_YAML}" >> "${HELM_RBAC_TEMPLATE}"

cat >> "${HELM_RBAC_TEMPLATE}" << 'EOF'
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "falco-operator.fullname" . }}-rolebinding
  labels:
    {{- include "falco-operator.labels" . | nindent 4 }}
    app.kubernetes.io/part-of: falco
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "falco-operator.fullname" . }}-role
subjects:
  - kind: ServiceAccount
    name: {{ include "falco-operator.serviceAccountName" . }}
    namespace: {{ .Release.Namespace }}
{{- end }}
EOF

echo "RBAC synced to chart/falco-operator/templates/rbac.yaml"
