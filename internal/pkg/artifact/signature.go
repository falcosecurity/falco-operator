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

package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"strconv"

	corev1 "k8s.io/api/core/v1"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

func computeOCISourceSignature(artifact *commonv1alpha1.OCIArtifact, authSecret *corev1.Secret) string {
	if artifact == nil {
		return ""
	}

	h := sha256.New()

	writeHashString(h, ResolveReference(artifact))

	opts := ResolveRegistryOptions(artifact)
	if opts == nil {
		writeHashBool(h, false)
		writeHashBool(h, false)
	} else {
		writeHashBool(h, opts.PlainHTTP)
		writeHashBool(h, opts.InsecureSkipVerify)
	}

	writeHashString(h, authSecretRefName(artifact))
	if authSecret != nil {
		writeHashBytes(h, authSecret.Data[commonv1alpha1.SecretUsernameKey])
		writeHashBytes(h, authSecret.Data[commonv1alpha1.SecretPasswordKey])
	}

	return hex.EncodeToString(h.Sum(nil))
}

func writeHashString(h hash.Hash, value string) {
	writeHashBytes(h, []byte(value))
}

func writeHashBool(h hash.Hash, value bool) {
	writeHashString(h, strconv.FormatBool(value))
}

func writeHashBytes(h hash.Hash, value []byte) {
	_, _ = io.WriteString(h, strconv.Itoa(len(value)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(value)
	_, _ = h.Write([]byte{0})
}
