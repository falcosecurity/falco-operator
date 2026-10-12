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

package testutil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"sigs.k8s.io/controller-runtime/pkg/client"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

// FakeFetcher is an artifact.ArtifactFetcher for tests. Inline content and ConfigMaps resolve through a real
// artifact.Fetcher over the test client, as in production; OCI artifacts are served from memory, so no artifact
// server is needed.
type FakeFetcher struct {
	Delegate *artifact.Fetcher
	// OCIErr, when set, is what FetchOCI returns.
	OCIErr error
	// OCIBytes is the content FetchOCI serves. Empty means "mock-oci-content".
	OCIBytes []byte
	// OnFetchOCI, when set, runs on every FetchOCI call before it returns.
	OnFetchOCI func()

	// OCICalls and ConfigMapCalls count the calls of FetchOCI and FetchConfigMap.
	OCICalls       int
	ConfigMapCalls int
	// OCIDigest is the digest the last FetchOCI call expected.
	OCIDigest string
}

// NewFakeFetcher returns a FakeFetcher resolving inline and ConfigMap content through cl.
func NewFakeFetcher(cl client.Client) *FakeFetcher {
	return &FakeFetcher{Delegate: &artifact.Fetcher{K8sClient: cl}}
}

func (f *FakeFetcher) FetchOCI(_ context.Context, _, _ string, _ artifact.Kind, expectedDigest string) (artifact.FetchResult, error) {
	f.OCICalls++
	f.OCIDigest = expectedDigest
	if f.OnFetchOCI != nil {
		f.OnFetchOCI()
	}
	if f.OCIErr != nil {
		return artifact.FetchResult{}, f.OCIErr
	}
	content := f.OCIBytes
	if content == nil {
		content = []byte("mock-oci-content")
	}
	return artifact.FetchResult{Content: content, ContentHash: SHA256Hex(content), Perm: 0o755}, nil
}

func (f *FakeFetcher) FetchInline(ctx context.Context, content []byte) (artifact.FetchResult, error) {
	return f.Delegate.FetchInline(ctx, content)
}

func (f *FakeFetcher) FetchConfigMap(
	ctx context.Context, namespace string, cmRef *commonv1alpha1.ConfigMapRef, kind artifact.Kind,
) (artifact.FetchResult, error) {
	f.ConfigMapCalls++
	return f.Delegate.FetchConfigMap(ctx, namespace, cmRef, kind)
}

// SHA256Hex is the hex-encoded SHA-256 of content, the form of an artifact's content hash.
func SHA256Hex(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}
