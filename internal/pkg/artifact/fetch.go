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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"runtime"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

// DefaultRetryDelay is the fallback delay RequeueDelay returns when a RetryableError carries
// no server-advertised Retry-After (a transport error, or a 503 with no header).
const DefaultRetryDelay = 10 * time.Second

// RetryableError wraps a transient FetchOCI failure (a transport error, or the artifact
// server's 503 "not cached yet" signal), so the caller can requeue via
// ctrl.Result{RequeueAfter: ...}.
type RetryableError struct {
	Err error
	// RetryAfter is the artifact server's advertised wait (parsed from its Retry-After
	// header), or zero if unavailable; callers should fall back to their own default delay
	// in that case (see RequeueDelay).
	RetryAfter time.Duration
}

func (e *RetryableError) Error() string { return e.Err.Error() }
func (e *RetryableError) Unwrap() error { return e.Err }

// RequeueDelay reports how long a caller should wait before retrying after err. It returns the
// server's advertised Retry-After when err is a *RetryableError that carries one, and a jittered
// DefaultRetryDelay otherwise. ok is false when err isn't retryable, in which case delay is
// meaningless.
func RequeueDelay(err error) (delay time.Duration, ok bool) {
	var retryErr *RetryableError
	if !errors.As(err, &retryErr) {
		return 0, false
	}
	if retryErr.RetryAfter > 0 {
		return wait.Jitter(retryErr.RetryAfter, 0.3), true
	}
	return wait.Jitter(DefaultRetryDelay, 0.5), true
}

// FetchResult is returned by every fetcher method.
// Content holds the raw bytes that will be written to disk.
// ContentHash is the SHA-256 hex digest of Content, computed by the fetcher.
type FetchResult struct {
	Content     []byte
	ContentHash string
	Perm        fs.FileMode
}

// OCIFetcher downloads a pre-extracted artifact binary from the central artifact server.
// The sidecar never touches the OCI registry directly; the server handles that.
type OCIFetcher interface {
	FetchOCI(ctx context.Context, namespace, name string, artifactType Type) (FetchResult, error)
}

// ConfigMapFetcher retrieves artifact content from a Kubernetes ConfigMap.
type ConfigMapFetcher interface {
	FetchConfigMap(ctx context.Context, namespace string, cmRef *commonv1alpha1.ConfigMapRef, artifactType Type) (FetchResult, error)
}

// InlineFetcher materializes inline spec content into a FetchResult.
type InlineFetcher interface {
	FetchInline(ctx context.Context, content []byte) (FetchResult, error)
}

// ArtifactFetcher is the combined interface that controllers depend on.
// Tests can mock it as a single unit; production code uses *Fetcher.
type ArtifactFetcher interface {
	OCIFetcher
	ConfigMapFetcher
	InlineFetcher
}

// NodeNameHeader is the HTTP request header FetchOCI sets to this node's name, identifying the
// requesting node to the artifact server.
const NodeNameHeader = "X-Node-Name"

// Fetcher implements ArtifactFetcher.
// OCI: HTTP GET to the central artifact server (no puller, no registry auth).
// ConfigMap: K8s API call.
// Inline: wraps the provided bytes.
type Fetcher struct {
	ServerURL  string
	HTTPClient *http.Client
	K8sClient  client.Client
	// NodeName is this node's name, sent on every FetchOCI request via NodeNameHeader.
	// Empty is fine (e.g. callers that only ever use FetchInline/FetchConfigMap); the
	// header is simply omitted.
	NodeName string
}

// FetchOCI streams the pre-extracted artifact binary for (namespace, name, type) from the
// central artifact server, computes a SHA-256 content hash, and returns a FetchResult. It makes
// exactly one attempt. A transient failure (a transport error, or a 503 meaning the artifact
// isn't cached yet) is returned as a *RetryableError for the caller to requeue via
// ctrl.Result{RequeueAfter: ...} (see RequeueDelay); a permanent failure (a non-503 error
// status, or a request-build/body-read failure) is returned as a plain error.
func (f *Fetcher) FetchOCI(ctx context.Context, namespace, name string, artifactType Type) (FetchResult, error) {
	var rawURL string
	switch artifactType {
	case TypePlugin:
		rawURL = fmt.Sprintf("%s/v1/artifacts/plugins/%s/%s?os=%s&arch=%s",
			f.ServerURL, namespace, name, runtime.GOOS, runtime.GOARCH)
	case TypeRulesfile:
		rawURL = fmt.Sprintf("%s/v1/artifacts/rulesfiles/%s/%s",
			f.ServerURL, namespace, name)
	default:
		return FetchResult{}, fmt.Errorf("artifact server does not support type %q", artifactType)
	}

	result, retryAfter, retryable, err := f.fetchOCIOnce(ctx, rawURL, namespace, name)
	if err != nil && retryable {
		return FetchResult{}, &RetryableError{Err: err, RetryAfter: retryAfter}
	}
	return result, err
}

// fetchOCIOnce performs a single HTTP GET to the artifact server. retryAfter is the parsed
// Retry-After header value (meaningful only when retryable is true); retryable reports
// whether FetchOCI's caller should retry; true for a transient transport error or a 503
// (the artifact server's "not cached yet" signal), false for anything else (a permanent
// client error, or a failure building the request or reading the response body).
func (f *Fetcher) fetchOCIOnce(ctx context.Context, rawURL, namespace, name string) (result FetchResult, retryAfter time.Duration, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return FetchResult{}, 0, false, fmt.Errorf("build artifact server request: %w", err)
	}
	if f.NodeName != "" {
		req.Header.Set(NodeNameHeader, f.NodeName)
	}

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return FetchResult{}, 0, true, fmt.Errorf("artifact server request for %s/%s: %w", namespace, name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusServiceUnavailable
		var ra time.Duration
		if retryable {
			if secs, parseErr := strconv.Atoi(resp.Header.Get("Retry-After")); parseErr == nil && secs > 0 {
				ra = time.Duration(secs) * time.Second
			}
		}
		return FetchResult{}, ra, retryable, fmt.Errorf("artifact server returned %d for %s/%s", resp.StatusCode, namespace, name)
	}

	perm := fs.FileMode(0o755)
	if modeStr := resp.Header.Get("X-Artifact-Mode"); modeStr != "" {
		if p, parseErr := strconv.ParseUint(modeStr, 10, 32); parseErr == nil {
			perm = fs.FileMode(p)
		}
	}

	h := sha256.New()
	content, err := io.ReadAll(io.TeeReader(resp.Body, h))
	if err != nil {
		return FetchResult{}, 0, false, fmt.Errorf("read artifact server response body: %w", err)
	}

	return FetchResult{
		Content:     content,
		ContentHash: hex.EncodeToString(h.Sum(nil)),
		Perm:        perm,
	}, 0, false, nil
}

// FetchConfigMap fetches the content for artifactType from the referenced ConfigMap.
func (f *Fetcher) FetchConfigMap(ctx context.Context, namespace string, cmRef *commonv1alpha1.ConfigMapRef, artifactType Type) (FetchResult, error) {
	var dataKey string
	switch artifactType {
	case TypeConfig:
		dataKey = commonv1alpha1.ConfigMapConfigKey
	case TypeRulesfile:
		dataKey = commonv1alpha1.ConfigMapRulesKey
	default:
		return FetchResult{}, fmt.Errorf("unsupported artifact type for ConfigMap fetch: %q", artifactType)
	}

	cm := &corev1.ConfigMap{}
	if err := f.K8sClient.Get(ctx, client.ObjectKey{Name: cmRef.Name, Namespace: namespace}, cm); err != nil {
		return FetchResult{}, err
	}

	data, ok := cm.Data[dataKey]
	if !ok {
		return FetchResult{}, fmt.Errorf("ConfigMap %s/%s missing expected key %q", namespace, cmRef.Name, dataKey)
	}

	content := []byte(data)
	h := sha256.Sum256(content)
	return FetchResult{
		Content:     content,
		ContentHash: hex.EncodeToString(h[:]),
		Perm:        0o600,
	}, nil
}

// FetchInline wraps inline content bytes into a FetchResult.
func (f *Fetcher) FetchInline(_ context.Context, content []byte) (FetchResult, error) {
	h := sha256.Sum256(content)
	return FetchResult{
		Content:     content,
		ContentHash: hex.EncodeToString(h[:]),
		Perm:        0o600,
	}, nil
}
