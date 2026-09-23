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

package puller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

type memoryDescriptorFetcher map[string][]byte

//nolint:gocritic // descriptorFetcher mirrors ORAS's Fetcher interface, which passes descriptors by value.
func (f memoryDescriptorFetcher) Fetch(_ context.Context, desc v1.Descriptor) (io.ReadCloser, error) {
	content, ok := f[desc.Digest.String()]
	if !ok {
		return nil, fmt.Errorf("descriptor %q not found", desc.Digest)
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

func (f memoryDescriptorFetcher) addJSON(t *testing.T, mediaType string, value any) v1.Descriptor {
	t.Helper()
	content, err := json.Marshal(value)
	require.NoError(t, err)
	desc := descriptorForContent(mediaType, content)
	f[desc.Digest.String()] = content
	return desc
}

func descriptorForContent(mediaType string, content []byte) v1.Descriptor {
	return orascontent.NewDescriptorFromBytes(mediaType, content)
}

func TestResolveConfigDescriptor_DirectManifest(t *testing.T) {
	fetcher := memoryDescriptorFetcher{}
	configDesc := descriptorForContent(FalcoPluginConfigMediaType, []byte(`{"name":"plugin"}`))
	rootDesc := fetcher.addJSON(t, v1.MediaTypeImageManifest, v1.Manifest{Config: configDesc})

	got, err := resolveConfigDescriptor(context.Background(), fetcher, "registry.example/plugin:1", &rootDesc)

	require.NoError(t, err)
	assert.Equal(t, configDesc, *got)
}

func TestResolveConfigDescriptor_IndexUsesFirstPlatformManifest(t *testing.T) {
	fetcher := memoryDescriptorFetcher{}
	configDesc := descriptorForContent(FalcoPluginConfigMediaType, []byte(`{"name":"plugin"}`))
	arm64 := fetcher.addJSON(t, v1.MediaTypeImageManifest, v1.Manifest{Config: configDesc})
	arm64.Platform = &v1.Platform{OS: "linux", Architecture: "arm64"}
	amd64 := descriptorForContent(v1.MediaTypeImageManifest, []byte("not fetched"))
	amd64.Platform = &v1.Platform{OS: "linux", Architecture: "amd64"}
	auxiliary := descriptorForContent(v1.MediaTypeImageManifest, []byte("not fetched"))
	unknownPlatform := descriptorForContent(v1.MediaTypeImageManifest, []byte("also not fetched"))
	unknownPlatform.Platform = &v1.Platform{OS: "unknown", Architecture: "unknown"}
	rootDesc := fetcher.addJSON(t, v1.MediaTypeImageIndex, v1.Index{
		Manifests: []v1.Descriptor{auxiliary, unknownPlatform, arm64, amd64},
	})

	got, err := resolveConfigDescriptor(context.Background(), fetcher, "registry.example/plugin:1", &rootDesc)

	require.NoError(t, err)
	assert.Equal(t, configDesc, *got)
}

func TestResolveConfigDescriptor_IndexRequiresPlatformManifest(t *testing.T) {
	fetcher := memoryDescriptorFetcher{}
	rootDesc := fetcher.addJSON(t, v1.MediaTypeImageIndex, v1.Index{
		Manifests: []v1.Descriptor{descriptorForContent(v1.MediaTypeImageManifest, []byte("auxiliary"))},
	})

	_, err := resolveConfigDescriptor(context.Background(), fetcher, "registry.example/plugin:1", &rootDesc)

	require.EqualError(t, err, `image index for "registry.example/plugin:1" has no platform manifests`)
}

func TestFetchConfig_RejectsContentDigestMismatch(t *testing.T) {
	for _, tc := range []struct {
		name        string
		original    string
		replacement string
	}{
		{name: "altered version", original: "1.0.0", replacement: "9.0.0"},
		{name: "altered name", original: "test-rules", replacement: "fake-rules"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, digest := testRegistryHandler(t)
			var alterContent atomic.Bool
			alterContent.Store(true)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, r)
				body := response.Body.Bytes()
				if alterContent.Load() && r.Method == http.MethodGet && response.Header().Get("Content-Type") == FalcoRulesfileConfigMediaType {
					body = bytes.ReplaceAll(body, []byte(tc.original), []byte(tc.replacement))
				}
				maps.Copy(w.Header(), response.Header())
				w.WriteHeader(response.Code)
				_, _ = w.Write(body)
			}))
			t.Cleanup(server.Close)
			ref := strings.TrimPrefix(server.URL, "http://") + "/test/rules@" + digest
			puller := NewOciPuller(nil)
			options := &RegistryOptions{PlainHTTP: true}
			config, resolved, err := puller.FetchConfig(t.Context(), ref, nil, options)
			require.ErrorIs(t, err, orascontent.ErrMismatchedDigest)
			assert.Nil(t, config)
			assert.Empty(t, resolved)

			alterContent.Store(false)
			config, resolved, err = puller.FetchConfig(t.Context(), ref, nil, options)
			require.NoError(t, err)
			assert.Equal(t, "1.0.0", config.Version)
			assert.Equal(t, digest, resolved)
		})
	}
}

func TestFetchBytes_VerifiesDescriptor(t *testing.T) {
	data := []byte(`{"name":"rules"}`)
	desc := descriptorForContent(FalcoRulesfileConfigMediaType, data)
	for _, tc := range []struct {
		name    string
		content []byte
		wantErr error
	}{
		{name: "valid", content: data},
		{name: "different bytes", content: []byte(`{"name":"other"}`), wantErr: orascontent.ErrMismatchedDigest},
		{name: "truncated", content: data[:len(data)-1], wantErr: io.ErrUnexpectedEOF},
		{name: "trailing bytes", content: append(append([]byte(nil), data...), '\n'), wantErr: orascontent.ErrTrailingData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetcher := memoryDescriptorFetcher{desc.Digest.String(): tc.content}
			got, err := fetchBytes(t.Context(), fetcher, &desc)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, data, got)
		})
	}
}

type testReadCloser struct {
	io.Reader
	closeErr   error
	closeCalls int
}

func (r *testReadCloser) Close() error {
	r.closeCalls++
	return r.closeErr
}

func TestReadAndClose_ErrorPrecedence(t *testing.T) {
	data := []byte("metadata")
	desc := descriptorForContent(FalcoRulesfileConfigMediaType, data)
	readErr := fmt.Errorf("read failed")
	closeErr := fmt.Errorf("close failed")
	for _, tc := range []struct {
		name     string
		reader   io.Reader
		closeErr error
		wantErr  error
	}{
		{name: "valid", reader: bytes.NewReader(data)},
		{name: "close failure", reader: bytes.NewReader(data), closeErr: closeErr, wantErr: closeErr},
		{name: "read failure", reader: iotest.ErrReader(readErr), closeErr: closeErr, wantErr: readErr},
		{name: "digest failure", reader: strings.NewReader("modified"), closeErr: closeErr, wantErr: orascontent.ErrMismatchedDigest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &testReadCloser{Reader: tc.reader, closeErr: tc.closeErr}
			got, err := readAndClose(reader, &desc)
			assert.Equal(t, 1, reader.closeCalls)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, data, got)
		})
	}
}

func TestRegistryCredentialIsolation(t *testing.T) {
	for _, operation := range []string{"Pull", "FetchConfig", "ResolveDigest", "FetchContent"} {
		t.Run(operation, func(t *testing.T) {
			handler, digest := testRegistryHandler(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				username, password, ok := r.BasicAuth()
				if !ok || username != "reader" || password != "test-password" {
					w.Header().Set("WWW-Authenticate", `Basic realm="test-registry"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			host := strings.TrimPrefix(server.URL, "http://")
			ref := host + "/test/rules@" + digest
			opts := &RegistryOptions{PlainHTTP: true}
			valid := auth.StaticCredential(host, auth.Credential{Username: "reader", Password: "test-password"})
			invalid := auth.StaticCredential(host, auth.Credential{Username: "other-reader", Password: "wrong-password"})

			err := runRegistryOperation(t.Context(), operation, ref, nil, opts)
			require.ErrorIs(t, err, auth.ErrBasicCredentialNotFound)
			require.NoError(t, runRegistryOperation(t.Context(), operation, ref, valid, opts))

			// The authenticated operation must not authorize the next caller.
			assert.ErrorIs(t, runRegistryOperation(t.Context(), operation, ref, nil, opts), auth.ErrBasicCredentialNotFound)
			var unauthorized *errcode.ErrorResponse
			require.ErrorAs(t, runRegistryOperation(t.Context(), operation, ref, invalid, opts), &unauthorized)
			assert.Equal(t, http.StatusUnauthorized, unauthorized.StatusCode)
			require.NoError(t, runRegistryOperation(t.Context(), operation, ref, valid, opts), "failed callers must not poison valid credentials")
		})
	}
}

func TestRegistryTLSIsolation(t *testing.T) {
	for _, operation := range []string{"Pull", "FetchConfig", "ResolveDigest", "FetchContent"} {
		t.Run(operation, func(t *testing.T) {
			handler, digest := testRegistryHandler(t)
			server := httptest.NewUnstartedServer(handler)
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			t.Cleanup(server.Close)
			ref := strings.TrimPrefix(server.URL, "https://") + "/test/rules@" + digest

			var authorityErr x509.UnknownAuthorityError
			require.ErrorAs(t, runRegistryOperation(t.Context(), operation, ref, nil, nil), &authorityErr)
			require.NoError(t, runRegistryOperation(t.Context(), operation, ref, nil, &RegistryOptions{InsecureSkipVerify: true}))
			assert.ErrorAs(t, runRegistryOperation(t.Context(), operation, ref, nil, nil), &authorityErr,
				"default clients must still verify TLS after an explicitly insecure pull")
			assert.ErrorAs(t, runRegistryOperation(t.Context(), operation, ref, nil, &RegistryOptions{}), &authorityErr,
				"explicit secure options must not inherit another client's transport")
		})
	}
}

const testRegistryRules = "- required_engine_version: 0.0.1\n"

// testRegistryHandler serves a real OCI manifest, config and compressed rules layer.
func testRegistryHandler(t *testing.T) (handler http.Handler, rootDigest string) {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{Name: "rules.yaml", Mode: 0o644, Size: int64(len(testRegistryRules))}))
	_, err := io.WriteString(tarWriter, testRegistryRules)
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())

	content := memoryDescriptorFetcher{}
	layer := descriptorForContent(FalcoRulesfileLayerMediaType, compressed.Bytes())
	content[layer.Digest.String()] = compressed.Bytes()
	config := content.addJSON(t, FalcoRulesfileConfigMediaType, ArtifactConfig{Name: "test-rules", Version: "1.0.0"})
	manifest := content.addJSON(t, v1.MediaTypeImageManifest, v1.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    config,
		Layers:    []v1.Descriptor{layer},
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead && r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var desc v1.Descriptor
		switch r.URL.Path {
		case "/v2/test/rules/manifests/" + manifest.Digest.String():
			desc = manifest
		case "/v2/test/rules/blobs/" + config.Digest.String():
			desc = config
		case "/v2/test/rules/blobs/" + layer.Digest.String():
			desc = layer
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", desc.MediaType)
		w.Header().Set("Content-Length", fmt.Sprint(desc.Size))
		w.Header().Set("Docker-Content-Digest", desc.Digest.String())
		if r.Method == http.MethodGet {
			_, _ = w.Write(content[desc.Digest.String()])
		}
	}), manifest.Digest.String()
}

func runRegistryOperation(ctx context.Context, operation, ref string, creds auth.CredentialFunc, opts *RegistryOptions) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := NewOciPuller(nil)
	_, wantDigest, _ := strings.Cut(ref, "@")
	switch operation {
	case "Pull":
		var compressed bytes.Buffer
		result, err := p.Pull(ctx, ref, "linux", "arm64", creds, opts, &compressed)
		if err != nil {
			return err
		}
		if result.RootDigest != wantDigest || result.Type != Rulesfile || compressed.Len() == 0 {
			return fmt.Errorf("unexpected pull result: %+v", result)
		}
	case "FetchConfig":
		config, digest, err := p.FetchConfig(ctx, ref, creds, opts)
		if err != nil {
			return err
		}
		if digest != wantDigest || config.Name != "test-rules" {
			return fmt.Errorf("unexpected config %v at digest %s", config, digest)
		}
	case "ResolveDigest":
		digest, err := p.ResolveDigest(ctx, ref, creds, opts)
		if err != nil {
			return err
		}
		if digest != wantDigest {
			return fmt.Errorf("unexpected digest %s", digest)
		}
	case "FetchContent":
		content, err := p.FetchContent(ctx, ref, creds, opts)
		if err != nil {
			return err
		}
		if string(content) != testRegistryRules {
			return fmt.Errorf("unexpected rules content: %q", content)
		}
	default:
		return fmt.Errorf("unknown registry operation %q", operation)
	}
	return nil
}
