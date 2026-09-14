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
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
)

const testRulesfileUpdatedTag = "updated"

func TestResolveRulesfileSources(t *testing.T) {
	t.Run("captures all inputs without resolving an OCI tag", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: "test"},
			Data:       map[string]string{commonv1alpha1.ConfigMapRulesKey: "old rules"},
		}
		cl := fake.NewClientBuilder().WithScheme(createTestScheme(t)).WithObjects(cm).Build()
		rf := &artifactv1alpha1.Rulesfile{
			ObjectMeta: metav1.ObjectMeta{Namespace: cm.Namespace},
			Spec: artifactv1alpha1.RulesfileSpec{
				OCIArtifact:  &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "test/rules", Tag: "latest"}},
				InlineRules:  &apiextensionsv1.JSON{Raw: []byte("[]")},
				ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: cm.Name},
			},
		}
		// No HTTP client/server is configured: resolving sources must not fetch OCI.
		sources, err := ResolveRulesfileSources(t.Context(), &Fetcher{K8sClient: cl}, rf)
		require.NoError(t, err)
		before, err := sources.Hash()
		require.NoError(t, err)
		rf.Spec.OCIArtifact.Image.Tag = testRulesfileUpdatedTag
		rf.Spec.InlineRules.Raw[0] = '{'
		rf.Spec.ConfigMapRef.Name = cm.Name + "-updated"
		cm.Data[commonv1alpha1.ConfigMapRulesKey] = "new rules"
		require.NoError(t, cl.Update(t.Context(), cm))
		after, err := sources.Hash()
		require.NoError(t, err)
		require.Equal(t, before, after)
		require.Equal(t, "latest", sources.OCIArtifact.Image.Tag)
		require.Equal(t, "[]", string(sources.InlineRules.Raw))
		require.Equal(t, "rules", sources.ConfigMapName)
		require.Equal(t, "old rules", string(sources.ConfigMap.Content))
		require.EqualValues(t, 0o644, sources.ConfigMap.Perm)
	})

	for _, tt := range []struct {
		name      string
		data      map[string]string
		missing   bool
		wantError bool
	}{
		{name: "missing ConfigMap", missing: true, wantError: true},
		{name: "missing required key", data: map[string]string{"unrelated": "rules"}, wantError: true},
		{name: "configured empty content", data: map[string]string{commonv1alpha1.ConfigMapRulesKey: ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(createTestScheme(t))
			if !tt.missing {
				builder.WithObjects(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: "test"}, Data: tt.data})
			}
			rf := &artifactv1alpha1.Rulesfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test"},
				Spec:       artifactv1alpha1.RulesfileSpec{ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "rules"}},
			}
			sources, err := ResolveRulesfileSources(t.Context(), &Fetcher{K8sClient: builder.Build()}, rf)
			if tt.wantError {
				require.Error(t, err)
				require.Nil(t, sources, "failed resolution must not return a partial snapshot")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, sources.ConfigMap)
			require.NotNil(t, sources.ConfigMap.Content, "configured empty content is not an absent source")
			require.Empty(t, sources.ConfigMap.Content)
		})
	}
}

func TestRulesfileSources_Hash(t *testing.T) {
	resolve := func(spec artifactv1alpha1.RulesfileSpec, content []byte) *RulesfileSources {
		t.Helper()
		builder := fake.NewClientBuilder().WithScheme(createTestScheme(t))
		if spec.ConfigMapRef != nil {
			builder.WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: spec.ConfigMapRef.Name, Namespace: "test"},
				Data:       map[string]string{commonv1alpha1.ConfigMapRulesKey: string(content)},
			})
		}
		rf := &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Namespace: "test"}, Spec: spec}
		sources, err := ResolveRulesfileSources(t.Context(), &Fetcher{K8sClient: builder.Build()}, rf)
		require.NoError(t, err)
		return sources
	}
	spec := artifactv1alpha1.RulesfileSpec{
		OCIArtifact:  &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "test/rules", Tag: "latest"}},
		ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "rules"},
		InlineRules:  &apiextensionsv1.JSON{Raw: []byte("[]")},
	}
	ociHash, err := ComputeOCIArtifactSpecHash(spec.OCIArtifact)
	require.NoError(t, err)
	for _, tt := range []struct {
		name    string
		spec    artifactv1alpha1.RulesfileSpec
		content []byte
		encoded string
	}{
		{
			name:    "all sources retain the persisted hash format",
			spec:    spec,
			content: []byte("rules"),
			encoded: fmt.Sprintf(`{"ociArtifactSpecHash":%q,"configMapName":"rules","configMapConfigured":true,"configMapRules":"cnVsZXM=","inlineConfigured":true,"inlineRules":"W10="}`, ociHash),
		},
		{
			name:    "no sources",
			encoded: `{"ociArtifactSpecHash":"","configMapName":"","configMapConfigured":false,"configMapRules":null,"inlineConfigured":false,"inlineRules":null}`,
		},
		{
			name:    "configured empty ConfigMap differs from no source",
			spec:    artifactv1alpha1.RulesfileSpec{ConfigMapRef: &commonv1alpha1.ConfigMapRef{Name: "rules"}},
			content: []byte(""),
			encoded: `{"ociArtifactSpecHash":"","configMapName":"rules","configMapConfigured":true,"configMapRules":"","inlineConfigured":false,"inlineRules":null}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sources := resolve(tt.spec, tt.content)
			hash, err := sources.Hash()
			require.NoError(t, err)
			require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(tt.encoded))), hash)
		})
	}

	sources := resolve(spec, []byte("rules"))
	hash, err := sources.Hash()
	require.NoError(t, err)
	for _, tt := range []struct {
		name    string
		mutate  func(*artifactv1alpha1.RulesfileSpec, *[]byte)
		changed bool
	}{
		{name: "ConfigMap rules", mutate: func(_ *artifactv1alpha1.RulesfileSpec, content *[]byte) { *content = []byte("updated") }, changed: true},
		{name: "ConfigMap name", mutate: func(s *artifactv1alpha1.RulesfileSpec, _ *[]byte) { s.ConfigMapRef.Name = "other" }, changed: true},
		{name: "ConfigMap removal", mutate: func(s *artifactv1alpha1.RulesfileSpec, _ *[]byte) { s.ConfigMapRef = nil }, changed: true},
		{name: "inline rules", mutate: func(s *artifactv1alpha1.RulesfileSpec, _ *[]byte) { s.InlineRules.Raw = []byte("[{}]") }, changed: true},
		{name: "inline removal", mutate: func(s *artifactv1alpha1.RulesfileSpec, _ *[]byte) { s.InlineRules = nil }, changed: true},
		{name: "OCI tag", mutate: func(s *artifactv1alpha1.RulesfileSpec, _ *[]byte) { s.OCIArtifact.Image.Tag = "new" }, changed: true},
		{name: "OCI removal", mutate: func(s *artifactv1alpha1.RulesfileSpec, _ *[]byte) { s.OCIArtifact = nil }, changed: true},
		{name: "priority does not change metadata", mutate: func(s *artifactv1alpha1.RulesfileSpec, _ *[]byte) { s.Priority++ }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			updatedSpec := spec.DeepCopy()
			content := []byte("rules")
			tt.mutate(updatedSpec, &content)
			updatedSources := resolve(*updatedSpec, content)
			updatedHash, err := updatedSources.Hash()
			require.NoError(t, err)
			require.Equal(t, tt.changed, hash != updatedHash)
		})
	}
}

type configMapFetcherFunc func(context.Context, string, *commonv1alpha1.ConfigMapRef, Type) (FetchResult, error)

func (f configMapFetcherFunc) FetchConfigMap(ctx context.Context, namespace string,
	ref *commonv1alpha1.ConfigMapRef, kind Type,
) (FetchResult, error) {
	return f(ctx, namespace, ref, kind)
}

func TestResolveRulesfileSources_ConfigMapSnapshot(t *testing.T) {
	ctx := t.Context()
	ref := &commonv1alpha1.ConfigMapRef{Name: "rules"}
	parent := &artifactv1alpha1.Rulesfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test"},
		Spec: artifactv1alpha1.RulesfileSpec{
			ConfigMapRef: ref,
			InlineRules:  &apiextensionsv1.JSON{Raw: []byte("[]")},
			OCIArtifact:  &commonv1alpha1.OCIArtifact{Image: commonv1alpha1.ImageSpec{Repository: "test/rules", Tag: "latest"}},
		},
	}

	t.Run("fetches once and detaches the content buffer", func(t *testing.T) {
		result := FetchResult{Content: []byte("rules"), ContentHash: "content-hash", Perm: 0o644}
		calls := 0
		fetcher := configMapFetcherFunc(func(gotCtx context.Context, namespace string,
			gotRef *commonv1alpha1.ConfigMapRef, kind Type,
		) (FetchResult, error) {
			calls++
			require.Equal(t, ctx, gotCtx)
			require.Equal(t, parent.Namespace, namespace)
			require.Equal(t, ref, gotRef)
			require.Equal(t, TypeRulesfile, kind)
			return result, nil
		})
		sources, err := ResolveRulesfileSources(ctx, fetcher, parent)
		require.NoError(t, err)
		require.Equal(t, result, *sources.ConfigMap)
		before, err := sources.Hash()
		require.NoError(t, err)

		result.Content[0] = 'X'
		require.Equal(t, "rules", string(sources.ConfigMap.Content))
		after, err := sources.Hash()
		require.NoError(t, err)
		require.Equal(t, before, after)
		require.Equal(t, 1, calls)
	})

	t.Run("returns no partial snapshot on fetch failure", func(t *testing.T) {
		fetchErr := errors.New("ConfigMap unavailable")
		fetcher := configMapFetcherFunc(func(context.Context, string, *commonv1alpha1.ConfigMapRef, Type) (FetchResult, error) {
			return FetchResult{Content: []byte("partial")}, fetchErr
		})
		sources, err := ResolveRulesfileSources(ctx, fetcher, parent)
		require.ErrorIs(t, err, fetchErr)
		require.ErrorContains(t, err, ref.Name)
		require.Nil(t, sources)
	})

	t.Run("does not fetch when ConfigMap is absent", func(t *testing.T) {
		withoutConfigMap := parent.DeepCopy()
		withoutConfigMap.Spec.ConfigMapRef = nil
		calls := 0
		fetcher := configMapFetcherFunc(func(context.Context, string, *commonv1alpha1.ConfigMapRef, Type) (FetchResult, error) {
			calls++
			return FetchResult{}, errors.New("unexpected ConfigMap fetch")
		})
		sources, err := ResolveRulesfileSources(ctx, fetcher, withoutConfigMap)
		require.NoError(t, err)
		require.Zero(t, calls)
		require.Nil(t, sources.ConfigMap)
		require.Empty(t, sources.ConfigMapName)
		require.Equal(t, parent.Spec.OCIArtifact, sources.OCIArtifact)
		require.Equal(t, parent.Spec.InlineRules, sources.InlineRules)
	})
}

func TestRulesfileSources_OCISpecHash(t *testing.T) {
	sources := &RulesfileSources{}
	hash, err := sources.OCISpecHash()
	require.NoError(t, err)
	require.Empty(t, hash)

	sources.OCIArtifact = &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{Repository: "test/rules", Tag: "latest"},
	}
	expected, err := ComputeOCIArtifactSpecHash(sources.OCIArtifact)
	require.NoError(t, err)
	hash, err = sources.OCISpecHash()
	require.NoError(t, err)
	require.Equal(t, expected, hash)

	sources.ConfigMapName = "rules"
	sources.ConfigMap = &FetchResult{Content: []byte("new rules")}
	sources.InlineRules = &apiextensionsv1.JSON{Raw: []byte("[]")}
	hash, err = sources.OCISpecHash()
	require.NoError(t, err)
	require.Equal(t, expected, hash, "local sources must not invalidate the pinned OCI revision")

	sources.OCIArtifact.Image.Tag = testRulesfileUpdatedTag
	hash, err = sources.OCISpecHash()
	require.NoError(t, err)
	require.NotEqual(t, expected, hash)
}

func TestRulesfileSources_HashIgnoresTransportFields(t *testing.T) {
	sources := &RulesfileSources{
		ConfigMapName: "rules",
		ConfigMap:     &FetchResult{Content: []byte("rules"), Perm: 0o644, ContentHash: "before"},
	}
	before, err := sources.Hash()
	require.NoError(t, err)
	sources.ConfigMap.Perm = 0o600
	sources.ConfigMap.ContentHash = "after"
	after, err := sources.Hash()
	require.NoError(t, err)
	require.Equal(t, before, after)
}
