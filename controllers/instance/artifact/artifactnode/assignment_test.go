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

package artifactnode

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
)

func cand(kind artifactv1alpha1.ArtifactKind, name, uid string, created metav1.Time) candidate {
	return candidate{ref: ref(kind, name, uid), created: created}
}

func withMeta(name string, created metav1.Time) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name), CreationTimestamp: created}
}

func refsOf(cands []candidate) (out refs) {
	for i := range cands {
		out = append(out, cands[i].ref)
	}
	return out
}

func TestSelects(t *testing.T) {
	nodeLabels := map[string]string{"pool": "gpu", "zone": "a"}
	expr := func(key string, op metav1.LabelSelectorOperator, values ...string) *metav1.LabelSelector {
		return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: key, Operator: op, Values: values}}}
	}

	tests := []struct {
		name    string
		sel     *metav1.LabelSelector
		want    bool
		wantErr bool
	}{
		{name: "a nil selector selects every node", sel: nil, want: true},
		{name: "an empty selector selects every node", sel: &metav1.LabelSelector{}, want: true},
		{name: "matchLabels that match", sel: selecting("gpu"), want: true},
		{name: "matchLabels that do not match", sel: selecting("cpu")},
		{name: "In with a listed value", sel: expr("zone", metav1.LabelSelectorOpIn, "a", "b"), want: true},
		{name: "In without the value", sel: expr("zone", metav1.LabelSelectorOpIn, "b")},
		{name: "NotIn without the value", sel: expr("zone", metav1.LabelSelectorOpNotIn, "b"), want: true},
		{name: "NotIn with the value", sel: expr("zone", metav1.LabelSelectorOpNotIn, "a")},
		{name: "Exists with the label", sel: expr("pool", metav1.LabelSelectorOpExists), want: true},
		{name: "Exists without the label", sel: expr("rack", metav1.LabelSelectorOpExists)},
		{name: "DoesNotExist without the label", sel: expr("rack", metav1.LabelSelectorOpDoesNotExist), want: true},
		{name: "DoesNotExist with the label", sel: expr("pool", metav1.LabelSelectorOpDoesNotExist)},
		{name: "an invalid operator", sel: expr("zone", "Bogus"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selects(tt.sel, nodeLabels)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCandidatesForNode(t *testing.T) {
	nodeLabels := map[string]string{"pool": "gpu"}
	bad := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "pool", Operator: "Bogus"}}}
	rulesfile := func(name string, sel *metav1.LabelSelector, created metav1.Time) artifactv1alpha1.Rulesfile {
		return artifactv1alpha1.Rulesfile{ObjectMeta: withMeta(name, created), Spec: artifactv1alpha1.RulesfileSpec{Selector: sel}}
	}
	plugin := func(name string, sel *metav1.LabelSelector) artifactv1alpha1.Plugin {
		return artifactv1alpha1.Plugin{ObjectMeta: withMeta(name, at(0)), Spec: artifactv1alpha1.PluginSpec{Selector: sel}}
	}
	config := func(name string, sel *metav1.LabelSelector) artifactv1alpha1.Config {
		return artifactv1alpha1.Config{ObjectMeta: withMeta(name, at(0)), Spec: artifactv1alpha1.ConfigSpec{Selector: sel}}
	}
	deleting := terminating(&artifactv1alpha1.Rulesfile{ObjectMeta: withMeta("gone", at(0))})

	tests := []struct {
		name        string
		nodeLabels  map[string]string
		rulesfiles  []artifactv1alpha1.Rulesfile
		plugins     []artifactv1alpha1.Plugin
		configs     []artifactv1alpha1.Config
		want        refs
		wantInvalid []string
	}{
		{
			name:       "a node without labels is selected by a nil selector",
			rulesfiles: []artifactv1alpha1.Rulesfile{rulesfile("rf", nil, at(0))},
			want:       refs{ref("Rulesfile", "rf", "uid-rf")},
		},
		{
			name:       "only the artifacts whose selector matches",
			nodeLabels: nodeLabels,
			rulesfiles: []artifactv1alpha1.Rulesfile{rulesfile("yes", selecting("gpu"), at(0)), rulesfile("no", selecting("cpu"), at(0))},
			want:       refs{ref("Rulesfile", "yes", "uid-yes")},
		},
		{
			name:       "all three kinds, in the order rulesfiles, plugins, configs",
			nodeLabels: nodeLabels,
			rulesfiles: []artifactv1alpha1.Rulesfile{rulesfile("rf", nil, at(0))},
			plugins:    []artifactv1alpha1.Plugin{plugin("pl", nil)},
			configs:    []artifactv1alpha1.Config{config("cfg", nil)},
			want:       refs{ref("Rulesfile", "rf", "uid-rf"), ref("Plugin", "pl", "uid-pl"), ref("Config", "cfg", "uid-cfg")},
		},
		{
			name:       "an artifact being deleted is not a candidate",
			nodeLabels: nodeLabels,
			rulesfiles: []artifactv1alpha1.Rulesfile{*deleting, rulesfile("live", nil, at(0))},
			want:       refs{ref("Rulesfile", "live", "uid-live")},
		},
		{
			name:        "an invalid selector is reported and does not block the others",
			nodeLabels:  nodeLabels,
			rulesfiles:  []artifactv1alpha1.Rulesfile{rulesfile("bad", bad, at(0)), rulesfile("good", nil, at(0))},
			plugins:     []artifactv1alpha1.Plugin{plugin("bad-plugin", bad)},
			configs:     []artifactv1alpha1.Config{config("bad-config", bad)},
			want:        refs{ref("Rulesfile", "good", "uid-good")},
			wantInvalid: []string{"Rulesfile/bad", "Plugin/bad-plugin", "Config/bad-config"},
		},
		{name: "nothing to select from", nodeLabels: nodeLabels},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cands, invalid := candidatesForNode(tt.nodeLabels, tt.rulesfiles, tt.plugins, tt.configs)

			assert.Equal(t, tt.wantInvalid, invalid)
			assert.Equal(t, tt.want, refsOf(cands))
		})
	}

	t.Run("a candidate carries the creation time of its artifact", func(t *testing.T) {
		cands, _ := candidatesForNode(nil, []artifactv1alpha1.Rulesfile{rulesfile("rf", nil, at(3))}, nil, nil)

		require.Len(t, cands, 1)
		assert.True(t, cands[0].created.Equal(&metav1.Time{Time: baseTime.Add(3 * time.Minute)}))
	})
}

func TestSelectArtifacts(t *testing.T) {
	overTheCap := func() (cands []candidate) {
		for i := range artifactv1alpha1.MaxNodeArtifacts + 5 {
			cands = append(cands, cand("Rulesfile", fmt.Sprintf("rf-%03d", i), fmt.Sprintf("u%d", i), at(i)))
		}
		return cands
	}

	tests := []struct {
		name         string
		existing     refs
		cands        []candidate
		limit        int
		wantSelected refs
		wantDropped  refs
	}{
		{
			name: "everything fits, sorted by kind then name",
			cands: []candidate{
				cand("Rulesfile", "b", "u3", at(0)), cand("Plugin", "z", "u2", at(0)),
				cand("Config", "a", "u1", at(0)), cand("Rulesfile", "a", "u4", at(0)),
			},
			limit: 10,
			wantSelected: refs{
				ref("Config", "a", "u1"), ref("Plugin", "z", "u2"), ref("Rulesfile", "a", "u4"), ref("Rulesfile", "b", "u3"),
			},
		},
		{
			name: "over the limit the newest are dropped",
			cands: []candidate{
				cand("Rulesfile", "old", "u1", at(1)), cand("Rulesfile", "mid", "u2", at(2)), cand("Rulesfile", "new", "u3", at(3)),
			},
			limit:        2,
			wantSelected: refs{ref("Rulesfile", "mid", "u2"), ref("Rulesfile", "old", "u1")},
			wantDropped:  refs{ref("Rulesfile", "new", "u3")},
		},
		{
			name: "equal creation times fall back to kind then name",
			cands: []candidate{
				cand("Rulesfile", "a", "u1", at(0)), cand("Plugin", "b", "u2", at(0)), cand("Plugin", "a", "u3", at(0)),
			},
			limit:        2,
			wantSelected: refs{ref("Plugin", "a", "u3"), ref("Plugin", "b", "u2")},
			wantDropped:  refs{ref("Rulesfile", "a", "u1")},
		},
		{
			name:     "entries already listed win over older newcomers",
			existing: refs{ref("Rulesfile", "installed", "u1")},
			cands: []candidate{
				cand("Rulesfile", "older-newcomer", "u2", at(1)), cand("Rulesfile", "other-newcomer", "u3", at(2)),
				cand("Rulesfile", "installed", "u1", at(9)),
			},
			limit:        2,
			wantSelected: refs{ref("Rulesfile", "installed", "u1"), ref("Rulesfile", "older-newcomer", "u2")},
			wantDropped:  refs{ref("Rulesfile", "other-newcomer", "u3")},
		},
		{
			name:     "the entries already listed are ranked among themselves like the others",
			existing: refs{ref("Rulesfile", "b", "u2"), ref("Rulesfile", "a", "u1")},
			cands: []candidate{
				cand("Rulesfile", "b", "u2", at(2)), cand("Rulesfile", "a", "u1", at(1)), cand("Rulesfile", "newcomer", "u3", at(0)),
			},
			limit:        2,
			wantSelected: refs{ref("Rulesfile", "a", "u1"), ref("Rulesfile", "b", "u2")},
			wantDropped:  refs{ref("Rulesfile", "newcomer", "u3")},
		},
		{
			name:     "an existing entry that is no longer a candidate frees its slot",
			existing: refs{ref("Rulesfile", "removed", "u1")},
			cands:    []candidate{cand("Rulesfile", "a", "u2", at(1)), cand("Rulesfile", "b", "u3", at(2))},
			limit:    2,
			wantSelected: refs{
				ref("Rulesfile", "a", "u2"), ref("Rulesfile", "b", "u3"),
			},
		},
		{
			name:     "a recreated artifact keeps its slot and takes the new uid",
			existing: refs{ref("Rulesfile", "x", "old-uid")},
			cands:    []candidate{cand("Rulesfile", "newcomer", "u2", at(1)), cand("Rulesfile", "x", "new-uid", at(9))},
			limit:    1,
			wantSelected: refs{
				ref("Rulesfile", "x", "new-uid"),
			},
			wantDropped: refs{ref("Rulesfile", "newcomer", "u2")},
		},
		{name: "no candidates selects nothing", existing: refs{ref("Rulesfile", "x", "u")}, limit: 5},
		{
			name:        "a limit of zero selects nothing",
			cands:       []candidate{cand("Rulesfile", "a", "u1", at(0))},
			limit:       0,
			wantDropped: refs{ref("Rulesfile", "a", "u1")},
		},
		{
			name:        "a negative limit selects nothing",
			cands:       []candidate{cand("Rulesfile", "a", "u1", at(0))},
			limit:       -1,
			wantDropped: refs{ref("Rulesfile", "a", "u1")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selected, dropped := selectArtifacts(tt.existing, tt.cands, tt.limit)

			assert.Equal(t, tt.wantSelected, selected)
			assert.Equal(t, tt.wantDropped, dropped)
		})
	}

	t.Run("the schema cap is respected, dropping the newest", func(t *testing.T) {
		selected, dropped := selectArtifacts(nil, overTheCap(), artifactv1alpha1.MaxNodeArtifacts)

		assert.Len(t, selected, artifactv1alpha1.MaxNodeArtifacts)
		assert.Len(t, dropped, 5)
		assert.Equal(t, "rf-104", dropped[len(dropped)-1].Name)
	})

	t.Run("the candidates given are not reordered", func(t *testing.T) {
		cands := []candidate{cand("Rulesfile", "b", "u2", at(2)), cand("Rulesfile", "a", "u1", at(1))}

		selectArtifacts(nil, cands, 1)

		assert.Equal(t, "b", cands[0].ref.Name)
	})
}

func TestSameArtifacts(t *testing.T) {
	a := refs{ref("Plugin", "p", "u1"), ref("Rulesfile", "r", "u2")}
	tests := []struct {
		name string
		a, b refs
		want bool
	}{
		{"the same, in the same order", a, refs{ref("Plugin", "p", "u1"), ref("Rulesfile", "r", "u2")}, true},
		{"the same, in another order", a, refs{ref("Rulesfile", "r", "u2"), ref("Plugin", "p", "u1")}, true},
		{"nil and empty", nil, refs{}, true},
		{"a different length", a, a[:1], false},
		{"a different uid is a different entry", a, refs{ref("Plugin", "p", "u1"), ref("Rulesfile", "r", "changed")}, false},
		{"a different name", a, refs{ref("Plugin", "p", "u1"), ref("Rulesfile", "other", "u2")}, false},
		{"a different kind", a, refs{ref("Plugin", "p", "u1"), ref("Config", "r", "u2")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sameArtifacts(tt.a, tt.b))
		})
	}

	t.Run("the arguments are not reordered", func(t *testing.T) {
		unsorted := refs{ref("Rulesfile", "r", "u2"), ref("Plugin", "p", "u1")}

		sameArtifacts(unsorted, a)

		assert.Equal(t, artifact.KindRulesfile, unsorted[0].Kind)
	})
}

// candidatesForNode takes one typed list per kind, and desiredArtifacts lists each of them: a kind added to the
// registry without a list here would never be assigned to a node.
func TestCandidatesForNode_CoversEveryRegisteredKind(t *testing.T) {
	selecting := metav1.ObjectMeta{Name: "selecting"}
	cands, invalid := candidatesForNode(nil,
		[]artifactv1alpha1.Rulesfile{{ObjectMeta: selecting}},
		[]artifactv1alpha1.Plugin{{ObjectMeta: selecting}},
		[]artifactv1alpha1.Config{{ObjectMeta: selecting}},
	)

	require.Empty(t, invalid)
	got := make([]artifactv1alpha1.ArtifactKind, 0, len(cands))
	want := make([]artifactv1alpha1.ArtifactKind, 0, len(artifact.Kinds()))
	for _, c := range cands {
		got = append(got, c.ref.Kind)
	}
	for _, info := range artifact.Kinds() {
		want = append(want, info.Kind)
	}
	assert.ElementsMatch(t, want, got)
}
