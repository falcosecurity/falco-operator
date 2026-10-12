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
	"io/fs"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// TestKinds_Registrations pins what each kind is registered as. The registry is the only
// statement of these facts, so an accidental edit to one of them should fail here rather than
// change how files are named, where they are written, or what modes they are written with.
func TestKinds_Registrations(t *testing.T) {
	want := map[Kind]struct {
		dir          string
		sources      []Medium
		perm         fs.FileMode
		tracksDeps   bool
		glob         string
		configMapKey string
		ociType      puller.ArtifactType
		perPlatform  bool
		sampleName   string
		sampleMedium Medium
		samplePrio   int32
		sampleFile   string
	}{
		KindRulesfile: {
			dir: "/rules", sources: []Medium{MediumOCI, MediumInline, MediumConfigMap},
			perm: 0o644, tracksDeps: true, glob: "*.yaml",
			configMapKey: commonv1alpha1.ConfigMapRulesKey, ociType: puller.Rulesfile,
			sampleName: "my-rules", sampleMedium: MediumOCI, samplePrio: 50,
			sampleFile: "50-01-my-rules-oci.yaml",
		},
		KindConfig: {
			dir: "/config", sources: []Medium{MediumInline, MediumConfigMap},
			perm: 0o644, glob: "*.yaml",
			configMapKey: commonv1alpha1.ConfigMapConfigKey,
			sampleName:   "my-config", sampleMedium: MediumConfigMap, samplePrio: 20,
			sampleFile: "20-02-my-config-configmap.yaml",
		},
		KindPlugin: {
			dir: "/plugins", sources: []Medium{MediumOCI},
			perm: 0o755, glob: "*.so",
			ociType: puller.Plugin, perPlatform: true,
			sampleName: "my-plugin", sampleMedium: MediumOCI, samplePrio: priority.DefaultPriority,
			sampleFile: "my-plugin.so",
		},
	}

	dirs := ArtifactDirs{Rulesfile: "/rules", Config: "/config", Plugin: "/plugins"}
	kinds := Kinds()
	require.Len(t, kinds, len(want), "a kind was added or removed without updating this table")

	for _, info := range kinds {
		expected, ok := want[info.Kind]
		require.True(t, ok, "unregistered kind %q", info.Kind)

		assert.Equal(t, expected.dir, info.Dir(dirs))
		assert.Equal(t, expected.sources, info.Sources, "source order is what a status listing reports")
		assert.Equal(t, expected.perm, info.Perm)
		assert.Equal(t, expected.tracksDeps, info.TracksDependencies,
			"only a kind whose files carry artifact metadata registers dependencies from them")
		assert.Equal(t, expected.glob, info.Glob)
		assert.Equal(t, expected.configMapKey, info.ConfigMapKey)
		assert.Equal(t, expected.ociType, info.OCIArtifactType)
		assert.Equal(t, expected.perPlatform, info.PlatformSpecific)
		assert.Equal(t, expected.configMapKey != "", info.Accepts(MediumConfigMap),
			"a ConfigMap data key exactly when the kind has a ConfigMap source")
		assert.Equal(t, expected.ociType != "", info.Accepts(MediumOCI),
			"an OCI artifact type exactly when the kind has an OCI source")

		base, err := info.FileName(expected.sampleName, expected.sampleMedium, expected.samplePrio)
		require.NoError(t, err)
		assert.Equal(t, expected.sampleFile, base, "filename convention for %s", info.Kind)

		for _, medium := range []Medium{MediumOCI, MediumInline, MediumConfigMap} {
			assert.Equal(t, slices.Contains(expected.sources, medium), info.Accepts(medium),
				"%s accepting %s", info.Kind, medium)
		}
	}
}

// TestSources_Registrations pins the source table: sub-priority orders one artifact's sources
// against each other, and Deferred decides whether the bytes are available before the
// compatibility decision or fetched from the artifact server after it.
func TestSources_Registrations(t *testing.T) {
	for _, tc := range []struct {
		medium      Medium
		subPriority int32
		deferred    bool
	}{
		{MediumOCI, priority.OCISubPriority, true},
		{MediumConfigMap, priority.CMSubPriority, false},
		{MediumInline, priority.InLineRulesSubPriority, false},
	} {
		source, err := InfoForMedium(tc.medium)
		require.NoError(t, err)
		assert.Equal(t, tc.subPriority, source.SubPriority, string(tc.medium))
		assert.Equal(t, tc.deferred, source.Deferred, string(tc.medium))
	}
}

// TestKindInfo_NamesRoundTripThroughParseName checks the invariant the store and the disk scan
// share: the store writes a filename and the scan parses it back.
//
// The property that holds for every kind is that whatever ParseName recovers regenerates the same
// filename. Plugin filenames encode neither medium nor priority, so they satisfy it by being
// canonical rather than by preserving what they were given; the kinds that do encode both are
// checked for exact recovery below.
func TestKindInfo_NamesRoundTripThroughParseName(t *testing.T) {
	// Names chosen to strain the parse: a hyphen, and a suffix that looks like a medium.
	names := []string{"my-artifact", "rules-oci", "a"}

	for _, info := range Kinds() {
		for _, medium := range info.Sources {
			for artifactPriority := int32(priority.MinPriority); artifactPriority <= priority.MaxPriority; artifactPriority++ {
				for _, name := range names {
					base, err := info.FileName(name, medium, artifactPriority)
					require.NoError(t, err)

					parsed, ok := info.ParseName(base)
					require.True(t, ok, "%s cannot parse the name it just wrote: %q", info.Kind, base)
					assert.Equal(t, name, parsed.Name, "%s: %q", info.Kind, base)

					again, err := info.FileName(parsed.Name, parsed.Medium, parsed.Priority)
					require.NoError(t, err)
					assert.Equal(t, base, again, "%s: parsing %q does not regenerate it", info.Kind, base)
				}
			}
		}
	}
}

// TestKindInfo_YAMLNamesRecoverMediumAndPriority is the stronger half of the round trip, for the
// kinds whose filenames carry the load order. A warm sync recovers a file's medium and priority
// from its name alone, so these have to come back exactly as they went in.
func TestKindInfo_YAMLNamesRecoverMediumAndPriority(t *testing.T) {
	for _, kind := range []Kind{KindRulesfile, KindConfig} {
		info, err := InfoForKind(kind)
		require.NoError(t, err)

		for _, medium := range info.Sources {
			for artifactPriority := int32(priority.MinPriority); artifactPriority <= priority.MaxPriority; artifactPriority++ {
				base, err := info.FileName("my-artifact", medium, artifactPriority)
				require.NoError(t, err)

				parsed, ok := info.ParseName(base)
				require.True(t, ok, base)
				assert.Equal(t, "my-artifact", parsed.Name)
				assert.Equal(t, medium, parsed.Medium, base)
				assert.Equal(t, artifactPriority, parsed.Priority, base)
			}
		}
	}
}

// TestKindInfo_ParseNameRejectsForeignFiles keeps the scan tolerant of files it did not write: a
// partial write or somebody else's file is skipped, not an error.
func TestKindInfo_ParseNameRejectsForeignFiles(t *testing.T) {
	rulesfile, err := InfoForKind("Rulesfile")
	require.NoError(t, err)
	plugin, err := InfoForKind("Plugin")
	require.NoError(t, err)

	for _, base := range []string{
		"50-01-my-rules-oci.yaml.tmp",
		"my-rules.yaml",
		"50-01-my-rules-smtp.yaml",
		"5-01-my-rules-oci.yaml",
		"README",
	} {
		_, ok := rulesfile.ParseName(base)
		assert.False(t, ok, "Rulesfile should not claim %q", base)
	}

	_, ok := plugin.ParseName("my-plugin.yaml")
	assert.False(t, ok)
}

// TestRegistryLookups_RejectUnregisteredInputs is the whole point of the registry: a kind or a
// medium nobody registered is an error, never a plausible default answer.
func TestRegistryLookups_RejectUnregisteredInputs(t *testing.T) {
	_, err := InfoForKind("Tracer")
	require.Error(t, err)

	_, err = InfoForKind(Kind("rulesfile"))
	require.Error(t, err, "a kind is spelled as its CRD's Kind")

	_, err = InfoForMedium(Medium("smtp"))
	require.Error(t, err)

	_, err = PermFor(Kind("Tracer"))
	require.Error(t, err)

	dirs := ArtifactDirs{Rulesfile: "/rules", Config: "/config", Plugin: "/plugins"}
	_, err = ArtifactPath(dirs, "x", 50, MediumOCI, Kind("tracer"))
	require.Error(t, err, "an unregistered kind used to be written to the working directory")

	_, err = (&LocalStore{Dirs: dirs}).ScanAll(t.Context(), Kind("tracer"))
	require.Error(t, err, "an unregistered kind used to scan as an empty node")
}

// TestArtifactPath_RejectsAMediumTheKindDoesNotAccept checks that a kind/medium pair that should not
// exist is refused, rather than given a sub-priority that invents a load order for it.
func TestArtifactPath_RejectsAMediumTheKindDoesNotAccept(t *testing.T) {
	dirs := ArtifactDirs{Rulesfile: "/rules", Config: "/config", Plugin: "/plugins"}

	_, err := ArtifactPath(dirs, "my-config", 99, MediumOCI, KindConfig)
	require.ErrorContains(t, err, "cannot be installed from medium")

	_, err = ArtifactPath(dirs, "my-plugin", 50, MediumInline, KindPlugin)
	require.ErrorContains(t, err, "cannot be installed from medium")

	path, err := ArtifactPath(dirs, "my-config", 99, MediumInline, KindConfig)
	require.NoError(t, err)
	assert.Equal(t, "/config/99-03-my-config-inline.yaml", path)
}
