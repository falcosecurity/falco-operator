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
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

// KindInfo is everything the operator knows about one artifact kind, in one value.
//
// Every lookup of it returns an error for a kind that is not registered, rather than a plausible
// default: a kind nobody registered cannot be silently mistaken for one that is.
type KindInfo struct {
	// Kind is the CR kind, "Rulesfile": the one identity of an artifact kind across the operator.
	Kind Kind
	// Dir selects this kind's directory out of the set the store was configured with.
	Dir func(ArtifactDirs) string
	// Sources are the mediums an artifact of this kind can be installed from, in the order a
	// status listing reports them.
	Sources []Medium
	// Perm is the mode the kind's files are written with. Plugins need the execute bit for
	// dlopen; rules and config files are read-only for Falco.
	Perm fs.FileMode
	// TracksDependencies is whether an installed source of this kind carries artifact metadata
	// whose dependencies the node registers. It decides two things: that writing a source also
	// commits a dependency revision, and that the node confirms an installed source by
	// re-checking that metadata rather than by hashing the file on disk.
	TracksDependencies bool
	// DeclaresRequirements is whether an artifact of this kind carries requirements on Falco in its metadata. On a
	// node that only advises on requirements, such an artifact is programmed without waiting for the instance
	// operator to observe its generation, and DependenciesSatisfied does not gate it.
	DeclaresRequirements bool
	// Glob matches the kind's files in its directory, for a scan that has no list of names.
	Glob string
	// ConfigMapKey is the data key a ConfigMap source of this kind is read from. Empty when the kind has
	// no ConfigMap source.
	ConfigMapKey string
	// OCIArtifactType is the type an OCI artifact of this kind must have when pulled. Unset when the kind
	// has no OCI source.
	OCIArtifactType puller.ArtifactType
	// PlatformSpecific is whether an OCI artifact of this kind is built per operating system and
	// architecture, so that it is cached, served and fetched for one platform.
	PlatformSpecific bool
	// FileName and ParseName are inverses, in the sense that ParseName recovers whatever
	// FileName encoded: applying FileName to ParseName's output reproduces the name it was
	// given. Plugin filenames encode neither medium nor priority, so for that kind ParseName
	// answers with the only values a plugin file can have rather than with what was passed.
	FileName  func(name string, medium Medium, artifactPriority int32) (string, error)
	ParseName func(base string) (ParsedName, bool)
}

// ParsedName is what one of this operator's filenames encodes. A scan of a directory recovers it
// without consulting any record of what was written, which is what lets a warm sync find files
// whose parent CR is gone.
type ParsedName struct {
	Name     string
	Medium   Medium
	Priority int32
}

// Accepts reports whether an artifact of this kind can be installed from medium.
func (k *KindInfo) Accepts(medium Medium) bool {
	return slices.Contains(k.Sources, medium)
}

// SourceInfo is everything known about one medium.
type SourceInfo struct {
	// Medium is the source's identity, as it appears in a filename and in installed status.
	Medium Medium
	// SubPriority orders the sources of a single artifact against each other within one
	// priority. It is a fact about the source, not about any kind that accepts it.
	SubPriority int32
	// Deferred is whether the bytes come from the artifact server, pinned to a digest the
	// compatibility decision produced, rather than being available up front from a spec field
	// or an informer-cached ConfigMap. A deferred source is never fetched for an artifact the
	// decision blocked, nor when the node can confirm what it already holds.
	Deferred bool
}

// sources is the registry of mediums.
var sources = []SourceInfo{
	{Medium: MediumOCI, SubPriority: priority.OCISubPriority, Deferred: true},
	{Medium: MediumConfigMap, SubPriority: priority.CMSubPriority},
	{Medium: MediumInline, SubPriority: priority.InLineRulesSubPriority},
}

// kinds is the registry of artifact kinds. Adding a kind to the node is adding an entry here.
var kinds = []KindInfo{
	{
		Kind:                 KindRulesfile,
		Dir:                  func(d ArtifactDirs) string { return d.Rulesfile },
		Sources:              []Medium{MediumOCI, MediumInline, MediumConfigMap},
		Perm:                 0o644,
		TracksDependencies:   true,
		DeclaresRequirements: true,
		Glob:                 "*.yaml",
		ConfigMapKey:         commonv1alpha1.ConfigMapRulesKey,
		OCIArtifactType:      puller.Rulesfile,
		FileName:             yamlFileName,
		ParseName:            parseYAMLFileName,
	},
	{
		Kind:         KindConfig,
		Dir:          func(d ArtifactDirs) string { return d.Config },
		Sources:      []Medium{MediumInline, MediumConfigMap},
		Perm:         0o644,
		Glob:         "*.yaml",
		ConfigMapKey: commonv1alpha1.ConfigMapConfigKey,
		FileName:     yamlFileName,
		ParseName:    parseYAMLFileName,
	},
	{
		Kind:                 KindPlugin,
		Dir:                  func(d ArtifactDirs) string { return d.Plugin },
		Sources:              []Medium{MediumOCI},
		Perm:                 0o755,
		DeclaresRequirements: true,
		Glob:                 "*.so",
		OCIArtifactType:      puller.Plugin,
		PlatformSpecific:     true,
		FileName:             pluginFileName,
		ParseName:            parsePluginFileName,
	},
}

// Kinds returns every registered kind, in a stable order. Callers that need to do something for
// each kind iterate this rather than writing the list out again.
func Kinds() []KindInfo {
	return slices.Clone(kinds)
}

// InfoForKind returns the KindInfo for a kind.
func InfoForKind(kind Kind) (KindInfo, error) {
	for i := range kinds {
		if kinds[i].Kind == kind {
			return kinds[i], nil
		}
	}
	return KindInfo{}, fmt.Errorf("unknown artifact kind %q", kind)
}

// InfoForMedium returns the SourceInfo for a medium.
func InfoForMedium(medium Medium) (SourceInfo, error) {
	for _, source := range sources {
		if source.Medium == medium {
			return source, nil
		}
	}
	return SourceInfo{}, fmt.Errorf("unknown artifact medium %q", medium)
}

// yamlFilenamePattern matches the "PP-SS-{name}-{medium}.yaml" convention yamlFileName produces,
// recovering priority, name, and medium from the filename alone. The medium alternatives are
// built from the registered sources rather than written out, so a newly registered source cannot
// end up written to disk in a form nothing can read back.
var yamlFilenamePattern = regexp.MustCompile(
	`^(\d{2})-\d{2}-(.+)-(` + strings.Join(registeredMediumPatterns(), "|") + `)\.yaml$`)

func registeredMediumPatterns() []string {
	patterns := make([]string, 0, len(sources))
	for _, source := range sources {
		patterns = append(patterns, regexp.QuoteMeta(string(source.Medium)))
	}
	return patterns
}

// yamlFileName names a rules or config file, encoding the load order the artifact's priority and
// its source's sub-priority give it.
func yamlFileName(name string, medium Medium, artifactPriority int32) (string, error) {
	source, err := InfoForMedium(medium)
	if err != nil {
		return "", err
	}
	return priority.NameFromPriorityAndSubPriority(artifactPriority, source.SubPriority,
		fmt.Sprintf("%s-%s.yaml", name, medium)), nil
}

func parseYAMLFileName(base string) (ParsedName, bool) {
	sub := yamlFilenamePattern.FindStringSubmatch(base)
	if sub == nil {
		return ParsedName{}, false
	}
	var artifactPriority int32
	if _, err := fmt.Sscanf(sub[1], "%d", &artifactPriority); err != nil {
		return ParsedName{}, false
	}
	return ParsedName{Name: sub[2], Medium: Medium(sub[3]), Priority: artifactPriority}, true
}

// pluginFileName names a plugin binary. Neither medium nor priority appears in it: a plugin has
// only one source and is always installed at the default priority, and the name is what Falco's
// plugins-config library_path has to match.
func pluginFileName(name string, _ Medium, _ int32) (string, error) {
	return name + ".so", nil
}

func parsePluginFileName(base string) (ParsedName, bool) {
	if !strings.HasSuffix(base, ".so") {
		return ParsedName{}, false
	}
	return ParsedName{
		Name:     strings.TrimSuffix(base, ".so"),
		Medium:   MediumOCI,
		Priority: priority.DefaultPriority,
	}, true
}
