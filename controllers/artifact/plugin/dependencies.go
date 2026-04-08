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

package plugin

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	commonv1alpha1 "github.com/falcosecurity/falco-operator/api/common/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/depresolver"
	"github.com/falcosecurity/falco-operator/internal/pkg/oci/puller"
	"github.com/falcosecurity/falco-operator/internal/pkg/priority"
)

const (
	dependencyManagedLabelKey   = "artifact.falcosecurity.dev/dependency-managed"
	dependencyManagedLabelValue = "true"
)

func (r *PluginReconciler) ensurePluginDependencies(ctx context.Context, plugin *artifactv1alpha1.Plugin) error {
	if plugin.Spec.OCIArtifact == nil {
		return r.cleanupManagedDependencies(ctx, plugin, map[string]struct{}{}, map[string]struct{}{})
	}

	rootRef := artifact.ResolveReference(plugin.Spec.OCIArtifact)

	cache := make(map[string]*puller.RegistryResult)
	configResolver := func(ref string) (*puller.RegistryResult, error) {
		if res, ok := cache[ref]; ok {
			return res, nil
		}

		res, err := r.artifactManager.InspectFromReference(ctx, ref, plugin.Spec.OCIArtifact)
		if err != nil {
			return nil, err
		}
		cache[ref] = res
		return res, nil
	}

	refResolver := func(parentRef, dependencyRef string) (string, error) {
		return r.resolveDependencyReference(parentRef, dependencyRef, configResolver)
	}

	resolved, err := depresolver.Resolve(configResolver, refResolver, rootRef)
	if err != nil {
		return err
	}

	desiredPlugins := make(map[string]struct{})
	desiredRulesfiles := make(map[string]struct{})

	for _, dep := range resolved {
		if dep.Ref == rootRef {
			continue
		}

		depOCIArtifact, err := ociArtifactFromReference(dep.Ref, plugin.Spec.OCIArtifact)
		if err != nil {
			return err
		}

		switch dep.Type {
		case puller.Plugin:
			name := dependencyResourceName(dep.Type, dep.Config.Name, dep.Ref)
			desiredPlugins[name] = struct{}{}
			if err := r.ensureDependencyPlugin(ctx, plugin, name, dep.Config.Name, depOCIArtifact); err != nil {
				return err
			}
		case puller.Rulesfile:
			name := dependencyResourceName(dep.Type, dep.Config.Name, dep.Ref)
			desiredRulesfiles[name] = struct{}{}
			if err := r.ensureDependencyRulesfile(ctx, plugin, name, depOCIArtifact); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported dependency artifact type %q for dependency %q", dep.Type, dep.Ref)
		}
	}

	return r.cleanupManagedDependencies(ctx, plugin, desiredPlugins, desiredRulesfiles)
}

func (r *PluginReconciler) ensureDependencyPlugin(
	ctx context.Context,
	root *artifactv1alpha1.Plugin,
	name, configName string,
	depOCIArtifact *commonv1alpha1.OCIArtifact,
) error {
	obj := &artifactv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: root.Namespace}}
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, obj, func() error {
		if obj.Labels == nil {
			obj.Labels = map[string]string{}
		}
		obj.Labels[dependencyManagedLabelKey] = dependencyManagedLabelValue
		ensureOwnerReference(obj, root)

		obj.Spec.OCIArtifact = depOCIArtifact
		obj.Spec.Selector = root.Spec.Selector.DeepCopy()
		obj.Spec.Config = &artifactv1alpha1.PluginConfig{Name: configName}
		return nil
	})
	return err
}

func (r *PluginReconciler) ensureDependencyRulesfile(
	ctx context.Context,
	root *artifactv1alpha1.Plugin,
	name string,
	depOCIArtifact *commonv1alpha1.OCIArtifact,
) error {
	obj := &artifactv1alpha1.Rulesfile{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: root.Namespace}}
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, obj, func() error {
		if obj.Labels == nil {
			obj.Labels = map[string]string{}
		}
		obj.Labels[dependencyManagedLabelKey] = dependencyManagedLabelValue
		ensureOwnerReference(obj, root)

		obj.Spec.OCIArtifact = depOCIArtifact
		obj.Spec.Selector = root.Spec.Selector.DeepCopy()
		obj.Spec.Priority = priority.DefaultPriority
		obj.Spec.ConfigMapRef = nil
		obj.Spec.InlineRules = nil
		return nil
	})
	return err
}

func (r *PluginReconciler) cleanupManagedDependencies(
	ctx context.Context,
	root *artifactv1alpha1.Plugin,
	desiredPlugins, desiredRulesfiles map[string]struct{},
) error {
	if err := r.cleanupManagedDependencyPlugins(ctx, root, desiredPlugins); err != nil {
		return err
	}
	return r.cleanupManagedDependencyRulesfiles(ctx, root, desiredRulesfiles)
}

func (r *PluginReconciler) cleanupManagedDependencyPlugins(ctx context.Context, root *artifactv1alpha1.Plugin, desired map[string]struct{}) error {
	logger := log.FromContext(ctx)
	list := &artifactv1alpha1.PluginList{}
	if err := r.List(ctx, list,
		client.InNamespace(root.Namespace),
		client.MatchingLabels{dependencyManagedLabelKey: dependencyManagedLabelValue},
	); err != nil {
		return err
	}

	for i := range list.Items {
		item := &list.Items[i]
		if !hasOwnerReference(item, root) {
			continue
		}
		if _, ok := desired[item.Name]; ok {
			continue
		}

		removeOwnerReference(item, root)
		if len(item.GetOwnerReferences()) == 0 {
			logger.V(3).Info("Deleting unmanaged dependency plugin", "name", item.Name)
			if err := r.Delete(ctx, item); client.IgnoreNotFound(err) != nil {
				return err
			}
			continue
		}

		if err := r.Update(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (r *PluginReconciler) cleanupManagedDependencyRulesfiles(ctx context.Context, root *artifactv1alpha1.Plugin, desired map[string]struct{}) error {
	logger := log.FromContext(ctx)
	list := &artifactv1alpha1.RulesfileList{}
	if err := r.List(ctx, list,
		client.InNamespace(root.Namespace),
		client.MatchingLabels{dependencyManagedLabelKey: dependencyManagedLabelValue},
	); err != nil {
		return err
	}

	for i := range list.Items {
		item := &list.Items[i]
		if !hasOwnerReference(item, root) {
			continue
		}
		if _, ok := desired[item.Name]; ok {
			continue
		}

		removeOwnerReference(item, root)
		if len(item.GetOwnerReferences()) == 0 {
			logger.V(3).Info("Deleting unmanaged dependency rulesfile", "name", item.Name)
			if err := r.Delete(ctx, item); client.IgnoreNotFound(err) != nil {
				return err
			}
			continue
		}

		if err := r.Update(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (r *PluginReconciler) resolveDependencyReference(
	parentRef, dependencyRef string,
	configResolver func(ref string) (*puller.RegistryResult, error),
) (string, error) {
	depName, depVersion, err := parseDependencyRef(dependencyRef)
	if err != nil {
		return "", err
	}

	candidates, err := dependencyReferenceCandidates(parentRef, depName, depVersion)
	if err != nil {
		return "", err
	}

	var firstErr error
	for _, candidate := range candidates {
		if _, err := configResolver(candidate); err == nil {
			return candidate, nil
		} else if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = fmt.Errorf("no candidates generated")
	}
	return "", fmt.Errorf("unable to resolve dependency reference %q from parent %q: %w", dependencyRef, parentRef, firstErr)
}

func parseDependencyRef(ref string) (string, string, error) {
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon <= lastSlash || lastColon == len(ref)-1 {
		return "", "", fmt.Errorf("invalid dependency reference %q, expected format name:version", ref)
	}
	return ref[:lastColon], ref[lastColon+1:], nil
}

func dependencyReferenceCandidates(parentRef, depName, depVersion string) ([]string, error) {
	parentRegistry, parentRepository, _, err := splitReference(parentRef)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	addRef := func(ref string, refs *[]string) {
		if _, ok := seen[ref]; ok {
			return
		}
		seen[ref] = struct{}{}
		*refs = append(*refs, ref)
	}

	var refs []string
	if !strings.Contains(depName, "/") {
		parentDir := path.Dir(parentRepository)
		if parentDir == "." {
			parentDir = ""
		}
		repos := []string{}
		if parentDir == "" {
			repos = append(repos, depName)
		} else {
			repos = append(repos, path.Join(parentDir, depName))
		}

		if prefix, _, ok := strings.Cut(parentRepository, "/ruleset/"); ok {
			repos = append(repos, path.Join(prefix, "plugin", depName))
		}
		if prefix, _, ok := strings.Cut(parentRepository, "/plugin/"); ok {
			repos = append(repos, path.Join(prefix, "ruleset", depName))
			if strings.HasSuffix(depName, "-rules") {
				repos = append(repos, path.Join(prefix, "ruleset", strings.TrimSuffix(depName, "-rules")))
			}
		}

		for _, repo := range repos {
			addRef(buildReference(parentRegistry, repo, depVersion), &refs)
		}
	}

	if len(refs) == 0 {
		return nil, fmt.Errorf("no reference candidates generated for dependency %q from parent %q", depName, parentRef)
	}

	return refs, nil
}

func buildReference(registry, repository, version string) string {
	if strings.HasPrefix(version, "sha256:") {
		return registry + "/" + repository + "@" + version
	}
	return registry + "/" + repository + ":" + version
}

func splitReference(ref string) (string, string, string, error) {
	firstSlash := strings.Index(ref, "/")
	if firstSlash <= 0 || firstSlash == len(ref)-1 {
		return "", "", "", fmt.Errorf("invalid reference %q", ref)
	}

	registry := ref[:firstSlash]
	remainder := ref[firstSlash+1:]

	if at := strings.LastIndex(remainder, "@"); at != -1 {
		repository := remainder[:at]
		version := remainder[at+1:]
		if repository == "" || version == "" {
			return "", "", "", fmt.Errorf("invalid reference %q", ref)
		}
		return registry, repository, version, nil
	}

	lastSlash := strings.LastIndex(remainder, "/")
	lastColon := strings.LastIndex(remainder, ":")
	if lastColon > lastSlash {
		repository := remainder[:lastColon]
		version := remainder[lastColon+1:]
		if repository == "" || version == "" {
			return "", "", "", fmt.Errorf("invalid reference %q", ref)
		}
		return registry, repository, version, nil
	}

	if remainder == "" {
		return "", "", "", fmt.Errorf("invalid reference %q", ref)
	}
	return registry, remainder, puller.DefaultTag, nil
}

func dependencyResourceName(artifactType puller.ArtifactType, name, ref string) string {
	prefix := "dep-art"
	switch artifactType {
	case puller.Plugin:
		prefix = "dep-plg"
	case puller.Rulesfile:
		prefix = "dep-rul"
	}

	base := sanitizeName(name)
	if len(base) > 40 {
		base = base[:40]
	}

	hash := sha1.Sum([]byte(ref)) //nolint:gosec // not used for security purposes
	return fmt.Sprintf("%s-%s-%s", prefix, base, hex.EncodeToString(hash[:])[:10])
}

func sanitizeName(in string) string {
	in = strings.ToLower(in)
	var b strings.Builder
	prevDash := false
	for _, r := range in {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if valid {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteRune('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "artifact"
	}
	return out
}

func ociArtifactFromReference(ref string, source *commonv1alpha1.OCIArtifact) (*commonv1alpha1.OCIArtifact, error) {
	registry, repository, version, err := splitReference(ref)
	if err != nil {
		return nil, err
	}

	registryCfg := cloneRegistryConfig(source)
	if registryCfg == nil {
		registryCfg = &commonv1alpha1.RegistryConfig{}
	}
	registryCfg.Name = registry

	return &commonv1alpha1.OCIArtifact{
		Image: commonv1alpha1.ImageSpec{
			Repository: repository,
			Tag:        version,
		},
		Registry: registryCfg,
	}, nil
}

func cloneRegistryConfig(source *commonv1alpha1.OCIArtifact) *commonv1alpha1.RegistryConfig {
	if source == nil || source.Registry == nil {
		return nil
	}

	src := source.Registry
	dst := &commonv1alpha1.RegistryConfig{
		Name: src.Name,
	}
	if src.Auth != nil {
		dst.Auth = &commonv1alpha1.RegistryAuth{}
		if src.Auth.SecretRef != nil {
			dst.Auth.SecretRef = &commonv1alpha1.SecretRef{Name: src.Auth.SecretRef.Name}
		}
	}
	if src.PlainHTTP != nil {
		v := *src.PlainHTTP
		dst.PlainHTTP = &v
	}
	if src.TLS != nil {
		dst.TLS = &commonv1alpha1.TLSConfig{InsecureSkipVerify: src.TLS.InsecureSkipVerify}
	}

	return dst
}

func ensureOwnerReference(obj metav1.Object, owner *artifactv1alpha1.Plugin) {
	refs := obj.GetOwnerReferences()
	for _, ref := range refs {
		if ownerRefMatches(ref, owner) {
			return
		}
	}
	obj.SetOwnerReferences(append(refs, dependencyOwnerReference(owner)))
}

func hasOwnerReference(obj metav1.Object, owner *artifactv1alpha1.Plugin) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if ownerRefMatches(ref, owner) {
			return true
		}
	}
	return false
}

func removeOwnerReference(obj metav1.Object, owner *artifactv1alpha1.Plugin) {
	refs := obj.GetOwnerReferences()
	out := make([]metav1.OwnerReference, 0, len(refs))
	for _, ref := range refs {
		if ownerRefMatches(ref, owner) {
			continue
		}
		out = append(out, ref)
	}
	obj.SetOwnerReferences(out)
}

func dependencyOwnerReference(owner *artifactv1alpha1.Plugin) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: artifactv1alpha1.GroupVersion.String(),
		Kind:       "Plugin",
		Name:       owner.Name,
		UID:        owner.UID,
	}
}

func ownerRefMatches(ref metav1.OwnerReference, owner *artifactv1alpha1.Plugin) bool {
	if ref.APIVersion != artifactv1alpha1.GroupVersion.String() || ref.Kind != "Plugin" || ref.Name != owner.Name {
		return false
	}
	if owner.UID == "" {
		return true
	}
	return ref.UID == owner.UID
}
