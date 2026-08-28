# Every pinned tool/dependency version used by hack/make/tools.mk and hack/make/cluster-addons.mk, in one
# place so Renovate can find and bump all of them from a single file (see the customManager in
# .github/renovate.json5, which reads the "# renovate: datasource=... depName=..." comment
# above each line below — that comment is what tells Renovate which upstream repo/release feed
# to check, since it can't infer that from a bare "HELM_VERSION" variable name).
#
# Go-based tools (controller-gen, golangci-lint, gci, addlicense, helm-docs, setup-envtest)
# don't need an entry here: they're pinned in go.mod's own `tool` block instead, which
# Dependabot/Renovate already understand natively as part of the Go module graph.
#
# All versions here keep their "v" prefix (even ones like KWOK/telepresence whose own docs
# often show it bare) so every line has the exact same shape for the regex above, and so a
# Renovate-driven bump can never accidentally double up or drop the prefix. Exception:
# FALCO_VERSION below is genuinely bare — Falco's own GitHub release tags and Docker Hub image
# tags both drop the "v" (e.g. "0.44.1", not "v0.44.1"), and it's used directly as a Docker tag
# suffix with nothing prepending a "v" of its own, so there's no double-prefix risk to guard
# against here the way there was for KWOK/telepresence's URL construction.

# renovate: datasource=github-releases depName=helm/helm
HELM_VERSION ?= v3.20.2
# renovate: datasource=github-releases depName=kubernetes/kubernetes
KUBECTL_VERSION ?= v1.31.0
# renovate: datasource=github-releases depName=kubernetes-sigs/kind
KIND_VERSION ?= v0.32.0
# renovate: datasource=github-releases depName=kyverno/chainsaw
CHAINSAW_VERSION ?= v0.2.15
# renovate: datasource=github-releases depName=telepresenceio/telepresence
TELEPRESENCE_VERSION ?= v2.21.1
# renovate: datasource=github-releases depName=falcosecurity/falcoctl
FALCOCTL_VERSION ?= v0.13.0
# renovate: datasource=github-releases depName=cert-manager/cert-manager
CERT_MANAGER_VERSION ?= v1.16.2
# renovate: datasource=github-releases depName=cert-manager/trust-manager
TRUST_MANAGER_VERSION ?= v0.13.0
# renovate: datasource=github-releases depName=kubernetes-sigs/kwok
KWOK_VERSION ?= v0.8.0
# renovate: datasource=github-releases depName=falcosecurity/falco
FALCO_VERSION ?= 0.44.1
