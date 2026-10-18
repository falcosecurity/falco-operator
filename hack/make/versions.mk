# Every pinned tool/dependency version used by hack/make/tools.mk and hack/make/cluster-addons.mk, in one
# place so Renovate can find and bump all of them from a single file (see the customManager in
# .github/renovate.json5, which reads the "# renovate: datasource=... depName=..." comment
# above each line below — that comment is what tells Renovate which upstream repo/release feed
# to check, since it can't infer that from a bare "HELM_VERSION" variable name).
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
KUBECTL_VERSION ?= v1.36.4
# renovate: datasource=github-releases depName=kubernetes-sigs/kind
KIND_VERSION ?= v0.32.0
# Keep the node image aligned with the Chainsaw clusters and KUBECTL_VERSION.
KIND_NODE_IMAGE ?= kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5
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
# renovate: datasource=go depName=sigs.k8s.io/controller-tools
CONTROLLER_GEN_VERSION ?= v0.17.0
# renovate: datasource=go depName=golang.org/x/tools
DEADCODE_VERSION ?= v0.49.0
# Keep in sync with the golangci-lint-action version in .github/workflows/lint.yml.
# renovate: datasource=go depName=github.com/golangci/golangci-lint/v2
GOLANGCI_LINT_VERSION ?= v2.11.1
# renovate: datasource=go depName=github.com/daixiang0/gci
GCI_VERSION ?= v0.13.7
# renovate: datasource=go depName=github.com/google/addlicense
ADDLICENSE_VERSION ?= v1.1.1
# renovate: datasource=go depName=sigs.k8s.io/controller-runtime/tools/setup-envtest
SETUP_ENVTEST_VERSION ?= v0.0.0-20260305142021-f9589b9f2b9d
# renovate: datasource=go depName=github.com/norwoodj/helm-docs
HELM_DOCS_VERSION ?= v1.11.0
