# Repo-local tool binaries: every non-Go-toolchain CLI the Makefile shells out to is downloaded
# here, into a gitignored bin/ directory, instead of assumed to be on the system PATH. This keeps
# `make` reproducible (everyone gets the exact pinned version) and never touches anything outside
# the repo. Go-based tools (controller-gen, golangci-lint, etc.) are built with `go install
# <pkg>@<version>` instead of tracked in go.mod's `tool` block, so their dependency trees don't
# end up in (and bump) the operator's own module graph.
#
# Pattern (same as kubebuilder's scaffolded Makefile / cert-manager's makefile-modules "tools"
# module): each tool is downloaded once to a version-suffixed path
# ($(LOCALBIN)/<tool>-<version>) and symlinked to a bare name ($(LOCALBIN)/<tool>) that both the
# Makefile variables below and any hack/ script can rely on. Bumping a *_VERSION variable is the
# entire upgrade — the old versioned binary is simply left in ./bin (`make tools.clean` removes
# everything).
#
# docker/podman, git, sed, curl, minikube are deliberately NOT vendored here: they need a system
# daemon or are assumed baseline OS tooling.

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

UNAME_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
UNAME_ARCH := $(shell uname -m)
ifeq ($(UNAME_ARCH),x86_64)
TOOLS_ARCH := amd64
else ifeq ($(UNAME_ARCH),aarch64)
TOOLS_ARCH := arm64
else
TOOLS_ARCH := $(UNAME_ARCH)
endif

include hack/make/versions.mk

## Tool Binaries — always the bare-name symlink; scripts under hack/ can rely on the same path
## by putting $(LOCALBIN) on PATH.
HELM ?= $(LOCALBIN)/helm
KUBECTL ?= $(LOCALBIN)/kubectl
KIND ?= $(LOCALBIN)/kind
CHAINSAW ?= $(LOCALBIN)/chainsaw
TELEPRESENCE ?= $(LOCALBIN)/telepresence
FALCOCTL ?= $(LOCALBIN)/falcoctl
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
DEADCODE ?= $(LOCALBIN)/deadcode
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GCI ?= $(LOCALBIN)/gci
ADDLICENSE ?= $(LOCALBIN)/addlicense
SETUP_ENVTEST ?= $(LOCALBIN)/setup-envtest
HELM_DOCS ?= $(LOCALBIN)/helm-docs

.PHONY: tools
tools: helm kubectl kind chainsaw telepresence falcoctl \
	controller-gen $(DEADCODE) golangci-lint gci addlicense setup-envtest helm-docs ## Download all repo-local tool binaries into ./bin.

.PHONY: tools.clean
tools.clean: ## Remove all repo-local tool binaries.
	rm -rf $(LOCALBIN)

.PHONY: helm
helm: $(HELM) ## Download helm locally if necessary.
$(LOCALBIN)/helm-$(HELM_VERSION): | $(LOCALBIN)
	@echo "Downloading helm $(HELM_VERSION)"
	@set -e; tmpdir=$$(mktemp -d); trap 'rm -rf "$$tmpdir"' EXIT; \
	tarball="helm-$(HELM_VERSION)-$(UNAME_OS)-$(TOOLS_ARCH).tar.gz"; \
	curl -fsSL -o "$$tmpdir/$$tarball" "https://get.helm.sh/$$tarball"; \
	checksum=$$(curl -fsSL "https://get.helm.sh/$$tarball.sha256sum" | awk '{print $$1}'); \
	echo "$$checksum  $$tmpdir/$$tarball" | sha256sum -c -; \
	tar -xzf "$$tmpdir/$$tarball" -C "$$tmpdir" "$(UNAME_OS)-$(TOOLS_ARCH)/helm"; \
	mv "$$tmpdir/$(UNAME_OS)-$(TOOLS_ARCH)/helm" "$@"
	chmod +x "$@"
$(HELM): $(LOCALBIN)/helm-$(HELM_VERSION)
	ln -sf $(LOCALBIN)/helm-$(HELM_VERSION) $(HELM)

.PHONY: kubectl
kubectl: $(KUBECTL) ## Download kubectl locally if necessary.
$(LOCALBIN)/kubectl-$(KUBECTL_VERSION): | $(LOCALBIN)
	@echo "Downloading kubectl $(KUBECTL_VERSION)"
	@set -e; url="https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(UNAME_OS)/$(TOOLS_ARCH)/kubectl"; \
	curl -fsSL -o "$@" "$$url"; \
	checksum=$$(curl -fsSL "$$url.sha256"); \
	echo "$$checksum  $@" | sha256sum -c -
	chmod +x "$@"
$(KUBECTL): $(LOCALBIN)/kubectl-$(KUBECTL_VERSION)
	ln -sf $(LOCALBIN)/kubectl-$(KUBECTL_VERSION) $(KUBECTL)

.PHONY: kind
kind: $(KIND) ## Download kind locally if necessary.
$(LOCALBIN)/kind-$(KIND_VERSION): | $(LOCALBIN)
	@echo "Downloading kind $(KIND_VERSION)"
	@set -e; asset="kind-$(UNAME_OS)-$(TOOLS_ARCH)"; \
	base="https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)"; \
	curl -fsSL -o "$@" "$$base/$$asset"; \
	checksum=$$(curl -fsSL "$$base/$$asset.sha256sum" | awk '{print $$1}'); \
	echo "$$checksum  $@" | sha256sum -c -
	chmod +x "$@"
$(KIND): $(LOCALBIN)/kind-$(KIND_VERSION)
	ln -sf $(LOCALBIN)/kind-$(KIND_VERSION) $(KIND)

.PHONY: chainsaw
chainsaw: $(CHAINSAW) ## Download chainsaw locally if necessary.
$(LOCALBIN)/chainsaw-$(CHAINSAW_VERSION): | $(LOCALBIN)
	@echo "Downloading chainsaw $(CHAINSAW_VERSION)"
	@set -e; tmpdir=$$(mktemp -d); trap 'rm -rf "$$tmpdir"' EXIT; \
	tarball="chainsaw_$(UNAME_OS)_$(TOOLS_ARCH).tar.gz"; \
	base="https://github.com/kyverno/chainsaw/releases/download/$(CHAINSAW_VERSION)"; \
	curl -fsSL -o "$$tmpdir/$$tarball" "$$base/$$tarball"; \
	checksum=$$(curl -fsSL "$$base/checksums.txt" | grep " $$tarball$$" | awk '{print $$1}'); \
	echo "$$checksum  $$tmpdir/$$tarball" | sha256sum -c -; \
	tar -xzf "$$tmpdir/$$tarball" -C "$$tmpdir" chainsaw; \
	mv "$$tmpdir/chainsaw" "$@"
	chmod +x "$@"
$(CHAINSAW): $(LOCALBIN)/chainsaw-$(CHAINSAW_VERSION)
	ln -sf $(LOCALBIN)/chainsaw-$(CHAINSAW_VERSION) $(CHAINSAW)

.PHONY: falcoctl
falcoctl: $(FALCOCTL) ## Download falcoctl locally if necessary.
$(LOCALBIN)/falcoctl-$(FALCOCTL_VERSION): | $(LOCALBIN)
	@echo "Downloading falcoctl $(FALCOCTL_VERSION)"
	@set -e; tmpdir=$$(mktemp -d); trap 'rm -rf "$$tmpdir"' EXIT; \
	ver="$(patsubst v%,%,$(FALCOCTL_VERSION))"; \
	tarball="falcoctl_$${ver}_$(UNAME_OS)_$(TOOLS_ARCH).tar.gz"; \
	base="https://github.com/falcosecurity/falcoctl/releases/download/$(FALCOCTL_VERSION)"; \
	curl -fsSL -o "$$tmpdir/$$tarball" "$$base/$$tarball"; \
	checksum=$$(curl -fsSL "$$base/falcoctl_$${ver}_checksums.txt" | grep " $$tarball$$" | awk '{print $$1}'); \
	echo "$$checksum  $$tmpdir/$$tarball" | sha256sum -c -; \
	tar -xzf "$$tmpdir/$$tarball" -C "$$tmpdir" falcoctl; \
	mv "$$tmpdir/falcoctl" "$@"
	chmod +x "$@"
$(FALCOCTL): $(LOCALBIN)/falcoctl-$(FALCOCTL_VERSION)
	ln -sf $(LOCALBIN)/falcoctl-$(FALCOCTL_VERSION) $(FALCOCTL)

.PHONY: telepresence
telepresence: $(TELEPRESENCE) ## Download telepresence locally if necessary.
$(LOCALBIN)/telepresence-$(TELEPRESENCE_VERSION): | $(LOCALBIN)
	@echo "Downloading telepresence $(TELEPRESENCE_VERSION)"
	curl -fsSL -o "$@" \
		"https://github.com/telepresenceio/telepresence/releases/download/$(TELEPRESENCE_VERSION)/telepresence-$(UNAME_OS)-$(TOOLS_ARCH)"
	chmod +x "$@"
$(TELEPRESENCE): $(LOCALBIN)/telepresence-$(TELEPRESENCE_VERSION)
	ln -sf $(LOCALBIN)/telepresence-$(TELEPRESENCE_VERSION) $(TELEPRESENCE)

# go-install-tool builds Go package $(1) at version $(2) into the rule's target ($@). The binary is
# built into a temp GOBIN and renamed, so a failed build never leaves a half-written tool behind.
define go-install-tool
@echo "Installing $(1)@$(2)"
@set -e; tmpdir=$$(mktemp -d); trap 'rm -rf "$$tmpdir"' EXIT; \
GOBIN="$$tmpdir" go install "$(1)@$(2)"; \
mv "$$tmpdir/$(notdir $(1))" "$@"
endef

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Install controller-gen locally if necessary.
$(LOCALBIN)/controller-gen-$(CONTROLLER_GEN_VERSION): | $(LOCALBIN)
	$(call go-install-tool,sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_GEN_VERSION))
$(CONTROLLER_GEN): $(LOCALBIN)/controller-gen-$(CONTROLLER_GEN_VERSION)
	ln -sf $(LOCALBIN)/controller-gen-$(CONTROLLER_GEN_VERSION) $(CONTROLLER_GEN)

# No phony alias: `deadcode` is already the Makefile target that runs it.
$(LOCALBIN)/deadcode-$(DEADCODE_VERSION): | $(LOCALBIN)
	$(call go-install-tool,golang.org/x/tools/cmd/deadcode,$(DEADCODE_VERSION))
$(DEADCODE): $(LOCALBIN)/deadcode-$(DEADCODE_VERSION)
	ln -sf $(LOCALBIN)/deadcode-$(DEADCODE_VERSION) $(DEADCODE)

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Install golangci-lint locally if necessary.
$(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION): | $(LOCALBIN)
	$(call go-install-tool,github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
$(GOLANGCI_LINT): $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION)
	ln -sf $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION) $(GOLANGCI_LINT)

.PHONY: gci
gci: $(GCI) ## Install gci locally if necessary.
$(LOCALBIN)/gci-$(GCI_VERSION): | $(LOCALBIN)
	$(call go-install-tool,github.com/daixiang0/gci,$(GCI_VERSION))
$(GCI): $(LOCALBIN)/gci-$(GCI_VERSION)
	ln -sf $(LOCALBIN)/gci-$(GCI_VERSION) $(GCI)

.PHONY: addlicense
addlicense: $(ADDLICENSE) ## Install addlicense locally if necessary.
$(LOCALBIN)/addlicense-$(ADDLICENSE_VERSION): | $(LOCALBIN)
	$(call go-install-tool,github.com/google/addlicense,$(ADDLICENSE_VERSION))
$(ADDLICENSE): $(LOCALBIN)/addlicense-$(ADDLICENSE_VERSION)
	ln -sf $(LOCALBIN)/addlicense-$(ADDLICENSE_VERSION) $(ADDLICENSE)

.PHONY: setup-envtest
setup-envtest: $(SETUP_ENVTEST) ## Install setup-envtest locally if necessary.
$(LOCALBIN)/setup-envtest-$(SETUP_ENVTEST_VERSION): | $(LOCALBIN)
	$(call go-install-tool,sigs.k8s.io/controller-runtime/tools/setup-envtest,$(SETUP_ENVTEST_VERSION))
$(SETUP_ENVTEST): $(LOCALBIN)/setup-envtest-$(SETUP_ENVTEST_VERSION)
	ln -sf $(LOCALBIN)/setup-envtest-$(SETUP_ENVTEST_VERSION) $(SETUP_ENVTEST)

.PHONY: helm-docs
helm-docs: $(HELM_DOCS) ## Install helm-docs locally if necessary.
$(LOCALBIN)/helm-docs-$(HELM_DOCS_VERSION): | $(LOCALBIN)
	$(call go-install-tool,github.com/norwoodj/helm-docs/cmd/helm-docs,$(HELM_DOCS_VERSION))
$(HELM_DOCS): $(LOCALBIN)/helm-docs-$(HELM_DOCS_VERSION)
	ln -sf $(LOCALBIN)/helm-docs-$(HELM_DOCS_VERSION) $(HELM_DOCS)
