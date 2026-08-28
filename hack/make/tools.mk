# Repo-local tool binaries: every non-Go-toolchain CLI the Makefile shells out to is downloaded
# here, into a gitignored bin/ directory, instead of assumed to be on the system PATH. This keeps
# `make` reproducible (everyone gets the exact pinned version) and never touches anything outside
# the repo. Go-based tools (controller-gen, golangci-lint, etc.) don't need this: they're already
# tracked via go.mod's native `tool` directive and fetched with `go tool <name>`.
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

## Go-toolchain-tracked tools — pinned via go.mod's `tool` directive (go.sum), not curl-downloaded
## like the ones above. No .PHONY fetch target or $(LOCALBIN) entry needed: `go tool <name>`
## builds and caches these itself on first use. Defined here anyway, alongside everything else,
## so every tool this Makefile shells out to has its variable in one single place.
CONTROLLER_GEN ?= go tool controller-gen
DEADCODE ?= go tool deadcode
GOLANGCI_LINT ?= go tool golangci-lint
GCI ?= go tool gci
ADDLICENSE ?= go tool addlicense
SETUP_ENVTEST ?= go tool setup-envtest
HELM_DOCS ?= go tool helm-docs

## Tool Binaries — always the bare-name symlink; scripts under hack/ can rely on the same path
## by putting $(LOCALBIN) on PATH.
HELM ?= $(LOCALBIN)/helm
KUBECTL ?= $(LOCALBIN)/kubectl
KIND ?= $(LOCALBIN)/kind
CHAINSAW ?= $(LOCALBIN)/chainsaw
TELEPRESENCE ?= $(LOCALBIN)/telepresence
FALCOCTL ?= $(LOCALBIN)/falcoctl

.PHONY: tools
tools: helm kubectl kind chainsaw telepresence falcoctl ## Download all repo-local tool binaries into ./bin.

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
