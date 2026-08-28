# Local dev cluster lifecycle, abstracted over which tool actually backs it. Each provider is
# its own file under hack/make/providers/ (kind.mk, minikube.mk, ...), implementing the same three
# primitives — cluster.create, cluster.delete, cluster.load.image — plus any provider-specific
# config/assets it needs alongside it. The rest of the Makefile never needs to know which one is
# active. Switch with CLUSTER_PROVIDER=kind (default: minikube).
#
# `make cluster.up` is the one-stop entrypoint: create the cluster, then install everything the
# operator or its e2e tests expect to already be running in it (see hack/make/cluster-addons.mk).

CLUSTER_PROVIDER ?= $(shell \
	if command -v minikube >/dev/null 2>&1 && minikube status >/dev/null 2>&1; then echo minikube; \
	elif command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -q .; then echo kind; \
	else echo minikube; fi)

include hack/make/cluster-addons.mk

ifeq ($(wildcard hack/make/providers/$(CLUSTER_PROVIDER).mk),)
$(error Unsupported CLUSTER_PROVIDER '$(CLUSTER_PROVIDER)': no hack/make/providers/$(CLUSTER_PROVIDER).mk found (supported: kind, minikube))
endif
include hack/make/providers/$(CLUSTER_PROVIDER).mk

.PHONY: cluster.up
cluster.up: ## Create the local dev cluster ($(CLUSTER_PROVIDER)) and install all enabled cluster-side dependencies.
	$(MAKE) cluster.create
	$(MAKE) addons

.PHONY: cluster.down
cluster.down: cluster.delete ## Delete the local dev cluster.

# cluster.load.image (defined per-provider above) only loads an already-built image — kept that
# way so a SKIP_BUILD-style workflow can reload a cached image without rebuilding. These compose
# a real build on top of it for the common "just get my change into the cluster" case.
.PHONY: cluster.load.instance
cluster.load.instance: docker.build.instance ## Build and load the instance operator image into the local dev cluster.
	$(MAKE) cluster.load.image IMG=$(IMG_INSTANCE)

.PHONY: cluster.load.artifact
cluster.load.artifact: docker.build.artifact ## Build and load the artifact operator image into the local dev cluster.
	$(MAKE) cluster.load.image IMG=$(IMG_ARTIFACT)

.PHONY: cluster.load
cluster.load: cluster.load.instance cluster.load.artifact ## Build and load both operator images into the local dev cluster.
