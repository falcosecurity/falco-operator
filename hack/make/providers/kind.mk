# kind cluster provider — see hack/make/cluster.mk for the provider dispatch/abstraction this
# implements (cluster.create, cluster.delete, cluster.load.image).

# "kind" is also kind's own zero-config default cluster name.
CLUSTER_NAME ?= kind
CLUSTER_TOOL_DEP := kind

.PHONY: cluster.create
cluster.create: $(CLUSTER_TOOL_DEP)
	@$(KIND) get clusters 2>/dev/null | grep -qx '$(CLUSTER_NAME)' || $(KIND) create cluster --name $(CLUSTER_NAME)

.PHONY: cluster.delete
cluster.delete: $(CLUSTER_TOOL_DEP)
	$(KIND) delete cluster --name $(CLUSTER_NAME)

.PHONY: cluster.load.image
cluster.load.image: $(CLUSTER_TOOL_DEP) ## Load IMG into the local dev cluster (make cluster.load.image IMG=repo:tag).
	$(KIND) load docker-image $(IMG) --name $(CLUSTER_NAME)
