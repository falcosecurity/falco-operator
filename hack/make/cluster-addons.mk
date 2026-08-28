# Cluster-side dependencies: things the operator or its e2e tests expect to already be running
# in the cluster, as opposed to a repo-local CLI (hack/make/tools.mk) or the cluster itself
# (hack/make/cluster.mk). Installed as a batch by `make addons` — which `make cluster.up` calls right
# after creating the cluster — or individually, e.g. `make cert-manager.install`.
#
# Each one can be skipped with its own WITH_* flag, e.g.:
#   make cluster.up WITH_TELEPRESENCE=false

include hack/make/versions.mk

NAMESPACE ?= falco-operator

WITH_CERT_MANAGER ?= true
WITH_TRUST_MANAGER ?= true
WITH_KWOK ?= true
WITH_TELEPRESENCE ?= true

# Default Kind service CIDR, used by telepresence.connect. Override if your cluster uses a
# different range.
CLUSTER_SERVICE_CIDR ?= 10.96.0.0/12

.PHONY: namespace.ensure
namespace.ensure: kubectl ## Ensure NAMESPACE exists (idempotent). trust-manager's chart needs it present before install — it creates a namespace-scoped Role/RoleBinding there, scoped by app.trust.namespace.
	$(KUBECTL) create namespace $(NAMESPACE) --dry-run=client -o yaml | $(KUBECTL) apply -f -

.PHONY: addons
addons: namespace.ensure ## Install all enabled cluster-side dependencies (see the WITH_* flags above).
ifeq ($(WITH_CERT_MANAGER),true)
	$(MAKE) cert-manager.install
endif
ifeq ($(WITH_TRUST_MANAGER),true)
	$(MAKE) trust-manager.install
endif
ifeq ($(WITH_KWOK),true)
	$(MAKE) kwok.install
endif
ifeq ($(WITH_TELEPRESENCE),true)
	$(MAKE) telepresence.install
endif

.PHONY: cert-manager.install
cert-manager.install: helm ## Install cert-manager $(CERT_MANAGER_VERSION) into the cluster.
	$(HELM) repo add jetstack https://charts.jetstack.io --force-update
	$(HELM) repo update jetstack
	$(HELM) upgrade --install cert-manager jetstack/cert-manager \
		--namespace cert-manager --create-namespace \
		--version "$(CERT_MANAGER_VERSION)" \
		--set crds.enabled=true \
		--set enableCertificateOwnerRef=true \
		--set "extraArgs={--cluster-resource-namespace=$(NAMESPACE)}" \
		--wait --timeout 180s

.PHONY: trust-manager.install
trust-manager.install: helm namespace.ensure ## Install trust-manager $(TRUST_MANAGER_VERSION) into the cluster (reads its Bundle CA source from $(NAMESPACE)).
	$(HELM) repo add jetstack https://charts.jetstack.io --force-update
	$(HELM) upgrade --install trust-manager jetstack/trust-manager \
		--namespace cert-manager --create-namespace \
		--version "$(TRUST_MANAGER_VERSION)" \
		--set "app.trust.namespace=$(NAMESPACE)" \
		--wait --timeout 180s

.PHONY: kwok.install
kwok.install: kubectl ## Install KWOK $(KWOK_VERSION) (CRDs, controller, RBAC) on the current cluster. Needed for chainsaw tests that simulate additional Nodes (e.g. artifact-cache-lifecycle's arm64 coverage).
	$(KUBECTL) apply -f "https://github.com/kubernetes-sigs/kwok/releases/download/$(KWOK_VERSION)/kwok.yaml"
	$(KUBECTL) apply -f "https://github.com/kubernetes-sigs/kwok/releases/download/$(KWOK_VERSION)/stage-fast.yaml"

.PHONY: telepresence.install
telepresence.install: telepresence ## Install the Telepresence Traffic Manager into the cluster.
	$(TELEPRESENCE) helm install

.PHONY: telepresence.connect
telepresence.connect: telepresence ## Connect Telepresence for out-of-cluster debugging. Proxies cluster DNS and service CIDR so ClusterIPs are reachable from the host.
	$(TELEPRESENCE) connect --also-proxy $(CLUSTER_SERVICE_CIDR)
