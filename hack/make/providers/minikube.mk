# minikube cluster provider — see hack/make/cluster.mk for the provider dispatch/abstraction this
# implements (cluster.create, cluster.delete, cluster.load.image).
#
# minikube isn't vendored in hack/make/tools.mk — it needs a local hypervisor/container-runtime
# driver, so it stays a system prerequisite like docker/podman.

# "minikube" is also minikube's own zero-config default profile name.
CLUSTER_NAME    ?= minikube
CLUSTER_TOOL_DEP :=

MINIKUBE_CPUS   ?= 4
MINIKUBE_NODES  ?= 1
# kvm2 (libvirt/KVM) is the only supported driver. It works for both single and multi-node
# clusters and gives VMs a real kernel — required for Falco's kernel module/eBPF probes.
# Prerequisite: set firewall_backend = "iptables" in /etc/libvirt/network.conf and restart
# libvirtd, otherwise VM internet access breaks (libvirt's nftables backend is broken on Fedora).

.PHONY: cluster.create
cluster.create:
	@command -v minikube >/dev/null 2>&1 || { echo "minikube is not installed. Please install it manually."; exit 1; }
	@minikube status -p $(CLUSTER_NAME) >/dev/null 2>&1 || minikube start -p $(CLUSTER_NAME) \
		--cpus=$(MINIKUBE_CPUS) \
		--nodes=$(MINIKUBE_NODES) \
		--driver=kvm2

.PHONY: cluster.delete
cluster.delete:
	minikube delete -p $(CLUSTER_NAME)

.PHONY: cluster.load.image
cluster.load.image:
	minikube image load $(IMG) -p $(CLUSTER_NAME)
