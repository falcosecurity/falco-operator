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

package resources

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/mounts"
	"github.com/falcosecurity/falco-operator/internal/pkg/version"
)

const (
	// FalcoTypeName is the type name for the Falco instance.
	FalcoTypeName = "falco"

	falcoConfigMapKey = "falco.yaml"
)

var restartPolicy = corev1.ContainerRestartPolicyAlways

// FalcoDefaults holds the default configuration for the Falco instance type.
var FalcoDefaults = &InstanceDefaults{
	ResourceType:         ResourceTypeDaemonSet,
	Replicas:             new(int32(1)),
	ContainerName:        "falco",
	SidecarContainerName: "artifact-operator",
	ImageRepository:      image.Registry + "/" + image.Repository + "/" + image.FalcoImage,
	ImageTag:             image.FalcoTag,
	DefaultArgs:          []string{"/usr/bin/falco"},
	ImagePullPolicy:      corev1.PullIfNotPresent,
	DefaultPorts: []corev1.ContainerPort{
		{ContainerPort: 8765, Name: "web", Protocol: corev1.ProtocolTCP},
	},
	StartupProbe: &corev1.Probe{
		InitialDelaySeconds: 3,
		TimeoutSeconds:      5,
		PeriodSeconds:       5,
		FailureThreshold:    20,
		SuccessThreshold:    1,
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(8765),
			},
		},
	},
	DefaultResources: corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1000m"),
			corev1.ResourceMemory: resource.MustParse("1024Mi"),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	},
	LivenessProbe: &corev1.Probe{
		InitialDelaySeconds: 0,
		TimeoutSeconds:      5,
		PeriodSeconds:       15,
		FailureThreshold:    3,
		SuccessThreshold:    1,
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(8765),
			},
		},
	},
	ReadinessProbe: &corev1.Probe{
		InitialDelaySeconds: 0,
		TimeoutSeconds:      5,
		PeriodSeconds:       15,
		FailureThreshold:    3,
		SuccessThreshold:    1,
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(8765),
			},
		},
	},
	SecurityContext: &corev1.SecurityContext{
		Privileged: new(true),
	},
	EnvVars: []corev1.EnvVar{
		{Name: "HOST_ROOT", Value: "/host"},
		{
			Name: "FALCO_HOSTNAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "spec.nodeName"},
			},
		},
		{
			Name: "FALCO_K8S_NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "spec.nodeName"},
			},
		},
	},
	Tolerations: []corev1.Toleration{
		{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
		{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule},
	},
	ServicePorts: []corev1.ServicePort{
		{Name: "web", Protocol: corev1.ProtocolTCP, Port: 8765, TargetPort: intstr.FromInt32(8765)},
	},
	ClusterRoleRules: []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs:     []string{"get", "list", "watch"},
		},
	},
	RoleRules: []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"events.k8s.io"},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		},
		{
			APIGroups: []string{artifactv1alpha1.GroupVersion.Group},
			Resources: []string{"configs"},
			Verbs:     []string{"get", "list", "watch", "update", "patch"},
		},
		{
			APIGroups: []string{artifactv1alpha1.GroupVersion.Group},
			Resources: []string{"rulesfiles", "plugins"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{artifactv1alpha1.GroupVersion.Group},
			Resources: []string{"configs/status", "rulesfiles/status", "plugins/status"},
			Verbs:     []string{"get", "update", "patch"},
		},
	},
	VolumeMounts: []corev1.VolumeMount{
		{Name: "root-falco-fs", MountPath: "/root/.falco"},
		{Name: "boot-fs", MountPath: "/host/boot", ReadOnly: true},
		{Name: "lib-modules", MountPath: "/host/lib/modules"},
		{Name: "usr-fs", MountPath: "/host/usr", ReadOnly: true},
		{Name: "proc-fs", MountPath: "/host/proc"},
		{Name: "etc-fs", MountPath: "/host/etc", ReadOnly: true},
		{Name: "dev-fs", MountPath: "/host/dev", ReadOnly: true},
		{Name: "sys-fs", MountPath: "/sys/module"},
		{Name: "docker-socket", MountPath: "/host/var/run/"},
		{Name: "containerd-socket", MountPath: "/host/run/containerd/"},
		{Name: "crio-socket", MountPath: "/host/run/crio/"},
		{Name: "host-containerd-socket", MountPath: "/host/run/host-containerd/"},
		{Name: "k3s-containerd-socket", MountPath: "/host/run/k3s/containerd/"},
		{Name: mounts.ConfigMountName, MountPath: mounts.ConfigDirPath},
		{Name: mounts.RulesfileMountName, MountPath: mounts.RulesfileDirPath},
		{Name: mounts.PluginMountName, MountPath: mounts.PluginDirPath},
	},
	Volumes: []corev1.Volume{
		{Name: "root-falco-fs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "boot-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/boot"}}},
		{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
		{Name: "usr-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr"}}},
		{Name: "etc-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}}},
		{Name: "dev-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/dev"}}},
		{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/module"}}},
		{Name: "docker-socket", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run"}}},
		{Name: "containerd-socket", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/containerd"}}},
		{Name: "crio-socket", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/crio"}}},
		{Name: "host-containerd-socket", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/host-containerd"}}},
		{Name: "k3s-containerd-socket", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/k3s/containerd"}}},
		{Name: "proc-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
		{Name: mounts.ConfigMountName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: mounts.RulesfileMountName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: mounts.PluginMountName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	},
	ConfigMapData: map[string]map[string]string{
		"Deployment": {falcoConfigMapKey: deploymentFalcoConfig},
		"DaemonSet":  {falcoConfigMapKey: daemonsetFalcoConfig},
	},
	ConfigMapVolume: &ConfigMapVolumeConfig{
		VolumeName: "falco-config-default",
		MountPath:  "/etc/falco/falco.yaml",
		SubPath:    "falco.yaml",
	},
	SidecarContainers: []corev1.Container{
		{
			Name:            "artifact-operator",
			Image:           version.ArtifactOperatorImage,
			ImagePullPolicy: corev1.PullIfNotPresent,
			RestartPolicy:   &restartPolicy,
			EnvFrom:         []corev1.EnvFromSource{},
			Env: []corev1.EnvVar{
				{
					Name: "POD_NAMESPACE",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"},
					},
				},
				{
					Name: "NODE_NAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "spec.nodeName"},
					},
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: mounts.ConfigMountName, MountPath: mounts.ConfigDirPath},
				{Name: mounts.RulesfileMountName, MountPath: mounts.RulesfileDirPath},
				{Name: mounts.PluginMountName, MountPath: mounts.PluginDirPath},
			},
			ReadinessProbe: &corev1.Probe{
				InitialDelaySeconds: 5,
				TimeoutSeconds:      5,
				PeriodSeconds:       10,
				FailureThreshold:    3,
				SuccessThreshold:    1,
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/healthz",
						Port: intstr.FromInt32(8081),
					},
				},
			},
			LivenessProbe: &corev1.Probe{
				InitialDelaySeconds: 15,
				TimeoutSeconds:      5,
				PeriodSeconds:       10,
				FailureThreshold:    3,
				SuccessThreshold:    1,
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/healthz",
						Port: intstr.FromInt32(8081),
					},
				},
			},
		},
	},
	SupportsDaemonSet: true,
	DeploymentStrategy: &appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
	},
	DaemonSetUpdateStrategy: &appsv1.DaemonSetUpdateStrategy{
		Type: appsv1.RollingUpdateDaemonSetStrategyType,
	},
}

// Falco configuration strings, keyed by workload type.
var daemonsetFalcoConfig = `append_output:
- suggested_output: true
base_syscalls:
  custom_set: []
  repair: false
buffered_outputs: false
config_files:
- /etc/falco/config.d
container_engines:
  bpm:
    enabled: false
  cri:
    enabled: true
    sockets:
    - /run/containerd/containerd.sock
    - /run/crio/crio.sock
    - /run/k3s/containerd/containerd.sock
    - /run/host-containerd/containerd.sock
  docker:
    enabled: true
  libvirt_lxc:
    enabled: false
  lxc:
    enabled: false
  podman:
    enabled: false
engine:
  ebpf:
    buf_size_preset: 4
    drop_failed_exit: false
    probe: ${HOME}/.falco/falco-bpf.o
  kind: modern_ebpf
  kmod:
    buf_size_preset: 4
    drop_failed_exit: false
  modern_ebpf:
    buf_size_preset: 4
    cpus_for_each_buffer: 2
    drop_failed_exit: false
falco_libs:
  thread_table_size: 262144
  thread_table_auto_purging_interval_s: 300
  thread_table_auto_purging_thread_timeout_s: 300
  snaplen: 80
file_output:
  enabled: false
  filename: ./events.txt
  keep_alive: false
grpc:
  bind_address: unix:///run/falco/falco.sock
  enabled: false
  threadiness: 0
grpc_output:
  enabled: false
http_output:
  ca_bundle: ""
  ca_cert: ""
  ca_path: /etc/falco/certs/
  client_cert: /etc/falco/certs/client/client.crt
  client_key: /etc/falco/certs/client/client.key
  compress_uploads: false
  echo: false
  enabled: false
  insecure: false
  keep_alive: false
  mtls: false
  url: ""
  user_agent: falcosecurity/falco
json_include_message_property: false
json_include_output_fields_property: true
json_include_output_property: true
json_include_tags_property: true
json_output: false
libs_logger:
  enabled: false
  severity: debug
load_plugins: []
log_level: info
log_stderr: true
log_syslog: true
metrics:
  convert_memory_to_mb: true
  enabled: true
  include_empty_values: false
  interval: 1h
  kernel_event_counters_enabled: true
  kernel_event_counters_per_cpu_enabled: false
  libbpf_stats_enabled: true
  output_rule: false
  resource_utilization_enabled: true
  rules_counters_enabled: true
  state_counters_enabled: true
output_timeout: 2000
outputs_queue:
  capacity: 0
plugins: []
plugins_hostinfo: true
priority: debug
program_output:
  enabled: false
  keep_alive: false
  program: 'jq ''{text: .output}'' | curl -d @- -X POST https://hooks.slack.com/services/XXX'
rule_matching: first
rules_files:
- /etc/falco/rules.d
stdout_output:
  enabled: true
syscall_event_drops:
  actions:
  - log
  - alert
  max_burst: 1
  rate: 0.03333
  simulate_drops: false
  threshold: 0.1
syscall_event_timeouts:
  max_consecutives: 1000
syslog_output:
  enabled: true
time_format_iso_8601: false
watch_config_files: true
webserver:
  enabled: true
  k8s_healthz_endpoint: /healthz
  listen_port: 8765
  prometheus_metrics_enabled: true
  ssl_certificate: /etc/falco/falco.pem
  ssl_enabled: false
  threadiness: 0
`

var deploymentFalcoConfig = `append_output:
- suggested_output: true
base_syscalls:
  custom_set: []
  repair: false
buffered_outputs: false
config_files:
- /etc/falco/config.d
container_engines:
  bpm:
    enabled: false
  cri:
    enabled: false
    sockets:
    - /run/containerd/containerd.sock
    - /run/crio/crio.sock
    - /run/k3s/containerd/containerd.sock
    - /run/host-containerd/containerd.sock
  docker:
    enabled: false
  libvirt_lxc:
    enabled: false
  lxc:
    enabled: false
  podman:
    enabled: false
engine:
  ebpf:
    buf_size_preset: 4
    drop_failed_exit: false
    probe: ${HOME}/.falco/falco-bpf.o
  kind: nodriver
  kmod:
    buf_size_preset: 4
    drop_failed_exit: false
  modern_ebpf:
    buf_size_preset: 4
    cpus_for_each_buffer: 2
    drop_failed_exit: false
falco_libs:
  thread_table_size: 262144
  thread_table_auto_purging_interval_s: 300
  thread_table_auto_purging_thread_timeout_s: 300
  snaplen: 80
file_output:
  enabled: false
  filename: ./events.txt
  keep_alive: false
grpc:
  bind_address: unix:///run/falco/falco.sock
  enabled: false
  threadiness: 0
grpc_output:
  enabled: false
http_output:
  ca_bundle: ""
  ca_cert: ""
  ca_path: /etc/falco/certs/
  client_cert: /etc/falco/certs/client/client.crt
  client_key: /etc/falco/certs/client/client.key
  compress_uploads: false
  echo: false
  enabled: false
  insecure: false
  keep_alive: false
  mtls: false
  url: ""
  user_agent: falcosecurity/falco
json_include_message_property: false
json_include_output_fields_property: true
json_include_output_property: true
json_include_tags_property: true
json_output: false
libs_logger:
  enabled: false
  severity: debug
load_plugins: []
log_level: info
log_stderr: true
log_syslog: true
metrics:
  convert_memory_to_mb: true
  enabled: true
  include_empty_values: false
  interval: 1h
  kernel_event_counters_enabled: true
  kernel_event_counters_per_cpu_enabled: false
  libbpf_stats_enabled: true
  output_rule: false
  resource_utilization_enabled: true
  rules_counters_enabled: true
  state_counters_enabled: true
output_timeout: 2000
outputs_queue:
  capacity: 0
plugins: []
plugins_hostinfo: true
priority: debug
program_output:
  enabled: false
  keep_alive: false
  program: 'jq ''{text: .output}'' | curl -d @- -X POST https://hooks.slack.com/services/XXX'
rule_matching: first
rules_files:
- /etc/falco/rules.d
stdout_output:
  enabled: true
syscall_event_drops:
  actions:
  - log
  - alert
  max_burst: 1
  rate: 0.03333
  simulate_drops: false
  threshold: 0.1
syscall_event_timeouts:
  max_consecutives: 1000
syslog_output:
  enabled: true
time_format_iso_8601: false
watch_config_files: true
webserver:
  enabled: true
  k8s_healthz_endpoint: /healthz
  listen_port: 8765
  prometheus_metrics_enabled: true
  ssl_certificate: /etc/falco/falco.pem
  ssl_enabled: false
  threadiness: 0
`
