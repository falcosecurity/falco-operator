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

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	artifactconfigctr "github.com/falcosecurity/falco-operator/controllers/instance/artifact/config"
	artifactpluginctr "github.com/falcosecurity/falco-operator/controllers/instance/artifact/plugin"
	artifactrulesfilectr "github.com/falcosecurity/falco-operator/controllers/instance/artifact/rulesfile"
	"github.com/falcosecurity/falco-operator/controllers/instance/component"
	"github.com/falcosecurity/falco-operator/controllers/instance/falco"
	configmapctr "github.com/falcosecurity/falco-operator/controllers/instance/reference/configmap"
	secretctr "github.com/falcosecurity/falco-operator/controllers/instance/reference/secret"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactcache"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifactserver"
	"github.com/falcosecurity/falco-operator/internal/pkg/envutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
	"github.com/falcosecurity/falco-operator/internal/pkg/logging"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
	"github.com/falcosecurity/falco-operator/internal/pkg/tlsutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/version"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

// stringSliceFlag accumulates repeated string flag values into a slice.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(instancev1alpha1.AddToScheme(scheme))
	utilruntime.Must(artifactv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var excludedLabels stringSliceFlag
	var tlsOpts []func(*tls.Config)
	var opts zap.Options

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.Var(&excludedLabels, "excluded-labels",
		"A label key to exclude from propagation onto operator-generated resources. "+
			"The '*' wildcard is supported (e.g. kustomize.toolkit.fluxcd.io/*). May be repeated.")

	var artifactServeAddr string
	var artifactCacheDir string
	var artifactCacheEvictionGracePeriod time.Duration
	var artifactServerURL string
	var artifactServerCertPath, artifactServerCertName, artifactServerCertKey string
	var artifactServerClientCAFile string
	var artifactClientCertIssuerName string
	var artifactCABundleConfigMapName string
	var artifactClientCertDuration, artifactClientCertRenewBefore time.Duration
	var artifactOperatorImage string
	var artifactServerMaxConcurrentRequests int
	flag.StringVar(&artifactServeAddr, "artifact-serve-addr", ":8082",
		"Address the artifact HTTP server binds to. Per-node artifact-operators download OCI artifacts from this server.")
	flag.StringVar(&artifactCacheDir, "artifact-cache-dir", "/var/cache/falco-operator/artifacts",
		"Directory used to cache OCI artifact tarballs served by the artifact HTTP server.")
	flag.DurationVar(&artifactCacheEvictionGracePeriod, "artifact-cache-eviction-grace-period",
		artifactcache.DefaultEvictionGracePeriod,
		"How long a dereferenced OCI artifact blob lingers on disk (still servable) before being "+
			"deleted, absorbing a delete-then-recreate of the same artifact without a registry "+
			"re-pull. Set to 0 to delete immediately instead (today's original behavior).")
	flag.StringVar(&artifactServerURL, "artifact-server-url", "",
		"URL of the artifact HTTP server to advertise to artifact-operator sidecars. "+
			"Overrides the default in-cluster URL derived from OPERATOR_NAMESPACE. "+
			"Useful when running the operator outside the cluster (e.g. during local development).")
	flag.StringVar(&artifactServerCertPath, "artifact-server-cert-path", "",
		"The directory that contains the artifact server's TLS certificate. When set, the artifact "+
			"HTTP server serves over HTTPS instead of plain HTTP.")
	flag.StringVar(&artifactServerCertName, "artifact-server-cert-name", "tls.crt", "The name of the artifact server certificate file.")
	flag.StringVar(&artifactServerCertKey, "artifact-server-cert-key", "tls.key", "The name of the artifact server key file.")
	flag.StringVar(&artifactServerClientCAFile, "artifact-server-client-ca-file", "",
		"Path to a PEM file containing the CA bundle used to verify client certificates presented by "+
			"artifact-operator sidecars. Requires --artifact-server-cert-path to also be set. When set, "+
			"the artifact server requires mTLS client certificates from all callers.")
	flag.StringVar(&artifactClientCertIssuerName, "artifact-client-cert-issuer-name", "",
		"Name of the cert-manager ClusterIssuer used to sign a unique, per-Falco-instance artifact "+
			"client mTLS certificate (with a SPIFFE URI SAN identifying the instance) in each instance's "+
			"own namespace. Empty disables per-instance mTLS certificate provisioning.")
	flag.StringVar(&artifactCABundleConfigMapName, "artifact-ca-bundle-configmap-name", "",
		"Name of the trust-manager Bundle-synced ConfigMap every artifact-operator sidecar reads to "+
			"verify the artifact server's certificate. Sourcing from this (rather than each sidecar's own "+
			"per-instance Secret) lets the Bundle hold two CA sources at once during a CA rotation, so a "+
			"sidecar keeps trusting the server (and vice versa) regardless of which side has rotated "+
			"first. Requires that Falco instance's own namespace be labeled for trust-manager sync; see "+
			"the chart's mtls.trustLabel value.")
	flag.DurationVar(&artifactClientCertDuration, "artifact-client-cert-duration", falco.DefaultArtifactClientCertDuration,
		"Validity period for a per-instance artifact client mTLS certificate.")
	flag.DurationVar(&artifactClientCertRenewBefore, "artifact-client-cert-renew-before", falco.DefaultArtifactClientCertRenewBefore,
		"How long before expiry cert-manager renews a per-instance artifact client mTLS certificate.")
	flag.StringVar(&artifactOperatorImage, "artifact-operator-image", "",
		"Overrides the artifact-operator sidecar image injected into every Falco pod. Normally this is "+
			"baked in at build time (version.ArtifactOperatorImage, via -ldflags) to match the release pair; "+
			"set this (or the ARTIFACT_OPERATOR_IMAGE env var) to repoint an already-built binary at a "+
			"different image, e.g. a private registry mirror or a local dev build, without rebuilding.")
	flag.IntVar(&artifactServerMaxConcurrentRequests, "artifact-server-max-concurrent-requests", 0,
		"Maximum number of concurrent artifact blob transfers the server handles simultaneously. "+
			"Excess requests receive 503 with a jittered Retry-After so retries spread out. "+
			"0 disables the limit (unlimited concurrency).")

	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	if err := envutil.BindFlagEnv(flag.CommandLine); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if artifactOperatorImage != "" {
		version.ArtifactOperatorImage = artifactOperatorImage
	}
	// Reassigning version.ArtifactOperatorImage above has no effect on FalcoDefaults, which was
	// already initialized from it at package-init time; this call applies the override directly.
	resources.SetArtifactOperatorImage(version.ArtifactOperatorImage)

	ctrl.SetLogger(logging.FilterEventRejectionOnTerminatingNamespace(zap.New(zap.UseFlagOptions(&opts))))

	setupLog.Info("Starting instance operator", "version", version.SemVersion, "commit", version.GitCommit,
		"buildDate", version.BuildDate, "compiler", version.Compiler, "platform", version.Platform,
		"artifactOperatorImage", version.ArtifactOperatorImage)
	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Create watchers for metrics and webhooks certificates
	var metricsCertWatcher, webhookCertWatcher *certwatcher.CertWatcher

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts

	if webhookCertPath != "" {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		var err error
		webhookCertWatcher, err = certwatcher.New(
			filepath.Join(webhookCertPath, webhookCertName),
			filepath.Join(webhookCertPath, webhookCertKey),
		)
		if err != nil {
			setupLog.Error(err, "Failed to initialize webhook certificate watcher")
			os.Exit(1)
		}

		webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
			config.GetCertificate = webhookCertWatcher.GetCertificate
		})
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: webhookTLSOpts,
	})

	// Metrics server options. The --metrics-bind-address and --metrics-secure flags
	// can be set via the Helm chart's `extraArgs` value. See:
	// https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/metrics/server
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// Protect the metrics endpoint with authn/authz. See:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// Without explicit certs, controller-runtime generates self-signed certs for the metrics
	// server. Not recommended for production; pass --metrics-cert-path via the Helm chart's
	// `extraArgs` together with a Secret mounted via `volumes`/`volumeMounts`.
	if metricsCertPath != "" {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(metricsCertPath, metricsCertName),
			filepath.Join(metricsCertPath, metricsCertKey),
		)
		if err != nil {
			setupLog.Error(err, "to initialize metrics certificate watcher", "error", err)
			os.Exit(1)
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}

	// Artifact server TLS/mTLS: opt-in, plain HTTP by default (unchanged from today). Setting
	// --artifact-server-cert-path switches it to HTTPS; additionally setting
	// --artifact-server-client-ca-file requires and verifies client certificates (mTLS).
	var artifactServerCertWatcher *certwatcher.CertWatcher
	var artifactServerClientCA *tlsutil.CAWatcher
	var artifactOpts []artifactserver.Option

	if artifactServerCertPath != "" {
		setupLog.Info("Initializing artifact server certificate watcher using provided certificates",
			"artifact-server-cert-path", artifactServerCertPath,
			"artifact-server-cert-name", artifactServerCertName, "artifact-server-cert-key", artifactServerCertKey)

		var err error
		artifactServerCertWatcher, err = certwatcher.New(
			filepath.Join(artifactServerCertPath, artifactServerCertName),
			filepath.Join(artifactServerCertPath, artifactServerCertKey),
		)
		if err != nil {
			setupLog.Error(err, "Failed to initialize artifact server certificate watcher")
			os.Exit(1)
		}
		artifactOpts = append(artifactOpts, artifactserver.WithTLS(artifactServerCertWatcher))
	}

	if artifactServerClientCAFile != "" {
		setupLog.Info("Initializing artifact server client CA watcher (mTLS enabled)",
			"artifact-server-client-ca-file", artifactServerClientCAFile)

		var err error
		artifactServerClientCA, err = tlsutil.NewCAWatcher(artifactServerClientCAFile)
		if err != nil {
			setupLog.Error(err, "Failed to initialize artifact server client CA watcher")
			os.Exit(1)
		}
		artifactOpts = append(artifactOpts, artifactserver.WithClientCAs(artifactServerClientCA))
	}

	// Build the label filter applied to generated resources.
	labelFilter := instance.NewLabelFilter(excludedLabels)
	setupLog.V(4).Info("Label propagation filter", "excludedLabels", []string(excludedLabels))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "1d54f32f.falcosecurity.dev",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	for _, idx := range index.All {
		if err := mgr.GetFieldIndexer().IndexField(ctx, idx.Object, idx.Field, idx.ExtractValueFn); err != nil {
			setupLog.Error(err, "unable to register field index", "field", idx.Field)
			os.Exit(1)
		}
	}

	if err = falco.NewReconciler(
		mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorder("falco-controller"),
		falco.WithLabelFilter(labelFilter),
		falco.WithArtifactMTLS(artifactClientCertIssuerName, artifactCABundleConfigMapName, artifactClientCertDuration, artifactClientCertRenewBefore),
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Falco")
		os.Exit(1)
	}

	// SPIFFE-based authorization: a client cert signed by our own CA is necessary but not
	// sufficient (every per-instance cert shares that CA); this additionally checks the SPIFFE
	// identity against the Falco instances the manager's own cache already knows about. Only
	// meaningful together with the client-CA verification configured above.
	if artifactServerClientCA != nil {
		artifactOpts = append(artifactOpts, artifactserver.WithAuthorizer(
			artifactserver.NewAuthorizer(mgr.GetClient(), mgr.GetLogger())))
	}

	if err = component.NewReconciler(
		mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorder("component-controller"),
		component.WithLabelFilter(labelFilter),
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Component")
		os.Exit(1)
	}

	if err := configmapctr.NewConfigMapReconciler(
		mgr.GetClient(), mgr.GetScheme(),
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", configmapctr.ControllerName)
		os.Exit(1)
	}

	if err := secretctr.NewSecretReconciler(
		mgr.GetClient(), mgr.GetScheme(),
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", secretctr.ControllerName)
		os.Exit(1)
	}

	artifactCache := artifactcache.NewCache(artifactCacheDir,
		artifactcache.WithEvictionGracePeriod(artifactCacheEvictionGracePeriod))
	if err := artifactCache.Load(); err != nil {
		setupLog.Error(err, "unable to load artifact cache snapshot")
		os.Exit(1)
	}

	if err := artifactrulesfilectr.NewRulesfileAggregatorReconciler(
		mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorder("instance-artifact-rulesfile"), artifactCache,
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", artifactrulesfilectr.ControllerName)
		os.Exit(1)
	}

	if err := artifactpluginctr.NewPluginAggregatorReconciler(
		mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorder("instance-artifact-plugin"), artifactCache,
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", artifactpluginctr.ControllerName)
		os.Exit(1)
	}

	if err := artifactconfigctr.NewConfigAggregatorReconciler(
		mgr.GetClient(), mgr.GetScheme(),
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", artifactconfigctr.ControllerName)
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	if metricsCertWatcher != nil {
		setupLog.Info("Adding metrics certificate watcher to manager")
		if err := mgr.Add(metricsCertWatcher); err != nil {
			setupLog.Error(err, "unable to add metrics certificate watcher to manager")
			os.Exit(1)
		}
	}

	if webhookCertWatcher != nil {
		setupLog.Info("Adding webhook certificate watcher to manager")
		if err := mgr.Add(webhookCertWatcher); err != nil {
			setupLog.Error(err, "unable to add webhook certificate watcher to manager")
			os.Exit(1)
		}
	}

	if artifactServerCertWatcher != nil {
		setupLog.Info("Adding artifact server certificate watcher to manager")
		if err := mgr.Add(artifactServerCertWatcher); err != nil {
			setupLog.Error(err, "unable to add artifact server certificate watcher to manager")
			os.Exit(1)
		}
	}

	if artifactServerClientCA != nil {
		setupLog.Info("Adding artifact server client CA watcher to manager")
		if err := mgr.Add(artifactServerClientCA); err != nil {
			setupLog.Error(err, "unable to add artifact server client CA watcher to manager")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Starts the centralized OCI artifact HTTP server that per-node artifact-operators download
	// artifacts from. Registered as a manager.Runnable (like the Sweeper below), so it runs on
	// every replica, not leader-gated.
	if artifactServerMaxConcurrentRequests > 0 {
		artifactOpts = append(artifactOpts, artifactserver.WithMaxConcurrentRequests(artifactServerMaxConcurrentRequests))
	}
	operatorNamespace := os.Getenv("OPERATOR_NAMESPACE")
	artifactSrv := artifactserver.New(artifactCache, artifactOpts...)
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return artifactSrv.Start(ctx, artifactServeAddr)
	})); err != nil {
		setupLog.Error(err, "unable to add artifact server to manager")
		os.Exit(1)
	}

	if err := mgr.Add(artifactcache.NewSweeper(artifactCache, artifactcache.DefaultSweepInterval)); err != nil {
		setupLog.Error(err, "unable to add artifact cache sweep to manager")
		os.Exit(1)
	}

	// Resolve the artifact server URL to advertise to sidecar containers.
	// Explicit flag takes priority; falls back to the in-cluster Service URL derived
	// from OPERATOR_NAMESPACE when running inside the cluster.
	if artifactServerURL == "" && operatorNamespace != "" {
		scheme := "http"
		if artifactServerCertPath != "" {
			scheme = "https"
		}
		artifactServerURL = fmt.Sprintf("%s://falco-operator.%s.svc.cluster.local%s", scheme, operatorNamespace, artifactServeAddr)
	}
	if artifactServerURL != "" {
		setupLog.Info("Artifact server URL configured for sidecar injection", "url", artifactServerURL)
		resources.SetArtifactServerURL(artifactServerURL)
	} else {
		setupLog.Info("No artifact server URL available; artifact-operator sidecars will pull OCI artifacts directly from the registry")
	}

	if artifactClientCertIssuerName != "" {
		setupLog.Info("Per-instance artifact client mTLS certificate provisioning enabled",
			"issuerName", artifactClientCertIssuerName, "caBundleConfigMapName", artifactCABundleConfigMapName,
			"duration", artifactClientCertDuration, "renewBefore", artifactClientCertRenewBefore)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
