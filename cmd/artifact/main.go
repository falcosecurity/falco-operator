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
	"net"
	"net/http"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	artifactv1alpha1 "github.com/falcosecurity/falco-operator/api/artifact/v1alpha1"
	"github.com/falcosecurity/falco-operator/controllers/artifact/config"
	"github.com/falcosecurity/falco-operator/controllers/artifact/plugin"
	"github.com/falcosecurity/falco-operator/controllers/artifact/rulesfile"
	"github.com/falcosecurity/falco-operator/internal/pkg/artifact"
	"github.com/falcosecurity/falco-operator/internal/pkg/compat"
	"github.com/falcosecurity/falco-operator/internal/pkg/envutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/index"
	"github.com/falcosecurity/falco-operator/internal/pkg/logging"
	"github.com/falcosecurity/falco-operator/internal/pkg/nodeartifacts"
	"github.com/falcosecurity/falco-operator/internal/pkg/tlsutil"
	"github.com/falcosecurity/falco-operator/internal/pkg/version"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

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
	var falcoBaseURL string
	var enforceRequirements bool
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
	flag.StringVar(&falcoBaseURL, "falco-url", compat.DefaultBaseURL,
		"Base URL for the Falco REST API used to verify plugin compatibility")
	flag.BoolVar(&enforceRequirements, "enforce-requirements", true,
		"Block artifact installation when OCI-declared requirements are not satisfied by the running "+
			"Falco instance, or when they cannot be verified. When false, the operator installs the "+
			"artifact anyway and records the unmet requirement in status and logs instead of blocking.")

	// artifactServerURL, artifactClientCertPath and artifactServerCAFile are normally set via the
	// ARTIFACT_SERVER_URL/ARTIFACT_CLIENT_CERT_PATH/ARTIFACT_SERVER_CA_FILE env vars (see
	// resources.WithArtifactClientCertOverlay for the Helm chart's cert-manager/trust-manager setup).
	// envutil.BindFlagEnv, called after flag.Parse below, applies each env var to its flag when the
	// flag isn't set on the command line.
	var artifactServerURL string
	var artifactClientCertPath, artifactClientCertName, artifactClientCertKey string
	var artifactServerCAFile string
	flag.StringVar(&artifactServerURL, "artifact-server-url", "",
		"URL of the central artifact HTTP server to fetch OCI artifacts from, instead of pulling "+
			"directly from the registry.")
	flag.StringVar(&artifactClientCertPath, "artifact-client-cert-path", "",
		"The directory that contains the client certificate used to authenticate to the central "+
			"artifact server via mTLS. Only meaningful when the artifact server requires client certs.")
	flag.StringVar(&artifactClientCertName, "artifact-client-cert-name", "tls.crt", "The name of the artifact client certificate file.")
	flag.StringVar(&artifactClientCertKey, "artifact-client-cert-key", "tls.key", "The name of the artifact client key file.")
	flag.StringVar(&artifactServerCAFile, "artifact-server-ca-file", "",
		"Path to a PEM file containing the CA bundle used to verify the artifact server's TLS "+
			"certificate, for deployments using a private CA. Empty uses the system trust store.")

	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	if err := envutil.BindFlagEnv(flag.CommandLine); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctrl.SetLogger(logging.FilterEventRejectionOnTerminatingNamespace(zap.New(zap.UseFlagOptions(&opts))))

	if artifactServerURL != "" {
		setupLog.Info("Artifact server mode enabled; OCI artifacts will be fetched from the central cache",
			"artifactServer", artifactServerURL)
	} else {
		setupLog.Info("Artifact server mode disabled; OCI artifacts will be pulled directly from the registry")
	}

	setupLog.Info("Starting artifact operator", "version", version.SemVersion, "commit", version.GitCommit,
		"buildDate", version.BuildDate, "compiler", version.Compiler, "platform", version.Platform)

	// Get the namespace from environment variable.
	namespace, ok := os.LookupEnv("POD_NAMESPACE")
	if !ok {
		setupLog.Error(nil, "unable to get POD_NAMESPACE environment variable")
		os.Exit(1)
	}

	// Get the node name from environment variable.
	nodeName, ok := os.LookupEnv("NODE_NAME")
	if !ok {
		setupLog.Error(nil, "unable to get NODE_NAME environment variable")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	// Waits for Falco to be available before starting the controllers; Falco starts in idle mode
	// (no plugins, no rules) as a regular container alongside the artifact operator. The fetched
	// snapshot seeds nodeManager's Falco-capability cache below, which compatibility checks read
	// instead of querying Falco live on every reconcile.
	setupLog.Info("Waiting for Falco to be available", "url", falcoBaseURL)
	initialFalcoVersions, err := compat.WaitAndFetch(ctx, falcoBaseURL)
	if err != nil {
		setupLog.Error(err, "failed to fetch Falco versions at startup")
		os.Exit(1)
	}
	setupLog.Info("Falco versions fetched successfully")

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

	// Metrics server options. The artifact operator runs as a sidecar of the Falco pod,
	// so flags are set by the instance operator when it builds the sidecar container spec. See:
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
	// server. Not recommended for production; provide real cert material via --metrics-cert-path
	// set on the sidecar container spec.
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

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "a7b8c9d0.falcosecurity.dev",
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				namespace: {},
			},
		},
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

	for _, idx := range index.All {
		setupLog.Info("Registering field index", "object", fmt.Sprintf("%T", idx.Object), "field", idx.Field)
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), idx.Object, idx.Field, idx.ExtractValueFn); err != nil {
			setupLog.Error(err, "unable to register field index", "field", idx.Field)
			os.Exit(1)
		}
	}

	// falcoFetcher is shared by nodeManager (post-install refresh) and versionsWatcher (periodic
	// refresh); both call the same Falco /versions endpoint on different triggers. See
	// nodeartifacts.Manager's doc comment.
	falcoFetcher := compat.NewHTTPVersionsFetcher(falcoBaseURL)

	// nodeManager coordinates disk writes across the Plugin/Rulesfile/Config reconcilers below,
	// keeping a plugin's config entry until no rules file on this node still requires it. It also
	// caches Falco's reported capabilities and plugin versions so compatibility checks never
	// require a live HTTP call. Warm-syncing provides/requires state from durable ArtifactNode
	// status happens in a WarmSyncRunnable (mgr.Add below), which controller-runtime runs after
	// the manager's cache syncs and before any reconciler starts; it uses the manager's own
	// cache-backed client (mgr.GetClient()) to avoid a fleet-wide direct-apiserver request storm
	// when every node's sidecar restarts at once.
	nodeManager := nodeartifacts.NewManager(artifact.NewLocalStore(), falcoFetcher)
	nodeManager.OnFalcoVersionsObserved(initialFalcoVersions) // seeds the cache from the fetch above
	if err := mgr.Add(nodeartifacts.NewWarmSyncRunnable(mgr.GetClient(), nodeManager, namespace, nodeName)); err != nil {
		setupLog.Error(err, "unable to add node artifact manager warm sync to manager")
		os.Exit(1)
	}

	if err = config.NewConfigReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
		mgr.GetEventRecorder("config-controller/"+nodeName),
		nodeName,
		namespace,
		nodeManager,
	).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Config")
		os.Exit(1)
	}

	versionsWatcher := compat.NewVersionsWatcher(falcoFetcher, compat.DefaultWatchInterval)
	versionsWatcher.SetSink(nodeManager.OnFalcoVersionsObserved)
	if err := mgr.Add(versionsWatcher); err != nil {
		setupLog.Error(err, "unable to add Falco versions watcher to manager")
		os.Exit(1)
	}

	// Backstop for a write to the shared plugins-config file landing during one of Falco's
	// SIGHUP-triggered restarts and never being picked up; see PluginConfigRetrier's doc comment.
	// FetchInline, the only ArtifactFetcher method this path uses, needs no server URL, HTTP
	// client, or K8s client, so a bare &artifact.Fetcher{} suffices.
	pluginConfigRetrier := nodeartifacts.NewPluginConfigRetrier(
		nodeManager, &artifact.Fetcher{},
		nodeartifacts.DefaultPluginConfigRetryInterval, nodeartifacts.DefaultPluginConfigMismatchGracePeriod,
	)
	if err := mgr.Add(pluginConfigRetrier); err != nil {
		setupLog.Error(err, "unable to add plugin config retrier to manager")
		os.Exit(1)
	}

	// Builds the shared HTTP client and Fetcher used by both the Rulesfile and Plugin
	// reconcilers' FetchOCI calls. TLS/mTLS identity and retry policy are configured once here
	// for both reconcilers.
	var artifactClientCertWatcher *certwatcher.CertWatcher
	var artifactCAWatcher *tlsutil.CAWatcher

	if artifactClientCertPath != "" {
		setupLog.Info("Initializing artifact client certificate watcher using provided certificates",
			"artifact-client-cert-path", artifactClientCertPath,
			"artifact-client-cert-name", artifactClientCertName, "artifact-client-cert-key", artifactClientCertKey)

		var certErr error
		artifactClientCertWatcher, certErr = certwatcher.New(
			filepath.Join(artifactClientCertPath, artifactClientCertName),
			filepath.Join(artifactClientCertPath, artifactClientCertKey),
		)
		if certErr != nil {
			setupLog.Error(certErr, "Failed to initialize artifact client certificate watcher")
			os.Exit(1)
		}
	}

	if artifactServerCAFile != "" {
		setupLog.Info("Initializing artifact server CA watcher", "artifact-server-ca-file", artifactServerCAFile)

		var caErr error
		artifactCAWatcher, caErr = tlsutil.NewCAWatcher(artifactServerCAFile)
		if caErr != nil {
			setupLog.Error(caErr, "Failed to initialize artifact server CA watcher")
			os.Exit(1)
		}
	}

	artifactTransport := http.DefaultTransport.(*http.Transport).Clone()
	if artifactClientCertWatcher != nil || artifactCAWatcher != nil {
		// http.Transport.TLSClientConfig is a single static *tls.Config shared across
		// connections; there is no client-side hook to re-read the trust pool or client cert
		// per connection. DialTLSContext instead builds a fresh tls.Config from the watchers'
		// current state on every new TCP connection, so a cert/CA reload takes effect the next
		// time a keep-alive connection is re-established.
		artifactTransport.DialTLSContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, network, addr)
			if dialErr != nil {
				return nil, dialErr
			}
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				host = addr
			}
			tlsConfig := &tls.Config{ServerName: host}
			if artifactCAWatcher != nil {
				tlsConfig.RootCAs = artifactCAWatcher.CertPool()
			}
			if artifactClientCertWatcher != nil {
				tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return artifactClientCertWatcher.GetCertificate(nil)
				}
			}
			tlsConn := tls.Client(conn, tlsConfig)
			if hsErr := tlsConn.HandshakeContext(dialCtx); hsErr != nil {
				_ = conn.Close()
				return nil, hsErr
			}
			return tlsConn, nil
		}
	}

	artifactFetcher := &artifact.Fetcher{
		ServerURL:  artifactServerURL,
		HTTPClient: &http.Client{Transport: artifactTransport},
		K8sClient:  mgr.GetClient(),
		NodeName:   nodeName,
	}

	if err := rulesfile.NewRulesfileReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
		mgr.GetEventRecorder("rulesfile-controller/"+nodeName),
		nodeName,
		namespace,
		enforceRequirements,
		artifactFetcher,
		nodeManager,
	).SetupWithManager(mgr, nodeManager.Events()); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Rulesfile")
		os.Exit(1)
	}

	if err := plugin.NewPluginReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
		mgr.GetEventRecorder("plugin-controller/"+nodeName),
		nodeName,
		namespace,
		enforceRequirements,
		artifactFetcher,
		nodeManager,
	).SetupWithManager(mgr, nodeManager.Events()); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Plugin")
		os.Exit(1)
	}

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

	if artifactClientCertWatcher != nil {
		setupLog.Info("Adding artifact client certificate watcher to manager")
		if err := mgr.Add(artifactClientCertWatcher); err != nil {
			setupLog.Error(err, "unable to add artifact client certificate watcher to manager")
			os.Exit(1)
		}
	}

	if artifactCAWatcher != nil {
		setupLog.Info("Adding artifact server CA watcher to manager")
		if err := mgr.Add(artifactCAWatcher); err != nil {
			setupLog.Error(err, "unable to add artifact server CA watcher to manager")
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

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
