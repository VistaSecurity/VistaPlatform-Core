// maintenance-service is the Core service behind the admin console's
// Maintenance section: platform backups, the new-release notice and the
// one-click update (spec docsv4/internal/developer/standards/features/platform-maintenance.md).
//
// It is the only backend whose pod mounts a Kubernetes ServiceAccount token
// (decision D1): a namespace-scoped Role lets it read the Helm release state
// and, in later work packages, create the backup and update Jobs. WP1 ships
// the skeleton — GET /admin/maintenance/status — and the write verbs gated on
// platform.maintenance, answering 501 until their work package lands.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/capabilities"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/versions"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// shutdownTimeout bounds graceful shutdown of the HTTP listeners.
const shutdownTimeout = 10 * time.Second

func main() {
	if err := godotenv.Load(); err != nil {
		logrus.Debug("no .env file found, using process environment")
	}

	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	level, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)
	log := logrus.WithField("service", handlers.ServiceName)

	if err := enforceStartupSecrets(); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	if os.Getenv("ENV") != "development" {
		gin.SetMode(gin.ReleaseMode)
	}

	// The database answers every route's platform permission check
	// (platform_user_has_permission); later work packages keep the run and
	// backup records here too.
	if os.Getenv("DATABASE_URL") == "" {
		log.Fatal("DATABASE_URL environment variable not set")
	}
	db, err := shareddatabase.Connect(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.WithError(err).Fatal("failed to connect to the database")
	}
	defer func() { _ = shareddatabase.CloseWithSessionPool(db) }()

	// NATS carries the update-completed event (a later phase). Losing it loses
	// a notification, never a run, so an unreachable NATS is a warning.
	var natsClient *events.NATSClient
	if nc, natsErr := events.NewNATSClient(""); natsErr != nil {
		log.WithError(natsErr).Warn("NATS unavailable; continuing without the event bus")
	} else {
		natsClient = nc
	}

	settings := capabilities.Settings{
		ReleaseName:    os.Getenv("HELM_RELEASE_NAME"),
		Namespace:      os.Getenv("POD_NAMESPACE"),
		PodName:        os.Getenv("POD_NAME"),
		BackupsEnabled: os.Getenv("MAINTENANCE_BACKUPS_ENABLED") == "true",
	}
	detector, err := capabilities.FromEnvironment(settings)
	if err != nil {
		// In a cluster but unable to build a client: report the cluster API as
		// unavailable rather than pretend this is not Kubernetes.
		log.WithError(err).Warn("capabilities: Kubernetes client unavailable")
		detector = clusterAPIUnavailable{}
	}

	var versionSource versions.Source
	if vc, vErr := versions.NewFromEnv(); vErr != nil {
		log.WithError(vErr).Warn("versions: monitoring-service client unavailable; the versions card will show its error state")
	} else {
		versionSource = vc
	}

	useMTLS := sharedconfig.GetEnvAsBool("USE_MTLS", true)
	clientCertPath := sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem")
	clientKeyPath := sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem")
	platformCACertPath := sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem")

	auditMW := auditmiddleware.NewMiddleware(auditmiddleware.ServiceConfig(
		handlers.ServiceName, useMTLS, clientCertPath, clientKeyPath, platformCACertPath,
	))
	defer auditMW.Stop()

	var natsState handlers.ConnectionState
	if natsClient != nil {
		natsState = natsClient
	}
	h := handlers.New(db, natsState, detector, versionSource, handlers.Config{
		Release:    capabilities.Release{Name: settings.ReleaseName, Namespace: settings.Namespace},
		SingleNode: os.Getenv("MAINTENANCE_SINGLE_NODE") == "true",
	}, log)

	// The update check (WP2): a scheduler writing platform_update_status, and
	// the service behind GET /updates and POST /updates/check. The scheduler
	// stops with the process context.
	bgCtx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()

	// Backups and the run machinery (WP3): reconciles runs a previous process
	// left running before the API serves.
	k8sClient, err := inClusterClient()
	if err != nil {
		log.WithError(err).Warn("maintenance runs: Kubernetes client unavailable; backups are off")
	}
	updateSvc := newUpdateService(bgCtx, db, settings.Namespace, log)
	h.SetUpdates(updateSvc)
	ops := newMaintenanceOps(db, k8sClient, backupsConfigFromEnv(), sharedAuditor{}, upgradeInputs{
		Detector:   detector,
		Tags:       updateSvc.Checker.Tags,
		Versions:   versionSource,
		SingleNode: os.Getenv("MAINTENANCE_SINGLE_NODE") == "true",
		AuditMW:    auditMW,
		PullSecret: pullSecretReader(settings.Namespace, log),
	}, log)
	defer ops.Stop()

	router := newRouter(h, auditMW, newAuthMiddleware(os.Getenv("JWT_SECRET")), db, ops)

	port := sharedconfig.GetEnv("PORT", "8080")
	tlsPort := sharedconfig.GetEnv("TLS_PORT", "8443")
	apiPort := port
	if useMTLS {
		apiPort = tlsPort
	}
	servers, err := sharedhttp.StartDualListeners(sharedhttp.DualListenerConfig{
		APIHandler:   router,
		ProbeHandler: newProbeRouter(h),
		UseMTLS:      useMTLS,
		APIPort:      apiPort,
		ProbePort:    port,
		CertPath:     sharedconfig.GetEnv("SERVICE_CERT_PATH", "/app/certs/server-cert.pem"),
		KeyPath:      sharedconfig.GetEnv("SERVICE_KEY_PATH", "/app/certs/server-key.pem"),
		CACertPath:   platformCACertPath,
	})
	if err != nil {
		log.WithError(err).Fatal("failed to start HTTP listeners")
	}
	log.WithFields(logrus.Fields{"api_port": apiPort, "probe_port": port, "mtls": useMTLS}).Info("maintenance-service started")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.WithField("signal", sig.String()).Info("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := servers.Shutdown(ctx); err != nil {
		log.WithError(err).Warn("error shutting down HTTP listeners")
	}
	if natsClient != nil {
		if err := natsClient.GracefulShutdown(ctx); err != nil {
			log.WithError(err).Warn("error draining NATS")
		}
	}
	log.Info("maintenance-service stopped")
}

// clusterAPIUnavailable is the detector when the process is in a cluster but
// could not build a Kubernetes client: nothing offered, the reason says why.
// Backups need the API too (they run as Jobs), so they are withheld as well.
type clusterAPIUnavailable struct{}

func (clusterAPIUnavailable) Detect(context.Context) capabilities.Capabilities {
	return capabilities.Capabilities{Reason: capabilities.ReasonClusterAPIUnavailable}
}
