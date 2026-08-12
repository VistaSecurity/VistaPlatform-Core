// Package main is the entry point for cbom-service.
//
// Phase 5 of the CBOM-centric reporting redesign demolished the legacy
// templated-report surface (13 built-in templates, lens reports, custom
// templates, scheduled reports, platform admin reports). The service now
// has three focused responsibilities, exposed under /api/v1/cbom-service:
//
//  1. Scopes — tenant-owned, named, versioned predicate definitions
//     (Phase 1). Routes registered by scopes.Handler.
//  2. CBOM Artifacts — immutable, content-hashed, optionally signed
//     snapshots (Phase 2 + Phase 4). Routes by cbom.Handler.
//  3. Comparison — diff two artifacts with categorized changes
//     (Phase 3). Routes by diff.Handler.
//
// The chart-level Traefik redirect for old /api/v1/report-generator/*
// URLs was retired in after the v2.4.x release window. Clients
// must use /api/v1/cbom-service/* directly.
package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/cbom"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/config"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/database"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/datasources"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	sharedrbacmw "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	resourcetracking "github.com/vistasecurity/vistaplatform/shared/middleware/resource-tracking"
	trial_lock "github.com/vistasecurity/vistaplatform/shared/middleware/trial_lock"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

// initCBOMArtifactStorage wires the shared/storage abstraction for CBOM
// artifacts. Returns nil (with a logged warning) if storage cannot be
// initialized — the cbom package handles nil by stashing artifact content
// inline in the cbom_artifacts.inline_content JSONB column, so the feature
// still works in dev / brand-new installs that haven't configured S3.
//
// Mirrors the pattern in services/auth-service/internal/api/storage_service.go.
func initCBOMArtifactStorage(db *database.DB, bypassDB *sql.DB) sharedstorage.ArtifactStorageService {
	masterKey := os.Getenv("ENCRYPTION_MASTER_KEY")
	if masterKey == "" {
		log.Printf("[cbom-storage] ENCRYPTION_MASTER_KEY not set — CBOM artifacts will be stored inline in Postgres until an admin configures S3")
		return nil
	}
	encSvc, err := encryption.NewService(masterKey)
	if err != nil {
		log.Printf("[cbom-storage] failed to create encryption service: %v — falling back to inline storage", err)
		return nil
	}
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	sqlDB := db.SQLDB()
	configProvider := sharedstorage.NewDatabaseConfigProvider(sqlDB)
	integrationProvider := sharedstorage.NewDatabaseIntegrationProvider(bypassDB, encSvc)
	svc := sharedstorage.NewS3StorageService(configProvider, integrationProvider, logger)

	// Retry the initial config load briefly. At pod startup the DB pool may not
	// be ready yet (or a startup context gets canceled mid-query — the
	// "context canceled" failure we observed), and a single transient failure
	// here previously disabled S3 for the entire process lifetime, silently
	// routing every CBOM to inline Postgres storage even when the operator had
	// configured a bucket. A few short retries cover the boot race.
	const maxAttempts = 5
	var reloadErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if reloadErr = svc.Reload(context.Background()); reloadErr == nil {
			break
		}
		log.Printf("[cbom-storage] storage config load attempt %d/%d failed: %v", attempt, maxAttempts, reloadErr)
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}
	if reloadErr != nil {
		// Return the live service (not nil) holding its safe default config
		// (S3 disabled): the persister falls back to inline storage so CBOM
		// generation keeps working, and a later Reload can still enable S3
		// without a process restart.
		log.Printf("[cbom-storage] storage config did not load after %d attempts — CBOM artifacts will use inline storage until reloaded: %v", maxAttempts, reloadErr)
		return svc
	}
	log.Printf("[cbom-storage] storage service initialized (CBOM artifact type enabled = %v)", svc.IsEnabled(sharedstorage.ArtifactTypeCBOM))
	return svc
}

func main() {
	cfg := config.Load()

	// First line of the log, so an operator can tell which binary is running
	// without inspecting the image. This is the whole reason edition() exists.
	log.Printf("[cbom-service] starting (edition: %s)", edition())

	db, err := database.NewConnection(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to open bypass database connection: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()

	// Resource tracking middleware.
	trackerConfig := resourcetracking.DefaultConfig()
	trackerConfig.ServiceName = "cbom-service"
	trackerConfig.TrackerURL = os.Getenv("RESOURCE_TRACKER_URL")
	if trackerConfig.TrackerURL == "" {
		trackerConfig.TrackerURL = sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled())
	}
	trackerConfig.UseMTLS = cfg.UseMTLS
	trackerConfig.ClientCertPath = cfg.ClientCertPath
	trackerConfig.ClientKeyPath = cfg.ClientKeyPath
	trackerConfig.PlatformCACertPath = cfg.PlatformCACertPath
	router.Use(resourcetracking.Middleware(trackerConfig))

	// Audit logging middleware.
	auditConfig := auditmiddleware.DefaultConfig()
	auditConfig.ServiceName = "cbom-service"
	auditConfig.AuditServiceURL = os.Getenv("AUDIT_SERVICE_URL")
	if auditConfig.AuditServiceURL == "" {
		if cfg.UseMTLS {
			auditConfig.AuditServiceURL = "https://audit-service:8443"
		} else {
			auditConfig.AuditServiceURL = sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled())
		}
	}
	auditConfig.Enabled = os.Getenv("AUDIT_LOGGING_ENABLED") != "false"
	auditConfig.UseMTLS = cfg.UseMTLS
	auditConfig.ClientCertPath = cfg.ClientCertPath
	auditConfig.ClientKeyPath = cfg.ClientKeyPath
	auditConfig.PlatformCACertPath = cfg.PlatformCACertPath
	auditMiddleware := auditmiddleware.NewMiddleware(auditConfig)
	router.Use(auditMiddleware.LogRequest())

	// Inventory data source — used by the CBOM builder to fetch the snapshot
	// of every asset / certificate / crypto-implementation / algorithm
	// matching the scope.
	inventoryDataSource, err := datasources.NewInventoryDataSource(sharedconfig.PeerURL("inventory-service", sharedconfig.MTLSEnabled()))
	if err != nil {
		log.Fatalf("Failed to create inventory data source: %v", err)
	}

	// CBOM generation pipeline (kept from the pre-Phase-5 design — it's the
	// workhorse that walks inventory and produces a CBOMData document).
	cbomReportHandler := handlers.NewCBOMReportHandler(inventoryDataSource)

	// Phase 1: Scopes.
	scopeRepo := scopes.NewRepository(db)
	scopeHandler := scopes.NewHandler(scopeRepo)

	// Phase 2 + Phase 4: CBOM Artifact persistence + signing + attestation.
	cbomArtifactStorage := initCBOMArtifactStorage(db, bypassDB)
	cbomRepo := cbom.NewRepository(db)
	cbomBuilder := cbom.NewBuilder(cbomReportHandler)
	// Signing + attestation are Enterprise (cmd/edition.go). In Core both
	// hooks are nil, so cbomSigner/attestationBuilder stay nil interfaces and
	// the persister's nil-tolerant paths generate unsigned, unattested
	// artifacts — the supported Core outcome.
	var cbomSigner cbom.Signer
	if hooks.NewSigner != nil {
		s, signerErr := hooks.NewSigner()
		if signerErr != nil {
			log.Printf("[cbom-sign] %v — artifacts will be generated unsigned", signerErr)
		} else {
			cbomSigner = s
		}
	}
	var attestationBuilder cbom.AttestationBuilder
	if hooks.NewAttestationBuilder != nil {
		attestationBuilder = hooks.NewAttestationBuilder(db.SQLDB())
	}
	cbomPersister := cbom.NewPersisterWithSigning(cbomRepo, cbomArtifactStorage, cbomSigner, attestationBuilder)
	cbomHandler := cbom.NewHandler(cbomRepo, cbomBuilder, cbomPersister, scopeRepo, cbomArtifactStorage)
	cbomHandler.SetFeatureChecker(sharedservices.NewLimitEnforcementService(db.SQLDB()))
	cbomHandler.SetSigner(cbomSigner)
	// SPDX/PDF export is Enterprise (cmd/edition.go). Left unset in Core, where
	// /cbom/artifacts/:id/download answers 402 for those formats and serves the
	// canonical CycloneDX form as always.
	if hooks.NewArtifactFormatter != nil {
		cbomHandler.SetArtifactFormatter(hooks.NewArtifactFormatter())
	}

	// Health check on main router (used when mTLS is disabled and API serves on port 8080).
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "cbom-service",
			"version": version.Get(),
		})
	})

	// API routes. Three small, focused handlers — that's the whole surface.
	api := router.Group("/api/v1/cbom-service")
	api.Use(middleware.RequireAuth(cfg.JWTSecret), middleware.StringifyUserID())
	// Trial-lock middleware gates writes when the calling tenant is in
	// PhaseLocked. Scope/CBOM/diff writes all flow through here.
	api.Use(trial_lock.Middleware(db.SQLDB(), nil))
	{
		// Write gates: scopes define the attestation boundary —
		// compliance configuration — while artifact generate/delete/verify is
		// evidence management. Reads (and diff, which is compute-only over
		// existing artifacts) stay open to any tenant member.
		scopeHandler.RegisterRoutes(api, sharedrbacmw.RequireTenantPermission(db.SQLDB(), rbac.PermissionComplianceUpdate))
		cbomHandler.RegisterRoutes(api, sharedrbacmw.RequireTenantPermission(db.SQLDB(), rbac.PermissionReportsManage))
		// Phase 3 comparison is Enterprise; the hook is nil in Core, so
		// these routes are simply never mounted. The tenant entitlement gate is
		// still required in Enterprise builds so a Core-tier tenant cannot call
		// the API directly around the UI lock card.
		if hooks.RegisterComparisonRoutes != nil {
			compare := api.Group("")
			compare.Use(sharedmw.RequireFeature(db.SQLDB(), cbom.FeatureCBOMSigning))
			hooks.RegisterComparisonRoutes(compare, cbomRepo, cbomArtifactStorage)
		}
	}

	// Health check server (HTTP, port 8080).
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "cbom-service",
			"version": version.Get(),
		})
	})

	port := cfg.Port
	if port == "" {
		port = "8080"
	}

	healthServer := &http.Server{
		Addr:              ":" + port,
		Handler:           healthRouter,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// API server (HTTPS with mTLS, port 8443).
	var apiServer *http.Server
	if cfg.UseMTLS {
		apiServer, err = sharedhttp.NewMTLSServer(
			cfg.ServiceCertPath,
			cfg.ServiceKeyPath,
			cfg.PlatformCACertPath,
			router,
		)
		if err != nil {
			log.Fatalf("Failed to create mTLS server: %v", err)
		}
		apiServer.Addr = ":" + cfg.TLSPort
		apiServer.ReadHeaderTimeout = 5 * time.Second
		apiServer.ReadTimeout = 10 * time.Second
		apiServer.WriteTimeout = 15 * time.Second
		apiServer.IdleTimeout = 60 * time.Second
	} else {
		apiServer = &http.Server{
			Addr:              ":" + port,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	if cfg.UseMTLS {
		go func() {
			log.Printf("Health check server starting on port %s", port)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health server: %v", err)
			}
		}()
	}

	go func() {
		if cfg.UseMTLS {
			log.Printf("cbom-service API server starting on port %s (mTLS)", cfg.TLSPort)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("cbom-service API server starting on port %s (HTTP fallback)", port)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down cbom-service...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}
	log.Println("cbom-service stopped")
}
