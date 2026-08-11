package api

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/services"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	rbac "github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// channelManagerIface / ruleEngineIface are the narrow service surfaces the
// HTTP handlers depend on (not the concrete *services.X types) so the handlers
// can be exercised against in-memory stubs — no database — in the spec-first
// contract tests (ADR-0001). The concrete *services.ChannelManager /
// *services.RuleEngine satisfy them; production wiring is unchanged.
type channelManagerIface interface {
	GetTenantChannels(ctx context.Context, tenantID uuid.UUID) ([]models.TenantNotificationChannel, error)
	GetTenantChannelByID(ctx context.Context, tenantID, channelID uuid.UUID) (*models.TenantNotificationChannel, error)
	CreateTenantChannel(ctx context.Context, tenantID uuid.UUID, req *models.CreateChannelRequest, createdBy *uuid.UUID) (*models.TenantNotificationChannel, error)
	UpdateTenantChannel(ctx context.Context, tenantID, channelID uuid.UUID, req *models.UpdateChannelRequest, updatedBy *uuid.UUID) (*models.TenantNotificationChannel, error)
	DeleteTenantChannel(ctx context.Context, tenantID, channelID uuid.UUID) error
	TestTenantChannel(ctx context.Context, tenantID, channelID uuid.UUID) error
	GetPlatformChannels() ([]models.PlatformNotificationChannel, error)
	GetPlatformChannelByID(channelID uuid.UUID) (*models.PlatformNotificationChannel, error)
	CreatePlatformChannel(req *models.CreateChannelRequest, createdBy *uuid.UUID) (*models.PlatformNotificationChannel, error)
	UpdatePlatformChannel(channelID uuid.UUID, req *models.UpdateChannelRequest, updatedBy *uuid.UUID) (*models.PlatformNotificationChannel, error)
	DeletePlatformChannel(channelID uuid.UUID) error
	TestPlatformChannel(ctx context.Context, channelID uuid.UUID) error
}

type ruleEngineIface interface {
	GetTenantRules(ctx context.Context, tenantID uuid.UUID) ([]models.TenantNotificationRule, error)
	CreateTenantRule(ctx context.Context, tenantID uuid.UUID, req *models.CreateRuleRequest) (*models.TenantNotificationRule, error)
	UpdateTenantRule(ctx context.Context, tenantID, ruleID uuid.UUID, req *models.UpdateRuleRequest) (*models.TenantNotificationRule, error)
	DeleteTenantRule(ctx context.Context, tenantID, ruleID uuid.UUID) error
	GetPlatformRules() ([]models.PlatformNotificationRule, error)
	CreatePlatformRule(req *models.CreateRuleRequest) (*models.PlatformNotificationRule, error)
	UpdatePlatformRule(ruleID uuid.UUID, req *models.UpdateRuleRequest) (*models.PlatformNotificationRule, error)
	DeletePlatformRule(ruleID uuid.UUID) error
}

// maintenanceIface is the narrow surface the platform maintenance-window
// handlers depend on, so they can be driven against an in-memory stub — no
// database — in the spec-first contract test (maintenance_contract_test.go).
// The concrete *services.NotificationService satisfies it.
type maintenanceIface interface {
	ListMaintenanceWindows(ctx context.Context) ([]services.MaintenanceWindow, error)
	CreateMaintenanceWindow(ctx context.Context, startsAt, endsAt time.Time, reason string, createdBy *uuid.UUID) (*services.MaintenanceWindow, error)
	DeleteMaintenanceWindow(ctx context.Context, id uuid.UUID) (bool, error)
}

type Server struct {
	config              *config.Config
	db                  *sqlx.DB
	notificationService *services.NotificationService
	channelManager      channelManagerIface
	ruleEngine          ruleEngineIface
	maintenance         maintenanceIface
	readStore           notificationReadStore
}

// NewServer wires the HTTP server. bypassDB is the BYPASSRLS handle
// (shared/database.ConnectBypass) threaded to the read store for the
// platform-history (tenant_id IS NULL) read, which crypto_app cannot see under
// RLS (Phase 4).
func NewServer(cfg *config.Config, db *sqlx.DB, bypassDB *sql.DB, notificationService *services.NotificationService) *Server {
	return &Server{
		config:              cfg,
		db:                  db,
		notificationService: notificationService,
		channelManager:      notificationService.ChannelManager(),
		ruleEngine:          notificationService.RuleEngine(),
		maintenance:         notificationService,
		readStore:           newNotificationReadStore(db, bypassDB),
	}
}

// newServerWithManagers builds a Server from already-constructed channel/rule
// managers. It exists so the tenant channel + rule HTTP handlers can be driven
// against in-memory stubs in the contract tests (ADR-0001); production wiring
// goes through NewServer.
func newServerWithManagers(channelManager channelManagerIface, ruleEngine ruleEngineIface) *Server {
	return &Server{
		channelManager: channelManager,
		ruleEngine:     ruleEngine,
	}
}

// newServerWithReadStore builds a Server with just the read store the tenant
// history + in-app notification handlers need, for the contract tests.
func newServerWithReadStore(readStore notificationReadStore) *Server {
	return &Server{readStore: readStore}
}

// newServerWithMaintenance builds a Server with just the maintenance-window
// surface the platform maintenance handlers need, for the contract tests.
func newServerWithMaintenance(m maintenanceIface) *Server {
	return &Server{maintenance: m}
}

func (s *Server) SetupRouter() *gin.Engine {
	// Set Gin mode
	if s.config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(sharedmw.SecurityHeaders())

	// Audit logging: auto-record every mutating request — notification channel
	// and routing-rule config changes were the last unaudited config surface
	// (§10.5). LogRequest reads the actor from the gin context after the
	// downstream auth middleware runs, so a global Use is correct. Best-effort
	// and disabled-safe (AUDIT_LOGGING_ENABLED=false to opt out).
	auditConfig := auditmiddleware.DefaultConfig()
	auditConfig.ServiceName = "notification-service"
	auditConfig.AuditServiceURL = os.Getenv("AUDIT_SERVICE_URL")
	if auditConfig.AuditServiceURL == "" {
		if s.config.UseMTLS {
			auditConfig.AuditServiceURL = "https://audit-service:8443"
		} else {
			auditConfig.AuditServiceURL = "http://audit-service:8080"
		}
	}
	auditConfig.Enabled = os.Getenv("AUDIT_LOGGING_ENABLED") != "false"
	auditConfig.UseMTLS = s.config.UseMTLS
	auditConfig.ClientCertPath = s.config.ClientCertPath
	auditConfig.ClientKeyPath = s.config.ClientKeyPath
	auditConfig.PlatformCACertPath = s.config.PlatformCACertPath
	router.Use(auditmiddleware.NewMiddleware(auditConfig).LogRequest())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "notification-service",
			"version": version.Get(),
		})
	})

	// API routes
	api := router.Group("/api/v1")
	{
		// Internal endpoint for other services to send notifications
		internal := api.Group("/notification-service/internal")
		// HMAC-only: /internal/send is the raw delivery path that
		// bypasses the rule engine — user JWTs must not reach it.
		internal.Use(middleware.RequireInternalHMAC())
		{
			internal.POST("/send", s.sendNotification) // Internal service-to-service
		}

		// Tenant endpoints
		tenant := api.Group("/notification-service/tenant")
		tenant.Use(middleware.RequireAuth(s.config.JWTSecret), middleware.StringifyUserID())
		tenant.Use(middleware.RequireTenant())
		// Write gate: channel/rule mutation is org notification
		// configuration — settings.update. Reads stay open so any member can
		// see where alerts route.
		writeGate := sharedrbac.RequireTenantPermission(s.db.DB, rbac.PermissionSettingsUpdate)
		{
			// Channels
			channels := tenant.Group("/channels")
			{
				channels.GET("", s.listTenantChannels)
				channels.POST("", writeGate, s.createTenantChannel)
				channels.GET("/:id", s.getTenantChannel)
				channels.PUT("/:id", writeGate, s.updateTenantChannel)
				channels.DELETE("/:id", writeGate, s.deleteTenantChannel)
				channels.POST("/:id/test", writeGate, s.testTenantChannel)
			}

			// Rules
			rules := tenant.Group("/rules")
			{
				rules.GET("", s.listTenantRules)
				rules.POST("", writeGate, s.createTenantRule)
				rules.GET("/:id", s.getTenantRule)
				rules.PUT("/:id", writeGate, s.updateTenantRule)
				rules.DELETE("/:id", writeGate, s.deleteTenantRule)
			}

			// History
			tenant.GET("/history", s.getTenantHistory)

			// In-app notifications (bell feed). Mark-read is deliberately NOT
			// behind writeGate — any member manages their own bell.
			tenant.GET("/notifications", s.getTenantInAppNotifications)
			tenant.PUT("/notifications/read-all", s.markAllTenantNotificationsRead)
			tenant.PUT("/notifications/:id/read", s.markTenantNotificationRead)
		}

		// Platform admin endpoints
		platform := api.Group("/notification-service/platform")
		platform.Use(middleware.RequireAuth(s.config.JWTSecret), middleware.StringifyUserID())
		platform.Use(sharedrbac.RequirePlatformPermission(s.db.DB, rbac.PermissionPlatformNotificationsManage))
		{
			// Channels
			channels := platform.Group("/channels")
			{
				channels.GET("", s.listPlatformChannels)
				channels.POST("", s.createPlatformChannel)
				channels.GET("/:id", s.getPlatformChannel)
				channels.PUT("/:id", s.updatePlatformChannel)
				channels.DELETE("/:id", s.deletePlatformChannel)
				channels.POST("/:id/test", s.testPlatformChannel)
			}

			// Rules
			rules := platform.Group("/rules")
			{
				rules.GET("", s.listPlatformRules)
				rules.POST("", s.createPlatformRule)
				rules.GET("/:id", s.getPlatformRule)
				rules.PUT("/:id", s.updatePlatformRule)
				rules.DELETE("/:id", s.deletePlatformRule)
			}

			// Maintenance windows (storm control §10.3): while an active window
			// is in effect, notification-service suppresses delivery.
			maint := platform.Group("/maintenance-windows")
			{
				maint.GET("", s.listMaintenanceWindows)
				maint.POST("", s.createMaintenanceWindow)
				maint.DELETE("/:id", s.deleteMaintenanceWindow)
			}

			// History
			platform.GET("/history", s.getPlatformHistory)
		}

		// Platform in-app inbox (admin-ui bell). Deliberately NOT behind
		// platform.notifications.manage — the bell is for every platform
		// staffer, so any real platform permission grants access.
		platformInbox := api.Group("/notification-service/platform/notifications")
		platformInbox.Use(middleware.RequireAuth(s.config.JWTSecret), middleware.StringifyUserID())
		platformInbox.Use(sharedrbac.RequireAnyPlatformPermission(s.db.DB,
			rbac.PermissionPlatformNotificationsManage,
			rbac.PermissionPlatformHealth,
			rbac.PermissionPlatformAnalytics,
			rbac.PermissionPlatformSettings,
			rbac.PermissionPlatformSecurity,
			rbac.PermissionPlatformUsersRead,
		))
		{
			platformInbox.GET("", s.getPlatformInAppNotifications)
			platformInbox.PUT("/read-all", s.markAllPlatformNotificationsRead)
			platformInbox.PUT("/:id/read", s.markPlatformNotificationRead)
		}
	}

	// Return router for main.go to handle server setup
	return router
}

func (s *Server) Start(addr string) error {
	router := s.SetupRouter()

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "notification-service",
			"version": version.Get(),
		})
	})

	healthServer := &http.Server{
		Addr:              addr,
		Handler:           healthRouter,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// API server (HTTPS with mTLS, port 8443)
	var apiServer *http.Server
	if s.config.UseMTLS {
		var err error
		apiServer, err = sharedhttp.NewMTLSServer(
			s.config.ServiceCertPath,
			s.config.ServiceKeyPath,
			s.config.PlatformCACertPath,
			router,
		)
		if err != nil {
			return err
		}
		apiServer.Addr = ":" + s.config.TLSPort
		apiServer.ReadHeaderTimeout = 5 * time.Second
		apiServer.ReadTimeout = 10 * time.Second
		apiServer.WriteTimeout = 15 * time.Second
		apiServer.IdleTimeout = 60 * time.Second
	} else {
		// Fallback to HTTP if mTLS disabled
		apiServer = &http.Server{
			Addr:              addr,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// Start health check server (only when mTLS is enabled - API server on different port)
	// When mTLS is disabled, API server includes /health endpoint on same port
	if s.config.UseMTLS {
		go func() {
			log.Printf("Health check server starting on %s", addr)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health server: %v", err)
			}
		}()
	}

	// Start API server
	go func() {
		if s.config.UseMTLS {
			log.Printf("Notification service API server starting on :%s (mTLS)", s.config.TLSPort)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("Notification service API server starting on %s (HTTP - includes /health)", addr)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down notification service...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown both servers
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}

	return nil
}
