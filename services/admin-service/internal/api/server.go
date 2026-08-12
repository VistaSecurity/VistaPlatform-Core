// Package api provides the HTTP server and routing for the SaaS Admin Service.
// It handles all platform administration endpoints including tenant management,
// user management, statistics, and system monitoring.
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

	"github.com/vistasecurity/vistaplatform/admin-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/middleware"
	adminservices "github.com/vistasecurity/vistaplatform/admin-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/cache"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	resourcetracking "github.com/vistasecurity/vistaplatform/shared/middleware/resource-tracking"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// Server represents the HTTP server instance with configuration,
// database connection, and router setup.
type Server struct {
	config *config.Config // Service configuration (port, database URL, JWT secret)
	db     *sql.DB        // Database connection for platform data access (RLS-enforcing crypto_app role)
	// bypassDB is the BYPASSRLS connection (crypto_bypass) used by every
	// deliberately cross-tenant path in this service (platform stats, tenant
	// directory, cross-tenant billing, etc.). See shared/database.ConnectBypass.
	bypassDB            *sql.DB
	router              *gin.Engine                       // Gin router with all endpoints and middleware
	rbacService         *rbac.RBACService                 // RBAC service for permission checking
	refreshTokenService *auth.PlatformRefreshTokenService // Refresh token service for secure token management
	cache               *cache.Client                     // Redis cache client (optional, nil if unavailable)
	cachedHandlers      *handlers.CachedHandlers          // Cached handlers (nil if cache unavailable)

	// hooks is the edition seam. Zero value = Core: no MSP management plane,
	// no billing routes, no billing workers, no Stripe. See edition.go.
	hooks EditionHooks
	// billingRuntime is the Enterprise billing worker handle, nil in Core.
	billingRuntime BillingRuntime
	// mspRuntime is the MSP management-plane background handle, nil in Core.
	mspRuntime MSPRuntime
}

// NewServer creates and initializes a Core-edition HTTP server instance.
// Equivalent to NewServerWithEdition with zero hooks.
func NewServer(cfg *config.Config, db *sql.DB) *Server {
	return NewServerWithEdition(cfg, db, EditionHooks{})
}

// NewServerWithEdition creates and initializes a new HTTP server instance.
// It sets up all routes, middleware, and handlers for the SaaS admin service.
//
// Parameters:
//   - cfg: Service configuration including port, database URL, and JWT secret
//   - db: Database connection for accessing platform and tenant data
//   - hooks: the edition seam. The zero value is the Core edition (no MSP
//     management plane, no billing); the Enterprise build passes populated
//     hooks from cmd/edition_ee.go.
//
// Returns:
//   - *Server: Configured server instance ready to start
func NewServerWithEdition(cfg *config.Config, db *sql.DB, hooks EditionHooks) *Server {
	// Open the BYPASSRLS connection (crypto_bypass) used by every deliberately
	// cross-tenant path in this service (Phase 4). ConnectBypass reads
	// BYPASS_DATABASE_URL and falls back to DATABASE_URL when unset, so this is
	// behavior-neutral until the RLS flip provisions the separate role.
	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to open bypass database connection: %v", err)
	}
	return NewServerWithConnections(cfg, db, bypassDB, hooks)
}

// NewServerWithConnections builds the server over pools that are already open.
//
// Split out of NewServerWithEdition so route registration can be exercised
// without a live database: ConnectBypass pings, which makes the normal
// constructor untestable, and the MSP carve needs a test that builds BOTH
// editions' routers so a gin radix-tree conflict fails a test instead of a pod
// start. Production callers should use NewServerWithEdition.
func NewServerWithConnections(cfg *config.Config, db, bypassDB *sql.DB, hooks EditionHooks) *Server {
	// Initialize RBAC service
	rbacService := rbac.NewRBACService(db)

	// Initialize platform refresh token service for secure token management
	refreshTokenService := auth.NewPlatformRefreshTokenService(db)

	// Configure auth-cookie Domain and Secure flag (must match auth-service values)
	handlers.InitializeCookieDomain(cfg.CookieDomain)
	handlers.InitializeSecureCookies(cfg.EnforceSecureCookies)

	// The cross-tenant dashboard aggregator, the cost-monitoring service and the
	// per-tenant integration service used to be constructed here. All three are
	// MSP and are now built inside the ee/msp tree by the RegisterMSP hook — in
	// a Core build that code does not exist.

	// Initialize security service for threat detection and compliance tracking
	handlers.InitializeSecurityService(db, bypassDB)

	// Initialize integration service for managing platform integrations (AWS, 3rd party)
	// This requires a master encryption key for encrypting credentials
	if cfg.EncryptionMasterKey != "" {
		logger := logrus.New()
		logger.SetLevel(logrus.InfoLevel)
		handlers.InitializeIntegrationService(db, bypassDB, cfg.EncryptionMasterKey, logger)

		// Initialize platform branding service with S3 storage support
		if err := handlers.InitializePlatformBrandingService(db, bypassDB, cfg.EncryptionMasterKey, logger); err != nil {
			log.Printf("Warning: Failed to initialize platform branding storage: %v", err)
		}
	} else {
		log.Printf("Warning: ENCRYPTION_MASTER_KEY not set, integration management will be disabled")
	}

	// Initialize tier and entitlement services for billing management.
	// The legacy InitializeOverrideService was dropped — tenant_limit_overrides
	// is superseded by tenant_entitlements (see EntitlementsService).
	handlers.InitializeTierService(db, bypassDB)
	handlers.InitializeEntitlementsService(db, bypassDB)

	// Initialize the platform audit emitter used by the RBAC handlers to record
	// role/permission and platform-user mutations. Reaches audit-service
	// over the same peer URL + mTLS the rest of the service uses.
	auditServiceURLForAudit := os.Getenv("AUDIT_SERVICE_URL")
	if auditServiceURLForAudit == "" {
		auditServiceURLForAudit = sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled())
	}
	handlers.InitializePlatformAuditor(handlers.AuditEmitterConfig{
		AuditServiceURL:    auditServiceURLForAudit,
		InternalAuthSecret: cfg.InternalAuthSecret,
		UseMTLS:            cfg.UseMTLS,
		ClientCertPath:     cfg.ClientCertPath,
		ClientKeyPath:      cfg.ClientKeyPath,
		PlatformCACertPath: cfg.PlatformCACertPath,
		Enabled:            os.Getenv("AUDIT_LOGGING_ENABLED") != "false",
	})

	// Initialize Redis cache (optional - service works without it)
	var cacheClient *cache.Client
	var cachedHandlers *handlers.CachedHandlers
	if cfg.RedisURL != "" {
		var err error
		cacheClient, err = cache.NewClient(cache.Options{
			RedisURL: cfg.RedisURL,
		})
		if err != nil {
			log.Printf("Warning: Failed to connect to Redis cache: %v (caching disabled)", err)
		} else {
			cachedHandlers = handlers.NewCachedHandlers(db, bypassDB, cacheClient)
			log.Printf("Redis cache initialized successfully")
		}
	}

	// Billing — Stripe, subscriptions, invoices, coupons, dunning, trials,
	// contract renewals and billing analytics — is an Enterprise/MSP
	// capability and is constructed inside the ee/ tree by the RegisterBilling
	// hook during setupRouter(). In a Core build the hook is nil, so none of
	// that code exists in the binary and none of those routes are mounted.
	//
	// NOTE: the metered/overage billing pipeline (OverageCalculator +
	// UsageSyncWorker) was removed 2026-07 — billing is flat per-tier.
	// Usage MONITORING still lives in resource-tracker-service.

	log.Printf("admin-service edition: %s", hooks.Edition())

	server := &Server{
		config:              cfg,
		db:                  db,
		bypassDB:            bypassDB,
		rbacService:         rbacService,
		refreshTokenService: refreshTokenService,
		cache:               cacheClient,
		cachedHandlers:      cachedHandlers,
		hooks:               hooks,
	}

	// Set up all routes, middleware, and handlers
	server.setupRouter()
	return server
}

// Router exposes the configured gin engine.
//
// Exported for the edition router tests, which build a Core and an Enterprise
// router and assert the exact route set each one mounts. gin panics at STARTUP
// on a radix-tree conflict, which is invisible to every other test, so the route
// set has to be assertable. Nothing in production reads this.
func (s *Server) Router() *gin.Engine { return s.router }

// setupRouter configures all HTTP routes, middleware, and handlers for the SaaS admin service.
// It sets up authentication, authorization, CORS, and all API endpoints.
func (s *Server) setupRouter() {
	// Set Gin mode based on environment
	if s.config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize Gin router with basic middleware
	s.router = gin.New()
	s.router.Use(gin.Logger())   // Request logging
	s.router.Use(gin.Recovery()) // Panic recovery
	s.router.Use(sharedmw.SecurityHeaders())

	// Resource tracking middleware
	trackerConfig := resourcetracking.DefaultConfig()
	trackerConfig.ServiceName = "admin-service"
	trackerConfig.TrackerURL = os.Getenv("RESOURCE_TRACKER_URL")
	if trackerConfig.TrackerURL == "" {
		trackerConfig.TrackerURL = sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled())
	}
	// mTLS configuration
	trackerConfig.UseMTLS = s.config.UseMTLS
	trackerConfig.ClientCertPath = s.config.ClientCertPath
	trackerConfig.ClientKeyPath = s.config.ClientKeyPath
	trackerConfig.PlatformCACertPath = s.config.PlatformCACertPath
	s.router.Use(resourcetracking.Middleware(trackerConfig))

	// CORS headers are handled by the Traefik API gateway
	// No need for duplicate CORS middleware in individual services

	// Health check endpoint for service monitoring
	// Used by load balancers and monitoring systems to check service health
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service":   "admin-service",
			"status":    "healthy",
			"timestamp": gin.H{},
			"version":   version.Get(),
		})
	})

	// Asymmetric platform-token signing. PLATFORM_JWT_SIGNING_KEY_FILE
	// (or _KEY) supplies the ES256 private key; absent, minting stays on the
	// legacy shared HS256 secret so an existing deployment is unaffected by the
	// upgrade. A key that is PRESENT but unusable is fatal — silently falling
	// back to the weaker path on an operator error is exactly the failure mode
	// this change exists to remove.
	platformSigner, err := jwtkeys.SignerFromEnv("PLATFORM_JWT")
	if err != nil {
		log.Fatalf("PLATFORM_JWT signing key is configured but unusable: %v", err)
	}
	if kid := handlers.InitTokenSigning(platformSigner); kid != "" {
		log.Printf("signing platform JWTs with ES256, kid=%s", kid)
	} else {
		log.Printf("no PLATFORM_JWT signing key configured; signing platform JWTs with the legacy shared HS256 secret (see #584)")
	}

	// JWKS for the platform token issuer. Public and unauthenticated — it holds
	// only public keys, and verifiers must be able to fetch it before they can
	// authenticate anything. Served only when this pod actually signs
	// asymmetrically; an empty document would read as "this issuer has no keys"
	// and make verifiers reject everything.
	if platformSigner != nil {
		s.router.GET(jwtkeys.JWKSPath, func(c *gin.Context) {
			jwtkeys.ServeJWKS(c.Writer, platformSigner)
		})
	}

	// Serve platform branding uploads (logos, favicons)
	// This allows the API gateway to proxy requests for /uploads/platform-branding/* to admin-service
	s.router.Static("/uploads/platform-branding", "/app/uploads/platform-branding")

	// API routes with service prefix for consistency
	// This follows the microservices pattern where each service has its own namespace
	// under the API gateway. This ensures:
	// 1. Clear service boundaries
	// 2. Consistent routing through the API gateway
	// 3. Centralized authentication and rate limiting
	// 4. Future-proof for additional services
	api := s.router.Group("/api/v1")
	adminGroup := api.Group("/admin-service")
	{
		// Authentication routes - Handle platform admin login and token refresh
		// These endpoints use platform user tables with same security features as tenant users
		auth := adminGroup.Group("/auth")
		{
			auth.POST("/login", handlers.Login(s.db, s.config.JWTSecret, s.refreshTokenService))          // Platform admin login with device fingerprinting
			auth.POST("/refresh", handlers.RefreshToken(s.db, s.config.JWTSecret, s.refreshTokenService)) // Token refresh with rotation and reuse detection
			// Unauthenticated: validates a time-limited token (from invite or admin reset email) and sets a new password
			auth.POST("/reset-password", handlers.ResetPassword(s.db))
			// Unauthenticated: self-service forgot-password (sends a reset email to the supplied address)
			auth.POST("/forgot-password", handlers.ForgotPassword(s.db))
		}

		// Staff admin SSO — public: these ESTABLISH the platform session, so
		// they're outside the protected group. Only authenticate existing
		// platform_users (no provisioning). Callback host = the admin host.
		staffSSO := adminGroup.Group("/admin/sso")
		{
			staffSSO.GET("/providers", handlers.ListStaffSsoProviders(s.db))
			staffSSO.GET("/:provider/authorize", handlers.StaffSsoAuthorize(s.db))
			staffSSO.GET("/:provider/callback", handlers.StaffSsoCallback(s.db, s.config.JWTSecret, s.refreshTokenService))
		}

		// Authenticated logout — revokes refresh tokens server-side and clears cookies.
		// Registered outside the /auth group so it uses the protected middleware (JWT required).
		adminLogoutGroup := adminGroup.Group("/admin/auth")
		adminLogoutGroup.Use(middleware.AuthMiddleware(s.config.JWTSecret))
		adminLogoutGroup.Use(middleware.StringifyUserID())
		{
			adminLogoutGroup.POST("/logout", handlers.Logout(s.db, s.refreshTokenService))
		}

		// Initialize RBAC middleware
		rbacMiddleware := middleware.NewRBACMiddleware(s.rbacService)

		// Protected routes - All admin endpoints require authentication and platform permissions
		// These routes are protected by JWT authentication and permission-based authorization
		protected := adminGroup.Group("/admin")
		protected.Use(middleware.AuthMiddleware(s.config.JWTSecret)) // JWT authentication
		protected.Use(middleware.StringifyUserID())                  // Compat: handlers expect userID as string
		// RLS: Tenant isolation uses WHERE tenant_id=$X in queries (primary) and PostgreSQL
		// RLS policies (defense-in-depth). For RLS session-variable enforcement, use
		// shared/database.WithTenantContext() at the repository level — never db.Exec().
		{
			// The whole tenant-management surface (/admin/tenants/**: directory,
			// detail, users, stats, update/suspend/activate, delete/purge,
			// onboarding + offboarding, and per-tenant settings) is the MSP
			// management plane and is mounted by the RegisterMSP hook below. In a
			// Core build the hook is nil, so a Core console has no tenant
			// directory — there is nothing to manage but the one organization
			// running it.
			//
			// The one /admin/tenants route Core keeps is
			// GET /tenants/:id/limits (effective entitlement limits), further
			// down: it is the read-out of the entitlement system, which is Core.

			// Platform user management endpoints - Manage SaaS administrators
			// These endpoints allow management of platform-level users (not tenant users)
			users := protected.Group("/users")
			{
				// Read: platform_users.read permission
				readUsers := users.Group("")
				readUsers.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformUsersRead))
				{
					readUsers.GET("", handlers.ListPlatformUsers(s.db))
					readUsers.GET("/:id", handlers.GetPlatformUser(s.db))
				}

				// Create/Update/Invite/PasswordOps: platform_users.manage permission
				manageUsers := users.Group("")
				manageUsers.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformUsersManage))
				{
					manageUsers.POST("", handlers.CreatePlatformUser(s.db))
					manageUsers.PUT("/:id", handlers.UpdatePlatformUser(s.db))
					// Invite: creates user and sends branded invitation email with one-time set-password link
					manageUsers.POST("/invite", handlers.InvitePlatformUser(s.db))
					// Admin directly sets a new password for a user (optionally forces change on next login)
					manageUsers.PUT("/:id/set-password", handlers.AdminSetPassword(s.db))
					// Admin triggers a branded password-reset email to an existing user
					manageUsers.POST("/:id/send-password-reset", handlers.AdminSendPasswordReset(s.db))
				}

				// Delete: platform_users.delete permission
				deleteUsers := users.Group("")
				deleteUsers.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformUsersDelete))
				{
					deleteUsers.DELETE("/:id", handlers.DeletePlatformUser(s.db))
				}
			}

			// Billing endpoints (admin-wide) — invoices, credits, webhook
			// events, dunning, trials, coupons and revenue analytics — are
			// Enterprise and are mounted by the billing hook below.

			// Subscription Tier Management endpoints.
			//
			// Tiers themselves are CORE: a Core deployment creates, edits and
			// ASSIGNS tiers, which is what shared/entitlements resolves
			// against. Only the Stripe Product/Price auto-provisioning that a
			// stripe-billed tier triggers on save is Enterprise, and it is
			// injected here as an optional pricer. With no pricer the tier
			// saves normally, just without a Stripe price attached.
			tierMgr := adminservices.NewTierService(s.db, s.bypassDB)
			if s.hooks.NewTierPricer != nil {
				if pricer := s.hooks.NewTierPricer(s.config); pricer != nil {
					tierMgr.SetPricer(pricer)
				}
			}
			tiers := protected.Group("/tiers")
			tiers.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformSettings))
			{
				tiers.GET("", handlers.ListTiers(tierMgr))                     // List all tiers
				tiers.POST("", handlers.CreateTier(tierMgr))                   // Create new tier
				tiers.GET("/:id", handlers.GetTier(tierMgr))                   // Get tier details
				tiers.PUT("/:id", handlers.UpdateTier(tierMgr))                // Update tier (grandfathers)
				tiers.DELETE("/:id", handlers.DeprecateTier(tierMgr))          // Deprecate tier
				tiers.GET("/:id/history", handlers.GetTierHistory(tierMgr))    // Get tier change history
				tiers.GET("/:id/impact-analysis", handlers.TierImpactAnalysis) // Tier migration impact analysis
				tiers.POST("/:id/assign", handlers.AssignTier)                 // Assign plan to a tenant (record-only for invoice plans)
				// Entitlements composition — backs the admin-UI tier composer.
				// Reads catalog-enriched rows; bulk-replaces the tier's composition
				// in one transaction (see EntitlementsService.ReplaceTierEntitlements).
				tiers.GET("/:id/entitlements", handlers.GetTierEntitlements)
				tiers.PUT("/:id/entitlements", handlers.UpdateTierEntitlements)
			}

			// Billable items catalog — every gateable/billable concept the
			// platform knows about. Read by the tier composer to render
			// its matrix; CRUD here for catalog management by super admins.
			billableItemSvc := adminservices.NewEntitlementsService(s.db, s.bypassDB)
			billableItems := protected.Group("/billable-items")
			billableItems.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformSettings))
			{
				billableItems.GET("", handlers.ListBillableItems(billableItemSvc))
				billableItems.POST("", handlers.CreateBillableItem(billableItemSvc))
				billableItems.PUT("/:id", handlers.UpdateBillableItem(billableItemSvc))
				billableItems.DELETE("/:id", handlers.DeleteBillableItem(billableItemSvc))
			}

			// Per-tenant entitlement OVERRIDES (/tenants/:id/entitlements) are
			// MSP — "this customer, unlike others on their plan, gets X" is only
			// a question when you manage other organizations. Mounted by the
			// RegisterMSP hook. The catalog above and the per-tier composition
			// stay Core, which is what makes entitlements work without MSP code.

			// Tenant Effective Limits endpoint — the entitlement read-out, and
			// the only /admin/tenants route Core mounts. A single-organization
			// operator legitimately asks "what are my limits?", and this is the
			// surface that proves tier assignment + entitlement resolution work
			// with no MSP or billing code in the binary.
			tenantLimits := protected.Group("/tenants/:id/limits")
			tenantLimits.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionTenantsRead))
			{
				tenantLimits.GET("", handlers.GetEffectiveLimits) // Get effective limits (tier + overrides)
			}

			// Cost monitoring (/admin/costs/**) is MSP: per-tenant cost
			// attribution and the platform-wide rollup both read the BYPASSRLS
			// handle across every tenant. Mounted by the RegisterMSP hook.

			// Platform roles and permissions endpoints - RBAC management
			// These endpoints manage platform-level roles and permissions
			rbacStore := handlers.NewPlatformRBACStore(s.db)
			roles := protected.Group("/roles")
			{
				// Read: platform_roles.read permission
				readRoles := roles.Group("")
				readRoles.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformRolesRead))
				{
					readRoles.GET("", handlers.ListPlatformRoles(rbacStore))
					readRoles.GET("/:id", handlers.GetPlatformRole(rbacStore))
				}

				// Create/Update/Delete: platform_roles.manage permission
				writeRoles := roles.Group("")
				writeRoles.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformRolesManage))
				{
					writeRoles.POST("", handlers.CreatePlatformRole(rbacStore))
					writeRoles.PUT("/:id", handlers.UpdatePlatformRole(rbacStore))
					writeRoles.PUT("/:id/permissions", handlers.SetPlatformRolePermissions(rbacStore))
					writeRoles.DELETE("/:id", handlers.DeletePlatformRole(rbacStore))
				}
			}

			permissions := protected.Group("/permissions")
			{
				// Read: platform_permissions.read permission
				permissions.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformPermissionsRead))
				permissions.GET("", handlers.ListPlatformPermissions(rbacStore))   // List all platform permissions
				permissions.GET("/:id", handlers.GetPlatformPermission(rbacStore)) // Get specific platform permission
			}

			// Current user permissions endpoint - Returns permissions for the authenticated user
			// No permission required - users can always check their own permissions
			protected.GET("/user/permissions", handlers.GetCurrentUserPermissions(s.rbacService))

			// Current platform user profile - Session validation and fresh user for admin-ui (GET /admin/auth/me)
			protected.GET("/auth/me", handlers.GetCurrentPlatformUser(s.db))
			// Authenticated user changes their own password (clears force_password_change flag on success)
			protected.POST("/auth/change-password", handlers.ChangePassword(s.db, s.config.JWTSecret, s.refreshTokenService))

			// Edition read-out — which optional surfaces this binary mounted.
			// CORE route by design: a Core build has to be able to answer it,
			// because the admin console uses it to stop rendering navigation
			// (Tenants, Comms, Billing & Revenue…) whose backend does not
			// exist here. Without it the console offers tabs that 404, which
			// reads as a broken product rather than an absent edition.
			// No permission gate: every operator's nav depends on it, same as
			// /auth/me and /user/permissions above.
			protected.GET("/platform/edition", PlatformEdition(s.hooks.Info()))

			// Platform statistics (/admin/stats/**) and the cross-tenant
			// dashboard (/admin/dashboard/**) are MSP: every one of those
			// handlers aggregates over EVERY tenant on the BYPASSRLS handle.
			// Mounted by the RegisterMSP hook.

			// System monitoring endpoints - Health checks and system monitoring.
			// This is Core's System Health surface: it reports on the DEPLOYMENT,
			// not on tenants. /monitoring/metrics is the exception and is MSP —
			// it reads the cross-tenant dashboard aggregator — so it is mounted
			// by the RegisterMSP hook alongside the aggregator it depends on.
			monitoring := protected.Group("/monitoring")
			{
				monitoring.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformHealth))
				monitoring.GET("/health", handlers.GetSystemHealth(s.db)) // System health check
				monitoring.GET("/logs", handlers.GetSystemLogs(s.db))     // System logs (future)
			}

			// Security endpoints - Threat detection, compliance, and incident management
			// These endpoints provide security monitoring and compliance tracking
			security := protected.Group("/security")
			security.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformSecurity))
			{
				// Security events
				security.GET("/events", handlers.GetSecurityEvents(handlers.SecurityService))
				security.GET("/dashboard-stats", handlers.GetSecurityDashboardStats(handlers.SecurityService))

				// Compliance frameworks
				security.GET("/compliance", handlers.GetAllComplianceFrameworks(handlers.SecurityService))
				security.GET("/compliance/:framework", handlers.GetComplianceFrameworkStatus(handlers.SecurityService))
			}

			// Platform Settings endpoints - Platform-wide configuration
			// Manage platform-wide settings like maintenance mode, limits, etc.
			platformSettings := protected.Group("/settings")
			platformSettings.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformSettings))
			{
				platformSettings.GET("", handlers.GetPlatformSettings(s.db))       // Get platform settings
				platformSettings.PUT("", handlers.UpdatePlatformSettings(s.db))    // Update platform settings
				platformSettings.POST("/test-email", handlers.SendTestEmail(s.db)) // Send SMTP test email
			}

			// Legal document AUTHORING — Terms of Service / Privacy Policy.
			// Platform admins publish new immutable versions. Core: a
			// single-organization deployment still has to publish the documents
			// its users accept.
			//
			// GET /legal/acceptances (the cross-tenant acceptance ledger, the
			// only legal route needing the bypass connection) is MSP and is
			// mounted by the RegisterMSP hook.
			platformLegal := protected.Group("/legal")
			platformLegal.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformSettings))
			{
				platformLegal.GET("/documents", handlers.ListLegalDocuments(s.db))
				platformLegal.POST("/documents", handlers.PublishLegalDocument(s.db))
			}

			// Platform Branding endpoints - Platform logo and branding assets
			platformBranding := protected.Group("/branding")
			platformBranding.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformSettings))
			{
				platformBranding.POST("/upload", handlers.UploadPlatformBrandingAsset(s.db))  // Upload platform logo/favicon
				platformBranding.DELETE("/:type", handlers.DeletePlatformBrandingAsset(s.db)) // Delete platform logo/favicon
			}

			// Platform Identity Providers — configure Vista's OWN OAuth app
			// (Google/Microsoft) used by social signup. Platform-wide, one per type.
			platformIdPs := protected.Group("/identity-providers")
			platformIdPs.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformSettings))
			{
				platformIdPs.GET("", handlers.ListPlatformIdentityProviders(s.db))
				platformIdPs.POST("", handlers.CreatePlatformIdentityProvider(s.db))
				platformIdPs.PUT("/:id", handlers.UpdatePlatformIdentityProvider(s.db))
				platformIdPs.DELETE("/:id", handlers.DeletePlatformIdentityProvider(s.db))
			}

			// Storage Configuration endpoints - Configure S3 storage for artifacts
			storageConfig := protected.Group("/storage")
			storageConfig.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformSettings))
			{
				storageConfig.GET("/config", handlers.GetStorageConfig(s.db, s.bypassDB))     // Get storage configuration
				storageConfig.PUT("/config", handlers.UpdateStorageConfig(s.db, s.bypassDB))  // Update storage configuration
				storageConfig.POST("/test", handlers.TestStorageConnection(s.db, s.bypassDB)) // Test storage connectivity
			}

			// Platform Integrations endpoints - AWS, 3rd party SaaS integrations
			// Manage integration credentials securely with encryption
			platformIntegrations := protected.Group("/integrations")
			platformIntegrations.Use(rbacMiddleware.RequirePlatformPermission(rbac.PermissionPlatformSettings)) // Require settings permission
			{
				platformIntegrations.GET("", handlers.GetIntegrations())           // List all integrations
				platformIntegrations.GET("/:id", handlers.GetIntegration())        // Get single integration (with decrypted credentials)
				platformIntegrations.POST("", handlers.CreateIntegration())        // Create new integration
				platformIntegrations.PUT("/:id", handlers.UpdateIntegration())     // Update integration
				platformIntegrations.DELETE("/:id", handlers.DeleteIntegration())  // Delete integration (soft delete)
				platformIntegrations.POST("/:id/test", handlers.TestIntegration()) // Test integration connection
			}

			// Per-tenant integrations (/tenants/:id/integrations), customer comms
			// (/announcements, /maintenance-windows), support tickets and tenant
			// notes are all MSP — they exist to run other people's
			// organizations. Mounted by the RegisterMSP hook.
		}

		// MSP management plane. In Core the hook is nil, so /admin/tenants/**,
		// /admin/stats/**, /admin/dashboard/**, /admin/costs/**,
		// /admin/announcements, /admin/maintenance-windows,
		// /admin/support-tickets, /admin/legal/acceptances and
		// /admin/monitoring/metrics simply do not exist.
		//
		// Registered here rather than inline: gin's radix tree is per-engine and
		// shared, so a group created with the same prefix from another package
		// lands in the same place. See ee/msp/routes.go for the ordering rules
		// that keeps it from panicking.
		if s.hooks.RegisterMSP != nil {
			s.mspRuntime = s.hooks.RegisterMSP(MSPDeps{
				DB:             s.db,
				BypassDB:       s.bypassDB,
				Config:         s.config,
				Protected:      protected,
				Cache:          s.cache,
				CachedHandlers: s.cachedHandlers,
				RequirePlatformPermission: func(permission string) gin.HandlerFunc {
					return rbacMiddleware.RequirePlatformPermission(permission)
				},
			})
		}

		// Enterprise billing surface. In Core the hook is nil, so the
		// platform /admin/billing/*, tenant /my-billing/*, onboarding
		// /billing/* and provider-webhook routes simply do not exist.
		if s.hooks.RegisterBilling != nil {
			s.billingRuntime = s.hooks.RegisterBilling(BillingDeps{
				DB:             s.db,
				BypassDB:       s.bypassDB,
				Config:         s.config,
				AdminGroup:     adminGroup,
				Protected:      protected,
				CachedHandlers: s.cachedHandlers,
				RequirePlatformPermission: func(permission string) gin.HandlerFunc {
					return rbacMiddleware.RequirePlatformPermission(permission)
				},
			})
		}
	}
}

// Start begins listening for HTTP requests on the configured port.
// This method starts both a health check server (HTTP) and an API server (HTTPS with mTLS).
// It blocks until the server is stopped or encounters an error.
//
// Returns:
//   - error: Any error that occurs while starting the server
func (s *Server) Start() error {
	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service":   "admin-service",
			"status":    "healthy",
			"timestamp": gin.H{},
			"version":   version.Get(),
		})
	})

	healthServer := &http.Server{
		Addr:              ":" + s.config.Port,
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
			s.router,
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
			Addr:              ":" + s.config.Port,
			Handler:           s.router,
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
			log.Printf("Health check server starting on port %s", s.config.Port)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health server: %v", err)
			}
		}()
	}

	// Start API server
	go func() {
		if s.config.UseMTLS {
			log.Printf("🚀 SaaS Admin Service API server listening on port %s (mTLS)", s.config.TLSPort)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("🚀 SaaS Admin Service API server listening on port %s (HTTP - includes /health)", s.config.Port)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Start MSP background work (the cross-tenant dashboard aggregator). Nil in
	// Core.
	if s.mspRuntime != nil {
		s.mspRuntime.Start()
	}

	// Start the Enterprise billing background workers (Stripe webhook
	// processor + contract renewal-notice sweep). Nil in Core.
	if s.billingRuntime != nil {
		s.billingRuntime.Start()
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down admin service...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop MSP background work. Nil in Core.
	if s.mspRuntime != nil {
		s.mspRuntime.Stop()
	}

	// Stop the Enterprise billing background workers. Nil in Core.
	if s.billingRuntime != nil {
		s.billingRuntime.Stop()
	}

	// Shutdown both servers
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}

	return nil
}
