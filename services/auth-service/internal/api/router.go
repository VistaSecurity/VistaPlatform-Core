package api

import (
	"database/sql"
	"net/http"
	"os"
	"time"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/apitokens"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/oauth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/rbac"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	resourcetracking "github.com/vistasecurity/vistaplatform/shared/middleware/resource-tracking"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// SetupRouter initializes and configures the Gin router
// bypassDB is the BYPASSRLS (crypto_bypass) connection threaded to every
// deliberately cross-tenant login/registration path (where the tenant is the
// query OUTPUT). Pre-flip it resolves to the same connection as db.
//
// hooks selects the edition. Its zero value is Core: no SSO routes are
// mounted and the login dispatcher enumerates password only. cmd/edition_ee.go
// (build tag `ee`) supplies the Enterprise implementations.
func SetupRouter(cfg *config.Config, db *sql.DB, bypassDB *sql.DB, redis *redis.Client, rateLimiter *middleware.RateLimiter, hooks EditionHooks) *gin.Engine {
	router := gin.New()

	// SSO enumeration for the email-first login dispatcher. Never nil — Core
	// resolves to a no-op that reports no SSO methods.
	ssoMethods := resolveSSOMethods(hooks, db, bypassDB)

	// Initialize JWT service.
	//
	// Asymmetric signing: AUTH_JWT_SIGNING_KEY_FILE (or _KEY) supplies
	// the ES256 private key that only this service and admin-service hold.
	// Absent, the service keeps signing HS256 with the legacy shared secret —
	// which is what makes this safe to deploy before the keys are provisioned.
	// A key that is PRESENT but malformed is fatal: that is an operator error
	// on security-critical material and must not degrade silently to the weaker
	// path.
	jwtSigner, err := jwtkeys.SignerFromEnv("AUTH_JWT")
	if err != nil {
		logrus.WithError(err).Fatal("AUTH_JWT signing key is configured but unusable")
	}
	if jwtSigner != nil {
		logrus.WithField("kid", jwtSigner.ActiveKID()).Info("signing JWTs with ES256")
	} else {
		logrus.Warn("no AUTH_JWT signing key configured; signing JWTs with the legacy shared HS256 secret (see #584)")
	}
	jwtService := auth.NewJWTServiceWithKeys(cfg.JWTSecret, jwtSigner, cfg.JWTExpiry, 7*24*time.Hour) // 7 days refresh expiry

	// Initialize auth service
	authService := auth.NewAuthService(db, bypassDB, redis, jwtService)

	// Initialize handlers
	authHandlers := NewAuthHandlers(authService, cfg, rateLimiter)

	// Initialize RBAC service and handlers
	rbacService := rbac.NewRBACService(db)
	rbacHandlers := rbac.NewRBACHandlers(rbacService)

	// Initialize shared RBAC service for platform permission checks
	sharedRBACService := sharedrbac.NewRBACService(db)

	// Initialize tenant storage service for S3 branding uploads
	if err := InitializeTenantStorageService(db, bypassDB); err != nil {
		logrus.WithError(err).Warn("Failed to initialize tenant storage service, falling back to local storage")
	}

	// Middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(sharedmw.SecurityHeaders())
	router.Use(middleware.RequestID())
	router.Use(middleware.Logging())

	// CORS is handled by Traefik API gateway - no need for duplicate headers

	// Health check endpoints - registered BEFORE rate limiting to ensure they always work
	router.GET("/health", healthCheck)
	router.GET("/ready", readinessCheck(db, redis))

	// OAuth 2.0 authorization server. Public endpoints — no auth middleware.
	// The well-known URI must be at the root of the issuer (RFC 8414).
	oauthHandler := oauth.NewHandler(db, bypassDB, jwtService, cfg)
	router.GET("/.well-known/oauth-authorization-server", oauthHandler.WellKnown)

	// JWKS. Public and unauthenticated by design: it contains only
	// public keys, and a verifying service has to be able to fetch it before it
	// can authenticate anything. Served only when this pod actually signs
	// asymmetrically — an empty JWKS would look like "the issuer has no keys"
	// and cause verifiers to reject everything, so 404 is the honest answer
	// when there is nothing to publish.
	if jwtSigner != nil {
		router.GET(jwtkeys.JWKSPath, func(c *gin.Context) {
			jwtkeys.ServeJWKS(c.Writer, jwtSigner)
		})
	}
	// Published so main.go can also mount it on the plaintext health listener,
	// which is how in-cluster verifiers fetch it under serviceMtls without
	// needing a client certificate. See the comment at that call site.
	setJWTSigner(jwtSigner)

	// Serve tenant branding and avatar uploads (local storage)
	router.Static("/uploads/branding", "/app/uploads/branding")
	router.Static("/uploads/avatars", "/app/uploads/avatars")

	// Rate limiting middleware (applied to all routes AFTER health checks)
	if rateLimiter != nil {
		router.Use(middleware.RateLimiting(rateLimiter))
	}

	// Resource tracking middleware
	trackerConfig := resourcetracking.DefaultConfig()
	trackerConfig.ServiceName = "auth-service"
	trackerConfig.TrackerURL = os.Getenv("RESOURCE_TRACKER_URL")
	if trackerConfig.TrackerURL == "" {
		trackerConfig.TrackerURL = sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled())
	}
	// mTLS configuration
	trackerConfig.UseMTLS = cfg.UseMTLS
	trackerConfig.ClientCertPath = cfg.ClientCertPath
	trackerConfig.ClientKeyPath = cfg.ClientKeyPath
	trackerConfig.PlatformCACertPath = cfg.PlatformCACertPath
	router.Use(resourcetracking.Middleware(trackerConfig))

	// Audit logging middleware
	auditConfig := auditmiddleware.DefaultConfig()
	auditConfig.ServiceName = "auth-service"
	auditConfig.AuditServiceURL = os.Getenv("AUDIT_SERVICE_URL")
	if auditConfig.AuditServiceURL == "" {
		if cfg.UseMTLS {
			auditConfig.AuditServiceURL = "https://audit-service:8443"
		} else {
			auditConfig.AuditServiceURL = sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled())
		}
	}
	auditConfig.Enabled = os.Getenv("AUDIT_LOGGING_ENABLED") != "false"
	// mTLS configuration
	auditConfig.UseMTLS = cfg.UseMTLS
	auditConfig.ClientCertPath = cfg.ClientCertPath
	auditConfig.ClientKeyPath = cfg.ClientKeyPath
	auditConfig.PlatformCACertPath = cfg.PlatformCACertPath
	auditMiddleware := auditmiddleware.NewMiddleware(auditConfig)

	// Store audit middleware in context for explicit audit logging in handlers
	router.Use(func(c *gin.Context) {
		c.Set("audit_middleware", auditMiddleware)
		c.Next()
	})
	router.Use(auditMiddleware.LogRequest())

	// API routes with service prefix for consistency
	// This follows the microservices pattern where each service has its own namespace
	// under the API gateway. This ensures:
	// 1. Clear service boundaries
	// 2. Consistent routing through the API gateway
	// 3. Centralized authentication and rate limiting
	// 4. Future-proof for additional services
	api := router.Group("/api")
	v1 := api.Group("/v1")

	authServiceGroup := v1.Group("/auth-service")
	{
		// Public endpoints (no auth required)
		authServiceGroup.GET("/tiers", getPublicTiersHandler(db))
		authServiceGroup.GET("/platform/config", GetPublicPlatformConfig(db))
		authServiceGroup.GET("/platform/ui-config", GetPublicPlatformUIConfig(db))

		// OAuth 2.0 endpoints — public, no RequireAuth middleware.
		oauthGroup := authServiceGroup.Group("/oauth")
		{
			oauthGroup.GET("/authorize", oauthHandler.AuthorizeGET)
			oauthGroup.POST("/authorize", oauthHandler.AuthorizePOST)
			oauthGroup.POST("/token", oauthHandler.Token)
		}

		// Authentication routes
		auth := authServiceGroup.Group("/auth")
		{
			// Basic authentication
			auth.POST("/register", authHandlers.Register)
			auth.POST("/verify-email", authHandlers.VerifyEmail)
			auth.POST("/resend-verification", authHandlers.ResendEmailVerification)
			auth.POST("/login", authHandlers.Login)
			auth.POST("/logout", middleware.RequireAuth(cfg, jwtService), authHandlers.Logout)
			auth.POST("/refresh", authHandlers.RefreshToken)
			auth.POST("/forgot-password", authHandlers.ForgotPassword)
			auth.POST("/reset-password", authHandlers.ResetPassword)

			// Current user management. GET /me is opt-in for impersonation
			// (a platform admin should be able to see the impersonated user's
			// profile to confirm context). Writes (PUT, change-password) are
			// access-only —, the impersonator's audit trail cannot
			// honestly attribute identity-mutating actions.
			auth.GET("/me", middleware.RequireAuth(cfg, jwtService, middleware.AllowImpersonation()), authHandlers.GetMe)
			auth.PUT("/me", middleware.RequireAuth(cfg, jwtService), authHandlers.UpdateMe)
			auth.POST("/change-password", middleware.RequireAuth(cfg, jwtService), authHandlers.ChangePassword)

			// Notification preferences — GET opt-in, PUT access-only.
			auth.GET("/me/preferences/notifications", middleware.RequireAuth(cfg, jwtService, middleware.AllowImpersonation()), authHandlers.GetNotificationPreferences)
			auth.PUT("/me/preferences/notifications", middleware.RequireAuth(cfg, jwtService), authHandlers.UpdateNotificationPreferences)

			// EULA acceptance — access-only; accepting EULA on behalf
			// of an impersonated user is exactly the kind of identity-mutating
			// action the audit trail can't legitimately attribute.
			auth.POST("/users/me/eula", middleware.RequireAuth(cfg, jwtService), authHandlers.AcceptEULA)

			// Registration completion with tier selection
			auth.POST("/register/complete", authHandlers.CompleteRegistration)

			// Legal documents (Terms of Service / Privacy Policy).
			// Current-version reads are public (signup + standalone pages);
			// pending/accept are access-only — accepting terms is an
			// identity-mutating action an impersonator can't attribute.
			auth.GET("/legal/current", GetCurrentLegalDocuments(bypassDB))
			auth.GET("/legal/documents/:docType", GetLegalDocumentByType(bypassDB))
			auth.GET("/legal/pending", middleware.RequireAuth(cfg, jwtService, middleware.AllowImpersonation()), GetPendingLegalAcceptances(bypassDB))
			auth.POST("/legal/accept", middleware.RequireAuth(cfg, jwtService), AcceptLegalDocuments(bypassDB))

			// Tier selection. Choosing the tenant's plan is a billing
			// mutation, so it is gated by `billing.update` — the one permission
			// the seeded role design withholds from tenant_admin precisely so
			// that changing what the tenant pays for stays with billing_admin.
			// It is NOT the signup path: onboarding assigns the tier through
			// the unauthenticated POST /auth/register/complete, which never
			// reaches this route, so gating here cannot break signup.
			// The handler additionally refuses any paid tier the tenant has no
			// active subscription for (validateTenantTierSelection) — the RBAC
			// gate says who may choose, the entitlement check says what.
			auth.POST("/select-tier",
				middleware.RequireAuth(cfg, jwtService),
				middleware.RequirePermission(rbacService, "billing.update"),
				authHandlers.SelectTier)

			// Onboarding — GET opt-in, POST access-only.
			auth.GET("/onboarding/status", middleware.RequireAuth(cfg, jwtService, middleware.AllowImpersonation()), authHandlers.GetOnboardingStatus)
			auth.POST("/onboarding/progress", middleware.RequireAuth(cfg, jwtService), authHandlers.UpdateOnboardingProgress)

			// Sessions management — GET opt-in, DELETE access-only.
			// Revoking sessions during impersonation could log the impersonated
			// user out of their other devices without their consent.
			auth.GET("/sessions", middleware.RequireAuth(cfg, jwtService, middleware.AllowImpersonation()), authHandlers.ListSessions)
			auth.DELETE("/sessions/:id", middleware.RequireAuth(cfg, jwtService), authHandlers.RevokeSession)

			// Connections management — GET opt-in, PUT access-only.
			auth.GET("/connections", middleware.RequireAuth(cfg, jwtService, middleware.AllowImpersonation()), authHandlers.ListConnections)
			auth.PUT("/connections/:id/primary", middleware.RequireAuth(cfg, jwtService), authHandlers.SetPrimaryAuth)

			// Avatar upload
			auth.POST("/upload-avatar", middleware.RequireAuth(cfg, jwtService), authHandlers.UploadAvatar)

			// Flexible authentication flow (frontend-agnostic)
			auth.POST("/initiate", AuthInitiate(bypassDB, redis, ssoMethods))
			auth.POST("/methods", AuthMethods(bypassDB, ssoMethods))

			// Public invitation accept surface. The token is the
			// authorization, so these are unauthenticated; SSO acceptance instead
			// rides the token through /auth/sso/:provider/authorize?invitation_token=.
			// These resolve tenant from an invitation token (auth-output): the
			// token lookup runs on bypassDB, all tenant-known writes via
			// WithTenantTx. See invitations.go.
			auth.GET("/invitations/lookup", LookupInvitation(db, bypassDB))
			auth.POST("/invitations/accept", AcceptInvitation(cfg, db, bypassDB, jwtService))
			auth.POST("/authenticate", AuthAuthenticate(cfg, db, bypassDB, redis, jwtService, ssoMethods))
			auth.POST("/complete", AuthComplete(cfg, db, bypassDB, redis, jwtService))
		}

		// User management routes. Per-permission gates supersede the prior
		// RequireAnyRole(tenant_admin, billing_admin) — billing_admin is now
		// scoped to billing only (Billing Admin) so it should NOT manage
		// users. Reads use users.read so security_admin / viewer can see the
		// membership list per the post-PR204 role design.
		users := authServiceGroup.Group("/users")
		users.Use(middleware.RequireAuth(cfg, jwtService))
		{
			users.GET("", middleware.RequirePermission(rbacService, "users.read"), ListUsers(db))
			users.POST("", middleware.RequirePermission(rbacService, "users.create"), CreateUser(db, bypassDB, cfg))
			users.GET("/:id", middleware.RequirePermission(rbacService, "users.read"), GetUser(db))
			users.PUT("/:id", middleware.RequirePermission(rbacService, "users.update"), UpdateUser(db))
			users.DELETE("/:id", middleware.RequirePermission(rbacService, "users.delete"), DeleteUser(db))
		}

		// Current tenant management routes. Write operations on tenant
		// config (PUT /, branding, invite) are gated by settings.update /
		// users.create. RequireAnyRole(tenant_admin, billing_admin) was
		// removed for the same reason as the /users group above: post-PR204,
		// billing_admin is the Billing Admin and has no business updating
		// branding or inviting members.
		tenant := authServiceGroup.Group("/tenant")
		tenant.Use(middleware.RequireAuth(cfg, jwtService))
		{
			tenant.GET("", getCurrentTenantHandler(db))
			tenant.PUT("", middleware.RequirePermission(rbacService, "settings.update"), updateCurrentTenantHandler(db))
			tenant.GET("/usage", getTenantUsageHandler(db))
			tenant.GET("/features", getTenantFeaturesHandler(db))
			tenant.GET("/trial-status", getTenantTrialStatusHandler(db))
			// Billing overview is gated by billing.read (tenant_admin +
			// billing_admin per the seeded role design).
			tenant.GET("/billing", middleware.RequirePermission(rbacService, "billing.read"), GetTenantBilling(db, cfg))
			tenant.GET("/ui-config", GetTenantUIConfig(db))
			tenant.GET("/branding", GetTenantBranding(db))
			// UI config updates require platform_admin role (platform admins set tenant design defaults)
			tenant.PUT("/ui-config", UpdateTenantUIConfig(db)) // Role check inside handler
			// Branding updates are tenant settings.
			tenant.PUT("/branding", middleware.RequirePermission(rbacService, "settings.update"), UpdateTenantBranding(db))
			// Branding asset upload
			tenant.POST("/branding/upload", middleware.RequirePermission(rbacService, "settings.update"), UploadBrandingAsset(db))
			// List users in a specific tenant (used by web-ui)
			// Roster read. Gated on users.read to match the flat GET /users and
			// the sibling GET /:tenantId/invitations — the handler's own
			// same-tenant check stays, but it only proves WHICH tenant you may
			// read, not that you may read the roster at all.
			tenant.GET("/:tenantId/users", middleware.RequirePermission(rbacService, "users.read"), ListTenantUsers(db))
			tenant.POST("/:tenantId/users/invite", middleware.RequirePermission(rbacService, "users.create"), InviteTenantMember(cfg, db, bypassDB, authService))
			// Pending invitations (auth-method-agnostic): list/revoke/resend.
			tenant.GET("/:tenantId/invitations", middleware.RequirePermission(rbacService, "users.read"), ListTenantInvitations(db))
			tenant.DELETE("/:tenantId/invitations/:id", middleware.RequirePermission(rbacService, "users.create"), RevokeTenantInvitation(db))
			tenant.POST("/:tenantId/invitations/:id/resend", middleware.RequirePermission(rbacService, "users.create"), ResendTenantInvitation(db, cfg))
			// Tenant-scoped member mutations (used by web-ui Settings → Users).
			// Same permission gates as the flat /users/:id mutations; the
			// handlers additionally enforce the tenant-path-access check used by
			// ListTenantUsers/InviteTenantMember and verify the target user
			// belongs to :tenantId before mutating.
			tenant.DELETE("/:tenantId/users/:userId", middleware.RequirePermission(rbacService, "users.delete"), DeleteTenantMember(db))
			tenant.PUT("/:tenantId/users/:userId/status", middleware.RequirePermission(rbacService, "users.update"), UpdateTenantMemberStatus(db))
		}

		// UI themes route (public, but requires auth for tier filtering)
		ui := authServiceGroup.Group("/ui")
		ui.Use(middleware.RequireAuth(cfg, jwtService))
		{
			ui.GET("/themes", GetUIThemes(db))
		}

		// Federated identity (tenant OIDC/SAML login, the social-signup IdP,
		// and the tenant SSO configuration surface) is Enterprise. In a Core
		// build this hook is nil and none of those routes exist — a Core
		// install authenticates with local credentials and invitations.
		//
		// Registration is deferred to the Enterprise package rather than
		// listed here so the open-source tree carries no dangling handler
		// names, but the paths, middleware, and permission gate are Core
		// policy and are handed over ready-made below.
		if hooks.RegisterSSORoutes != nil {
			hooks.RegisterSSORoutes(SSORouteDeps{
				ServiceGroup:          authServiceGroup,
				AuthGroup:             auth,
				Cfg:                   cfg,
				DB:                    db,
				BypassDB:              bypassDB,
				Redis:                 redis,
				JWTService:            jwtService,
				AuthService:           authService,
				RequireAuth:           middleware.RequireAuth(cfg, jwtService),
				RequireSettingsUpdate: middleware.RequirePermission(rbacService, "settings.update"),
				Core:                  coreSSOSupport(),
			})
		}

		// API tokens (PATs) — bearer credentials for programmatic access
		// (v1 consumer: mcp-service). Each user mints and manages their own
		// tokens; tokens carry a read-only permission subset and are
		// exchanged for short-lived JWTs via the internal endpoint below.
		apiTokenHandlers := apitokens.NewHandlers(apitokens.NewService(db, bypassDB), authService, jwtService)
		apiTokens := authServiceGroup.Group("/api-tokens")
		apiTokens.Use(middleware.RequireAuth(cfg, jwtService))
		{
			apiTokens.GET("", apiTokenHandlers.ListTokens)
			apiTokens.POST("", apiTokenHandlers.CreateToken)
			apiTokens.DELETE("/:id", apiTokenHandlers.RevokeToken)
		}
		// PAT→JWT exchange: HMAC service auth ONLY, never user-callable.
		authServiceGroup.POST("/internal/api-tokens/exchange",
			middleware.RequireInternalOnly(), apiTokenHandlers.Exchange)

		// Billing and subscription routes. Every route in this group is
		// read-shaped (check-limits inspects limits without mutating), so the
		// whole group is gated by billing.read — granted to tenant_admin and
		// billing_admin by the seeded role design. The unauthenticated
		// tier catalog lives at GET /tiers outside this group.
		billing := authServiceGroup.Group("/billing")
		billing.Use(middleware.RequireAuth(cfg, jwtService))
		billing.Use(middleware.RequirePermission(rbacService, "billing.read"))
		{
			billing.GET("/tiers", getSubscriptionTiersHandler(db))
			billing.GET("/usage/current", GetCurrentUsage(db))
			billing.GET("/usage/history", GetUsageHistory(db))
			billing.POST("/check-limits", CheckLimits(db))
		}

		// Feature availability routes
		features := authServiceGroup.Group("/features")
		features.Use(middleware.RequireAuth(cfg, jwtService))
		{
			features.GET("/availability", GetFeatureAvailability(db))
		}

		// =================================================================
		// RBAC (Role-Based Access Control) Routes
		// =================================================================

		// Tenant role management routes
		tenantRoles := authServiceGroup.Group("/tenant/:tenantId/roles")
		tenantRoles.Use(middleware.RequireAuth(cfg, jwtService))
		tenantRoles.Use(middleware.RequirePermission(rbacService, "users.manage"))
		{
			tenantRoles.GET("", rbacHandlers.GetTenantRoles)
			tenantRoles.POST("", rbacHandlers.CreateTenantRole)
			tenantRoles.GET("/:roleId/matrix", rbacHandlers.GetPermissionMatrix)
			tenantRoles.PUT("/:roleId/permissions", rbacHandlers.UpdateRolePermissions)
			// Custom roles only — DeleteTenantRole refuses is_system_role=true.
			tenantRoles.DELETE("/:roleId", rbacHandlers.DeleteTenantRole)
		}

		// Tenant permissions routes
		tenantPermissions := authServiceGroup.Group("/permissions")
		tenantPermissions.Use(middleware.RequireAuth(cfg, jwtService))
		{
			tenantPermissions.GET("", rbacHandlers.GetTenantPermissions)
		}

		// Current user permissions route (for frontend)
		authServiceGroup.GET("/user/permissions", middleware.RequireAuth(cfg, jwtService), rbacHandlers.GetCurrentUserPermissions)

		// User role assignment routes
		userRoles := authServiceGroup.Group("/tenant/:tenantId/users/:userId/roles")
		userRoles.Use(middleware.RequireAuth(cfg, jwtService))
		userRoles.Use(middleware.RequirePermission(rbacService, "users.manage"))
		{
			userRoles.GET("", rbacHandlers.GetUserRoles)
			userRoles.POST("", rbacHandlers.AssignRole)
			userRoles.DELETE("/:roleId", rbacHandlers.RemoveRole)
		}

		// User permissions routes
		userPermissions := authServiceGroup.Group("/tenant/:tenantId/users/:userId/permissions")
		userPermissions.Use(middleware.RequireAuth(cfg, jwtService))
		userPermissions.Use(middleware.RequireAnyPermission(rbacService, "users.read", "users.manage"))
		{
			userPermissions.GET("", rbacHandlers.GetUserPermissions)
		}

		// Permission check routes
		permissionCheck := authServiceGroup.Group("/permissions/check")
		permissionCheck.Use(middleware.RequireAuth(cfg, jwtService))
		{
			permissionCheck.POST("", rbacHandlers.CheckPermission)
		}

		// NOTE: /platform is NOT free real estate. The public branding
		// endpoints (/platform/config, /platform/ui-config, and the ee
		// /platform/sso-providers) live under it, and the ingress denies the
		// rest of the prefix on the tenant host (see admin_plane in
		// standards/service-registry.yaml). A new gated route here must be
		// platform-permission-gated; a new PUBLIC route here must be added to
		// the registry's public_exceptions or it 404s on every Kubernetes
		// install — which is exactly how platform branding silently broke.

		// Admin impersonation routes (platform admin only)
		adminImpersonation := authServiceGroup.Group("/admin")
		adminImpersonation.Use(middleware.RequireAuth(cfg, jwtService))
		adminImpersonation.Use(middleware.RequireNotRevoked(authService.Redis()))
		// Platform permission check using shared RBAC service
		adminImpersonation.Use(middleware.RequirePlatformPermission(sharedRBACService, sharedrbac.PermissionPlatformImpersonate))
		// Set authService in context for impersonation handlers
		adminImpersonation.Use(func(c *gin.Context) {
			c.Set("authService", authService)
			c.Next()
		})
		{
			adminImpersonation.POST("/impersonations", InitiateAdminImpersonation)
			adminImpersonation.POST("/impersonations/stop", StopAdminImpersonation)
			adminImpersonation.GET("/impersonations/audit", ListImpersonationAudit)
		}

		// Tenant security endpoints - For tenant health service (platform admin only)
		tenantSecurity := authServiceGroup.Group("/tenant/:tenantId")
		tenantSecurity.Use(middleware.RequireAuth(cfg, jwtService))
		tenantSecurity.Use(middleware.RequireAnyRole("platform_admin", "super_admin"))
		{
			tenantSecurity.GET("/security-summary", getTenantSecuritySummaryHandler(authService))
			// UI config endpoints for platform admins (tenant ID in path)
			tenantSecurity.GET("/ui-config", GetTenantUIConfigByID(db))
			tenantSecurity.PUT("/ui-config", UpdateTenantUIConfigByID(db))
		}

		// Onboarding workflow routes
		onboarding := authServiceGroup.Group("/onboarding")
		onboarding.Use(middleware.RequireAuth(cfg, jwtService))
		{
			onboarding.GET("/status", GetOnboardingStatus(db, bypassDB))
			onboarding.GET("/workflow", GetOnboardingWorkflow(db, bypassDB))
			onboarding.POST("/steps/:id/complete", CompleteOnboardingStep(db, bypassDB))
			onboarding.GET("/progress", GetOnboardingProgress(db, bypassDB))
			onboarding.POST("/steps/:id/skip", SkipOnboardingStep(db, bypassDB))
			// Per-user dismiss (any authed user) + org-wide toggle (tenant admin).
			onboarding.POST("/dismiss", DismissOnboarding(db, bypassDB))
			onboarding.PUT("/settings", middleware.RequirePermission(rbacService, "settings.update"), UpdateOnboardingSettings(db, bypassDB))
		}
	}

	return router
}

// getTenantSecuritySummaryHandler returns security metrics for a specific tenant
func getTenantSecuritySummaryHandler(authService *auth.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantIDStr := c.Param("tenantId")
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		summary, err := authService.GetTenantSecuritySummary(tenantID)
		if err != nil {
			logrus.WithError(err).WithField("tenant_id", tenantID).Error("Failed to get tenant security summary")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get tenant security summary",
			})
			return
		}

		c.JSON(http.StatusOK, summary)
	}
}

// healthCheck returns a simple health status. The `version` field surfaces
// the deployed image tag + chart version so the About-page aggregator can
// detect version skew across the running deployment.
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "auth-service",
		"timestamp": gin.H{},
		"version":   version.Get(),
	})
}

// readinessCheck checks if the service is ready to handle requests
func readinessCheck(db *sql.DB, redis *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check database connection
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not ready",
				"error":  "database connection failed",
			})
			return
		}

		// Check Redis connection
		if err := redis.Ping(c.Request.Context()).Err(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not ready",
				"error":  "redis connection failed",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "ready",
			"service": "auth-service",
		})
	}
}

// jwtSignerRef holds the process's JWT signing key so both the API router and
// the plaintext probe listener can serve the same JWKS. Set once during
// SetupRouter; nil when no key is provisioned and the service is still on the
// legacy shared-secret path.
var jwtSignerRef *jwtkeys.Signer

func setJWTSigner(s *jwtkeys.Signer) { jwtSignerRef = s }

// JWTSigner returns the signing key, or nil on the legacy HS256 path.
func JWTSigner() *jwtkeys.Signer { return jwtSignerRef }
