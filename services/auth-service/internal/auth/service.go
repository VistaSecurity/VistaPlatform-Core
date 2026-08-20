// Package auth provides comprehensive authentication services for the crypto inventory platform.
// It handles user registration, login, JWT token management, multi-tenant user isolation,
// password security, and session management with Redis caching.
//
// Key Features:
// - Multi-tenant user management with subscription tiers
// - JWT-based authentication with access/refresh token pattern
// - Argon2id password hashing for security
// - Redis-based session management and token blacklisting
// - Email verification and password reset workflows
// - SSO provider integration support
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/security/authpolicy"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailExists        = errors.New("email already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrAccountLocked      = errors.New("account temporarily locked. Try again later")
	ErrSessionNotFound    = errors.New("session not found")
	ErrConnectionNotFound = errors.New("connection not found")
	ErrPersonalEmail      = errors.New("personal email addresses are not allowed. Please use your work email address")
	// ErrWeakPassword wraps a password-strength validation failure so the API
	// layer can return 400 (client error) with the policy detail instead of a
	// generic 500. Unwrap with errors.Is / errors.Unwrap for the message.
	ErrWeakPassword = errors.New("password does not meet strength requirements")
)

// personalEmailBlocked reports whether signup should reject consumer email
// domains. It reads platform_settings.block_personal_email_domains.
//
// The default is FALSE — personal addresses are allowed — and that default is
// deliberate for the open-source Core edition.
//
// Rejecting gmail/outlook/proton is a sensible acquisition filter for a hosted
// SaaS, where you are qualifying inbound signups. It is actively wrong for
// software somebody self-hosts: signup is the ONLY way into a deployment (there
// is no admin tenant-create; that is the MSP management plane), so this list was
// the single front door. Someone evaluating Core on their own hardware with a
// personal address could not create an account at all, and was told to "use your
// work email address" — advice that makes no sense when they are the operator.
//
// Operators running a hosted offering flip this on in admin-ui Settings → Access.
//
// Fails OPEN (returns false) on a missing row, bad value, or query error, for the
// same reason signupEnabled fails open: a settings hiccup must not silently wall
// off the only route into the platform.
func personalEmailBlocked(db *sql.DB) bool {
	if db == nil {
		return false
	}
	var raw []byte
	if err := db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = 'block_personal_email_domains'`).Scan(&raw); err != nil {
		return false
	}
	var blocked bool
	if err := json.Unmarshal(raw, &blocked); err != nil {
		return false
	}
	return blocked
}

// EnforceWorkEmailPolicy applies the work-email rule only when the operator has
// enabled it. Every registration route must go through THIS, not
// ValidateWorkEmail directly — a policy enforced on the password path but not
// the SSO path (or vice versa) is not a policy, it is a bug with a changelog
// entry. ValidateWorkEmail remains exported because it is the pure predicate and
// is unit-tested as such.
func EnforceWorkEmailPolicy(db *sql.DB, email string) error {
	if !personalEmailBlocked(db) {
		return nil
	}
	return ValidateWorkEmail(email)
}

// ValidateWorkEmail validates that the email address is a work email (not a personal email domain)
func ValidateWorkEmail(email string) error {
	// List of common personal email domains to reject
	personalDomains := []string{
		"gmail.com",
		"yahoo.com",
		"outlook.com",
		"hotmail.com",
		"aol.com",
		"icloud.com",
		"mail.com",
		"protonmail.com",
		"yandex.com",
		"gmx.com",
		"zoho.com",
		"live.com",
		"msn.com",
		"yahoo.co.uk",
		"yahoo.fr",
		"yahoo.de",
		"rediffmail.com",
		"inbox.com",
		"fastmail.com",
	}

	// Extract domain from email
	parts := strings.Split(strings.ToLower(email), "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format")
	}

	domain := parts[1]

	// Check if domain is in the personal domains list
	for _, personalDomain := range personalDomains {
		if domain == personalDomain {
			return ErrPersonalEmail
		}
	}

	return nil
}

// AuthService handles authentication operations
type AuthService struct {
	db                  *sql.DB
	bypassDB            *sql.DB
	redis               *redis.Client
	jwt                 *JWTService
	password            *passwordsvc.PasswordService
	emailResolver       *email.EmailConfigResolver
	refreshTokenService *RefreshTokenService
}

// NewAuthService creates a new authentication service.
//
// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
// deliberately cross-tenant login/registration paths annotated
// `// RLS: cross-tenant — runs on the bypass role (Phase 4)`, where the tenant
// is the query OUTPUT (resolve email/user-id → tenant) and cannot be set on
// app.tenant_id ahead of time. Pre-flip it resolves to the same connection as
// db, so behavior is unchanged until the role split is deployed.
func NewAuthService(db *sql.DB, bypassDB *sql.DB, redis *redis.Client, jwt *JWTService) *AuthService {
	encryptionKey := os.Getenv("ENCRYPTION_MASTER_KEY")
	return &AuthService{
		db:                  db,
		bypassDB:            bypassDB,
		redis:               redis,
		jwt:                 jwt,
		password:            passwordsvc.NewPasswordService(),
		emailResolver:       email.NewEmailConfigResolver(db, encryptionKey),
		refreshTokenService: NewRefreshTokenService(db),
	}
}

// emailServiceFromDB resolves current SMTP config from platform_settings and
// returns a ready-to-use EmailService. Falls back to env-var config when
// platform_settings has no email_config row yet.
func (a *AuthService) emailServiceFromDB() (*email.EmailService, error) {
	cfg, err := a.emailResolver.GetPlatformEmailConfig()
	if err != nil {
		return nil, fmt.Errorf("email not configured: %w", err)
	}
	return email.NewEmailService(*cfg), nil
}

// webUIBaseURL returns the tenant web-UI base URL from platform_settings
// (falls back to the env var WEB_UI_BASE_URL, then a localhost default).
func (a *AuthService) webUIBaseURL() string {
	var raw []byte
	if err := a.db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = 'platform_domain'`).Scan(&raw); err == nil {
		var domain string
		if json.Unmarshal(raw, &domain) == nil && domain != "" {
			return "https://" + domain
		}
	}
	if v := os.Getenv("WEB_UI_BASE_URL"); v != "" {
		return v
	}
	return "http://localhost:3000"
}

// JWT returns the underlying JWT service (used by handlers that need custom TTLs)
func (a *AuthService) JWT() *JWTService {
	return a.jwt
}

// Redis returns the Redis client (for denylist / session ops)
func (a *AuthService) Redis() *redis.Client {
	return a.redis
}

// GetDB returns the database connection (for handlers that need direct DB access)
func (a *AuthService) GetDB() *sql.DB {
	return a.db
}

// GetBypassDB returns the BYPASSRLS (crypto_bypass) connection used by the
// deliberately cross-tenant paths (login/registration lookups where the tenant
// is the query OUTPUT). Handlers that run such a query directly should use this
// handle, NOT GetDB().
func (a *AuthService) GetBypassDB() *sql.DB {
	return a.bypassDB
}

// BypassDB returns the bypass database handle (alias for GetBypassDB).
func (a *AuthService) BypassDB() *sql.DB {
	return a.GetBypassDB()
}

// Public wrappers for methods needed by platform SSO registration.
// These delegate to the private implementations used by the main Register flow.

func (a *AuthService) CreateTenantPublic(name string) (*models.Tenant, error) {
	return a.createTenant(name)
}

func (a *AuthService) EnsureTenantRolesPublic(tenantID uuid.UUID) error {
	return a.ensureTenantRoles(tenantID)
}

func (a *AuthService) AssignTenantRolePublic(userID, tenantID uuid.UUID, roleName string) error {
	return a.assignTenantRole(userID, tenantID, roleName)
}

func (a *AuthService) AutoLicenseBestPracticesPublic(tenantID uuid.UUID) error {
	return a.autoLicenseBestPractices(tenantID)
}

func (a *AuthService) GetUserPrimaryRolePublic(userID, tenantID uuid.UUID) string {
	return a.getUserPrimaryRole(userID, tenantID)
}

// ensureTenantRoles ensures that default tenant roles exist for a tenant.
// If they don't exist, creates them (billing_admin, tenant_admin, security_admin, viewer, api_user).
// Also ensures permissions are assigned to these roles.
//
// NOTE: `billing_admin` (display name "Billing Admin") is a finance/billing
// scope only — it pays the bills and has read-only visibility into users and
// settings, with no operational access. It was renamed from the legacy
// internal identifier `tenant_owner` in.
//
// IMPORTANT: The role labels and grant filters below MUST match
// scripts/database/seed.sql's "Ensure Tenant Roles for All Tenants" DO
// block. Filter drift between these two locations would silently give
// new tenants different permissions than existing ones.
func (a *AuthService) ensureTenantRoles(tenantID uuid.UUID) error {
	// Create default tenant roles (idempotent - won't create if they already exist)
	defaultRoles := []struct {
		name        string
		displayName string
		description string
	}{
		{"billing_admin", "Billing Admin", "Billing and account ownership. Pays the bills; cannot perform operational work."},
		{"tenant_admin", "Tenant Administrator", "Full operational and user management; reads billing but cannot change it."},
		{"security_admin", "Security Administrator", "Security operations, compliance, reports; reads users and settings for incident response."},
		{"viewer", "Viewer", "Read-only access to tenant operational data (no billing)."},
		{"api_user", "API User", "Read-only integration scope across operational data."},
	}

	// RLS-scoped write: tenant_roles carries a tenant_isolation policy. The tenant
	// is known here (just-created or existing tenant being reconciled), so the loop
	// runs inside WithTenantTx — app.tenant_id satisfies the policy WITH CHECK on
	// each INSERT. The explicit tenant_id column value is kept as the primary control.
	err := shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		for _, role := range defaultRoles {
			if _, e := tx.ExecContext(context.Background(), `
				INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
				VALUES ($1, $2, $3, $4, true)
				ON CONFLICT (tenant_id, name) DO NOTHING
			`, tenantID, role.name, role.displayName, role.description); e != nil {
				return fmt.Errorf("failed to create tenant role %s: %w", role.name, e)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Always ensure permissions are assigned (idempotent - won't duplicate if already assigned)
	// This ensures both new tenants and existing tenants without permissions get them
	if err := a.assignRolePermissions(tenantID); err != nil {
		return fmt.Errorf("failed to assign permissions to tenant roles: %w", err)
	}

	return nil
}

// EnsureDefaultTenantRoles creates default tenant_roles rows and permission links if missing (idempotent).
func (a *AuthService) EnsureDefaultTenantRoles(tenantID uuid.UUID) error {
	return a.ensureTenantRoles(tenantID)
}

// assignRolePermissions assigns default permissions to tenant roles for a
// tenant.
//
// The filters are NOT written here: they come from roleGrantFilters in
// role_grants_gen.go, generated from standards/permissions.yaml by
// scripts/generate-permissions.mjs — the same YAML that generates the
// reconciliation DO block in scripts/database/seed.sql. seed.sql is the path
// existing tenants take on every helm upgrade; this function is the path new
// tenants and every ensureTenantRoles() call take. Filter drift used to be
// possible (commit 8ada815f lost the 'alerts' resource exactly this way) and
// would silently give the two cohorts different access; generating both from
// one source makes it structurally impossible.
//
// For each built-in role, stale grants outside the desired set are removed,
// then missing grants are inserted.
func (a *AuthService) assignRolePermissions(tenantID uuid.UUID) error {
	// Reconcile each role with a DELETE-then-INSERT pair inside a single
	// transaction so a failure (or pod restart) between a role's DELETE and
	// INSERT can't leave that role with partial grants on a freshly-onboarding
	// tenant..
	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin role-permission reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	// RLS-scoped: the reconciliation joins against tenant_roles (tenant_isolation
	// policy) to resolve role IDs, so the tenant context must be set on this tx or
	// the joins would see zero rows once RLS enforces. tenant_role_permissions and
	// tenant_permissions are global; scoping is harmless for them.
	if err := shareddatabase.SetTenantContext(context.Background(), tx, tenantID); err != nil {
		return err
	}

	for _, f := range roleGrantFilters {
		if _, err := tx.Exec(`
			DELETE FROM tenant_role_permissions trp
			USING tenant_roles tr, tenant_permissions tp
			WHERE trp.role_id = tr.id AND trp.permission_id = tp.id
			  AND tr.tenant_id = $1 AND tr.name = $2 AND tr.is_system_role = true
			  AND `+f.Revoke, tenantID, f.Role); err != nil {
			return fmt.Errorf("failed to reconcile permissions for %s: %w", f.Role, err)
		}
		if _, err := tx.Exec(`
			INSERT INTO tenant_role_permissions (role_id, permission_id)
			SELECT tr.id, tp.id
			FROM tenant_roles tr
			JOIN tenant_permissions tp ON true
			WHERE tr.tenant_id = $1 AND tr.name = $2
			  AND `+f.Grant+`
			ON CONFLICT (role_id, permission_id) DO NOTHING`, tenantID, f.Role); err != nil {
			return fmt.Errorf("failed to assign permissions to %s: %w", f.Role, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit role-permission reconciliation: %w", err)
	}
	return nil
}

// assignTenantRole assigns a RBAC role to a user in a tenant
func (a *AuthService) assignTenantRole(userID, tenantID uuid.UUID, roleName string) error {
	// RLS-scoped: tenant_roles and user_tenant_roles both carry tenant_isolation
	// policies; the tenant is known, so the lookup + assignment run inside one
	// WithTenantTx. Explicit WHERE/column tenant_id kept as the primary control.
	err := shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		// Get the role ID
		var roleID uuid.UUID
		e := tx.QueryRowContext(context.Background(), `
			SELECT id FROM tenant_roles
			WHERE tenant_id = $1 AND name = $2
		`, tenantID, roleName).Scan(&roleID)
		if e != nil {
			if e == sql.ErrNoRows {
				return fmt.Errorf("role %s not found for tenant", roleName)
			}
			return fmt.Errorf("failed to get role ID: %w", e)
		}

		// Assign the role
		if _, e := tx.ExecContext(context.Background(), `
			INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
			VALUES ($1, $2, $3, NOW(), true)
			ON CONFLICT (user_id, tenant_id, role_id)
			DO UPDATE SET is_active = true, assigned_at = NOW()
		`, userID, tenantID, roleID); e != nil {
			return fmt.Errorf("failed to assign role: %w", e)
		}
		return nil
	})
	return err
}

// getUserPrimaryRole gets the user's primary role from RBAC system
// Returns the role name (e.g., "admin", "viewer") or "viewer" as default if no role found
func (a *AuthService) getUserPrimaryRole(userID, tenantID uuid.UUID) string {
	query := `
		SELECT tr.name
		FROM tenant_roles tr
		JOIN user_tenant_roles utr ON tr.id = utr.role_id
		WHERE utr.user_id = $1 AND tr.tenant_id = $2 AND utr.is_active = true
		  AND (utr.expires_at IS NULL OR utr.expires_at > NOW())
		ORDER BY utr.assigned_at DESC
		LIMIT 1
	`

	// RLS-scoped: tenant_roles + user_tenant_roles both carry tenant_isolation
	// policies. The tenant is known (caller already resolved the user's tenant),
	// so the read runs inside WithTenantTx. On any error it falls back to "viewer".
	var roleName string
	err := shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), query, userID, tenantID).Scan(&roleName)
	})
	if err != nil {
		// If no role found, return default "viewer"
		// This shouldn't happen in production as migration ensures all users have roles
		return "viewer"
	}

	return roleName
}

// DB returns the underlying database handle (alias for GetDB)
func (a *AuthService) DB() *sql.DB {
	return a.GetDB()
}

// Register creates a new user account with the following business rules:
// - Password must meet strength requirements (8+ chars, mixed case, numbers, symbols)
// - Email must be unique across all tenants
// - If tenant_name is provided, creates new tenant; otherwise joins existing tenant
// - Returns user with hashed password and tenant association
// - Triggers email verification workflow
func (a *AuthService) Register(req *models.RegisterRequest) (*models.User, error) {
	// Validate password strength according to security policy
	if err := passwordsvc.ValidatePasswordStrengthWithPolicy(a.db, req.Password); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWeakPassword, err)
	}

	// Validate work email domain — only when the operator has opted in. Off by
	// default so a self-hosted Core deployment does not reject its own operator.
	if err := EnforceWorkEmailPolicy(a.bypassDB, req.Email); err != nil {
		return nil, err
	}

	// Check if email already exists across all tenants (global uniqueness)
	existingUser, err := a.GetUserByEmail(req.Email)
	if err != nil && err != ErrUserNotFound {
		return nil, err
	}
	if existingUser != nil {
		return nil, ErrEmailExists
	}

	// Hash password
	passwordHash, err := a.password.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create tenant if specified
	var tenantID uuid.UUID
	if req.TenantName != "" {
		tenant, err := a.createTenant(req.TenantName)
		if err != nil {
			return nil, fmt.Errorf("failed to create tenant: %w", err)
		}
		tenantID = tenant.ID
	} else {
		// TODO: Handle case where user joins existing tenant
		return nil, errors.New("tenant selection not implemented")
	}

	// Ensure default tenant roles exist (they should be created by seed script, but ensure they exist)
	err = a.ensureTenantRoles(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure tenant roles: %w", err)
	}

	// Create user
	userID := uuid.New()

	// Auto-license Best Practices framework to new tenant
	// This ensures all tenants have access to the platform default framework
	// This is non-blocking - if it fails, tenant creation still succeeds
	err = a.autoLicenseBestPractices(tenantID)
	if err != nil {
		// Log error but don't fail tenant creation
		// Best Practices can be licensed later via migration or manually
		logrus.WithError(err).WithField("tenant_id", tenantID).Warn("Failed to auto-license Best Practices framework")
	}
	user := &models.User{
		ID:            userID,
		TenantID:      tenantID,
		Email:         strings.ToLower(req.Email),
		PasswordHash:  passwordHash,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		IsActive:      true,
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err = a.createUser(user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Assign tenant_admin role to first user (founder of tenant)
	err = a.assignTenantRole(userID, tenantID, "tenant_admin")
	if err != nil {
		return nil, fmt.Errorf("failed to assign role to user: %w", err)
	}

	// Get the user's primary role from RBAC system
	user.Role = a.getUserPrimaryRole(user.ID, user.TenantID)

	// Send email verification if required
	emailVerificationRequired, err := a.IsEmailVerificationRequired(tenantID)
	if err != nil {
		// Log error but don't fail registration
		logrus.WithError(err).Warn("Failed to check email verification requirement")
	} else if emailVerificationRequired {
		// Send verification email (non-blocking)
		go func() {
			if err := a.SendEmailVerification(userID); err != nil {
				logrus.WithError(err).WithField("email", user.Email).Warn("Failed to send email verification")
			}
		}()
	}

	return user, nil
}

// IsEmailVerificationRequired checks if email verification is required for a tenant.
// Returns true if required, false if not required.
// Priority: tenant override > platform default (defaults to false if neither set)
func (a *AuthService) IsEmailVerificationRequired(tenantID uuid.UUID) (bool, error) {
	// First, check for tenant-specific override.
	// RLS-scoped: tenant_admin_settings carries a tenant_isolation policy; the
	// tenant is known, so the read runs inside WithTenantTx.
	var tenantConfigJSON []byte
	err := shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(context.Background(), `
			SELECT config
			FROM tenant_admin_settings
			WHERE tenant_id = $1
		`, tenantID).Scan(&tenantConfigJSON)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		return scanErr
	})

	if err == nil && len(tenantConfigJSON) > 0 {
		var tenantConfig map[string]interface{}
		if err := json.Unmarshal(tenantConfigJSON, &tenantConfig); err == nil {
			if emailVerification, ok := tenantConfig["email_verification_required"].(bool); ok {
				// Tenant has explicit override
				return emailVerification, nil
			}
		}
	}

	// Fall back to platform default
	var platformValueJSON []byte
	err = a.db.QueryRow(`
		SELECT setting_value
		FROM platform_settings
		WHERE setting_key = 'email_verification_required'
	`).Scan(&platformValueJSON)

	if err == nil && len(platformValueJSON) > 0 {
		var platformValue bool
		if err := json.Unmarshal(platformValueJSON, &platformValue); err == nil {
			return platformValue, nil
		}
	}

	// Neither override is set, so fall back to whether this deployment can
	// actually deliver the mail.
	//
	// This used to return an unconditional true on the reasoning that new
	// installs should require verification out of the box. Correct in intent,
	// wrong in effect: a new install usually has no SMTP configured, so the
	// verification mail fails to send — a logged warning, nothing more — and
	// then login refuses the account that just registered. The deployment locks
	// out its own first user, and the only way through is knowing to log into
	// admin-ui as a platform admin and turn the setting off. That was invisible
	// enough to look like a bug in signup.
	//
	// Requiring proof of an address we cannot write to is not a security
	// control, it is a dead end. So: mail configured → require verification,
	// as intended for any real deployment. No mail configured → do not,
	// because the check could never pass. Both explicit overrides above still
	// win, so an operator who wants verification on a mail-less install can
	// still say so and lock the door deliberately.
	return a.emailDeliveryConfigured(), nil
}

// emailDeliveryConfigured reports whether this deployment has somewhere to send
// mail: either the admin-UI-managed platform email config, or SMTP_HOST in the
// environment.
//
// Reads SMTP_HOST through os.Getenv rather than the shared config helper on
// purpose — that helper defaults the value to "localhost", which would make
// every deployment look configured and reinstate the lockout this replaces.
func (a *AuthService) emailDeliveryConfigured() bool {
	var raw []byte
	err := a.db.QueryRow(`
		SELECT setting_value FROM platform_settings WHERE setting_key = 'email_config'
	`).Scan(&raw)
	if err == nil && len(raw) > 0 {
		var cfg map[string]interface{}
		if json.Unmarshal(raw, &cfg) == nil {
			if host, ok := cfg["smtp_host"].(string); ok && strings.TrimSpace(host) != "" {
				return true
			}
		}
	}
	return strings.TrimSpace(os.Getenv("SMTP_HOST")) != ""
}

// Login authenticates a user and returns JWT tokens with the following process:
// - Validates email format and password presence
// - Retrieves user from database with tenant information
// - Verifies user account is active and email is verified
// - Validates password using Argon2id hash comparison
// - Generates access token (15min) and refresh token (7 days)
// - Stores refresh token in database with device fingerprint
// - Updates last login timestamp
func (a *AuthService) Login(req *models.LoginRequest, clientIP, userAgent string) (*models.AuthResponse, error) {
	// Get user by email with tenant information for multi-tenant isolation
	user, err := a.GetUserByEmail(req.Email)
	if err != nil {
		if err == ErrUserNotFound {
			// Check if this is a platform user
			platformUser, passwordHash, platformRoleName, platformErr := a.getPlatformUserByEmail(req.Email)
			if platformErr != nil {
				return nil, ErrInvalidCredentials
			}

			// Check if platform user is active
			if !platformUser.IsActive {
				return nil, ErrUserInactive
			}

			// Check if the account is locked due to too many failed attempts
			//. Platform admins are the highest-privilege accounts and now
			// get the same lockout the tenant path has always had.
			platformLocked, lockErr := a.checkPlatformAccountLocked(platformUser.ID)
			if lockErr != nil {
				logrus.WithError(lockErr).WithField("platform_user_id", platformUser.ID).Warn("Failed to check platform account lockout status")
			} else if platformLocked {
				return nil, ErrAccountLocked
			}

			// Verify password for platform user
			valid, err := a.password.VerifyPassword(req.Password, passwordHash)
			if err != nil {
				return nil, err
			}
			if !valid {
				a.recordPlatformFailedLogin(platformUser.ID)
				return nil, ErrInvalidCredentials
			}

			// Reset the failed-login counter on a successful authentication.
			a.resetPlatformFailedLoginAttempts(platformUser.ID)

			// Generate tokens for platform user (no tenant_id for platform users)
			accessToken, refreshToken, err := a.jwt.GenerateTokens(
				platformUser.ID, uuid.Nil, platformUser.Email, platformRoleName)
			if err != nil {
				return nil, fmt.Errorf("failed to generate tokens: %w", err)
			}

			// Update last login time for platform user.
			// Best-effort: a failure here must not fail the login.
			now := time.Now()
			_, _ = a.db.Exec(
				"UPDATE platform_users SET last_login_at = $1 WHERE id = $2",
				now, platformUser.ID,
			)

			// Store refresh token
			expiresAt := time.Now().Add(authpolicy.SessionLifetime(a.db, a.jwt.GetRefreshExpiry()))
			_, err = a.refreshTokenService.StoreRefreshToken(
				platformUser.ID,
				refreshToken,
				nil,
				expiresAt,
				clientIP,
				userAgent,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to store refresh token: %w", err)
			}

			return &models.AuthResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				User: &models.User{
					ID:        platformUser.ID,
					Email:     platformUser.Email,
					FirstName: platformUser.FirstName,
					LastName:  platformUser.LastName,
					Role:      platformRoleName,
					IsActive:  platformUser.IsActive,
				},
			}, nil
		}
		return nil, err
	}

	// Check if user is active
	if !user.IsActive {
		return nil, ErrUserInactive
	}

	// Check if account is locked due to too many failed attempts
	locked, err := a.checkAccountLocked(user.ID)
	if err != nil {
		logrus.WithError(err).WithField("user_id", user.ID).Warn("Failed to check account lockout status")
	} else if locked {
		return nil, ErrAccountLocked
	}

	// Verify password
	valid, err := a.password.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		return nil, err
	}
	if !valid {
		a.recordFailedLogin(user.ID)
		return nil, ErrInvalidCredentials
	}

	// Reset failed login attempts on successful authentication
	a.resetFailedLoginAttempts(user.ID)

	// Check email verification requirement
	emailVerificationRequired, err := a.IsEmailVerificationRequired(user.TenantID)
	if err != nil {
		logrus.WithError(err).Warn("Failed to check email verification requirement during login")
	} else if emailVerificationRequired && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	// Generate tokens
	accessToken, refreshToken, err := a.jwt.GenerateTokens(
		user.ID, user.TenantID, user.Email, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	err = a.updateUserLastLogin(user.ID, now)
	if err != nil {
		logrus.WithError(err).WithField("user_id", user.ID).Warn("Failed to update last login time")
	}

	// Store refresh token in database with device fingerprint
	expiresAt := time.Now().Add(authpolicy.SessionLifetime(a.db, a.jwt.GetRefreshExpiry()))
	familyID, err := a.refreshTokenService.StoreRefreshToken(
		user.ID,
		refreshToken,
		nil, // Create new token family on login
		expiresAt,
		clientIP,
		userAgent,
	)
	if err != nil {
		logrus.WithError(err).WithField("user_id", user.ID).Error("Failed to store refresh token")
	} else {
		logrus.WithFields(logrus.Fields{"user_id": user.ID, "family_id": familyID}).Debug("Stored refresh token")
	}

	return &models.AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(a.jwt.GetAccessExpiry().Seconds()),
	}, nil
}

// RefreshToken generates new tokens using a refresh token with rotation and reuse detection
func (a *AuthService) RefreshToken(refreshToken string, clientIP, userAgent string) (*models.AuthResponse, error) {
	// Validate refresh token
	claims, err := a.jwt.ValidateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if claims.Type != "refresh" {
		return nil, ErrInvalidToken
	}

	// Get user — for platform users, TenantID is uuid.Nil; fall back to platform_users if needed
	user, err := a.GetUserByID(claims.UserID)
	if err != nil {
		if err != ErrUserNotFound || claims.TenantID != uuid.Nil {
			return nil, err
		}
		// Platform user token on tenant endpoint: look up in platform_users
		platformUser, roleName, platformErr := a.getPlatformUserByID(claims.UserID)
		if platformErr != nil {
			return nil, ErrUserNotFound
		}
		if !platformUser.IsActive {
			return nil, ErrUserInactive
		}
		accessToken, newRefreshToken, err := a.jwt.GenerateTokens(
			platformUser.ID, uuid.Nil, platformUser.Email, roleName)
		if err != nil {
			return nil, fmt.Errorf("failed to generate tokens: %w", err)
		}
		expiresAt := time.Now().Add(authpolicy.SessionLifetime(a.db, a.jwt.GetRefreshExpiry()))
		_, err = a.refreshTokenService.ValidateAndRotateToken(
			refreshToken,
			platformUser.ID,
			newRefreshToken,
			expiresAt,
			clientIP,
			userAgent,
		)
		if err != nil {
			if err == ErrTokenReuseDetected {
				// ValidateAndRotateToken already revoked the entire token family.
				// Do NOT call RevokeAllUserTokens — that would kill every session for this
				// user across all devices/browsers, which is disproportionate. Family
				// revocation is the right blast radius for a detected replay.
				return nil, ErrTokenReuseDetected
			}
			return nil, err
		}
		return &models.AuthResponse{
			AccessToken:  accessToken,
			RefreshToken: newRefreshToken,
			ExpiresIn:    int64(a.jwt.GetAccessExpiry().Seconds()),
		}, nil
	}

	// Reject refresh for a deactivated user. Login enforces this on the front
	// door, but without re-checking here a user deactivated mid-session keeps
	// minting fresh 7-day tokens on every refresh and never loses access. Mirrors
	// the platform-user branch above.
	if !user.IsActive {
		return nil, ErrUserInactive
	}

	// Generate new tokens
	accessToken, newRefreshToken, err := a.jwt.GenerateTokens(
		user.ID, user.TenantID, user.Email, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Validate old token, rotate it, and store new token (with reuse detection)
	expiresAt := time.Now().Add(authpolicy.SessionLifetime(a.db, a.jwt.GetRefreshExpiry()))
	_, err = a.refreshTokenService.ValidateAndRotateToken(
		refreshToken,
		user.ID,
		newRefreshToken,
		expiresAt,
		clientIP,
		userAgent,
	)
	if err != nil {
		if err == ErrTokenReuseDetected {
			// ValidateAndRotateToken already revoked the entire token family.
			// Do NOT call RevokeAllUserTokens — that would kill every session for this
			// user across all devices/browsers, which is disproportionate. Family
			// revocation is the right blast radius for a detected replay.
			return nil, ErrTokenReuseDetected
		}
		return nil, err
	}

	return &models.AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(a.jwt.GetAccessExpiry().Seconds()),
	}, nil
}

// Logout invalidates all refresh tokens for the user
func (a *AuthService) Logout(userID uuid.UUID) error {
	return a.refreshTokenService.RevokeAllUserTokens(userID)
}

// getPlatformUserByID retrieves a platform user by UUID
func (a *AuthService) getPlatformUserByID(userID uuid.UUID) (*models.PlatformUser, string, error) {
	query := `
		SELECT pu.id, pu.email, pu.first_name, pu.last_name,
		       pu.is_active, pu.email_verified, pu.last_login_at, pu.created_at,
		       pr.name as role_name
		FROM platform_users pu
		JOIN platform_roles pr ON pu.role_id = pr.id
		WHERE pu.id = $1`

	user := &models.PlatformUser{}
	var roleName string
	err := a.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Email,
		&user.FirstName, &user.LastName, &user.IsActive,
		&user.EmailVerified, &user.LastLoginAt, &user.CreatedAt,
		&roleName,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", ErrUserNotFound
		}
		return nil, "", err
	}
	return user, roleName, nil
}

// getPlatformUserByEmail retrieves a platform user by email with password hash and role name
func (a *AuthService) getPlatformUserByEmail(email string) (*models.PlatformUser, string, string, error) {
	query := `
		SELECT pu.id, pu.email, pu.password_hash, pu.first_name, pu.last_name,
		       pu.is_active, pu.email_verified, pu.last_login_at, pu.created_at,
		       pr.name as role_name
		FROM platform_users pu
		JOIN platform_roles pr ON pu.role_id = pr.id
		WHERE pu.email = $1`

	user := &models.PlatformUser{}
	var passwordHash sql.NullString // NULL for SSO-only platform users (#891)
	var roleName string
	err := a.db.QueryRow(query, strings.ToLower(email)).Scan(
		&user.ID, &user.Email, &passwordHash,
		&user.FirstName, &user.LastName, &user.IsActive,
		&user.EmailVerified, &user.LastLoginAt, &user.CreatedAt,
		&roleName,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", "", ErrUserNotFound
		}
		return nil, "", "", err
	}

	return user, passwordHash.String, roleName, nil
}

// GetUserByEmail retrieves a user by email
func (a *AuthService) GetUserByEmail(email string) (*models.User, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Login/registration
	// resolve the tenant FROM the email here; we cannot set app.tenant_id to a
	// tenant we are still discovering. Wrapping would fail closed.
	query := `
		SELECT id, tenant_id, email, password_hash, first_name, last_name,
		       is_active, email_verified, last_login_at, avatar_url, timezone, preferences,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL`

	user := &models.User{}
	var preferencesJSON []byte
	// password_hash is NULL for SSO-only users (no password set) — scan through a
	// NullString so loading them doesn't fail. Login/registration resolve
	// the tenant FROM the email, so this lookup runs on the bypass role (Phase 4).
	var passwordHash sql.NullString
	err := a.bypassDB.QueryRow(query, strings.ToLower(email)).Scan(
		&user.ID, &user.TenantID, &user.Email, &passwordHash,
		&user.FirstName, &user.LastName, &user.IsActive,
		&user.EmailVerified, &user.LastLoginAt, &user.AvatarURL, &user.Timezone,
		&preferencesJSON, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	user.PasswordHash = passwordHash.String

	// Parse preferences JSON
	if len(preferencesJSON) > 0 {
		if err := json.Unmarshal(preferencesJSON, &user.Preferences); err != nil {
			user.Preferences = make(map[string]interface{})
		}
	} else {
		user.Preferences = make(map[string]interface{})
	}

	// Get the user's primary role from RBAC system
	user.Role = a.getUserPrimaryRole(user.ID, user.TenantID)

	return user, nil
}

// GetUserByID retrieves a user by ID
func (a *AuthService) GetUserByID(userID uuid.UUID) (*models.User, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). JWT/refresh-token
	// hydration resolves the tenant FROM the user id; the tenant is the query
	// OUTPUT, not a known input. Wrapping would fail closed.
	query := `
		SELECT id, tenant_id, email, password_hash, first_name, last_name,
		       is_active, email_verified, last_login_at, avatar_url, timezone, preferences,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL`

	user := &models.User{}
	var preferencesJSON []byte
	// password_hash is NULL for SSO-only users (no password set) — scan through a
	// NullString so loading them (e.g. /auth/me after SSO login) doesn't fail.
	// JWT hydration resolves the tenant FROM the user id → bypass role (Phase 4).
	var passwordHash sql.NullString
	err := a.bypassDB.QueryRow(query, userID).Scan(
		&user.ID, &user.TenantID, &user.Email, &passwordHash,
		&user.FirstName, &user.LastName, &user.IsActive,
		&user.EmailVerified, &user.LastLoginAt, &user.AvatarURL, &user.Timezone,
		&preferencesJSON, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	user.PasswordHash = passwordHash.String

	// Parse preferences JSON
	if len(preferencesJSON) > 0 {
		if err := json.Unmarshal(preferencesJSON, &user.Preferences); err != nil {
			// If parsing fails, initialize empty map
			user.Preferences = make(map[string]interface{})
		}
	} else {
		user.Preferences = make(map[string]interface{})
	}

	// Get the user's primary role from RBAC system
	user.Role = a.getUserPrimaryRole(user.ID, user.TenantID)

	return user, nil
}

// GetTenantByID retrieves a tenant by ID
func (a *AuthService) GetTenantByID(tenantID uuid.UUID) (*models.Tenant, error) {
	query := `
		SELECT id, name, slug, domain, subscription_tier_id, trial_ends_at,
		       billing_email, payment_status, settings,
		       created_at, updated_at, deleted_at
		FROM tenants
		WHERE id = $1 AND deleted_at IS NULL`

	tenant := &models.Tenant{}
	var settingsJSON []byte
	var subscriptionTierID *uuid.UUID
	err := a.db.QueryRow(query, tenantID).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain,
		&subscriptionTierID, &tenant.TrialEndsAt,
		&tenant.BillingEmail, &tenant.PaymentStatus, &settingsJSON,
		&tenant.CreatedAt, &tenant.UpdatedAt, &tenant.DeletedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("tenant not found")
		}
		return nil, err
	}

	// Handle nullable subscription_tier_id
	if subscriptionTierID != nil {
		tenant.SubscriptionTierID = *subscriptionTierID
	}

	// Parse settings JSON
	if len(settingsJSON) > 0 {
		if err := json.Unmarshal(settingsJSON, &tenant.Settings); err != nil {
			tenant.Settings = make(map[string]interface{})
		}
	} else {
		tenant.Settings = make(map[string]interface{})
	}

	return tenant, nil
}

// createUser inserts a new user into the database
// Note: Role is no longer stored in users table - it's managed via RBAC (user_tenant_roles)
func (a *AuthService) createUser(user *models.User) error {
	query := `
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	// RLS-scoped write: users carries a tenant_isolation policy. The tenant is
	// known (user.TenantID, just created in Register), so the INSERT runs inside
	// WithTenantTx — app.tenant_id satisfies the policy WITH CHECK.
	return shareddatabase.WithTenantTx(context.Background(), a.db, user.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), query,
			user.ID, user.TenantID, user.Email, user.PasswordHash,
			user.FirstName, user.LastName, user.IsActive,
			user.EmailVerified, user.CreatedAt, user.UpdatedAt,
		)
		return err
	})
}

// DefaultSignupTierName is the subscription tier a newly created tenant lands
// on when the signup request names no tier of its own.
//
// It is "community" because that is the Core edition's floor: unlimited
// CAPACITY, zero paid CAPABILITIES (see the seed.sql block that creates it, and
// shared/entitlements/editions.go for why capability gating is independent of
// tier). A tenant with NO tier resolves every numeric cap to
// billable_items.default_value, and those defaults are deliberately
// conservative — max_sensors 0, max_assets 0 — so a tier-less tenant cannot
// register a sensor or track an asset. Sensors are the platform's primary
// collection path, so "no tier" is indistinguishable from "product does not
// work".
//
// Overridable with DEFAULT_SIGNUP_TIER for the one deployment shape where a
// different floor is correct: a commercial multi-tenant SaaS, which wants new
// signups on the "free" trial tier instead. Self-hosted installs — Core or
// commercial — want the community floor, since their entitlements come from an
// edition token's tenant_entitlements overrides, not from the tier.
const DefaultSignupTierName = "community"

// defaultSignupTierName returns the configured default tier name for new
// tenants.
func defaultSignupTierName() string {
	if v := strings.TrimSpace(os.Getenv("DEFAULT_SIGNUP_TIER")); v != "" {
		return v
	}
	return DefaultSignupTierName
}

// lookupDefaultSignupTier resolves the default tier name to an id.
//
// Deliberately does NOT filter on is_active: the community tier is
// is_active=false precisely so it stays off the customer-facing plan-comparison
// surface, and it is still the tier we assign. Returns (nil, nil) when no such
// tier row exists — the caller treats that as "leave NULL and warn" rather than
// failing signup, because a missing seed row must not make the product
// unregisterable.
func (a *AuthService) lookupDefaultSignupTier() (*uuid.UUID, error) {
	name := defaultSignupTierName()
	var id uuid.UUID
	err := a.db.QueryRow(`SELECT id FROM subscription_tiers WHERE name = $1`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("look up default signup tier %q: %w", name, err)
	}
	return &id, nil
}

// createTenant creates a new tenant.
//
// The tenant is placed on the default signup tier (see DefaultSignupTierName).
// Callers that know the tenant's real plan — the invite/paid flows, which carry
// an explicit subscription_tier_id — overwrite it immediately afterwards, so
// this is a floor rather than a decision. It used to be left NULL "until the
// user selects a tier", but no self-signup surface ever asks: the tenant UI has
// no tier picker, so every self-signup tenant stayed capped at 0 sensors and 0
// assets forever.
func (a *AuthService) createTenant(name string) (*models.Tenant, error) {
	tenantID := uuid.New()
	slug := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), " ", "-"))

	subscriptionTierID, err := a.lookupDefaultSignupTier()
	if err != nil {
		return nil, err
	}
	if subscriptionTierID == nil {
		logrus.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"tier_name": defaultSignupTierName(),
		}).Warn("Default signup tier not found; tenant created with no tier — sensor and asset limits will resolve to 0 until a tier is assigned")
	}

	modelTierID := uuid.Nil
	if subscriptionTierID != nil {
		modelTierID = *subscriptionTierID
	}

	tenant := &models.Tenant{
		ID:                 tenantID,
		Name:               name,
		Slug:               slug,
		SubscriptionTierID: modelTierID, // uuid.Nil when the tier row is missing (DB stores NULL)
		BillingEmail:       "",          // Will be set during registration
		PaymentStatus:      "trial",
		Settings:           make(map[string]interface{}),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	// Note: trial_ends_at is handled by the database trigger.
	// onboarding_status is left at its 'pending' default: the tier here is a
	// system-assigned floor, not a choice the user made, and the MSP onboarding
	// funnel reads that column as "has this tenant been through onboarding".
	query := `
		INSERT INTO tenants (id, name, slug, subscription_tier_id, billing_email, payment_status, settings, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	// Run inside WithTenantTx so app.tenant_id is set to the new tenant's UUID
	// for the duration of the transaction. The DB triggers that fire on this
	// INSERT (auto_license_best_practices, auto_license_iec62351_for_enterprise)
	// insert into tenant_framework_licenses, which carries an RLS policy that
	// requires app.tenant_id = tenant_id. Without this, those triggers fail.
	// tenants itself has no RLS policy so the context does not constrain the
	// INSERT itself.
	if err := shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(context.Background(), query,
			tenant.ID, tenant.Name, tenant.Slug, subscriptionTierID,
			tenant.BillingEmail, tenant.PaymentStatus, "{}", tenant.CreatedAt, tenant.UpdatedAt,
		)
		return e
	}); err != nil {
		return nil, err
	}

	// Seed the default notification pack. Best-effort: a pack failure must
	// not fail tenant creation, so this runs in its own transaction and only
	// logs on error.
	if err := a.seedDefaultNotificationPack(tenantID); err != nil {
		logrus.WithError(err).WithField("tenant_id", tenantID).
			Warn("Failed to seed default notification pack")
	}

	return tenant, nil
}

// seedDefaultNotificationPack pre-wires a new tenant so alerts land from day
// one (NOTIFICATION_ALERTING_ARCHITECTURE.md §7). Without it, detection that
// fires into zero configured channels is silently dropped. Seeds:
//   - an in-app channel (bell feed, zero config)
//   - an email channel resolving recipients from the tenant_admin role at
//     send time (no address exists yet at tenant creation)
//   - "Default critical alerts": all sources, critical+high → in-app + email
//   - "Default activity feed": all sources, medium+low+info → in-app only
//     (info is not a spare band: asset_limit_approaching opens there at its 80%
//     rung, billing notifications are emitted there, and NormalizeSeverity
//     degrades any unrecognized producer severity to it. Leaving it out of the
//     pack dropped every one of those on the floor, silently.)
//   - discovery_alert_configs defaults (job_completed / job_failed /
//     new_findings), fixing the create-time gap left by the one-time backfill
//     migration
//
// Everything is editable/deletable by the tenant afterwards.
func (a *AuthService) seedDefaultNotificationPack(tenantID uuid.UUID) error {
	inAppChannelID := uuid.New()
	emailChannelID := uuid.New()

	return shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		ctx := context.Background()

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_notification_channels (id, tenant_id, channel_name, channel_type, config, enabled, description)
			VALUES
			  ($1, $3, 'In-app', 'in_app', '{}'::jsonb, true, 'Default in-app notifications (bell). Seeded at tenant creation.'),
			  ($2, $3, 'Tenant admin email', 'email', '{"recipients": [], "recipient_role": "tenant_admin"}'::jsonb, true, 'Emails all tenant admins (resolved at send time). Seeded at tenant creation.')
		`, inAppChannelID, emailChannelID, tenantID); err != nil {
			return fmt.Errorf("seed channels: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_notification_rules (tenant_id, rule_name, alert_source, channel_ids, severity_filter, frequency, enabled, priority)
			VALUES
			  ($1, 'Default critical alerts', 'all', $2::uuid[], ARRAY['critical','high']::varchar[], 'immediate', true, 100),
			  ($1, 'Default activity feed',   'all', $3::uuid[], ARRAY['medium','low','info']::varchar[], 'immediate', true, 50)
		`, tenantID,
			pq.Array([]string{inAppChannelID.String(), emailChannelID.String()}),
			pq.Array([]string{inAppChannelID.String()}),
		); err != nil {
			return fmt.Errorf("seed rules: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO discovery_alert_configs (tenant_id, alert_type, enabled, email_enabled, slack_enabled, in_app_enabled)
			VALUES
			  ($1, 'job_completed', true, false, false, true),
			  ($1, 'job_failed',    true, false, false, true),
			  ($1, 'new_findings',  true, false, false, true)
			ON CONFLICT (tenant_id, alert_type) DO NOTHING
		`, tenantID); err != nil {
			return fmt.Errorf("seed discovery alert configs: %w", err)
		}

		return nil
	})
}

// BootstrapTrialIfApplicable creates a billing_trial_tracking row for a
// tenant if the tenant is on a trial tier (subscription_tiers.is_trial =
// true with non-zero trial_days_full + trial_days_soft).
//
// Idempotent: if a trial row already exists for the tenant, this is a
// no-op. Safe to call from CompleteRegistration's tier-set path even if
// the tenant was created earlier under a different flow.
//
// Returns nil and does nothing when:
//   - the tenant has no subscription_tier_id (onboarding not finished)
//   - the tier is not a trial tier (paid tier selected at signup)
//   - a trial row already exists (replay / re-entry)
//
// We don't create a Stripe subscription here — that's TrialManager's job
// in admin-service when a stripe_price_id is configured and the trial
// is administratively created (e.g. POC tenant). Auth-service stays
// Stripe-unaware so signup works in environments without Stripe.
func (a *AuthService) BootstrapTrialIfApplicable(tenantID uuid.UUID) error {
	var (
		isTrial       sql.NullBool
		trialDaysFull sql.NullInt64
		trialDaysSoft sql.NullInt64
	)
	err := a.db.QueryRow(`
		SELECT st.is_trial, st.trial_days_full, st.trial_days_soft
		FROM tenants t
		JOIN subscription_tiers st ON st.id = t.subscription_tier_id
		WHERE t.id = $1
	`, tenantID).Scan(&isTrial, &trialDaysFull, &trialDaysSoft)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up tier trial config: %w", err)
	}
	if !isTrial.Valid || !isTrial.Bool {
		return nil
	}

	totalDays := 0
	if trialDaysFull.Valid {
		totalDays += int(trialDaysFull.Int64)
	}
	if trialDaysSoft.Valid {
		totalDays += int(trialDaysSoft.Int64)
	}
	if totalDays <= 0 {
		return nil
	}

	// Idempotency: only insert when no row exists. ON CONFLICT would
	// require a UNIQUE constraint we haven't added; the LIMIT 1 + skip
	// pattern matches what TrialManager.CreateTrial does in admin-service.
	//
	// RLS-scoped: billing_trial_tracking carries a tenant_isolation policy. The
	// tenant is known, so the existence check + INSERT run inside one WithTenantTx
	// (app.tenant_id set for both the read and the WITH CHECK on insert).
	now := time.Now()
	trialEnd := now.Add(time.Duration(totalDays) * 24 * time.Hour)
	bootstrapped := false
	wrapErr := shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		var existingID uuid.UUID
		checkErr := tx.QueryRowContext(context.Background(), `
			SELECT id FROM billing_trial_tracking WHERE tenant_id = $1 LIMIT 1
		`, tenantID).Scan(&existingID)
		if checkErr == nil {
			return nil // already bootstrapped
		}
		if checkErr != sql.ErrNoRows {
			return fmt.Errorf("check existing trial: %w", checkErr)
		}

		if _, e := tx.ExecContext(context.Background(), `
			INSERT INTO billing_trial_tracking (tenant_id, trial_start, trial_end, created_at, updated_at)
			VALUES ($1, $2, $3, NOW(), NOW())
		`, tenantID, now, trialEnd); e != nil {
			return fmt.Errorf("insert trial tracking row: %w", e)
		}
		bootstrapped = true
		return nil
	})
	if wrapErr != nil {
		return wrapErr
	}
	if !bootstrapped {
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"tenant_id":       tenantID,
		"trial_days_full": trialDaysFull.Int64,
		"trial_days_soft": trialDaysSoft.Int64,
		"trial_end":       trialEnd,
	}).Info("Trial bootstrapped at signup")
	return nil
}

// autoLicenseBestPractices automatically licenses the Best Practices framework to a new tenant
// This creates a license record in tenant_framework_licenses, ensuring all tenants have access
// to the platform default framework. This simplifies queries throughout the system.
func (a *AuthService) autoLicenseBestPractices(tenantID uuid.UUID) error {
	// Get Best Practices framework ID
	var bestPracticesFrameworkID uuid.UUID
	err := a.db.QueryRow(`
		SELECT id FROM platform_frameworks
		WHERE is_platform_default = true AND status = 'published'
		LIMIT 1
	`).Scan(&bestPracticesFrameworkID)
	if err != nil {
		if err == sql.ErrNoRows {
			// Best Practices framework doesn't exist yet - this is OK, it will be created by migration
			return nil
		}
		return fmt.Errorf("failed to get Best Practices framework: %w", err)
	}

	// tenant_framework_licenses carries a tenant_isolation policy. The tenant is
	// known, so the existence checks + the INSERT all run inside one WithTenantTx
	// so app.tenant_id is set for both the reads and the WITH CHECK on insert.
	return shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		// Check if tenant already has Best Practices license
		var existingCount int
		if e := tx.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM tenant_framework_licenses
			WHERE tenant_id = $1 AND platform_framework_id = $2
		`, tenantID, bestPracticesFrameworkID).Scan(&existingCount); e != nil {
			return fmt.Errorf("failed to check existing license: %w", e)
		}
		if existingCount > 0 {
			// Already licensed, nothing to do
			return nil
		}

		// Check if tenant has any other licenses (to determine if this should be default)
		var otherLicenseCount int
		if e := tx.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM tenant_framework_licenses
			WHERE tenant_id = $1
		`, tenantID).Scan(&otherLicenseCount); e != nil {
			return fmt.Errorf("failed to check other licenses: %w", e)
		}

		// Create license - make it default if tenant has no other licenses
		isDefault := otherLicenseCount == 0
		if _, e := tx.ExecContext(context.Background(), `
			INSERT INTO tenant_framework_licenses (
				id, tenant_id, platform_framework_id, is_locked, locked_at, locked_by,
				is_default, purchased_at, created_at, updated_at
			) VALUES (
				gen_random_uuid(), $1, $2, false, NULL, NULL, $3, NOW(), NOW(), NOW()
			)
			ON CONFLICT (tenant_id, platform_framework_id) DO NOTHING
		`, tenantID, bestPracticesFrameworkID, isDefault); e != nil {
			return fmt.Errorf("failed to create Best Practices license: %w", e)
		}
		return nil
	})
}

// checkAccountLocked returns true if the user's account is currently locked.
func (a *AuthService) checkAccountLocked(userID uuid.UUID) (bool, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Part of the login
	// flow, keyed only by user id before the tenant is established; the tenant is
	// not available here. Wrapping would fail closed.
	var lockedUntil sql.NullTime
	err := a.bypassDB.QueryRow(
		"SELECT locked_until FROM users WHERE id = $1", userID,
	).Scan(&lockedUntil)
	if err != nil {
		return false, err
	}
	if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
		return true, nil
	}
	return false, nil
}

// recordFailedLogin increments the failed login counter and locks the account
// once it reaches the operator-configured maximum — admin-ui Security ▸ Policy,
// "Maximum login attempts" and "Lockout duration (minutes)". Falls back to the
// historical 5 attempts / 15 minutes when those settings have never been saved.
func (a *AuthService) recordFailedLogin(userID uuid.UUID) {
	policy := authpolicy.Lockout(a.db)
	maxAttempts := policy.MaxAttempts
	lockoutDuration := policy.Duration

	// RLS: cross-tenant — runs on the bypass role (Phase 4). Login-flow write
	// keyed only by user id; the tenant is not yet established. Wrapping would
	// fail closed.
	_, err := a.bypassDB.Exec(
		`UPDATE users
		 SET failed_login_attempts = failed_login_attempts + 1,
		     locked_until = CASE
		         WHEN failed_login_attempts + 1 >= $1 THEN $2
		         ELSE locked_until
		     END,
		     updated_at = $3
		 WHERE id = $4`,
		maxAttempts, time.Now().Add(lockoutDuration), time.Now(), userID,
	)
	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Warn("Failed to record failed login attempt")
	}
}

// resetFailedLoginAttempts clears the failed login counter and lock on successful login.
func (a *AuthService) resetFailedLoginAttempts(userID uuid.UUID) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Login-flow write
	// keyed only by user id; the tenant is not yet established. Wrapping would
	// fail closed.
	_, err := a.bypassDB.Exec(
		`UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = $1 WHERE id = $2`,
		time.Now(), userID,
	)
	if err != nil {
		logrus.WithError(err).WithField("user_id", userID).Warn("Failed to reset failed login attempts")
	}
}

// --- platform_users lockout ---
//
// These mirror the tenant-user helpers above against the platform_users table,
// so the highest-privilege accounts (super_admin / platform_admin) get the same
// lockout the tenant path has always had. Previously the
// platform-login branch had NO lockout — only the rate limiter stood between an
// attacker and unlimited password guesses against a platform admin.

func (a *AuthService) checkPlatformAccountLocked(userID uuid.UUID) (bool, error) {
	var lockedUntil sql.NullTime
	err := a.db.QueryRow(
		"SELECT locked_until FROM platform_users WHERE id = $1", userID,
	).Scan(&lockedUntil)
	if err != nil {
		return false, err
	}
	if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
		return true, nil
	}
	return false, nil
}

// recordPlatformFailedLogin increments the platform user's failed login counter
// and locks the account once it reaches the operator-configured maximum. It
// reads the SAME policy as the tenant path: a lockout rule the highest-privilege
// accounts are exempt from is not a lockout rule.
func (a *AuthService) recordPlatformFailedLogin(userID uuid.UUID) {
	policy := authpolicy.Lockout(a.db)
	maxAttempts := policy.MaxAttempts
	lockoutDuration := policy.Duration

	_, err := a.db.Exec(
		`UPDATE platform_users
		 SET failed_login_attempts = failed_login_attempts + 1,
		     locked_until = CASE
		         WHEN failed_login_attempts + 1 >= $1 THEN $2
		         ELSE locked_until
		     END,
		     updated_at = $3
		 WHERE id = $4`,
		maxAttempts, time.Now().Add(lockoutDuration), time.Now(), userID,
	)
	if err != nil {
		logrus.WithError(err).WithField("platform_user_id", userID).Warn("Failed to record platform failed login attempt")
	}
}

// resetPlatformFailedLoginAttempts clears the platform user's failed login
// counter and lock on a successful login.
func (a *AuthService) resetPlatformFailedLoginAttempts(userID uuid.UUID) {
	_, err := a.db.Exec(
		`UPDATE platform_users SET failed_login_attempts = 0, locked_until = NULL, updated_at = $1 WHERE id = $2`,
		time.Now(), userID,
	)
	if err != nil {
		logrus.WithError(err).WithField("platform_user_id", userID).Warn("Failed to reset platform failed login attempts")
	}
}

func (a *AuthService) updateUserLastLogin(userID uuid.UUID, lastLogin time.Time) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Login-flow write
	// keyed only by user id. Wrapping would fail closed.
	query := `UPDATE users SET last_login_at = $1, updated_at = $2 WHERE id = $3`
	_, err := a.bypassDB.Exec(query, lastLogin, time.Now(), userID)
	return err
}

// UpdateUser updates user profile information
func (a *AuthService) UpdateUser(userID uuid.UUID, req *models.UpdateUserRequest) (*models.User, error) {
	// Get current user
	user, err := a.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if req.FirstName != nil && *req.FirstName != "" {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil && *req.LastName != "" {
		user.LastName = *req.LastName
	}
	if req.Email != nil && *req.Email != "" && *req.Email != user.Email {
		// Check if new email is already taken
		existingUser, err := a.GetUserByEmail(*req.Email)
		if err != nil && err != ErrUserNotFound {
			return nil, err
		}
		if existingUser != nil {
			return nil, ErrEmailExists
		}
		user.Email = strings.ToLower(*req.Email)
		user.EmailVerified = false // Require re-verification for email changes
	}
	if req.AvatarURL != nil {
		user.AvatarURL = req.AvatarURL
	}
	if req.Timezone != nil && *req.Timezone != "" {
		user.Timezone = req.Timezone
	}
	if req.Preferences != nil {
		user.Preferences = req.Preferences
	}

	user.UpdatedAt = time.Now()

	// Update in database
	preferencesJSON, err := json.Marshal(user.Preferences)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal preferences: %w", err)
	}

	// RLS: cross-tenant — runs on the bypass role (Phase 4). Self-service profile
	// update keyed only by user id; tenant is not threaded into this method.
	// Wrapping would fail closed.
	query := `
		UPDATE users
		SET first_name = $1, last_name = $2, email = $3, email_verified = $4,
		    avatar_url = $5, timezone = $6, preferences = $7, updated_at = $8
		WHERE id = $9`

	_, err = a.bypassDB.Exec(query, user.FirstName, user.LastName, user.Email, user.EmailVerified,
		user.AvatarURL, user.Timezone, preferencesJSON, user.UpdatedAt, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return user, nil
}

// GetNotificationPreferences gets notification preferences for a user
func (a *AuthService) GetNotificationPreferences(userID uuid.UUID) (map[string]interface{}, error) {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	// Extract notification preferences from user preferences
	notifPrefs, ok := user.Preferences["notifications"]
	if !ok {
		// Return default preferences if not set
		return map[string]interface{}{
			"categories": map[string]bool{
				"security": true,
				"sensors":  true,
				"billing":  true,
				"system":   true,
				"reports":  true,
				"users":    true,
			},
			"delivery": map[string]bool{
				"inApp": true,
				"email": false,
			},
			"frequency": "immediate",
		}, nil
	}

	// Type assert to map
	prefsMap, ok := notifPrefs.(map[string]interface{})
	if !ok {
		// If type assertion fails, return defaults
		return map[string]interface{}{
			"categories": map[string]bool{
				"security": true,
				"sensors":  true,
				"billing":  true,
				"system":   true,
				"reports":  true,
				"users":    true,
			},
			"delivery": map[string]bool{
				"inApp": true,
				"email": false,
			},
			"frequency": "immediate",
		}, nil
	}

	return prefsMap, nil
}

// UpdateNotificationPreferences updates notification preferences for a user
func (a *AuthService) UpdateNotificationPreferences(userID uuid.UUID, prefs map[string]interface{}) error {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Merge notification preferences into user preferences
	if user.Preferences == nil {
		user.Preferences = make(map[string]interface{})
	}
	user.Preferences["notifications"] = prefs

	// Update user with merged preferences
	preferencesJSON, err := json.Marshal(user.Preferences)
	if err != nil {
		return fmt.Errorf("failed to marshal preferences: %w", err)
	}

	// RLS: cross-tenant — runs on the bypass role (Phase 4). Self-service write
	// keyed only by user id; tenant not threaded here. Wrapping would fail closed.
	query := `UPDATE users SET preferences = $1, updated_at = $2 WHERE id = $3`
	_, err = a.bypassDB.Exec(query, preferencesJSON, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update notification preferences: %w", err)
	}

	return nil
}

// ChangePassword changes a user's password
func (a *AuthService) ChangePassword(userID uuid.UUID, req *models.ChangePasswordRequest) error {
	// Get current user
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Verify current password
	valid, err := a.password.VerifyPassword(req.CurrentPassword, user.PasswordHash)
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidCredentials
	}

	// Validate new password strength
	if err := passwordsvc.ValidatePasswordStrengthWithPolicy(a.db, req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	newPasswordHash, err := a.password.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password in database.
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Self-service password
	// change keyed only by user id; tenant not threaded here. Wrapping would fail
	// closed.
	query := `UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`
	_, err = a.bypassDB.Exec(query, newPasswordHash, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Invalidate all refresh tokens for security
	if err := a.refreshTokenService.RevokeAllUserTokens(userID); err != nil {
		// Log error but don't fail password change
		logrus.WithError(err).WithField("user_id", userID).Warn("Failed to revoke refresh tokens after password change")
	}

	return nil
}

// ForgotPassword initiates password reset process
func (a *AuthService) ForgotPassword(req *models.ForgotPasswordRequest) error {
	// Get user by email
	user, err := a.GetUserByEmail(req.Email)
	if err != nil {
		if err == ErrUserNotFound {
			// Don't reveal if email exists or not for security
			return nil
		}
		return err
	}

	// Generate reset token
	resetToken := uuid.New().String()
	expiry := time.Now().Add(1 * time.Hour) // 1 hour expiry

	// Store reset token in Redis
	key := fmt.Sprintf("password_reset:%s", resetToken)
	resetData := map[string]interface{}{
		"user_id": user.ID.String(),
		"email":   user.Email,
		"expiry":  expiry.Unix(),
	}

	err = a.redis.HSet(context.Background(), key, resetData).Err()
	if err != nil {
		return fmt.Errorf("failed to store reset token: %w", err)
	}

	// Set expiry on the key
	err = a.redis.Expire(context.Background(), key, 1*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to set reset token expiry: %w", err)
	}

	// Send email with reset link
	svc, err := a.emailServiceFromDB()
	if err != nil {
		logrus.WithError(err).WithField("email", user.Email).Warn("Email not configured — skipping password reset email")
		return nil
	}
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", a.webUIBaseURL(), resetToken)
	err = svc.SendPasswordResetEmail(user.Email, resetLink)
	if err != nil {
		logrus.WithError(err).WithField("email", user.Email).Warn("Failed to send password reset email")
	}

	return nil
}

// ResetPassword resets password using reset token
func (a *AuthService) ResetPassword(req *models.ResetPasswordRequest) error {
	// Get reset token data from Redis
	key := fmt.Sprintf("password_reset:%s", req.Token)
	resetData, err := a.redis.HGetAll(context.Background(), key).Result()
	if err != nil {
		return fmt.Errorf("failed to get reset token: %w", err)
	}

	if len(resetData) == 0 {
		return ErrInvalidToken
	}

	// Check if token is expired
	expiryUnix, err := strconv.ParseInt(resetData["expiry"], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid reset token format: %w", err)
	}

	if time.Now().Unix() > expiryUnix {
		// Clean up expired token
		a.redis.Del(context.Background(), key)
		return ErrExpiredToken
	}

	// Get user ID
	userID, err := uuid.Parse(resetData["user_id"])
	if err != nil {
		return fmt.Errorf("invalid user ID in reset token: %w", err)
	}

	// Validate new password strength
	if err := passwordsvc.ValidatePasswordStrengthWithPolicy(a.db, req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	newPasswordHash, err := a.password.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password in database.
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Password reset keyed
	// only by the user id carried in the Redis reset token; tenant is not known
	// here. Wrapping would fail closed.
	query := `UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`
	_, err = a.bypassDB.Exec(query, newPasswordHash, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Clean up reset token
	a.redis.Del(context.Background(), key)

	// Invalidate all refresh tokens for security
	if err := a.refreshTokenService.RevokeAllUserTokens(userID); err != nil {
		logrus.WithError(err).WithField("user_id", userID).Warn("Failed to revoke refresh tokens after password reset")
	}

	return nil
}

// VerifyEmail verifies user email address
func (a *AuthService) VerifyEmail(token string) error {
	// Get verification token data from Redis
	key := fmt.Sprintf("email_verification:%s", token)
	verificationData, err := a.redis.HGetAll(context.Background(), key).Result()
	if err != nil {
		return fmt.Errorf("failed to get verification token: %w", err)
	}

	if len(verificationData) == 0 {
		return ErrInvalidToken
	}

	// Check if token is expired
	expiryUnix, err := strconv.ParseInt(verificationData["expiry"], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid verification token format: %w", err)
	}

	if time.Now().Unix() > expiryUnix {
		// Clean up expired token
		a.redis.Del(context.Background(), key)
		return ErrExpiredToken
	}

	// Get user ID
	userID, err := uuid.Parse(verificationData["user_id"])
	if err != nil {
		return fmt.Errorf("invalid user ID in verification token: %w", err)
	}

	// Update user email verification status.
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Email verify keyed
	// only by the user id carried in the Redis verification token; tenant is not
	// known here. Wrapping would fail closed.
	query := `UPDATE users SET email_verified = true, updated_at = $1 WHERE id = $2`
	_, err = a.bypassDB.Exec(query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to verify email: %w", err)
	}

	// Clean up verification token
	a.redis.Del(context.Background(), key)

	return nil
}

// SendEmailVerification sends email verification token
func (a *AuthService) SendEmailVerification(userID uuid.UUID) error {
	// Get user
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	if user.EmailVerified {
		return errors.New("email already verified")
	}

	// Generate verification token
	verificationToken := uuid.New().String()
	expiry := time.Now().Add(24 * time.Hour) // 24 hour expiry

	// Store verification token in Redis
	key := fmt.Sprintf("email_verification:%s", verificationToken)
	verificationData := map[string]interface{}{
		"user_id": user.ID.String(),
		"email":   user.Email,
		"expiry":  expiry.Unix(),
	}

	err = a.redis.HSet(context.Background(), key, verificationData).Err()
	if err != nil {
		return fmt.Errorf("failed to store verification token: %w", err)
	}

	// Set expiry on the key
	err = a.redis.Expire(context.Background(), key, 24*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to set verification token expiry: %w", err)
	}

	// Send email with verification link
	svc, err := a.emailServiceFromDB()
	if err != nil {
		logrus.WithError(err).WithField("email", user.Email).Warn("Email not configured — skipping verification email")
		return nil
	}
	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", a.webUIBaseURL(), verificationToken)
	err = svc.SendEmailVerificationEmail(user.Email, verificationLink)
	if err != nil {
		logrus.WithError(err).WithField("email", user.Email).Warn("Failed to send email verification")
	}

	return nil
}

// GetUserSessions returns active sessions for a user.
// refresh_tokens is a GLOBAL table (no tenant_isolation policy); left unwrapped.
func (a *AuthService) GetUserSessions(userID uuid.UUID) ([]models.Session, error) {
	query := `
		SELECT id, user_id, family_id, expires_at, last_used_at, is_revoked,
		       created_from_ip, user_agent, created_at, revoked_at
		FROM refresh_tokens
		WHERE user_id = $1 AND is_revoked = false AND expires_at > NOW()
		ORDER BY last_used_at DESC`

	rows, err := a.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []models.Session
	for rows.Next() {
		var session models.Session
		err := rows.Scan(
			&session.ID, &session.UserID, &session.FamilyID, &session.ExpiresAt,
			&session.LastUsedAt, &session.IsRevoked, &session.CreatedFromIP,
			&session.UserAgent, &session.CreatedAt, &session.RevokedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// RevokeRefreshToken revokes a specific refresh token
func (a *AuthService) RevokeRefreshToken(userID, sessionID uuid.UUID) error {
	return a.refreshTokenService.RevokeToken(userID, sessionID)
}

// GetUserAuthMethods returns authentication methods for a user.
// user_auth_methods is a GLOBAL table (no tenant_isolation policy); left unwrapped.
func (a *AuthService) GetUserAuthMethods(userID uuid.UUID) ([]models.Connection, error) {
	query := `
		SELECT id, user_id, auth_type, sso_provider_id, external_user_id,
		       external_email, is_primary, last_used_at, metadata, created_at, updated_at
		FROM user_auth_methods
		WHERE user_id = $1
		ORDER BY is_primary DESC, created_at ASC`

	rows, err := a.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query auth methods: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var connections []models.Connection
	for rows.Next() {
		var connection models.Connection
		err := rows.Scan(
			&connection.ID, &connection.UserID, &connection.AuthType, &connection.SSOProviderID,
			&connection.ExternalUserID, &connection.ExternalEmail, &connection.IsPrimary,
			&connection.LastUsedAt, &connection.Metadata, &connection.CreatedAt, &connection.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan connection: %w", err)
		}
		connections = append(connections, connection)
	}

	return connections, nil
}

// SetPrimaryAuthMethod sets a connection as the primary authentication method
func (a *AuthService) SetPrimaryAuthMethod(userID, connectionID uuid.UUID) error {
	// Start transaction
	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// First, unset all primary flags for this user
	_, err = tx.Exec("UPDATE user_auth_methods SET is_primary = false WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to unset primary flags: %w", err)
	}

	// Then set the specified connection as primary
	result, err := tx.Exec("UPDATE user_auth_methods SET is_primary = true WHERE id = $1 AND user_id = $2", connectionID, userID)
	if err != nil {
		return fmt.Errorf("failed to set primary auth method: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrConnectionNotFound
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// UpdateUserAvatar updates a user's avatar URL
func (a *AuthService) UpdateUserAvatar(userID uuid.UUID, avatarURL string) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Self-service write
	// keyed only by user id; tenant not threaded here. Wrapping would fail closed.
	query := `UPDATE users SET avatar_url = $1, updated_at = NOW() WHERE id = $2`

	result, err := a.bypassDB.Exec(query, avatarURL, userID)
	if err != nil {
		return fmt.Errorf("failed to update avatar: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// TenantSecuritySummary represents security metrics for a tenant
type TenantSecuritySummary struct {
	TenantID           uuid.UUID `json:"tenant_id"`
	FailedLogins       int       `json:"failed_logins"`        // Count of failed login attempts in last 24h
	SecurityAlerts     int       `json:"security_alerts"`      // Count of security alerts
	ComplianceScore    float64   `json:"compliance_score"`     // Compliance score (0-100)
	LastSecurityUpdate time.Time `json:"last_security_update"` // Last password change or security update
	LastUpdated        time.Time `json:"last_updated"`
}

// GetTenantSecuritySummary returns security metrics for a specific tenant
func (a *AuthService) GetTenantSecuritySummary(tenantID uuid.UUID) (*TenantSecuritySummary, error) {
	summary := &TenantSecuritySummary{
		TenantID:        tenantID,
		LastUpdated:     time.Now(),
		FailedLogins:    0,
		SecurityAlerts:  0,    // Placeholder - could query compliance-engine or security logs
		ComplianceScore: 85.0, // Default score - could query compliance-engine
	}

	// Get user security metrics
	query := `
		SELECT
			COUNT(*) FILTER (WHERE email_verified = false) as unverified_count,
			COUNT(*) FILTER (WHERE password_changed_at IS NULL OR password_changed_at < NOW() - INTERVAL '90 days') as old_password_count,
			MAX(COALESCE(password_changed_at, created_at)) as last_security_update
		FROM users
		WHERE tenant_id = $1 AND deleted_at IS NULL
	`

	var unverifiedCount, oldPasswordCount int
	var lastSecurityUpdate sql.NullTime
	var failedLogins int
	var securityAlerts int
	noUsers := false

	// RLS-scoped: users, audit.activity_logs, and audit.audit_logs all carry
	// tenant_isolation policies. The tenant is known, so all three reads run
	// inside one WithTenantTx (app.tenant_id set). The audit counts keep their
	// existing "tolerate error → 0" semantics by swallowing errors locally.
	err := shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(context.Background(), query, tenantID).Scan(
			&unverifiedCount,
			&oldPasswordCount,
			&lastSecurityUpdate,
		)
		if scanErr == sql.ErrNoRows {
			noUsers = true
			return nil
		}
		if scanErr != nil {
			return fmt.Errorf("failed to query tenant security metrics: %w", scanErr)
		}

		// Count failed login events from activity logs (last 24 hours; users.failed_login_attempts is cumulative, not time-bounded)
		if e := tx.QueryRowContext(context.Background(), `
			SELECT COUNT(*)
			FROM audit.activity_logs
			WHERE tenant_id = $1
			  AND event_type = 'user.login_failed'
			  AND occurred_at > NOW() - INTERVAL '24 hours'
		`, tenantID).Scan(&failedLogins); e != nil {
			failedLogins = 0
		}

		// Query actual security alerts from audit logs (last 24 hours)
		if e := tx.QueryRowContext(context.Background(), `
			SELECT COUNT(*)
			FROM audit.audit_logs
			WHERE tenant_id = $1
			  AND created_at > NOW() - INTERVAL '24 hours'
			  AND (action ILIKE '%failed%' OR action ILIKE '%lockout%' OR action ILIKE '%unauthorized%' OR severity IN ('high', 'critical'))
		`, tenantID).Scan(&securityAlerts); e != nil {
			securityAlerts = 0
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if noUsers {
		// No users found for tenant
		summary.LastSecurityUpdate = time.Now()
		return summary, nil
	}

	// Set last security update
	if lastSecurityUpdate.Valid {
		summary.LastSecurityUpdate = lastSecurityUpdate.Time
	} else {
		summary.LastSecurityUpdate = time.Now()
	}

	summary.FailedLogins = failedLogins
	summary.SecurityAlerts = securityAlerts

	// Calculate compliance score (0-100)
	// Deduct points for unverified emails and old passwords
	baseScore := 100.0
	scoreDeduction := float64(unverifiedCount) * 5.0  // 5 points per unverified email
	scoreDeduction += float64(oldPasswordCount) * 3.0 // 3 points per old password
	summary.ComplianceScore = baseScore - scoreDeduction
	if summary.ComplianceScore < 0 {
		summary.ComplianceScore = 0
	}

	return summary, nil
}
