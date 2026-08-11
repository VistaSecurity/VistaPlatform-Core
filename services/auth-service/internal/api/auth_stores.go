package api

// Store interfaces for the auth-service HTTP handlers.
//
// These are introduced for the spec-first API contract pilot
// (`cross_cutter_contract_test.go`). They let the contract test exercise the
// real gin handlers with an in-memory stub — no DB, no Redis, no live
// `*auth.AuthService` or `*sharedservices.LimitEnforcementService`.
//
// Production wiring is unchanged: `router.go` still calls
// `NewAuthHandlers(*auth.AuthService, ...)`, `rbac.NewRBACHandlers(*RBACService)`,
// and `getTenantFeaturesHandler(*sql.DB)`. The concrete service types satisfy
// these interfaces by virtue of having matching method sets, so the
// production code path is untouched and `cmd/main.go` is byte-identical to
// main.
//
// Keep these in sync with the methods the corresponding handler files
// actually call. If a handler grows a new service dependency, add the method
// here too — contract tests will fail to compile until the stub catches up,
// which is the desired guardrail.

import (
	"context"
	"database/sql"
	"time"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"

	"github.com/google/uuid"
)

// authServiceStore is the persistence + auth surface that `AuthHandlers`
// needs. `*auth.AuthService` is the production implementation; depending on
// the interface (rather than the concrete type) lets the cross-cutter
// handlers (`GetMe`) be exercised by the contract test with an in-memory
// stub, no database required.
//
// This interface is intentionally the **union** of every method any handler
// in `handlers.go` calls — including the out-of-scope handlers (Register /
// Login / Logout / RefreshToken / sessions / connections / password / EULA
// / preferences / etc.). Listing them keeps `handlers.go` compilable without
// a concrete-service field; the contract-test stub fills in panicking or
// no-op returns for the methods this slice does not exercise. Same pattern
// as compliance-engine's `frameworkLicenseStore` and inventory-service's
// `assetStore`.
//
// In scope (used by `GetMe`, the cross-cutter):
//   - GetUserByID, GetTenantByID
//
// Out of scope but referenced by other AuthHandlers methods — the contract
// test's stub will not exercise these.
type authServiceStore interface {
	// In scope for this slice.
	GetUserByID(userID uuid.UUID) (*models.User, error)
	GetTenantByID(tenantID uuid.UUID) (*models.Tenant, error)

	// Out of scope but referenced elsewhere in handlers.go. These keep the
	// file compiling without a concrete-service field.
	GetDB() *sql.DB
	// GetBypassDB returns the BYPASSRLS (crypto_bypass) connection used by the
	// cross-tenant self-service handlers (AcceptEULA, onboarding-status) that
	// resolve the tenant FROM the JWT's user id.
	GetBypassDB() *sql.DB
	Register(req *models.RegisterRequest) (*models.User, error)
	Login(req *models.LoginRequest, clientIP, userAgent string) (*models.AuthResponse, error)
	Logout(userID uuid.UUID) error
	RefreshToken(refreshToken, clientIP, userAgent string) (*models.AuthResponse, error)
	GetUserByEmail(email string) (*models.User, error)
	BootstrapTrialIfApplicable(tenantID uuid.UUID) error
	UpdateUser(userID uuid.UUID, req *models.UpdateUserRequest) (*models.User, error)
	GetNotificationPreferences(userID uuid.UUID) (map[string]interface{}, error)
	UpdateNotificationPreferences(userID uuid.UUID, prefs map[string]interface{}) error
	ChangePassword(userID uuid.UUID, req *models.ChangePasswordRequest) error
	ForgotPassword(req *models.ForgotPasswordRequest) error
	ResetPassword(req *models.ResetPasswordRequest) error
	VerifyEmail(token string) error
	SendEmailVerification(userID uuid.UUID) error
	GetUserSessions(userID uuid.UUID) ([]models.Session, error)
	RevokeRefreshToken(userID, sessionID uuid.UUID) error
	GetUserAuthMethods(userID uuid.UUID) ([]models.Connection, error)
	SetPrimaryAuthMethod(userID, connectionID uuid.UUID) error
	UpdateUserAvatar(userID uuid.UUID, avatarURL string) error
	// RevokeJTI adds an access token's jti to the shared revocation denylist
	// with the given TTL. Reuses the denylist so logout /
	// change-password immediately kill the live access token across all
	// services, not just the refresh token.
	RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error
}

// limitChecker is the slice of `*sharedservices.LimitEnforcementService` that
// `getTenantFeaturesHandler` actually calls. Production wires the concrete
// service from `router.go`; the contract test wires a stub that returns
// canned feature-availability bools and a synthetic compliance-framework
// usage.
type limitChecker interface {
	CheckFeatureAccess(tenantID uuid.UUID, feature string) (bool, error)
	GetComplianceFrameworkUsage(tenantID uuid.UUID) (current int, limit *int, err error)
}
