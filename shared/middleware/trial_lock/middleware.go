// Package trial_lock provides a Gin middleware that gates write
// requests when the calling tenant's trial has hard-locked.
//
// The web-ui HardLockGuard intercepts navigation client-side, but a
// determined locked tenant could craft API calls directly. This
// middleware is the defense-in-depth backstop: any mutation (POST /
// PUT / PATCH / DELETE) that isn't on the billing/auth allow-list
// returns 423 Locked when the tenant resolves to PhaseLocked via
// shared/trials.Compute.
//
// Reads always pass — locked tenants can still view their data so
// the upgrade flow is informed. Internal service-to-service requests
// (no tenant context) also pass; only authenticated tenant requests
// are gated.
package trial_lock

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/trials"
)

// Config tunes the middleware's behavior. Defaults are safe for the
// "first-customer SaaS" deployment; production rollouts can dial up
// AllowedPathPrefixes when new self-service endpoints land.
type Config struct {
	// AllowedPathPrefixes are URL prefixes (e.g. "/api/v1/auth-service/auth")
	// that bypass the lock even on writes. Used for billing/upgrade
	// flows the customer needs to escape the lock with. Defaults are
	// the auth, billing, and tenant-self-service paths every service
	// agrees on. Tested as a prefix match.
	AllowedPathPrefixes []string

	// Enabled lets ops kill the middleware at runtime via env without
	// a redeploy. true by default.
	Enabled bool
}

// DefaultConfig returns the safe defaults for the middleware: enforce
// the lock and pass through every billing/auth/account path the
// locked tenant could need to reach to upgrade or log out.
func DefaultConfig() *Config {
	return &Config{
		Enabled: true,
		AllowedPathPrefixes: []string{
			// Auth + session — never block.
			"/api/v1/auth-service/auth",
			// Tenant self-service billing surface — the customer's
			// only on-ramp out of the lock.
			"/api/v1/auth-service/tenant/trial-status",
			"/api/v1/auth-service/tenant/billing",
			"/api/v2/admin-service/my-billing",
			// Notification-service inbound webhook (Stripe etc.) — the
			// platform's own callbacks, not the tenant's writes.
			"/api/v2/admin-service/admin/billing/webhook",
		},
	}
}

// Middleware returns a Gin middleware that enforces the trial lock.
// db is the *sql.DB used to resolve the calling tenant's phase. The
// query is a single JOIN; a covering index on (subscription_tier_id,
// id) on tenants + the existing PK on billing_trial_tracking keep it
// cheap enough for the hot path.
func Middleware(db *sql.DB, cfg *Config) gin.HandlerFunc {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return func(c *gin.Context) {
		if !cfg.Enabled {
			c.Next()
			return
		}
		if isReadOnly(c.Request.Method) {
			c.Next()
			return
		}
		if isAllowedPath(c.Request.URL.Path, cfg.AllowedPathPrefixes) {
			c.Next()
			return
		}
		// Unauthenticated / internal traffic has no tenant in context.
		// Pass — auth middleware (or the absence of one) governs those
		// paths; this middleware only enforces against authenticated
		// tenant requests.
		tenantID, ok := tenantIDFromContext(c)
		if !ok {
			c.Next()
			return
		}

		phase, err := resolveTenantPhase(c.Request.Context(), db, tenantID, time.Now())
		if err != nil {
			// Fail open on resolver errors so a DB hiccup doesn't lock
			// every tenant out. Logged so we notice.
			log.Printf("trial_lock: resolve phase for tenant %s failed (passing through): %v", tenantID, err)
			c.Next()
			return
		}
		if phase != trials.PhaseLocked {
			c.Next()
			return
		}

		// 423 Locked is the HTTP-correct status for "this resource is
		// locked due to account state." The body mirrors the web-ui
		// HardLockGuard copy so the API surface is consistent.
		c.AbortWithStatusJSON(http.StatusLocked, gin.H{
			"error":        "trial_locked",
			"message":      "Your trial has ended. Upgrade to continue using the platform.",
			"upgrade_path": "/settings/organization",
		})
	}
}

// isReadOnly returns true for HTTP methods that don't mutate state.
// HEAD and OPTIONS are included for completeness — middleware before
// us in the chain may not have stripped them.
func isReadOnly(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// isAllowedPath returns true if the request path matches any of the
// prefixes the caller marked as bypassed. Prefix match is enough —
// the allow-list is short and the prefixes are namespaced.
func isAllowedPath(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// tenantIDFromContext reads the tenant UUID set by upstream auth
// middleware (RequireJWTAuth stores uuid.UUID under "tenantID"; some
// tests and legacy paths use a string). Delegates to the shared helper
// so type coercion matches the rest of the platform.
func tenantIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	return middleware.GetTenantIDFromContext(c)
}

// resolveTenantPhase issues the single SQL statement that derives the
// trial phase. Returns trials.PhaseNone for tenants with no trial
// row (paid signups), keeping the middleware permissive for non-trial
// customers.
func resolveTenantPhase(ctx context.Context, db *sql.DB, tenantID uuid.UUID, now time.Time) (trials.Phase, error) {
	var (
		trialDaysFull sql.NullInt64
		trialDaysSoft sql.NullInt64
		trialStart    sql.NullTime
		converted     sql.NullBool
	)
	// billing_trial_tracking is RLS-scoped, and it is reached through a LEFT
	// JOIN — so on the RLS-scoped handle without app.tenant_id the join simply
	// contributes NULLs instead of raising. trial_start comes back NULL, the
	// phase resolves to PhaseNone, and the lock never engages for anyone. Every
	// caller passes the crypto_app pool, so this must set the tenant context;
	// tenantID is an INPUT here, so wrapping is correct (and keeps RLS enforcing)
	// rather than reaching for the bypass role.
	err := database.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT
			    st.trial_days_full,
			    st.trial_days_soft,
			    btt.trial_start,
			    btt.converted_to_paid
			FROM tenants t
			LEFT JOIN subscription_tiers st ON st.id = t.subscription_tier_id
			LEFT JOIN billing_trial_tracking btt ON btt.tenant_id = t.id
			WHERE t.id = $1
		`, tenantID).Scan(&trialDaysFull, &trialDaysSoft, &trialStart, &converted)
	})
	if errors.Is(err, sql.ErrNoRows) {
		// Unknown tenant ID — treat as no trial. The actual auth
		// layer should have rejected an unknown tenant; we just
		// stay out of the way.
		return trials.PhaseNone, nil
	}
	if err != nil {
		return trials.PhaseNone, err
	}

	inputs := trials.Inputs{Now: now}
	if trialStart.Valid {
		inputs.TrialStart = trialStart.Time
	}
	if converted.Valid {
		inputs.ConvertedToPaid = converted.Bool
	}
	if trialDaysFull.Valid {
		v := int(trialDaysFull.Int64)
		inputs.TrialDaysFull = &v
	}
	if trialDaysSoft.Valid {
		v := int(trialDaysSoft.Int64)
		inputs.TrialDaysSoft = &v
	}
	return trials.Compute(inputs), nil
}
