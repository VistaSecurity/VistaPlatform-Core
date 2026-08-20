// Package authpolicy reads the operator-configured authentication policy from
// platform_settings — the values a platform admin sets in admin-ui under
// Security ▸ Policy.
//
// WHY THIS EXISTS. Those fields persisted, redisplayed on reload, and were read
// by NOTHING. recordFailedLogin hardcoded 5 attempts / 15 minutes (twice — once
// for tenant users, once for platform users), admin-service hardcoded a 7-day
// session in four places, and the password floor was a literal `< 8`. An
// operator who set 3 attempts / 60 minutes / 14 characters was told "Security
// policy saved.", saw the values on reload, and got none of them.
//
// It lives in shared/ rather than in either service because BOTH auth-service
// and admin-service issue sessions and lock accounts. A policy enforced on one
// login path and not the other is not a policy — it is the same bug with a
// smaller blast radius.
//
// FAILURE BIAS. Every reader here falls back to the built-in default and clamps
// what it finds. This is deliberately the opposite of the signup toggles
// (signupEnabled, personalEmailBlocked), which fail OPEN because a settings
// hiccup must not wall off the only route into a self-hosted deployment. An
// authentication control that silently evaporates is a weakening, so these fail
// to the stricter answer instead.
//
// platform_settings is a global (non-RLS) table, so a plain *sql.DB is correct
// here; no app.tenant_id is needed and none is available on a login path anyway.
package authpolicy

import (
	"database/sql"
	"encoding/json"
	"time"
)

const (
	// DefaultMaxLoginAttempts and DefaultLockoutDuration are the values that were
	// hardcoded before the setting was wired up. They remain the behaviour of any
	// deployment whose operator has never saved the Policy page.
	DefaultMaxLoginAttempts = 5
	DefaultLockoutDuration  = 15 * time.Minute

	// Clamps. A max-attempts below 1 would lock an account over a request that has
	// not happened; the upper bounds keep a typo (600000 minutes) from turning a
	// temporary lockout into a permanent one.
	MinMaxLoginAttempts = 1
	MaxMaxLoginAttempts = 100
	MinLockoutDuration  = 1 * time.Minute
	MaxLockoutDuration  = 7 * 24 * time.Hour

	// Session clamps. The floor stops an operator configuring a session that
	// expires before the UI can use it.
	MinSessionLifetime = 5 * time.Minute
	MaxSessionLifetime = 90 * 24 * time.Hour
)

// settingInt reads one integer-valued platform_settings row. The second result
// is false for a missing row, a query error, or a value that is not a JSON
// number — every case in which the caller should keep its own default.
func settingInt(db *sql.DB, key string) (int, bool) {
	if db == nil {
		return 0, false
	}
	var raw []byte
	if err := db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = $1`, key).Scan(&raw); err != nil {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	return n, true
}

// LockoutPolicy is the failed-login lockout rule in force.
type LockoutPolicy struct {
	// MaxAttempts is the number of consecutive failures that triggers a lock.
	MaxAttempts int
	// Duration is how long the account then stays locked.
	Duration time.Duration
}

// Lockout resolves the failed-login lockout rule from
// platform_settings.max_login_attempts / .lockout_duration_minutes, falling back
// to the historical 5 attempts / 15 minutes.
//
// It is read per failed login rather than cached. Failed logins are rare and
// already rate-limited, and a cached security control that keeps enforcing a
// value the operator has since changed is its own version of this bug.
func Lockout(db *sql.DB) LockoutPolicy {
	p := LockoutPolicy{MaxAttempts: DefaultMaxLoginAttempts, Duration: DefaultLockoutDuration}
	if n, ok := settingInt(db, "max_login_attempts"); ok {
		p.MaxAttempts = clampInt(n, MinMaxLoginAttempts, MaxMaxLoginAttempts)
	}
	if n, ok := settingInt(db, "lockout_duration_minutes"); ok {
		p.Duration = clampDuration(time.Duration(n)*time.Minute, MinLockoutDuration, MaxLockoutDuration)
	}
	return p
}

// SessionLifetime returns how long a newly issued refresh token stays valid —
// the practical length of a session, since the refresh token is what keeps one
// alive and refresh_tokens.expires_at is checked on every rotation.
//
// It honours platform_settings.session_timeout_minutes ("Session timeout
// (minutes)" on the Policy page), falling back to the caller's own configured
// refresh expiry when the setting is absent or unusable.
//
// Note the semantics: rotation re-issues with a fresh expiry, so this is an IDLE
// timeout — a session ends after that long WITHOUT activity, not that long after
// sign-in. That is the ordinary meaning of "session timeout" in an admin console
// and what the field label claims.
func SessionLifetime(db *sql.DB, fallback time.Duration) time.Duration {
	n, ok := settingInt(db, "session_timeout_minutes")
	if !ok {
		return fallback
	}
	return clampDuration(time.Duration(n)*time.Minute, MinSessionLifetime, MaxSessionLifetime)
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampDuration(v, lo, hi time.Duration) time.Duration {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
