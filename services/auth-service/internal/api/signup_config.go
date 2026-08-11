package api

// Self-service signup gate. Signup is the ONLY tenant-onboarding path
// (the admin tenant-create was removed in), so this toggle is the single
// switch that closes the platform's front door. Platform admins flip it in
// admin-ui Settings → Access (platform_settings.registration_enabled);
// default is enabled. The public /platform/config endpoint mirrors the flag
// as signup_enabled so the /signup page knows whether to render the form.

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

// signupEnabled reads platform_settings.registration_enabled. Missing row,
// unreadable value, or query error all mean enabled — the gate fails open so
// a settings hiccup can't silently close signups.
func signupEnabled(db *sql.DB) bool {
	if db == nil {
		return true
	}
	var raw []byte
	if err := db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = 'registration_enabled'`).Scan(&raw); err != nil {
		return true
	}
	var enabled bool
	if err := json.Unmarshal(raw, &enabled); err != nil {
		return true
	}
	return enabled
}

// rejectIfSignupDisabled writes the 403 and reports whether it did. Handlers
// on every registration path (password + social) call this first.
func rejectIfSignupDisabled(c *gin.Context, db *sql.DB) bool {
	if signupEnabled(db) {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "Self-service sign-up is disabled on this platform. Contact your platform operator for access."})
	return true
}
