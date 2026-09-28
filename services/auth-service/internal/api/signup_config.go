package api

// Self-service signup gate. Signup is the ONLY tenant-onboarding
// path on Core and Enterprise (tenant creation is the MSP management plane), so
// this is the switch on the platform's front door. The rule lives in
// shared/entitlements (signup_gate.go): an explicit operator choice in
// admin-ui Settings → Access wins; with none, MSP is open, and Core and
// Enterprise are open only until the install's first tenant exists. The public
// /platform/config endpoint mirrors the answer as signup_enabled so the
// /signup page knows whether to render the form.

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// signupEnabled reports whether sign-up is open right now. It fails CLOSED: a
// read error means no new tenant. The transaction that creates the tenant
// re-decides under a lock (entitlements.AdmitSignupTenant); this early check
// only saves a refused visitor the rest of the handler.
func signupEnabled(db *sql.DB) bool {
	if db == nil {
		// No database wired (handler unit harnesses). Nothing can be created
		// without one, and AdmitSignupTenant in the tenant transaction is the
		// check that holds, so the early refusal has nothing to add here.
		return true
	}
	open, err := entitlements.SignupOpen(context.Background(), db, time.Now())
	if err != nil {
		logrus.WithError(err).Warn("Sign-up gate could not be evaluated; refusing sign-up")
		return false
	}
	return open
}

// rejectIfSignupDisabled writes the 403 and reports whether it did. Handlers
// on every registration path (password + social) call this first.
func rejectIfSignupDisabled(c *gin.Context, db *sql.DB) bool {
	if signupEnabled(db) {
		return false
	}
	respondSignupClosed(c)
	return true
}

// respondSignupClosed is the refusal every sign-up path returns, whether the
// early check or the in-transaction admission refused it.
func respondSignupClosed(c *gin.Context) {
	c.JSON(http.StatusForbidden, gin.H{"error": entitlements.SignupClosedPublicMessage})
}

// RespondSignupClosed lets the Enterprise social-signup path return the same
// refusal when tenant creation is refused by the gate.
func RespondSignupClosed(c *gin.Context) { respondSignupClosed(c) }
