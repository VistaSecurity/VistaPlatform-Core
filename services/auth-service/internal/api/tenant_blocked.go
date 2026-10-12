package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/shared/tenantstate"
)

// respondTenantBlocked writes the refusal for a session mint the tenant gate
// stopped (see auth.JWTService.SetTenantGate) and reports whether it did. The
// shape — 403 with a tenant_suspended / tenant_deleted code and a sentence the
// sign-in page shows verbatim — is the same one every JWT middleware answers
// with, so the web UI handles both from one place.
func respondTenantBlocked(c *gin.Context, err error) bool {
	be, ok := tenantstate.AsBlocked(err)
	if !ok {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": tenantstate.Message(be.Code), "code": be.Code})
	return true
}

// respondPlatformAccount answers the 403 for valid platform credentials (or a
// platform refresh token) presented at a tenant sign-in path: the
// platform_account_use_admin_console code, plus admin_url when the service
// knows the admin console's address so the UI can link to it.
func respondPlatformAccount(c *gin.Context, err error) bool {
	pe, ok := auth.AsPlatformAccount(err)
	if !ok {
		return false
	}
	body := gin.H{
		"error": "This is a platform account. Sign in at the admin console instead.",
		"code":  auth.PlatformAccountCode,
	}
	if pe.AdminURL != "" {
		body["admin_url"] = pe.AdminURL
	}
	c.JSON(http.StatusForbidden, body)
	return true
}
