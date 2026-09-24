package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
