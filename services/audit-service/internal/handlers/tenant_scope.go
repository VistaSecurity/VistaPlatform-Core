package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/middleware"
)

// byIDTenantScope returns the tenant a by-id lookup/mutation must be constrained
// to: the caller's own tenant for tenant users, or nil for platform users (who
// may legitimately operate cross-tenant). When ok is false a 403 has already
// been written and the handler must return.
//
// Closes the by-id IDOR class from the RBAC audit: handlers
// that resolve a row by id alone otherwise read or mutate other tenants' rows.
// Services apply the scope as `AND tenant_id = $N` only when it is non-nil.
func byIDTenantScope(c *gin.Context) (*uuid.UUID, bool) {
	if middleware.GetUserType(c) == middleware.UserTypeTenant {
		t := middleware.GetTenantID(c)
		if t == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return nil, false
		}
		return t, true
	}
	return nil, true // platform user: unrestricted
}
