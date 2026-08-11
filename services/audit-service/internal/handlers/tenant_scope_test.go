package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/middleware"
)

// Regression for (by-id IDOR): byIDTenantScope must constrain tenant users
// to their own tenant, leave platform users unrestricted, and reject a tenant
// user with no tenant context.
func TestByIDTenantScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tid := uuid.New()

	run := func(setup func(c *gin.Context)) (*uuid.UUID, bool, int) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		setup(c)
		scope, ok := byIDTenantScope(c)
		return scope, ok, w.Code
	}

	// tenant user → scoped to their own tenant
	if scope, ok, _ := run(func(c *gin.Context) {
		c.Set("userType", middleware.UserTypeTenant)
		c.Set("tenantID", tid.String())
	}); !ok || scope == nil || *scope != tid {
		t.Fatalf("tenant user: scope=%v ok=%v, want %v/true", scope, ok, tid)
	}

	// platform user → unrestricted (nil scope, ok)
	if scope, ok, _ := run(func(c *gin.Context) {
		c.Set("userType", "platform")
	}); !ok || scope != nil {
		t.Fatalf("platform user: scope=%v ok=%v, want nil/true", scope, ok)
	}

	// tenant user with no tenant context → 403, ok=false
	if scope, ok, code := run(func(c *gin.Context) {
		c.Set("userType", middleware.UserTypeTenant)
	}); ok || scope != nil || code != http.StatusForbidden {
		t.Fatalf("tenant user w/o tenant: scope=%v ok=%v code=%d, want nil/false/403", scope, ok, code)
	}
}
