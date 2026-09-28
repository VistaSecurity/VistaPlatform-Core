package api

// Device-agent registration is the unauthenticated bootstrap, mounted ahead of
// the auth middleware: unless the handler records the tenant the registration
// key belongs to, the audit middleware logs every registration with no tenant
//. The audit middleware reads the context after c.Next(); the capture
// here does the same. Delete the c.Set in registerAgentPublicHandler and this
// fails.
//
// Skips without TEST_DATABASE_URL (make test-integration-db / nightly).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AgentRegister_RecordsTheKeysTenantForAudit(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	key := "REG-" + uuid.NewString()
	if _, err := owner.Exec(`
		INSERT INTO pending_sensor_registrations
		       (tenant_id, registration_key, name, ip_address, profile, status, expires_at)
		VALUES ($1,$2,'audit-agent','192.0.2.21','device_interrogation','pending',$3)`,
		tenant, key, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(`DELETE FROM device_agents WHERE registration_key = $1`, key)
		_, _ = owner.Exec(`DELETE FROM pending_sensor_registrations WHERE registration_key = $1`, key)
	})

	// The handler loads the service config, which requires this; production
	// refuses to start without it.
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-key-for-route-registration-only")
	gin.SetMode(gin.TestMode)
	var seen any
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Next()
		seen, _ = c.Get("tenantID")
	})
	r.POST("/agents/register", registerAgentPublicHandler(app, owner, nil))

	req := httptest.NewRequest(http.MethodPost, "/agents/register",
		strings.NewReader(`{"registration_key":"`+key+`","platform":"linux","version":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code >= 300 {
		t.Fatalf("registration: %d %s", w.Code, w.Body.String())
	}
	if got, _ := seen.(uuid.UUID); got != tenant {
		t.Fatalf("tenantID in the audit context = %v, want the registration key's tenant %s", seen, tenant)
	}
}
