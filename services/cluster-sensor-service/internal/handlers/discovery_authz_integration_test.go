package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedDiscoveryJob inserts a minimal queued discovery job for a tenant and returns
// its id. discovery_jobs.execution_mode is NOT NULL; everything else has defaults.
func seedDiscoveryJob(t *testing.T, db *sqlx.DB, tenantID uuid.UUID) string {
	t.Helper()
	id := uuid.New().String()
	// created_by is scanned into a non-nullable string by DiscoveryService.GetJob
	// and carries an FK to users(id), so seed a user in the tenant and reference it.
	creator := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		creator, tenantID, creator.String()+"@example.test",
	); err != nil {
		t.Fatalf("seed user for tenant %s: %v", tenantID, err)
	}
	_, err := db.Exec(
		`INSERT INTO discovery_jobs (id, tenant_id, created_by, execution_mode, status) VALUES ($1, $2, $3, 'passive', 'queued')`,
		id, tenantID, creator,
	)
	if err != nil {
		t.Fatalf("seedDiscoveryJob(tenant %s): %v", tenantID, err)
	}
	return id
}

// newTestContext builds a gin context carrying tenantID in the context (as the
// RequireTenant middleware would) and the :id route param, plus a recorder.
func newTestContext(tenantID uuid.UUID, jobID string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Set(sharedmw.CtxKeyTenantID, tenantID)
	c.Params = gin.Params{{Key: "id", Value: jobID}}
	return c, w
}

// TestIntegration_DiscoveryHandler_GetJob_CrossTenantBlocked proves the fix
// on the cluster-sensor by-id discovery routes: DiscoveryService.GetJob runs on the
// BYPASSRLS role (it is shared with the tenant-agnostic NATS job_processor), so a
// tenant user requesting another tenant's job by id would receive it unless the
// handler enforces ownership. The fix compares the row's tenant_id to the caller's
// JWT tenant and returns 404 on a mismatch. This exercises that against a real DB.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).
func TestIntegration_DiscoveryHandler_GetJob_CrossTenantBlocked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sqlDB := testdb.Connect(t)
	db := sqlx.NewDb(sqlDB, "postgres")

	tenantA := testdb.NewTenant(t, db.DB)
	tenantB := testdb.NewTenant(t, db.DB)
	jobA := seedDiscoveryJob(t, db, tenantA)

	// discoveryService is the only dependency authorizeJob/GetJob touches.
	h := NewDiscoveryHandler(services.NewDiscoveryService(db, db), nil, nil, nil)

	// Owner (tenant A) gets 200.
	cOwner, wOwner := newTestContext(tenantA, jobA)
	h.GetJob(cOwner)
	if wOwner.Code != http.StatusOK {
		t.Fatalf("GetJob as owner tenant = %d, want 200", wOwner.Code)
	}

	// Foreign tenant (tenant B) requesting tenant A's job gets 404 — never the row.
	cForeign, wForeign := newTestContext(tenantB, jobA)
	h.GetJob(cForeign)
	if wForeign.Code != http.StatusNotFound {
		t.Fatalf("GetJob as foreign tenant = %d, want 404 (cross-tenant read leaked)", wForeign.Code)
	}
}
