package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// expectLiveAgentTenant queues the tenant-state read AgentAuth performs after
// authenticating an agent (RC-4 /) and answers "active, not deleted".
func expectLiveAgentTenant(mock sqlmock.Sqlmock, tenantID uuid.UUID) {
	expectAgentTenantState(mock, tenantID, "active", false)
}

func expectAgentTenantState(mock sqlmock.Sqlmock, tenantID uuid.UUID, status string, deleted bool) {
	mock.ExpectQuery(`FROM tenants WHERE id = \$1`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"payment_status", "deleted", "session_version"}).AddRow(status, deleted, 0))
}

// TestAgentAuth_RefusesAgentsOfBlockedTenants — a device agent of a suspended,
// canceled or deleted tenant is turned away with 403 and a machine-readable
// code (so the agent logs a clear reason and keeps its normal retry loop), and
// the job handler never runs. Mutation: delete the EnforceTenantState call at
// the end of AgentAuth and every blocked case reaches the handler (200).
func TestAgentAuth_RefusesAgentsOfBlockedTenants(t *testing.T) {
	cases := []struct {
		status   string
		deleted  bool
		wantCode string
	}{
		{"suspended", false, "tenant_suspended"},
		{"canceled", false, "tenant_suspended"},
		{"active", true, "tenant_deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.wantCode+"/"+tc.status, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			agentID, tenantID := uuid.New(), uuid.New()
			mock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
				WithArgs(agentID).
				WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
			expectAgentTenantState(mock, tenantID, tc.status, tc.deleted)

			reached := false
			r := gin.New()
			g := r.Group("/agents")
			g.Use(AgentAuth(db, db, false))
			g.GET("/:id/jobs", func(c *gin.Context) { reached = true; c.Status(http.StatusOK) })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/agents/"+agentID.String()+"/jobs", nil))
			var body struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != http.StatusForbidden || body.Code != tc.wantCode || reached {
				t.Fatalf("status=%d code=%q reached=%v, want 403 %q and the handler not run; body=%s",
					w.Code, body.Code, reached, tc.wantCode, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
