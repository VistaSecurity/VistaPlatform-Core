package main

// The record of a person's consent to scan outside their networks is a
// precondition of the scan, not a courtesy ( W5.13b): when it cannot be
// written, the job is cancelled before it is announced and the caller is told.
//
// Mutation: make auditExternalTargets' failure ignorable again (call it and drop
// the error in CreateJob) and the job is left queued, turning this red.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ExternalTargets_ScanIsNotStartedWhenTheAuditCannotBeWritten(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	gin.SetMode(gin.TestMode)

	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	user := uuid.New()
	if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, user, tenant, "scanner-"+user.String()[:8]+"@example.com"); err != nil {
		t.Fatal(err)
	}
	var role uuid.UUID
	if err := raw.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, 'scan_starter', 'Scan starter') RETURNING id`, tenant).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) SELECT $1, id FROM tenant_permissions WHERE name = 'discovery.create'`, role); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active) VALUES ($1, $2, $3, true)`, user, tenant, role); err != nil {
		t.Fatal(err)
	}

	h := handlers.NewDiscoveryHandler(services.NewDiscoveryService(db, db), services.NewRateLimiter(db), nil, nil)
	router := gin.New()
	router.Use(gin.Recovery())
	// The real discovery routes, with NO audit middleware on the context: the
	// state auditExternalTargets must treat as "cannot record".
	registerDiscoveryRoutes(router, h, raw, gateTestJWTSecret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/jobs",
		strings.NewReader(`{"targets":["93.184.216.34"],"external_targets_confirmed":true,"protocols":["TLS"],"ports":[443],"execution_mode":"auto"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+mintToken(t, user, tenant, "member"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusInternalServerError || body["error"] != "audit_unavailable" {
		t.Fatalf("status=%d body=%s, want 500 audit_unavailable", w.Code, w.Body.String())
	}
	var queued, cancelled int
	if err := raw.QueryRow(`SELECT count(*) FILTER (WHERE status = 'queued'), count(*) FILTER (WHERE status = 'cancelled') FROM discovery_jobs WHERE tenant_id = $1`, tenant).Scan(&queued, &cancelled); err != nil {
		t.Fatal(err)
	}
	if queued != 0 || cancelled != 1 {
		t.Fatalf("jobs queued=%d cancelled=%d, want the unaudited external scan cancelled and none queued", queued, cancelled)
	}
}
