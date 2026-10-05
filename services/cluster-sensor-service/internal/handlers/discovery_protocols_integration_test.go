package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_DiscoveryHandler_CreateJob_RefusesOTProtocolsField drives the
// REAL handler and service (H6 of): an OT name in `protocols` is a 400
// validation_error that names the allowed values and points at
// ot_probe_protocols, and no job row is created; TLS/SSH is accepted.
func TestIntegration_DiscoveryHandler_CreateJob_RefusesOTProtocolsField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sqlDB := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, sqlDB)
	db := sqlx.NewDb(sqlDB, "postgres")
	tenant := testdb.NewTenant(t, sqlDB)

	h := NewDiscoveryHandler(services.NewDiscoveryService(db, db), services.NewRateLimiter(db), nil, nil)
	engine := gin.New()
	engine.POST("/jobs", func(c *gin.Context) {
		c.Set(sharedmw.CtxKeyTenantID, tenant)
		c.Set("userID", "system")
		h.CreateJob(c)
	})
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewBufferString(body)))
		return w
	}
	jobs := func() int {
		var n int
		if err := sqlDB.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id=$1`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	w := post(`{"targets":["10.183.0.10"],"execution_mode":"auto","protocols":["TLS","Modbus"],"ports":[443,502]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	var parsed struct {
		Error   string `json:"error"`
		Details string `json:"details"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if parsed.Error != "validation_error" || !strings.Contains(parsed.Details, "ot_probe_protocols") || !strings.Contains(parsed.Details, "TLS, SSH, SMB") {
		t.Errorf("body = %s, want validation_error naming the allowed values and ot_probe_protocols", w.Body.String())
	}
	if n := jobs(); n != 0 {
		t.Fatalf("a refused request left %d job row(s)", n)
	}

	w = post(`{"targets":["10.183.0.10"],"execution_mode":"auto","protocols":["TLS","SSH"],"ports":[443,22]}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("[TLS SSH] status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	if n := jobs(); n != 1 {
		t.Fatalf("job rows = %d, want 1", n)
	}
}
