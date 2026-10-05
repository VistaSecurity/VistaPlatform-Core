package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// (H4): the scanner expands at most MaxTargetAddresses hosts per target
// and used to drop the rest silently, so a /19 was scanned as its first /20 and
// the job still ended "completed". This drives the REAL CreateJob handler: a
// target the scanner cannot fully expand is refused with a coded 422 that names
// the numbers, and an in-limit target is still accepted.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).
func TestIntegration_CreateJob_RefusesTargetsTheScannerCannotExpand(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sqlDB := testdb.Connect(t)
	db := sqlx.NewDb(sqlDB, "postgres")
	tenant := testdb.NewTenant(t, db.DB)
	user := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, user, tenant, user.String()+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	h := NewDiscoveryHandler(services.NewDiscoveryService(db, db), services.NewRateLimiter(db), nil, nil)
	r := gin.New()
	r.POST("/jobs", func(c *gin.Context) {
		c.Set(sharedmw.CtxKeyTenantID, tenant)
		c.Set("userID", user.String())
		h.CreateJob(c)
	})
	post := func(targets ...string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]interface{}{
			"targets": targets, "protocols": []string{"TLS"}, "ports": []int{443}, "execution_mode": "auto",
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewReader(body)))
		return w
	}

	// A /19 is 8192 addresses against a 4096 limit.
	w := post("10.20.0.0/19")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("/19 = %d (%s), want 422", w.Code, w.Body)
	}
	var refused struct {
		Error           string                      `json:"error"`
		Message         string                      `json:"message"`
		OversizeTargets []shareddisc.OversizeTarget `json:"oversize_targets"`
		TargetLimit     uint64                      `json:"target_limit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &refused); err != nil {
		t.Fatal(err)
	}
	if refused.Error != shareddisc.CodeScanTargetTooLarge || refused.TargetLimit != 4096 ||
		len(refused.OversizeTargets) != 1 || refused.OversizeTargets[0].Target != "10.20.0.0/19" || refused.OversizeTargets[0].Addresses != "8192" {
		t.Fatalf("refusal does not name the numbers: %+v", refused)
	}

	// Together over the job limit although each target is in limit.
	w = post("10.0.0.0/20", "10.1.0.0/20", "10.2.0.0/20", "10.3.0.0/20", "10.4.0.0/24")
	var total struct {
		Error        string `json:"error"`
		JobAddresses string `json:"job_addresses"`
		JobLimit     uint64 `json:"job_limit"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &total)
	if w.Code != http.StatusUnprocessableEntity || total.Error != shareddisc.CodeScanTargetTooLarge || total.JobAddresses != "16640" || total.JobLimit != 16384 {
		t.Fatalf("job total = %d %s", w.Code, w.Body)
	}

	// The other polarity: an in-limit target (a /24, and a /20 exactly at the limit) is accepted.
	for _, ok := range []string{"10.20.1.0/24", "10.30.0.0/20"} {
		if w := post(ok); w.Code != http.StatusAccepted {
			t.Fatalf("%s = %d (%s), want 202", ok, w.Code, w.Body)
		}
	}
}
