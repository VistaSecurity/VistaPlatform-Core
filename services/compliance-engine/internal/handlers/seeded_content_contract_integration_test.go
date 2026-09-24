package handlers

// Contract: the seeded-content fields and the three accept-update routes
// (decision 4, RC-12) against api/openapi/compliance-engine.openapi.yaml.
//
// The admin framework handlers sit on the concrete, database-backed
// PlatformFrameworkService, so this contract test needs a database: a scratch
// one holding an offer on a framework, a control and a measurement rule. Named
// TestIntegration_Contract_* so both the contract run (-run Contract) and the
// integration runner pick it up; it skips without TEST_DATABASE_URL.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Contract_SeededContentAccept(t *testing.T) {
	scratch := testdb.ScratchDatabase(t)
	sv := loadSpec(t)

	mustExec := func(q string) {
		t.Helper()
		if _, err := scratch.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// The admin's edits.
	mustExec(`UPDATE platform_frameworks SET status = 'archived' WHERE code = 'pqc-readiness'`)
	mustExec(`UPDATE platform_framework_controls SET title = 'Contract title' WHERE control_id = 'BP-001'`)
	mustExec(`UPDATE control_measurements cm SET weight = 3 FROM platform_framework_controls c
		WHERE c.id = cm.control_id AND c.control_id = 'BP-003' AND cm.framework_type = 'platform'`)

	// A later release: new shipped framework description and control title
	// (through the seed), and a corrected measurement weight (the shape of the
	// seed's correction UPDATEs, run in a seed pass).
	body, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts", "database", "seed.sql"))
	if err != nil {
		t.Fatal(err)
	}
	next := string(body)
	for _, r := range [][2]string{
		{"'TLS Version Requirements',", "'TLS Version Requirements (v2)',"},
		{"'Tracks post-quantum exposure across certificates AND crypto-configurations.", "'Tracks post-quantum exposure (v2) across certificates AND crypto-configurations."},
	} {
		if strings.Count(next, r[0]) != 1 {
			t.Fatalf("fixture %q occurs %d times in seed.sql, want 1", r[0], strings.Count(next, r[0]))
		}
		next = strings.Replace(next, r[0], r[1], 1)
	}
	mustExec(next)
	conn, err := scratch.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SET vista.seed_apply = on`,
		`UPDATE control_measurements cm SET weight = 9 FROM platform_framework_controls c
		  WHERE c.id = cm.control_id AND c.control_id = 'BP-003' AND cm.framework_type = 'platform'`,
		`RESET vista.seed_apply`,
	} {
		if _, err := conn.ExecContext(t.Context(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = conn.Close()

	var pqcID, bpID, bp001, bp003, ruleID uuid.UUID
	if err := scratch.QueryRow(`SELECT id FROM platform_frameworks WHERE code = 'pqc-readiness'`).Scan(&pqcID); err != nil {
		t.Fatal(err)
	}
	if err := scratch.QueryRow(`SELECT framework_id, id FROM platform_framework_controls WHERE control_id = 'BP-001'`).Scan(&bpID, &bp001); err != nil {
		t.Fatal(err)
	}
	if err := scratch.QueryRow(`SELECT c.id, cm.id FROM control_measurements cm JOIN platform_framework_controls c ON c.id = cm.control_id
		WHERE c.control_id = 'BP-003' AND cm.framework_type = 'platform' LIMIT 1`).Scan(&bp003, &ruleID); err != nil {
		t.Fatal(err)
	}

	h := NewPlatformFrameworkHandlers(services.NewPlatformFrameworkService(sqlx.NewDb(scratch, "postgres")))
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/admin")
	g.GET("/frameworks", h.ListFrameworks)
	g.GET("/frameworks/:id", h.GetFramework)
	g.POST("/frameworks/:id/accept-update", h.AcceptFrameworkUpdate)
	g.POST("/frameworks/:id/controls/:controlId/accept-update", h.AcceptControlUpdate)
	g.GET("/controls/:id/measurements", h.ListControlMeasurements)
	g.POST("/controls/:id/measurements/:measurementId/accept-update", h.AcceptMeasurementUpdate)
	do := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	want := func(w *httptest.ResponseRecorder, code int, schema, mustContain string) {
		t.Helper()
		if w.Code != code {
			t.Fatalf("status %d, want %d: %s", w.Code, code, w.Body)
		}
		if schema != "" {
			sv.assertConforms(t, schema, w.Body.Bytes())
		}
		if mustContain != "" && !strings.Contains(w.Body.String(), mustContain) {
			t.Errorf("response lacks %s: %s", mustContain, w.Body)
		}
	}

	// Reads carry the seeded-content fields, and they conform.
	want(do(http.MethodGet, "/admin/frameworks"), http.StatusOK, "AdminFrameworkListResponse", `"content_origin":"vista"`)
	want(do(http.MethodGet, "/admin/frameworks/"+bpID.String()), http.StatusOK, "AdminFrameworkResponse", `"update_available":true`)
	want(do(http.MethodGet, "/admin/controls/"+bp003.String()+"/measurements"), http.StatusOK, "MeasurementListResponse", `"offered_update":{"weight":9}`)

	// Accepts, one per entity.
	want(do(http.MethodPost, "/admin/frameworks/"+pqcID.String()+"/accept-update"), http.StatusOK, "AdminFrameworkResponse", `(v2)`)
	want(do(http.MethodPost, "/admin/frameworks/"+bpID.String()+"/controls/"+bp001.String()+"/accept-update"), http.StatusOK, "AdminControlResponse", `"title":"TLS Version Requirements (v2)"`)
	want(do(http.MethodPost, "/admin/controls/"+bp003.String()+"/measurements/"+ruleID.String()+"/accept-update"), http.StatusOK, "AdminMeasurementResponse", `"weight":9`)

	// Nothing left to accept, a wrong parent, and a malformed id.
	want(do(http.MethodPost, "/admin/frameworks/"+pqcID.String()+"/accept-update"), http.StatusConflict, "", "No update available")
	want(do(http.MethodPost, "/admin/controls/"+uuid.NewString()+"/measurements/"+ruleID.String()+"/accept-update"), http.StatusNotFound, "", "")
	want(do(http.MethodPost, "/admin/frameworks/not-a-uuid/accept-update"), http.StatusBadRequest, "", "")

	// The archive the admin chose is still in force after accepting the new
	// description: accepting offers never republishes.
	var status string
	if err := scratch.QueryRow(`SELECT status FROM platform_frameworks WHERE id = $1`, pqcID).Scan(&status); err != nil || status != "archived" {
		t.Errorf("pqc-readiness status after accept = %q (%v), want archived", status, err)
	}
}
