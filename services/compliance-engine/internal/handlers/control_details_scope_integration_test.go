package handlers

// GetControlDetails through the real handler and the real service, on a real
// database:
//
//   - tenant_framework_controls has no tenant_id and no RLS policy (only its
//     parent tenant_frameworks does), so a plain "WHERE id = $1" let any tenant
//     that knew another tenant's custom-control UUID read its title,
//     description and severity. A foreign id must read exactly like a missing one.
//   - the findings page is cut in SQL (LIMIT/OFFSET), with the total from an
//     aggregate, rather than loading every finding and slicing in Go.
//   - malformed page/page_size is a 400, not a silent fall back to page 1.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedCustomControl gives the tenant a custom policy with one control.
func seedCustomControl(t *testing.T, raw *sql.DB, tenant uuid.UUID, code, title string) (frameworkID, controlID uuid.UUID) {
	t.Helper()
	frameworkID, controlID = uuid.New(), uuid.New()
	if _, err := raw.Exec(`INSERT INTO tenant_frameworks (id, tenant_id, name, version) VALUES ($1, $2, $3, '1.0')`,
		frameworkID, tenant, "Custom "+code); err != nil {
		t.Fatalf("seed tenant framework: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO tenant_framework_controls (id, framework_id, control_id, title, description, baseline_severity)
		VALUES ($1, $2, $3, $4, 'secret description', 'high')`, controlID, frameworkID, code, title); err != nil {
		t.Fatalf("seed tenant control: %v", err)
	}
	t.Cleanup(func() {
		_, _ = raw.Exec(`DELETE FROM findings WHERE control_id = $1`, controlID)
		_, _ = raw.Exec(`DELETE FROM tenant_framework_controls WHERE id = $1`, controlID)
		_, _ = raw.Exec(`DELETE FROM tenant_frameworks WHERE id = $1`, frameworkID)
	})
	return frameworkID, controlID
}

// controlDetailsRouter mounts the real handler on the production path, with the
// caller's tenant set the way the auth middleware does.
func controlDetailsRouter(t *testing.T, db *sqlx.DB, tenant uuid.UUID) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := NewWorkspaceHandlers(services.NewEvaluationService(db), nil, nil, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(sharedmw.CtxKeyTenantID, tenant); c.Next() })
	r.GET("/api/v1/compliance-engine/controls/:id", h.GetControlDetails)
	return r
}

func getControl(r *gin.Engine, id, query string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance-engine/controls/"+id+query, nil)
	r.ServeHTTP(w, req)
	return w
}

func TestIntegration_ControlDetails_ForeignTenantControlIsNotFound(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenantA, tenantB := testdb.NewTenant(t, raw), testdb.NewTenant(t, raw)
	_, controlB := seedCustomControl(t, raw, tenantB, "SECRET-B1", "Tenant B private policy")

	// The owner reads it.
	if w := getControl(controlDetailsRouter(t, db, tenantB), controlB.String(), ""); w.Code != http.StatusOK {
		t.Fatalf("owner GET own control: %d %s, want 200", w.Code, w.Body)
	}

	// Another tenant that knows the UUID does not.
	w := getControl(controlDetailsRouter(t, db, tenantA), controlB.String(), "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("tenant A GET tenant B's control by id: %d %s, want 404", w.Code, w.Body)
	}
	for _, leak := range []string{"Tenant B private policy", "secret description"} {
		if body := w.Body.String(); strings.Contains(body, leak) {
			t.Errorf("404 body leaks %q: %s", leak, body)
		}
	}

	// Nor can it resolve it by its string code.
	if w := getControl(controlDetailsRouter(t, db, tenantA), "SECRET-B1", ""); w.Code == http.StatusOK {
		t.Fatalf("tenant A resolved tenant B's control code: %d %s", w.Code, w.Body)
	}
	// The owner can.
	if w := getControl(controlDetailsRouter(t, db, tenantB), "SECRET-B1", ""); w.Code != http.StatusOK {
		t.Fatalf("owner resolve own code: %d %s, want 200", w.Code, w.Body)
	}
}

func TestIntegration_ControlDetails_PagedInSQL(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	_, control := seedCustomControl(t, raw, tenant, "PG-1", "Paged control")

	const n = 250
	base := time.Now().Add(-24 * time.Hour)
	for i := 1; i <= n; i++ {
		// finding-001 is the newest; the page order is last_seen DESC.
		if _, err := raw.Exec(`
			INSERT INTO findings (id, tenant_id, producer, kind, control_id, subject_id, subject_type, severity, summary,
			                      detection_state, workflow_status, first_seen, last_seen)
			VALUES ($1, $2, 'compliance', 'control_noncompliant', $3, $4, 'certificate', 'low', $5, 'ACTIVE', 'NEW', $6, $6)`,
			uuid.New(), tenant, control, uuid.New(), fmt.Sprintf("finding-%03d", i), base.Add(-time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("seed finding %d: %v", i, err)
		}
	}
	r := controlDetailsRouter(t, db, tenant)

	type page struct {
		Findings []struct {
			Summary string `json:"summary"`
		} `json:"findings"`
		Evidence struct {
			Failing  int `json:"failing_findings_count"`
			Affected int `json:"affected_assets_count"`
		} `json:"evidence_summary"`
		Pagination struct {
			Page     int `json:"page"`
			PageSize int `json:"page_size"`
			Total    int `json:"total"`
		} `json:"pagination"`
	}
	read := func(q string) page {
		t.Helper()
		w := getControl(r, control.String(), q)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", q, w.Code, w.Body)
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	p2 := read("?page=2&page_size=100")
	if len(p2.Findings) != 100 {
		t.Fatalf("page 2 of 100 returned %d rows, want 100", len(p2.Findings))
	}
	if p2.Findings[0].Summary != "finding-101" || p2.Findings[99].Summary != "finding-200" {
		t.Fatalf("page 2 is %s..%s, want finding-101..finding-200", p2.Findings[0].Summary, p2.Findings[99].Summary)
	}
	if p2.Pagination.Total != n || p2.Evidence.Failing != n || p2.Evidence.Affected != n {
		t.Fatalf("total=%d failing=%d affected=%d, want %d each", p2.Pagination.Total, p2.Evidence.Failing, p2.Evidence.Affected, n)
	}
	// The last page is short, and an out-of-range page is empty with the total intact.
	if p3 := read("?page=3&page_size=100"); len(p3.Findings) != 50 || p3.Pagination.Total != n {
		t.Fatalf("page 3: %d rows, total %d; want 50 rows, total %d", len(p3.Findings), p3.Pagination.Total, n)
	}
	if p9 := read("?page=9&page_size=100"); len(p9.Findings) != 0 || p9.Pagination.Total != n {
		t.Fatalf("page 9: %d rows, total %d; want 0 rows, total %d", len(p9.Findings), p9.Pagination.Total, n)
	}

	for _, q := range []string{"?page=abc", "?page_size=xyz", "?page=0", "?page_size=-5"} {
		if w := getControl(r, control.String(), q); w.Code != http.StatusBadRequest {
			t.Errorf("GET %s: %d, want 400", q, w.Code)
		}
	}
}
