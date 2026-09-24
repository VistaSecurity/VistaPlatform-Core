package main

// Retention policies through the REAL audit-service router against a real
// Postgres (security-staff-16, admin-ui review decision 14):
//
//   - a 0 or negative age, or a total shorter than the hot period, is a 400
//     that names the field, and nothing is written;
//   - a valid policy is stored and read back, with no cold_storage_days on the
//     wire and no cold_storage_days column in the table (schema.sql drops it
//     in POST-MIGRATIONS);
//   - an older console that still sends cold_storage_days is not refused.
//
// Skipped unless TEST_DATABASE_URL is set (make test-integration-db).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/database"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_RetentionPolicies_ValidatedAndColdTierGone_RealRouter(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		JWT:                config.JWTConfig{Secret: testJWTSecret},
		InternalAuthSecret: "test-internal-secret",
	}
	r := newRouter(cfg, &database.DB{DB: db}, newTestAuditMiddleware(t), routerHandlers{
		retention: handlers.NewRetentionHandler(services.NewRetentionService(db, db)),
	})
	role := testdb.NewPlatformRole(t, db, rbac.PermissionPlatformAudit, rbac.PermissionPlatformAuditManage)
	token := testdb.SignPlatformToken(t, testJWTSecret, testdb.NewPlatformUser(t, db, role), "platform_admin")

	name := "retention-it-" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM audit.retention_policies WHERE policy_name LIKE $1`, name+"%") })
	stored := func(policyName string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit.retention_policies WHERE policy_name = $1`, policyName).Scan(&n); err != nil {
			t.Fatalf("count policies: %v", err)
		}
		return n
	}
	send := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/v1/audit-service"+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	policy := func(n string, hot, total int, extra string) string {
		b, _ := json.Marshal(map[string]interface{}{"policy_name": n, "hot_storage_days": hot, "total_retention_days": total, "is_active": false})
		if extra != "" {
			return strings.TrimSuffix(string(b), "}") + "," + extra + "}"
		}
		return string(b)
	}

	t.Run("the column is gone from the table", func(t *testing.T) {
		var n int
		if err := db.QueryRow(`
			SELECT COUNT(*) FROM information_schema.columns
			WHERE table_schema = 'audit' AND table_name = 'retention_policies' AND column_name = 'cold_storage_days'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatal("audit.retention_policies still has cold_storage_days")
		}
	})

	for label, tc := range map[string]struct {
		hot, total int
		field      string
	}{
		"zero total":             {30, 0, "total_retention_days must be at least 1"},
		"negative hot":           {-1, 365, "hot_storage_days"},
		"total shorter than hot": {90, 30, "cannot be shorter"},
	} {
		t.Run("create refuses "+label, func(t *testing.T) {
			n := name + "-bad"
			w := send(http.MethodPost, "/retention-policies", policy(n, tc.hot, tc.total, ""))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.field) {
				t.Fatalf("status = %d, want 400 naming %q; body=%s", w.Code, tc.field, w.Body.String())
			}
			if stored(n) != 0 {
				t.Fatal("a refused policy was written")
			}
		})
	}

	var id string
	t.Run("a valid policy is stored and read back without a cold tier", func(t *testing.T) {
		w := send(http.MethodPost, "/retention-policies", policy(name, 30, 365, `"cold_storage_days":90`))
		if w.Code != http.StatusCreated {
			t.Fatalf("create status = %d, want 201; body=%s", w.Code, w.Body.String())
		}
		var out struct {
			Policy struct {
				ID string `json:"id"`
			} `json:"policy"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Policy.ID == "" {
			t.Fatalf("create response has no policy id: %s", w.Body.String())
		}
		id = out.Policy.ID
		w = send(http.MethodGet, "/retention-policies/"+id, "")
		if w.Code != http.StatusOK {
			t.Fatalf("get status = %d; body=%s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "cold_storage_days") {
			t.Fatalf("read-back still carries cold_storage_days: %s", w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"total_retention_days":365`) {
			t.Fatalf("read-back lost the stored ages: %s", w.Body.String())
		}
	})

	t.Run("update refuses a zero hot period and leaves the stored policy alone", func(t *testing.T) {
		if id == "" {
			t.Skip("no policy from the create subtest")
		}
		w := send(http.MethodPut, "/retention-policies/"+id, policy(name, 0, 365, ""))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "hot_storage_days") {
			t.Fatalf("status = %d, want 400 naming hot_storage_days; body=%s", w.Code, w.Body.String())
		}
		var hot int
		if err := db.QueryRow(`SELECT hot_storage_days FROM audit.retention_policies WHERE id = $1`, id).Scan(&hot); err != nil || hot != 30 {
			t.Fatalf("stored hot_storage_days = %d (err %v), want 30 unchanged", hot, err)
		}
	})
}
