package main

// SECURITY: a global alert rule (tenant_id IS NULL) is visible to every tenant,
// so it is the platform's. A tenant admin holding audit.manage must be able to
// read it, must NOT be able to edit or delete it (that rewrites what every
// other tenant is shown), and must still manage the rules their own tenant
// owns. Drives the real router (newRouter) with the real handlers, the real
// user_has_permission() and a real Postgres. Skipped unless TEST_DATABASE_URL
// is set (make test-integration-db).
//
// Mutation record: admitting a nil owner in tenantMayModifyAlertRule turns this
// red. The service predicate is pinned separately, below the handler, by
// internal/services/alert_rule_scope_integration_test.go; with both layers
// reverted this test shows the original defect (a tenant admin deleting a
// platform-wide rule with a 200).

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func auditTenantAdmin(t *testing.T, db *sql.DB, tenant uuid.UUID, perms ...string) uuid.UUID {
	t.Helper()
	user := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		user, tenant, "rule-admin-"+user.String()[:8]+"@example.test"); err != nil {
		t.Fatal(err)
	}
	var role uuid.UUID
	if err := db.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, $2) RETURNING id`,
		tenant, "rule-admin-"+user.String()[:8]).Scan(&role); err != nil {
		t.Fatal(err)
	}
	for _, p := range perms {
		if res, err := db.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) SELECT $1, id FROM tenant_permissions WHERE name = $2`, role, p); err != nil {
			t.Fatal(err)
		} else if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("permission %q is not in the seeded catalogue", p)
		}
	}
	if _, err := db.Exec(`INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active) VALUES ($1, $2, $3, true)`, user, tenant, role); err != nil {
		t.Fatal(err)
	}
	return user
}

func seedAlertRule(t *testing.T, db *sql.DB, tenant *uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO audit.alert_rules (id, tenant_id, name, description, rule_type, is_enabled, severity, conditions, actions, created_by)
		VALUES ($1, $2, $3, 'probe', 'threshold', true, 'high', '{}', '{}', $4)`, id, tenant, name, uuid.New()); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM audit.alert_rules WHERE id = $1`, id) })
	return id
}

func TestIntegration_AlertRules_TenantCannotModifyGlobalRules(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("REDIS_URL", "")
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: testJWTSecret}, InternalAuthSecret: "test-internal-secret"}
	r := newRouter(cfg, &database.DB{DB: db}, newTestAuditMiddleware(t), coreRouterHandlers(db))

	tenantA := testdb.NewTenant(t, db)
	tenantB := testdb.NewTenant(t, db)
	admin := auditTenantAdmin(t, db, tenantA, "audit.read", "audit.manage")

	global := seedAlertRule(t, db, nil, "platform-wide rule")
	own := seedAlertRule(t, db, &tenantA, "tenant A rule")
	foreign := seedAlertRule(t, db, &tenantB, "tenant B rule")

	call := func(method string, id uuid.UUID, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/audit-service/alert-rules/"+id.String(), bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+testdb.SignTenantToken(t, testJWTSecret, admin, tenantA, "tenant_admin"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	name := func(id uuid.UUID) (string, bool) {
		var n string
		err := db.QueryRow(`SELECT name FROM audit.alert_rules WHERE id = $1`, id).Scan(&n)
		return n, err == nil
	}

	// A tenant can still SEE the global rule (reads union it in) ...
	if w := call(http.MethodGet, global, ""); w.Code != http.StatusOK {
		t.Fatalf("GET global rule = %d %s; tenants must still be able to read platform rules", w.Code, w.Body.String())
	}
	// ... but not rewrite or delete it, and not touch another tenant's.
	for label, id := range map[string]uuid.UUID{"global rule": global, "another tenant's rule": foreign} {
		if w := call(http.MethodPut, id, `{"name":"HIJACKED"}`); w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			t.Errorf("PUT %s = %d %s; want 403/404", label, w.Code, w.Body.String())
		}
		if w := call(http.MethodDelete, id, ""); w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			t.Errorf("DELETE %s = %d %s; want 403/404", label, w.Code, w.Body.String())
		}
		if n, ok := name(id); !ok || strings.Contains(n, "HIJACKED") {
			t.Errorf("%s was modified or deleted by a tenant admin (name=%q exists=%v)", label, n, ok)
		}
	}

	// The tenant's OWN rule is still theirs to edit and delete.
	if w := call(http.MethodPut, own, `{"name":"renamed by owner"}`); w.Code != http.StatusOK {
		t.Fatalf("PUT own rule = %d %s; want 200", w.Code, w.Body.String())
	}
	if n, _ := name(own); n != "renamed by owner" {
		t.Errorf("own rule name = %q after a 200 PUT", n)
	}
	if w := call(http.MethodDelete, own, ""); w.Code != http.StatusOK {
		t.Fatalf("DELETE own rule = %d %s; want 200", w.Code, w.Body.String())
	}
}
