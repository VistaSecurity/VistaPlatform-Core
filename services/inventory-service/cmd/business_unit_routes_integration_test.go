package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The five routes exactly as main() mounts them (registerBusinessUnitRoutes),
// over the real service and a real Postgres. Deleting a gate lets the
// "no permission" / "dcim.read only" writes through.
func TestIntegration_BusinessUnitRoutes_Gates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)

	user := func(perms ...string) uuid.UUID {
		id := uuid.New()
		if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, id, tenant, "bu-"+id.String()[:8]+"@example.com"); err != nil {
			t.Fatal(err)
		}
		if len(perms) == 0 {
			return id
		}
		var role uuid.UUID
		if err := raw.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, 'BU test') RETURNING id`, tenant, "bu_"+id.String()[:8]).Scan(&role); err != nil {
			t.Fatal(err)
		}
		for _, p := range perms {
			if _, err := raw.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) SELECT $1, id FROM tenant_permissions WHERE name = $2`, role, p); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := raw.Exec(`INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active) VALUES ($1, $2, $3, true)`, id, tenant, role); err != nil {
			t.Fatal(err)
		}
		return id
	}
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	h := handlers.NewBusinessUnitHandler(services.NewBusinessUnitService(db))

	call := func(as uuid.UUID, method, path, body string) (int, map[string]any) {
		r := gin.New()
		r.Use(gin.Recovery(), func(c *gin.Context) {
			c.Set("tenantID", tenant)
			c.Set("userID", as)
			c.Next()
		})
		registerBusinessUnitRoutes(r, raw, h)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	const base = "/inventory-service/dcim/business-units"
	nobody, reader, admin := user(), user("dcim.read"), user("dcim.read", "business_units.manage")

	if code, _ := call(nobody, http.MethodGet, base, ""); code != http.StatusForbidden {
		t.Errorf("list with no permission: %d, want 403", code)
	}
	if code, _ := call(reader, http.MethodGet, base, ""); code != http.StatusOK {
		t.Errorf("list with dcim.read: %d, want 200", code)
	}
	if code, _ := call(reader, http.MethodPost, base, `{"name":"Finance"}`); code != http.StatusForbidden {
		t.Errorf("create with dcim.read only: %d, want 403", code)
	}
	code, out := call(admin, http.MethodPost, base, `{"name":"Finance"}`)
	if code != http.StatusCreated || out["slug"] != "finance" {
		t.Fatalf("create as manager: %d %v", code, out)
	}
	id := out["id"].(string)
	if code, _ := call(reader, http.MethodPut, base+"/"+id, `{"description":"x"}`); code != http.StatusForbidden {
		t.Errorf("update with dcim.read only: %d, want 403", code)
	}
	if code, _ := call(admin, http.MethodPut, base+"/"+id, `{"description":"x"}`); code != http.StatusOK {
		t.Errorf("update as manager: %d, want 200", code)
	}
	if code, _ := call(reader, http.MethodDelete, base+"/"+id, ""); code != http.StatusForbidden {
		t.Errorf("delete with dcim.read only: %d, want 403", code)
	}
	if code, _ := call(admin, http.MethodPost, base, `{"name":"Finance","slug":"finance"}`); code != http.StatusConflict {
		t.Errorf("duplicate slug: %d, want 409", code)
	}
	// Reference check: 409 while an asset uses the unit, 204 with a target.
	_, to := call(admin, http.MethodPost, base, `{"name":"Target"}`)
	if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status,business_unit_id) VALUES($1,$2,'h','server','hardware.computer.server','monitoring',$3)`, uuid.New(), tenant, id); err != nil {
		t.Fatal(err)
	}
	if code, out := call(admin, http.MethodDelete, base+"/"+id, ""); code != http.StatusConflict || out["assets"] != float64(1) {
		t.Errorf("delete while referenced: %d %v, want 409 with assets=1", code, out)
	}
	if code, _ := call(admin, http.MethodDelete, base+"/"+id+"?reassign_to="+to["id"].(string), ""); code != http.StatusNoContent {
		t.Errorf("delete with reassign_to: %d, want 204", code)
	}
	if code, _ := call(admin, http.MethodGet, base+"/"+id, ""); code != http.StatusNotFound {
		t.Errorf("get after delete: %d, want 404", code)
	}
}
