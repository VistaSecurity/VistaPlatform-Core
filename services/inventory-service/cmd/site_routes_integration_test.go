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

// The twenty routes exactly as main() mounts them (registerSiteRoutes), over
// the real service and a real Postgres: a tenant builds Region › Site group ›
// Site › Location, reads the site with its counts, and cannot delete a site
// that holds assets without naming where they go. Deleting a gate lets the
// dcim.read-only writes through; deleting the in-use check lets the first
// delete succeed.
func TestIntegration_SiteRoutes_TreeGatesAndDelete(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)

	user := func(perms ...string) uuid.UUID {
		id := uuid.New()
		if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, id, tenant, "site-"+id.String()[:8]+"@example.com"); err != nil {
			t.Fatal(err)
		}
		if len(perms) == 0 {
			return id
		}
		var role uuid.UUID
		if err := raw.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, 'Site test') RETURNING id`, tenant, "site_"+id.String()[:8]).Scan(&role); err != nil {
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
	h := handlers.NewSiteHandler(services.NewSiteService(db))

	call := func(as uuid.UUID, method, path, body string) (int, map[string]any) {
		r := gin.New()
		r.Use(gin.Recovery(), func(c *gin.Context) {
			c.Set("tenantID", tenant)
			c.Set("userID", as)
			c.Next()
		})
		registerSiteRoutes(r, raw, h)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	const base = "/inventory-service/dcim"
	nobody, reader, admin := user(), user("dcim.read"), user("dcim.read", "dcim.manage")

	if code, _ := call(nobody, http.MethodGet, base+"/sites", ""); code != http.StatusForbidden {
		t.Errorf("list sites with no permission: %d, want 403", code)
	}
	if code, _ := call(reader, http.MethodGet, base+"/sites", ""); code != http.StatusOK {
		t.Errorf("list sites with dcim.read: %d, want 200", code)
	}
	for _, p := range []string{"/regions", "/site-groups", "/sites"} {
		if code, _ := call(reader, http.MethodPost, base+p, `{"name":"X"}`); code != http.StatusForbidden {
			t.Errorf("create %s with dcim.read only: %d, want 403", p, code)
		}
	}

	// Region › Site group › Site › Location, as Settings → Sites builds it.
	code, region := call(admin, http.MethodPost, base+"/regions", `{"name":"Europe"}`)
	if code != http.StatusCreated || region["slug"] != "europe" {
		t.Fatalf("create region: %d %v", code, region)
	}
	code, group := call(admin, http.MethodPost, base+"/site-groups", `{"name":"Branches"}`)
	if code != http.StatusCreated {
		t.Fatalf("create site group: %d %v", code, group)
	}
	code, site := call(admin, http.MethodPost, base+"/sites", `{"name":"AMS-1","region_id":"`+region["id"].(string)+`","group_id":"`+group["id"].(string)+`","facility":"Equinix AM3","time_zone":"Europe/Amsterdam","latitude":52.3,"longitude":4.9,"asns":[64512]}`)
	if code != http.StatusCreated || site["slug"] != "ams-1" || site["region_name"] != "Europe" || site["group_name"] != "Branches" {
		t.Fatalf("create site: %d %v", code, site)
	}
	siteID := site["id"].(string)
	code, hall := call(admin, http.MethodPost, base+"/locations", `{"site_id":"`+siteID+`","name":"Hall 2"}`)
	if code != http.StatusCreated || hall["path"] != "AMS-1 / Hall 2" {
		t.Fatalf("create location: %d %v", code, hall)
	}
	code, cage := call(admin, http.MethodPost, base+"/locations", `{"site_id":"`+siteID+`","parent_id":"`+hall["id"].(string)+`","name":"Cage 7"}`)
	if code != http.StatusCreated || cage["path"] != "AMS-1 / Hall 2 / Cage 7" {
		t.Fatalf("create sub-location: %d %v", code, cage)
	}
	if code, _ := call(reader, http.MethodPost, base+"/locations", `{"site_id":"`+siteID+`","name":"Hall 3"}`); code != http.StatusForbidden {
		t.Errorf("create location with dcim.read only: %d, want 403", code)
	}
	if code, _ := call(admin, http.MethodPost, base+"/sites", `{"name":"ams-1"}`); code != http.StatusConflict {
		t.Errorf("a second site named ams-1 (case-insensitively): %d, want 409", code)
	}

	// The site page's read carries the counts.
	if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status,site_id,location_id) VALUES($1,$2,'h','server','hardware.computer.server','monitoring',$3,$4)`, uuid.New(), tenant, siteID, cage["id"]); err != nil {
		t.Fatal(err)
	}
	code, got := call(reader, http.MethodGet, base+"/sites/"+siteID, "")
	counts, _ := got["counts"].(map[string]any)
	if code != http.StatusOK || counts["assets"] != float64(1) || counts["locations"] != float64(2) || counts["racks"] != float64(0) {
		t.Errorf("site with counts: %d %v", code, got)
	}

	// Delete: 409 while assets are in the site, 204 with a target.
	_, target := call(admin, http.MethodPost, base+"/sites", `{"name":"AMS-2"}`)
	if code, out := call(admin, http.MethodDelete, base+"/sites/"+siteID, ""); code != http.StatusConflict || out["assets"] != float64(1) {
		t.Errorf("delete a site holding an asset: %d %v, want 409 with assets=1", code, out)
	}
	if code, _ := call(reader, http.MethodDelete, base+"/sites/"+siteID+"?reassign_to="+target["id"].(string), ""); code != http.StatusForbidden {
		t.Errorf("delete with dcim.read only: %d, want 403", code)
	}
	if code, _ := call(admin, http.MethodDelete, base+"/sites/"+siteID+"?reassign_to="+target["id"].(string), ""); code != http.StatusNoContent {
		t.Errorf("delete with reassign_to: %d, want 204", code)
	}
	var moved, locs int
	if err := raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND site_id=$2 AND location_id IS NULL`, tenant, target["id"]).Scan(&moved); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow(`SELECT count(*) FROM locations WHERE tenant_id=$1 AND site_id=$2`, tenant, siteID).Scan(&locs); err != nil {
		t.Fatal(err)
	}
	if moved != 1 || locs != 0 {
		t.Errorf("after reassign: %d asset(s) moved without a location (want 1), %d location(s) left (want 0)", moved, locs)
	}
	if code, _ := call(admin, http.MethodGet, base+"/sites/"+siteID, ""); code != http.StatusNotFound {
		t.Errorf("get after delete: %d, want 404", code)
	}
}
