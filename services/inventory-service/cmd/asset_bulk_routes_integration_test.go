package main

// The bulk-action routes as main() builds them: assetBulkChain's
// permission in front of the real handler over the real services, against a
// real Postgres. Deleting a chain's gate lets the "no permissions" requests
// through; gating delete on assets.update lets the editor delete. The scan
// half drives assetScanChain with a QUERY selection — the path the Inventory
// bulk bar takes — to an httptest cluster-sensor-service.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AssetBulkRoutes_PermissionsAndQuerySelections(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)

	mk := func(env, addr string) uuid.UUID {
		id := uuid.New()
		if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status,environment)
			VALUES($1,$2,$3,$5::inet,'server','hardware.computer.server','monitoring',$4::environment_type)`,
			id, tenant, "bulk-route-"+id.String()[:8], env, addr); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, c := mk("staging", "10.20.0.11"), mk("staging", "10.20.0.12"), mk("production", "10.20.0.13")

	user := func(perms ...string) uuid.UUID {
		id := uuid.New()
		if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, id, tenant, "bulk-"+id.String()[:8]+"@example.com"); err != nil {
			t.Fatal(err)
		}
		if len(perms) == 0 {
			return id
		}
		var role uuid.UUID
		if err := raw.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, 'Bulk test') RETURNING id`, tenant, "bulk_"+id.String()[:8]).Scan(&role); err != nil {
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
	assetSvc := services.NewAssetService(db)
	bulk := handlers.NewAssetBulkHandler(assetSvc, services.NewAssetLifecycleService(db))

	post := func(as uuid.UUID, action, body string) (int, map[string]any) {
		r := gin.New()
		r.Use(gin.Recovery(), func(c *gin.Context) {
			c.Set("tenantID", tenant)
			c.Set("userID", as)
			c.Next()
		})
		r.POST("/bulk", assetBulkChain(raw, bulk, action)...)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/bulk", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	ids := `{"asset_ids":["` + a.String() + `","` + b.String() + `"]}`

	nobody := user()
	for action := range assetBulkActions {
		if code, _ := post(nobody, action, ids); code != http.StatusForbidden {
			t.Errorf("%s with no permissions: %d, want 403", action, code)
		}
	}
	editor := user("assets.update")
	if code, _ := post(editor, "delete", ids); code != http.StatusForbidden {
		t.Errorf("delete with assets.update only: %d, want 403 — editing an asset is not deleting it", code)
	}
	if code, out := post(editor, "archive", ids); code != http.StatusOK || out["changed"] != float64(2) {
		t.Errorf("archive: %d %v, want 200 changed 2", code, out)
	}
	if code, out := post(editor, "restore", ids); code != http.StatusOK || out["changed"] != float64(2) {
		t.Errorf("restore: %d %v, want 200 changed 2", code, out)
	}

	// A query selection: the two staging assets, confirmed as two.
	q := `"query":"environment:staging"`
	if code, out := post(editor, "update", `{`+q+`,"expected_count":2,"changes":{"business_unit":"Payments"}}`); code != http.StatusOK || out["matched"] != float64(2) || out["changed"] != float64(2) {
		t.Errorf("update by query: %d %v, want 200 matched 2 changed 2", code, out)
	}
	var payments int
	_ = raw.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND business_unit='Payments'`, tenant).Scan(&payments)
	if payments != 2 {
		t.Errorf("%d assets in Payments, want the 2 staging ones (not %s)", payments, c)
	}
	// Confirmed one, the query matches two: refused, nothing changed.
	if code, out := post(editor, "update", `{`+q+`,"expected_count":1,"changes":{"business_unit":"Cards"}}`); code != http.StatusConflict || out["count"] != float64(2) {
		t.Errorf("update with a stale count: %d %v, want 409 count 2", code, out)
	}
	var cards int
	_ = raw.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND business_unit='Cards'`, tenant).Scan(&cards)
	if cards != 0 {
		t.Errorf("a refused selection changed %d assets", cards)
	}
	// No expected_count with a query: refused before anything runs.
	if code, _ := post(editor, "archive", `{`+q+`}`); code != http.StatusBadRequest {
		t.Errorf("query without expected_count: %d, want 400", code)
	}
	// An edit that changes nothing is refused before the selection is read.
	if code, out := post(editor, "update", `{`+q+`,"expected_count":2,"changes":{}}`); code != http.StatusBadRequest || out["error"] != "invalid_changes" {
		t.Errorf("empty edit: %d %v, want 400 invalid_changes", code, out)
	}
	if code, out := post(user("assets.delete"), "delete", `{"query":"environment:production","expected_count":1}`); code != http.StatusOK || out["changed"] != float64(1) {
		t.Errorf("delete by query with assets.delete: %d %v, want 200 changed 1", code, out)
	}

	// The bulk scan: the same query selection through the Active Scan route.
	var mu sync.Mutex
	var dispatched []map[string]any
	cluster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		dispatched = append(dispatched, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job":{"id":"` + uuid.NewString() + `","status":"queued"}}`))
	}))
	t.Cleanup(cluster.Close)
	t.Setenv("CLUSTER_SENSOR_SERVICE_URL", cluster.URL)
	ds, err := services.NewDiscoveryService(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	scanHandler := newAssetLifecycleHandler(nil, services.NewRevalidationService(db, ds, nil, nil), assetSvc, raw)
	scan := func(body string) (int, string) {
		r := gin.New()
		r.Use(gin.Recovery(), func(c *gin.Context) {
			c.Set("tenantID", tenant)
			c.Set("userID", editor)
			c.Next()
		})
		r.POST("/scan", assetScanChain(raw, scanHandler)...)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	if code, out := scan(`{` + q + `,"expected_count":2,"run_from":"platform"}`); code != http.StatusOK || !strings.Contains(out, `"count":2`) {
		t.Fatalf("scan by query: %d %s, want 200 count 2", code, out)
	}
	if len(dispatched) != 1 {
		t.Fatalf("%d dispatches, want 1", len(dispatched))
	}
	targets, _ := json.Marshal(dispatched[0]["targets"])
	if strings.Count(string(targets), "10.20.0.") != 2 {
		t.Errorf("dispatched targets %s, want the two staging assets' addresses", targets)
	}
	if code, out := scan(`{` + q + `,"expected_count":1,"run_from":"platform"}`); code != http.StatusConflict {
		t.Errorf("scan with a stale count: %d %s, want 409", code, out)
	}
	// The old body still works.
	if code, out := scan(`{"asset_ids":["` + a.String() + `"],"run_from":"platform"}`); code != http.StatusOK {
		t.Errorf("scan by asset_ids: %d %s, want 200", code, out)
	}
}
