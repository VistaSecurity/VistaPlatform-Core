package main

// The Active Scan route as main() builds it (review N3): assetScanChain's
// assets.update gate in front of the handler newAssetLifecycleHandler returns,
// whose own discovery.create check guards a confirmed external scan. Real
// Postgres for the permission checks and the asset rows; an httptest server
// stands in for cluster-sensor-service. Deleting the permission-checker wiring
// in newAssetLifecycleHandler turns the "both permissions" case into a 403;
// deleting the route gate lets the "no permissions" case through.

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
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AssetScanRoute_ExternalConfirmationPermissions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)

	asset := uuid.New()
	if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,'partner-portal','93.184.216.34','server','hardware.computer.server','monitoring')`, asset, tenant); err != nil {
		t.Fatal(err)
	}
	user := func(perms ...string) uuid.UUID {
		id := uuid.New()
		if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, id, tenant, "scan-"+id.String()[:8]+"@example.com"); err != nil {
			t.Fatal(err)
		}
		if len(perms) == 0 {
			return id
		}
		var role uuid.UUID
		if err := raw.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, 'Scan test') RETURNING id`, tenant, "scan_"+id.String()[:8]).Scan(&role); err != nil {
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

	var mu sync.Mutex
	var dispatched []map[string]interface{}
	cluster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(b, &body)
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
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	revalidation := services.NewRevalidationService(db, ds, nil, nil)

	post := func(as uuid.UUID, confirmed bool) (int, string) {
		r := gin.New()
		r.Use(gin.Recovery(), func(c *gin.Context) {
			c.Set("tenantID", tenant)
			c.Set("userID", as)
			c.Next()
		})
		r.POST("/scan", assetScanChain(raw, newAssetLifecycleHandler(nil, revalidation, nil, raw))...)
		body := `{"asset_ids":["` + asset.String() + `"],"run_from":"platform"`
		if confirmed {
			body += `,"external_targets_confirmed":true`
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewBufferString(body+"}"))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	// No permissions: the route's assets.update gate refuses.
	if code, out := post(user(), true); code != http.StatusForbidden || !strings.Contains(out, "assets.update") {
		t.Fatalf("no permissions: %d %s, want 403 naming assets.update", code, out)
	}
	// assets.update only, unconfirmed: asked (422), nothing dispatched.
	scanner := user("assets.update")
	if code, out := post(scanner, false); code != http.StatusUnprocessableEntity || !strings.Contains(out, "partner-portal") {
		t.Fatalf("unconfirmed: %d %s, want 422 naming the asset", code, out)
	}
	// assets.update only, confirmed: the handler's discovery.create check refuses.
	if code, out := post(scanner, true); code != http.StatusForbidden || !strings.Contains(out, "discovery.create") {
		t.Fatalf("confirmed without discovery.create: %d %s, want 403 naming discovery.create", code, out)
	}
	if len(dispatched) != 0 {
		t.Fatalf("%d dispatch(es) before any permitted confirmation", len(dispatched))
	}
	// Both: scanned, with the confirmation carried to cluster-sensor-service.
	if code, out := post(user("assets.update", "discovery.create"), true); code != http.StatusOK {
		t.Fatalf("confirmed with both permissions: %d %s, want 200", code, out)
	}
	if len(dispatched) != 1 || dispatched[0]["external_targets_confirmed"] != true {
		t.Fatalf("dispatched %v, want one job carrying the confirmation", dispatched)
	}
}
