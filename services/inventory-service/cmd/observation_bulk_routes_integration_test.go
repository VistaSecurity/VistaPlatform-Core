package main

// POST /discovery/observations/bulk as main() builds it: the
// assets.update gate of observationBulkChain in front of the real handler and
// service, against a real Postgres. Deleting the gate from the chain lets the
// "no permissions" case through; the per-item statuses are the single
// endpoints' own, read back from the HTTP response the UI will parse.

import (
	"bytes"
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
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ObservationBulkRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	other := testdb.NewTenant(t, raw)

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
	if _, err := raw.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
	 SELECT $1,id,'{"quantity":1}'::jsonb,'bulk route regression' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
		t.Fatal(err)
	}
	observation := func(tenant uuid.UUID, state, reason, addr string) uuid.UUID {
		var id uuid.UUID
		ev := fmt.Sprintf(`{"identifiers":[{"kind":"ip_address","value":%q}],"endpoints":[{"address":%q,"port":22,"transport":"tcp","protocol":"ssh"}]}`, addr, addr)
		if err := raw.QueryRow(`INSERT INTO identity_observations(tenant_id,fingerprint,source_kind,source_ref,evidence,admission_reasons,state,first_seen_at,last_seen_at)
		 VALUES($1,$2,'measured','scan',$3,$4,$5,$6,$6) RETURNING id`, tenant, uuid.NewString(), ev, pq.Array([]string{reason}), state, time.Now().UTC().Add(-time.Hour)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ready1 := observation(tenant, "unresolved", "dynamic_address_without_device_binding", "192.0.2.31")
	ready2 := observation(tenant, "unresolved", "dynamic_address_without_device_binding", "192.0.2.32")
	relayed := observation(tenant, "unresolved", "unverified_relayed_advertisement", "192.0.2.33")
	conflicted := observation(tenant, "conflict", "dynamic_address_without_device_binding", "192.0.2.34")
	foreign := observation(other, "unresolved", "dynamic_address_without_device_binding", "192.0.2.35")

	h := handlers.NewIdentityObservationHandler(services.NewAssetService(&database.DB{DB: sqlx.NewDb(raw, "postgres")}))
	post := func(as uuid.UUID, body any) (int, string) {
		r := gin.New()
		r.Use(gin.Recovery(), func(c *gin.Context) {
			c.Set("tenantID", tenant)
			c.Set("userID", as)
			c.Next()
		})
		r.POST("/bulk", observationBulkChain(raw, h)...)
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/bulk", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	body := func(action string, ids ...uuid.UUID) map[string]any {
		return map[string]any{"action": action, "ids": ids, "reason": "Recognised on the office network"}
	}

	// RBAC through the real chain: assets.read is not enough.
	if code, out := post(user("assets.read"), body("dismiss", relayed)); code != http.StatusForbidden || !strings.Contains(out, "assets.update") {
		t.Fatalf("without assets.update: %d %s, want 403 naming assets.update", code, out)
	}
	reviewer := user("assets.update")

	// Shape errors are the request's, not an item's.
	tooMany := make([]uuid.UUID, 201)
	for i := range tooMany {
		tooMany[i] = uuid.New()
	}
	for name, b := range map[string]any{
		"empty ids":      body("confirm"),
		"201 ids":        body("dismiss", tooMany...),
		"unknown action": body("relink", ready1),
		"no reason":      map[string]any{"action": "dismiss", "ids": []uuid.UUID{ready1}, "reason": "  "},
		"malformed id":   map[string]any{"action": "dismiss", "ids": []string{"not-a-uuid"}, "reason": "x"},
		"reason too big": map[string]any{"action": "dismiss", "ids": []uuid.UUID{ready1}, "reason": strings.Repeat("x", 2001)},
	} {
		if code, out := post(reviewer, b); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, code, out)
		}
	}
	// Link is a bulk action now, but only toward an owner the table
	// suggested: a row nothing owns is a per-item 422, not a request error.
	if code, out := post(reviewer, body("link", ready1)); code != http.StatusOK || !strings.Contains(out, `"code":"not_ready_to_confirm"`) {
		t.Fatalf("link of an unowned row: %d %s, want 200 with a not_ready item", code, out)
	}
	if code, out := post(reviewer, body("dismiss", tooMany[:200]...)); code != http.StatusOK {
		t.Fatalf("200 ids: %d %s, want 200 (every item reported not found)", code, out)
	}

	code, out := post(reviewer, body("confirm", ready1, ready2, relayed, conflicted, foreign))
	if code != http.StatusOK {
		t.Fatalf("mixed batch: %d %s, want 200", code, out)
	}
	var resp handlers.BulkObservationResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.BatchID == uuid.Nil || len(resp.Results) != 5 {
		t.Fatalf("response %s", out)
	}
	want := []struct {
		id      uuid.UUID
		outcome string
		status  int
		code    string
	}{
		{ready1, "ok", 200, ""},
		{ready2, "failed", 402, "asset_allowance_reached"},
		{relayed, "failed", 422, "not_ready_to_confirm"},
		{conflicted, "failed", 422, "not_ready_to_confirm"},
		{foreign, "failed", 404, "not_found"},
	}
	for i, w := range want {
		got := resp.Results[i]
		if got.ID != w.id || got.Outcome != w.outcome || got.Status != w.status || got.Code != w.code || got.Message == "" {
			t.Errorf("result %d = %+v, want %+v", i, got, w)
		}
	}
	if resp.Results[0].AssetID == "" {
		t.Error("a confirmed item does not name the asset it created")
	}
	// The 402 item's message is the single endpoint's own.
	if resp.Results[1].Message != services.ErrObservationAllowance.Error() {
		t.Errorf("402 message %q, want the single endpoint's %q", resp.Results[1].Message, services.ErrObservationAllowance.Error())
	}

	// Dismissing a conflicted observation is the single endpoint's 409.
	code, out = post(reviewer, body("dismiss", conflicted, relayed))
	if code != http.StatusOK || !strings.Contains(out, `"status":409`) || !strings.Contains(out, `"code":"observation_changed"`) {
		t.Fatalf("dismiss batch: %d %s", code, out)
	}
	var audit int
	if err := raw.QueryRow(`SELECT count(*) FROM identity_observation_decisions WHERE tenant_id=$1 AND details ? 'batch_id'`, tenant).Scan(&audit); err != nil || audit != 2 {
		t.Fatalf("audit rows with a batch id: %d %v, want 2 (one confirm, one dismiss)", audit, err)
	}
}
