package main

// The "Claim as mine" routes as main() mounts them (owner decision D8):
// segmentClaimChain's settings.update gate in front of the real handler and
// the real service, against real Postgres — the service connected as the
// non-owner app role, so every read and write here goes through RLS.
//
// Ownership is asserted where it is decided, not inferred from the response:
// dispatchguard.LoadTargetScope (what a scan a person asks for is checked
// against) and dispatchguard.OwnedNetworks (what sensors are told is the
// tenant's), both read inside a tenant-scoped app-role transaction.
//
// Deleting the gate from segmentClaimChain lets the no-permission case
// through; deleting withServerOwnedKeys from Update lets the forged PUT grant
// ownership; deleting the claim clause from learnedSegmentSQL leaves the
// claimed range out of scope.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SegmentClaimRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	app := testdb.ConnectAsAppRole(t, raw)
	tenant := testdb.NewTenant(t, raw)

	user := func(first string, perms ...string) uuid.UUID {
		id := uuid.New()
		if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email, first_name, last_name) VALUES ($1, $2, $3, $4, 'Admin')`,
			id, tenant, "claim-"+id.String()[:8]+"@example.com", first); err != nil {
			t.Fatal(err)
		}
		if len(perms) == 0 {
			return id
		}
		var role uuid.UUID
		if err := raw.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, 'Claim test') RETURNING id`, tenant, "claim_"+id.String()[:8]).Scan(&role); err != nil {
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
	segment := func(name, segType, value, networkType, metadata string) uuid.UUID {
		var id uuid.UUID
		if err := raw.QueryRow(`INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
			VALUES ($1, $2, $3, $4, $5, 'production', true, $6::jsonb) RETURNING id`, tenant, name, segType, value, networkType, metadata).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	firewall := uuid.NewString()
	learned := `{"source":"interrogation","source_device_type":"fortinet","source_asset_id":"` + firewall + `","dhcp":"unknown"}`
	dmz := segment("dmz", "cidr", "93.184.216.0/28", "public", learned)
	transit := segment("wan-transit", "cidr", "93.184.216.64/30", "public", learned)
	lan := segment("lan", "cidr", "10.20.30.0/24", "private", learned)
	declared := segment("Our estate", "cidr", "93.184.217.0/24", "public", `{}`)
	byName := segment("partner", "domain", "partner.example", "public", learned)
	broad := segment("everything", "cidr", "40.0.0.0/7", "public", learned) // saved before the breadth cap

	mw := func() *audithelpers.Middleware {
		cfg := audithelpers.DefaultConfig()
		cfg.ServiceName = "inventory-service"
		cfg.AuditServiceURL = "http://127.0.0.1:1"
		cfg.BatchSize = 1000
		cfg.FlushInterval = time.Hour
		cfg.Timeout = time.Millisecond
		cfg.RetryAttempts = 0
		cfg.UseNATS = false
		m := audithelpers.NewMiddleware(cfg)
		t.Cleanup(m.Stop)
		return m
	}()
	audited := func(eventType string) []*audithelpers.ActivityLogRequest {
		var out []*audithelpers.ActivityLogRequest
		for _, e := range mw.PendingEntries() {
			if e.EventType == eventType {
				out = append(out, e)
			}
		}
		return out
	}

	db := &database.DB{DB: sqlx.NewDb(app, "postgres")}
	h := handlers.NewNetworkSegmentHandler(services.NewNetworkSegmentService(db, services.NewLocationService(db)))
	call := func(as uuid.UUID, method string, id uuid.UUID, body string) (int, map[string]interface{}) {
		r := gin.New()
		r.Use(gin.Recovery(), func(c *gin.Context) {
			c.Set("tenantID", tenant)
			c.Set("userID", as)
			c.Set("email", "token@example.com")
			c.Set("audit_middleware", mw)
			c.Next()
		})
		r.POST("/network-segments/:id/claim", segmentClaimChain(raw, h.ClaimNetworkSegment)...)
		r.DELETE("/network-segments/:id/claim", segmentClaimChain(raw, h.RevokeNetworkSegmentClaim)...)
		r.PUT("/network-segments/:id", h.UpdateNetworkSegment) // gate covered elsewhere; this drives Update's key protection
		path := "/network-segments/" + id.String()
		if method != http.MethodPut {
			path += "/claim"
		}
		var reader *bytes.Buffer
		if body != "" {
			reader = bytes.NewBufferString(body)
		} else {
			reader = &bytes.Buffer{}
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, reader)
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	inScope := func(addr string) bool {
		var err error
		testdb.AsTenant(t, raw, tenant, func(tx *sql.Tx) {
			var scope dispatchguard.TargetScope
			if scope, err = dispatchguard.LoadTargetScope(tx, tenant.String()); err == nil {
				err = scope.Authorize(addr)
			}
		})
		return err == nil
	}
	ownedBySensors := func(prefix string) bool {
		var owned []string
		testdb.AsTenant(t, raw, tenant, func(tx *sql.Tx) {
			got, err := dispatchguard.OwnedNetworks(tx, tenant.String())
			if err != nil {
				t.Fatalf("OwnedNetworks: %v", err)
			}
			owned = got.Prefixes
		})
		return slices.Contains(owned, prefix)
	}
	storedClaim := func(id uuid.UUID) (map[string]interface{}, string) {
		var rawMeta []byte
		if err := raw.QueryRow(`SELECT metadata FROM network_segments WHERE id = $1`, id).Scan(&rawMeta); err != nil {
			t.Fatal(err)
		}
		meta := map[string]interface{}{}
		_ = json.Unmarshal(rawMeta, &meta)
		claim, _ := meta[dispatchguard.SegmentClaimKey].(map[string]interface{})
		source, _ := meta["source"].(string)
		return claim, source
	}

	// Before anything: the learned public range is not the tenant's.
	if inScope("93.184.216.5") || ownedBySensors("93.184.216.0/28") {
		t.Fatal("an unclaimed learned public range is already in scope — the premise of the claim is gone")
	}

	// No permission: the route's settings.update gate refuses, both ways.
	viewer := user("Vic")
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		if code, out := call(viewer, method, dmz, ""); code != http.StatusForbidden || !strings.Contains(fmt.Sprint(out), "settings.update") {
			t.Fatalf("%s without settings.update: %d %v, want 403 naming settings.update", method, code, out)
		}
	}
	if claim, _ := storedClaim(dmz); claim != nil {
		t.Fatalf("a refused claim was recorded: %v", claim)
	}

	admin := user("Ada", "settings.update")

	// Nothing to claim, or too broad: refused, nothing written, nothing audited.
	for _, tc := range []struct {
		name string
		id   uuid.UUID
		want int
	}{
		{"declared public", declared, http.StatusConflict},
		{"learned private", lan, http.StatusConflict},
		{"learned non-cidr", byName, http.StatusConflict},
		{"too broad", broad, http.StatusBadRequest},
		{"unknown", uuid.New(), http.StatusNotFound},
	} {
		if code, out := call(admin, http.MethodPost, tc.id, ""); code != tc.want {
			t.Errorf("claim %s: %d %v, want %d", tc.name, code, out, tc.want)
		}
	}
	if code, out := call(admin, http.MethodDelete, declared, ""); code != http.StatusConflict {
		t.Errorf("revoke on a declared segment: %d %v, want 409", code, out)
	}
	if claim, _ := storedClaim(broad); claim != nil || inScope("40.1.2.3") {
		t.Fatalf("too-broad range was claimed (%v) or is in scope", claim)
	}
	if n := len(audited(audithelpers.EventTypeNetworkSegmentClaimed)); n != 0 {
		t.Fatalf("%d claim audit entries after only refusals", n)
	}

	// A forged claim through the ordinary PUT grants nothing — with `source`
	// sent, or omitted (which used to make the row declared).
	for _, meta := range []string{
		`{"source":"interrogation","claimed":{"by":"` + admin.String() + `","at":"2026-10-01T00:00:00Z"}}`,
		`{"claimed":{"by":"` + admin.String() + `","at":"2026-10-01T00:00:00Z"}}`,
		`{}`,
	} {
		body := `{"name":"wan-transit","segment_type":"cidr","value":"93.184.216.64/30","network_type":"public","environment":"production","metadata":` + meta + `}`
		if code, out := call(admin, http.MethodPut, transit, body); code != http.StatusOK {
			t.Fatalf("PUT %s: %d %v", meta, code, out)
		}
		if claim, source := storedClaim(transit); claim != nil || source != "interrogation" {
			t.Fatalf("PUT metadata %s left claim=%v source=%q; the claim and the learned provenance are server-owned", meta, claim, source)
		}
		if inScope("93.184.216.65") || ownedBySensors("93.184.216.64/30") {
			t.Fatalf("PUT metadata %s made an unclaimed learned public range the tenant's", meta)
		}
	}

	// The claim: recorded, audited, and ownership follows in both readers.
	code, out := call(admin, http.MethodPost, dmz, "")
	if code != http.StatusOK {
		t.Fatalf("claim: %d %v, want 200", code, out)
	}
	claim, source := storedClaim(dmz)
	if claim["by"] != admin.String() || claim["by_name"] != "Ada Admin" || source != "interrogation" {
		t.Fatalf("stored claim %v source %q, want by=%s by_name=Ada Admin and the learned provenance kept", claim, source, admin)
	}
	if respMeta, _ := out["metadata"].(map[string]interface{}); respMeta[dispatchguard.SegmentClaimKey] == nil {
		t.Fatalf("response metadata carries no claim: %v", out["metadata"])
	}
	firstAt := claim["at"]
	entries := audited(audithelpers.EventTypeNetworkSegmentClaimed)
	if len(entries) != 1 {
		t.Fatalf("%d claim audit entries, want 1", len(entries))
	}
	e := entries[0]
	if e.UserID == nil || *e.UserID != admin || e.TenantID == nil || *e.TenantID != tenant || e.ResourceID == nil || *e.ResourceID != dmz {
		t.Fatalf("claim audit entry user=%v tenant=%v resource=%v, want %s/%s/%s", e.UserID, e.TenantID, e.ResourceID, admin, tenant, dmz)
	}
	if e.Metadata["cidr"] != "93.184.216.0/28" || e.Metadata["source_device_type"] != "fortinet" || e.Metadata["source_asset_id"] != firewall {
		t.Fatalf("claim audit metadata %v, want the CIDR and the device it was learned from", e.Metadata)
	}
	if !inScope("93.184.216.5") {
		t.Fatal("a claimed learned public range is not in scope for a scan a person asks for")
	}
	if !ownedBySensors("93.184.216.0/28") {
		t.Fatal("a claimed learned public range is not in the sensors' owned set")
	}
	if inScope("93.184.216.65") {
		t.Fatal("claiming one learned range put a different, unclaimed one in scope")
	}

	// Idempotent: same claim, no second audit entry.
	if code, out := call(admin, http.MethodPost, dmz, ""); code != http.StatusOK {
		t.Fatalf("second claim: %d %v, want 200", code, out)
	}
	if claim, _ := storedClaim(dmz); claim["at"] != firstAt || claim["by"] != admin.String() {
		t.Fatalf("second claim rewrote the first: %v", claim)
	}
	if n := len(audited(audithelpers.EventTypeNetworkSegmentClaimed)); n != 1 {
		t.Fatalf("%d claim audit entries after a repeat claim, want 1", n)
	}

	// An unrelated edit that replaces the metadata blob does not withdraw it.
	body := `{"name":"dmz (renamed)","segment_type":"cidr","value":"93.184.216.0/28","network_type":"public","environment":"production","metadata":{}}`
	if code, out := call(admin, http.MethodPut, dmz, body); code != http.StatusOK {
		t.Fatalf("rename: %d %v", code, out)
	}
	if claim, _ := storedClaim(dmz); claim["by"] != admin.String() || !inScope("93.184.216.5") {
		t.Fatalf("an unrelated edit erased the claim: %v", claim)
	}

	// Revoke: the range goes back to learned, audited once, idempotent.
	if code, out := call(admin, http.MethodDelete, dmz, ""); code != http.StatusOK {
		t.Fatalf("revoke: %d %v, want 200", code, out)
	}
	if claim, source := storedClaim(dmz); claim != nil || source != "interrogation" {
		t.Fatalf("after revoke: claim %v source %q", claim, source)
	}
	if inScope("93.184.216.5") || ownedBySensors("93.184.216.0/28") {
		t.Fatal("a revoked claim still grants ownership")
	}
	if code, _ := call(admin, http.MethodDelete, dmz, ""); code != http.StatusOK {
		t.Fatalf("repeat revoke: %d, want 200", code)
	}
	revoked := audited(audithelpers.EventTypeNetworkSegmentClaimRevoked)
	if len(revoked) != 1 || revoked[0].UserID == nil || *revoked[0].UserID != admin {
		t.Fatalf("revoke audit entries %v, want exactly one by %s", revoked, admin)
	}
}

// Declaring a range another segment already holds is a 409 that says what is
// in the way (Step 0 b). It used to be a 500 "Failed to create network
// segment". When the segment in the way is a LEARNED PUBLIC range, the person
// is trying to make it theirs, and the message points at the claim action.
func TestIntegration_SegmentCreate_DuplicateIsAConflictThatNamesTheFix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	app := testdb.ConnectAsAppRole(t, raw)
	tenant := testdb.NewTenant(t, raw)

	firewall := uuid.New()
	if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,'fw-edge','10.0.0.1','server','hardware.computer.server','monitoring')`, firewall, tenant); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, value, networkType, metadata string }{
		{"wan", "93.184.216.0/28", "public", `{"source":"interrogation","source_device_type":"fortinet","source_asset_id":"` + firewall.String() + `"}`},
		{"wan2", "93.184.216.16/28", "public", `{"source":"interrogation","source_device_type":"fortinet"}`},
		{"lan", "10.20.30.0/24", "private", `{"source":"interrogation","source_device_type":"fortinet","source_asset_id":"` + firewall.String() + `"}`},
		{"Our estate", "93.184.217.0/24", "public", `{}`},
	} {
		if _, err := raw.Exec(`INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
			VALUES ($1, $2, 'cidr', $3, $4, 'production', true, $5::jsonb)`, tenant, row.name, row.value, row.networkType, row.metadata); err != nil {
			t.Fatal(err)
		}
	}

	db := &database.DB{DB: sqlx.NewDb(app, "postgres")}
	h := handlers.NewNetworkSegmentHandler(services.NewNetworkSegmentService(db, services.NewLocationService(db)))
	r := gin.New()
	r.Use(gin.Recovery(), func(c *gin.Context) { c.Set("tenantID", tenant); c.Next() })
	r.POST("/network-segments", h.CreateNetworkSegment)
	create := func(value, networkType string) (int, string) {
		body := `{"name":"declared","segment_type":"cidr","value":"` + value + `","network_type":"` + networkType + `","environment":"production"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/network-segments", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		msg, _ := out["error"].(string)
		return w.Code, msg
	}

	for _, tc := range []struct {
		name, value, networkType string
		want                     int
		says, never              []string
	}{
		{"learned public, device known", "93.184.216.0/28", "public", http.StatusConflict,
			[]string{"learned from fw-edge", "Claim as mine", `"wan"`}, nil},
		{"learned public, device gone", "93.184.216.16/28", "public", http.StatusConflict,
			[]string{"learned from a fortinet device", "Claim as mine"}, nil},
		{"learned private", "10.20.30.0/24", "private", http.StatusConflict,
			[]string{"already exists", `"lan"`}, []string{"Claim"}},
		{"declared", "93.184.217.0/24", "public", http.StatusConflict,
			[]string{"already exists", `"Our estate"`}, []string{"Claim", "learned"}},
		{"new range", "93.184.218.0/24", "public", http.StatusCreated, nil, nil},
	} {
		code, msg := create(tc.value, tc.networkType)
		if code != tc.want {
			t.Errorf("%s: %d %q, want %d", tc.name, code, msg, tc.want)
			continue
		}
		for _, s := range tc.says {
			if !strings.Contains(msg, s) {
				t.Errorf("%s: error %q does not say %q", tc.name, msg, s)
			}
		}
		for _, s := range tc.never {
			if strings.Contains(msg, s) {
				t.Errorf("%s: error %q says %q", tc.name, msg, s)
			}
		}
		if strings.Contains(msg, "pq:") || strings.Contains(msg, "duplicate key") {
			t.Errorf("%s: the database's wording reached the client: %q", tc.name, msg)
		}
	}
}
