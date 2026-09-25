package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/handlers"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Follow-ups from the review, on the real heartbeat handler and the
// real store.

func seedSegment(t *testing.T, exec func(string, ...any) error, tenant uuid.UUID, value, networkType, metadata string) {
	t.Helper()
	if err := exec(`INSERT INTO public.network_segments
		(tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
		VALUES ($1, $2, 'cidr', $3, $4, 'production', true, $5::jsonb)`,
		tenant, "seg-"+value, value, networkType, metadata); err != nil {
		t.Fatalf("seeding segment %s: %v", value, err)
	}
}

func seedElevated(t *testing.T, exec func(string, ...any) error, tenant uuid.UUID, ip string) {
	t.Helper()
	asset := uuid.New()
	if err := exec(`INSERT INTO public.assets (id, tenant_id, hostname, class_key, class_path, asset_status, asset_ownership)
		VALUES ($1, $2, $3, 'external', 'external', 'monitoring', 'third_party')`, asset, tenant, "vendor-"+ip); err != nil {
		t.Fatalf("seeding elevated asset: %v", err)
	}
	if err := exec(`INSERT INTO public.external_connections (tenant_id, source_ip, dest_ip, dest_port, protocol, elevated_asset_id)
		VALUES ($1, '10.0.0.5', $2, 443, 'TLS', $3)`, tenant, ip, asset); err != nil {
		t.Fatalf("seeding elevated connection: %v", err)
	}
}

// When the owned set cannot be built — here the tenant's scan-restriction
// settings do not parse — the heartbeat must NOT leave owned_networks out (the
// sensor would keep its last ownership indefinitely). It sends an explicit,
// incomplete set: no prefixes, no endpoints, and every exclusion it could read.
//
// Mutation check: send nothing on error (the pre-review behaviour) and the
// block is absent; drop the segment exclusions from the incomplete answer and
// `excluded` comes back empty.
func TestIntegration_HeartbeatSendsNoOwnershipWhenTheSetCannotBeBuilt(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenant)
	app := testdb.ConnectAsAppRole(t, admin)
	exec := func(q string, args ...any) error { _, err := admin.Exec(q, args...); return err }

	seedSegment(t, exec, tenant, "203.0.113.0/24", "public", `{}`)
	seedSegment(t, exec, tenant, "192.0.2.0/25", "public", `{"sensitive":true}`)
	seedElevated(t, exec, tenant, "198.51.100.7")
	if err := exec(`INSERT INTO public.tenant_admin_settings (tenant_id, config)
		VALUES ($1, '{"identity_enrichment":{"excluded_cidrs":["not-a-cidr"]}}'::jsonb)`, tenant); err != nil {
		t.Fatal(err)
	}

	repo := database.NewSensorRepository(admin, admin)
	h := handlers.NewHandlerWithBoth(services.NewSensorService(admin, admin), services.NewSensorServiceV2(repo), repo, app, admin)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/sensors/:sensor_id/heartbeat", h.Heartbeat)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sensors/"+sensorID.String()+"/heartbeat",
		bytes.NewBufferString(`{"sensor_id":"`+sensorID.String()+`","status":"active"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat = %d: %s", w.Code, w.Body.String())
	}
	var got struct {
		OwnedNetworks *struct {
			Prefixes   []string `json:"prefixes"`
			Endpoints  []string `json:"endpoints"`
			Excluded   []string `json:"excluded"`
			Incomplete bool     `json:"incomplete"`
		} `json:"owned_networks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.OwnedNetworks == nil {
		t.Fatal("owned_networks absent on a build failure; the sensor would keep stale ownership indefinitely")
	}
	o := got.OwnedNetworks
	if !o.Incomplete || len(o.Prefixes) != 0 || len(o.Endpoints) != 0 {
		t.Errorf("owned_networks = %+v, want incomplete with no prefixes and no endpoints", *o)
	}
	if !reflect.DeepEqual(o.Excluded, []string{"192.0.2.0/25"}) {
		t.Errorf("excluded = %v, want the sensitive segment the platform could still read", o.Excluded)
	}
}

// M5/M5b: the owned-network queries carry explicit tenant_id predicates, and
// those must hold on their own — not only because RLS happens to be on for the
// app role. Run as the table OWNER (RLS bypassed), with a second tenant holding
// a declared segment, an elevated endpoint and a scan exclusion, and none of it
// may leak into the first tenant's answer.
func TestIntegration_OwnedNetworksTenantPredicatesHoldWithoutRLS(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	mine := testdb.NewTenant(t, admin)
	theirs := testdb.NewTenant(t, admin)
	exec := func(q string, args ...any) error { _, err := admin.Exec(q, args...); return err }

	seedSegment(t, exec, mine, "203.0.113.0/24", "public", `{}`)
	seedElevated(t, exec, mine, "198.51.100.7")

	seedSegment(t, exec, theirs, "198.51.100.0/25", "public", `{}`)
	seedSegment(t, exec, theirs, "192.0.2.0/25", "public", `{"sensitive":true}`)
	seedElevated(t, exec, theirs, "198.51.100.200")
	if err := exec(`INSERT INTO public.tenant_admin_settings (tenant_id, config)
		VALUES ($1, '{"identity_enrichment":{"excluded_cidrs":["10.99.0.0/16"]}}'::jsonb)`, theirs); err != nil {
		t.Fatal(err)
	}

	got, err := dispatchguard.OwnedNetworks(admin, mine.String())
	if err != nil {
		t.Fatalf("OwnedNetworks as owner: %v", err)
	}
	if !reflect.DeepEqual(got.Prefixes, []string{"203.0.113.0/24"}) {
		t.Errorf("prefixes = %v — another tenant's segment leaked without RLS", got.Prefixes)
	}
	if !reflect.DeepEqual(got.Endpoints, []string{"198.51.100.7:443"}) {
		t.Errorf("endpoints = %v — another tenant's elevated endpoint leaked without RLS", got.Endpoints)
	}
	if len(got.Excluded) != 0 {
		t.Errorf("excluded = %v — another tenant's exclusions leaked without RLS", got.Excluded)
	}
}

// Turning the opt-in on is a consent, and the console's confirmation is only
// worth something if it is recorded: who, when, and what moved. The refused,
// unconfirmed attempt records nothing.
func TestIntegration_ThirdPartyOptInIsAudited(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	app := testdb.ConnectAsAppRole(t, admin)
	h := handlers.NewSensorConfigHandler(app)
	user := uuid.New()

	put := func(body string) int {
		t.Helper()
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPut, "/sensors/config/defaults", bytes.NewBufferString(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set("tenantID", tenant)
		c.Set("userID", user)
		h.PutSensorFleetDefaults(c)
		return w.Code
	}
	auditRows := func() int {
		t.Helper()
		var n int
		if err := admin.QueryRow(`SELECT count(*) FROM public.agent_config_audit
			WHERE tenant_id = $1 AND runtime = 'sensor' AND scope = 'fleet'
			  AND values_after->>'third_party_tls_enrichment' = 'true'`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	before := time.Now().Add(-time.Minute)
	if code := put(`{"values":{"third_party_tls_enrichment":true}}`); code != http.StatusConflict {
		t.Fatalf("unconfirmed opt-in = %d, want 409", code)
	}
	if n := auditRows(); n != 0 {
		t.Errorf("an unconfirmed, refused opt-in left %d audit rows", n)
	}
	if code := put(`{"values":{"third_party_tls_enrichment":true},"confirmed":true}`); code != http.StatusOK {
		t.Fatalf("confirmed opt-in = %d", code)
	}
	var changedBy uuid.UUID
	var changedAt time.Time
	var beforeVal *string
	if err := admin.QueryRow(`SELECT changed_by, changed_at, values_before->>'third_party_tls_enrichment'
		FROM public.agent_config_audit
		WHERE tenant_id = $1 AND runtime = 'sensor' AND scope = 'fleet'
		  AND values_after->>'third_party_tls_enrichment' = 'true'`, tenant).Scan(&changedBy, &changedAt, &beforeVal); err != nil {
		t.Fatalf("no audit row for the confirmed opt-in: %v", err)
	}
	if changedBy != user {
		t.Errorf("audit changed_by = %s, want the confirming user %s", changedBy, user)
	}
	if changedAt.Before(before) {
		t.Errorf("audit changed_at = %s, want the time of the confirmation", changedAt)
	}
	if beforeVal != nil && *beforeVal == "true" {
		t.Error("audit values_before already carried the opt-in")
	}
}
