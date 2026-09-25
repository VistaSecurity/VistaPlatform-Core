package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/handlers"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Third-party TLS enrichment consent ( W5.13, owner decision Q10) reaches
// a sensor through the REAL heartbeat handler: the tenant's opt-in rides the
// desired-state values, and the tenant's declared public space, elevated
// endpoints and exclusions ride beside it.
//
// The handler's database is the APP role, as deployed, so the owned-network
// read has to go through a tenant-scoped transaction to see anything — a
// plain-pool read would return "this tenant owns nothing" and pass every
// assertion that only checks the empty case, which is why this test seeds rows
// that MUST come back.
//
// Mutation checks: delete `response.OwnedNetworks = owned` (owned_networks
// absent); drop `seg.Learned ||` in dispatchguard.OwnedNetworks (learned
// 198.51.100.0/24 appears); drop the `case seg.Blocked` arm (192.0.2.0/25 moves
// from excluded into prefixes); drop the asset_status/deleted_at filter (the
// deleted asset's endpoint appears); drop whollyOwnedByAddressClass (the
// private 10.20.0.0/16 appears); drop the TooBroadToClaim arm (0.0.0.0/0 and
// 3ffe::/15 appear).
func TestIntegration_SensorHeartbeatCarriesThirdPartyConsent(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	other := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenant)
	app := testdb.ConnectAsAppRole(t, admin)

	repo := database.NewSensorRepository(admin, admin)
	h := handlers.NewHandlerWithBoth(services.NewSensorService(admin, admin), services.NewSensorServiceV2(repo), repo, app, admin)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/sensors/:sensor_id/heartbeat", h.Heartbeat)
	beat := func() map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/sensors/"+sensorID.String()+"/heartbeat",
			bytes.NewBufferString(`{"sensor_id":"`+sensorID.String()+`","status":"active"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat = %d: %s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding %q: %v", w.Body.String(), err)
		}
		return out
	}
	optIn := func(got map[string]any) any {
		t.Helper()
		cfg, ok := got["config"].(map[string]any)
		if !ok {
			t.Fatalf("no config block: %v", got)
		}
		values, _ := cfg["values"].(map[string]any)
		return values[string(agentconfig.KeyThirdPartyTLSEnrichment)]
	}
	owned := func(got map[string]any, field string) []string {
		t.Helper()
		block, ok := got["owned_networks"].(map[string]any)
		if !ok {
			t.Fatalf("heartbeat response carried no owned_networks block: %v\n"+
				"Without it the sensor treats only private space as the tenant's own.", got)
		}
		out := []string{}
		for _, v := range block[field].([]any) {
			out = append(out, v.(string))
		}
		return out
	}

	// A tenant that has said nothing: the opt-in is an explicit false, and
	// the owned networks are present and empty.
	got := beat()
	if v := optIn(got); v != false {
		t.Errorf("third_party_tls_enrichment = %v, want an explicit false by default", v)
	}
	for _, field := range []string{"prefixes", "endpoints", "excluded"} {
		if v := owned(got, field); len(v) != 0 {
			t.Errorf("owned_networks.%s = %v, want empty for a tenant that declared nothing", field, v)
		}
	}

	// The opt-in is set where every other sensor setting is set: the fleet
	// defaults, confirmed, on the app role.
	cfgHandler := handlers.NewSensorConfigHandler(app)
	if w := call(t, cfgHandler.PutSensorFleetDefaults, tenant, http.MethodPut,
		`{"values":{"third_party_tls_enrichment":true}}`, nil); w.Code != http.StatusConflict {
		t.Fatalf("unconfirmed opt-in = %d, want 409 asking for confirmation: %s", w.Code, w.Body.String())
	}
	if w := call(t, cfgHandler.PutSensorFleetDefaults, tenant, http.MethodPut,
		`{"values":{"third_party_tls_enrichment":true},"confirmed":true}`, nil); w.Code != http.StatusOK {
		t.Fatalf("confirmed opt-in = %d: %s", w.Code, w.Body.String())
	}

	segment := func(tenantID uuid.UUID, value, networkType, metadata string, active bool) {
		t.Helper()
		if _, err := admin.Exec(`INSERT INTO public.network_segments
			(tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
			VALUES ($1, $2, 'cidr', $3, $4, 'production', $5, $6::jsonb)`,
			tenantID, "seg-"+value, value, networkType, active, metadata); err != nil {
			t.Fatalf("seeding segment %s: %v", value, err)
		}
	}
	segment(tenant, "203.0.113.0/24", "public", `{}`, true)                             // declared public: owned
	segment(tenant, "192.0.2.128/25", "private", `{}`, true)                            // declared "private" over public space: owned
	segment(tenant, "198.51.100.0/24", "public", `{"source":"interrogation"}`, true)    // LEARNED: never owned
	segment(tenant, "10.20.0.0/16", "private", `{}`, true)                              // private by class: not sent
	segment(tenant, "192.0.2.0/25", "public", `{"sensitive":true}`, true)               // sensitive: excluded
	segment(tenant, "10.30.0.0/16", "private", `{"active_probes_disabled":true}`, true) // probes disabled: excluded
	segment(tenant, "2001:db8:5::/48", "public", `{}`, false)                           // inactive: nothing
	segment(other, "2001:db8:99::/48", "public", `{}`, true)                            // another tenant's: nothing
	// Saved before inventory-service refused them: too broad to be anybody's,
	// so never ownership (owner decision on). A /8 at the floor is.
	segment(tenant, "0.0.0.0/0", "public", `{}`, true)
	segment(tenant, "3ffe::/15", "public", `{}`, true)
	segment(tenant, "198.0.0.0/8", "public", `{}`, true)

	if _, err := admin.Exec(`INSERT INTO public.tenant_admin_settings (tenant_id, config)
		VALUES ($1, '{"identity_enrichment":{"excluded_cidrs":["203.0.113.64/26"]}}'::jsonb)`, tenant); err != nil {
		t.Fatalf("seeding scan exclusions: %v", err)
	}

	elevate := func(ip string, status string, deleted bool) {
		t.Helper()
		asset := uuid.New()
		if _, err := admin.Exec(`INSERT INTO public.assets (id, tenant_id, hostname, class_key, class_path, asset_status, asset_ownership, deleted_at)
			VALUES ($1, $2, $3, 'external', 'external', $4, 'third_party', CASE WHEN $5 THEN now() END)`,
			asset, tenant, "vendor-"+ip, status, deleted); err != nil {
			t.Fatalf("seeding elevated asset: %v", err)
		}
		if _, err := admin.Exec(`INSERT INTO public.external_connections (tenant_id, source_ip, dest_ip, dest_port, protocol, elevated_asset_id)
			VALUES ($1, '10.0.0.5', $2, 443, 'TLS', $3)`, tenant, ip, asset); err != nil {
			t.Fatalf("seeding elevated connection: %v", err)
		}
	}
	elevate("198.51.100.7", "monitoring", false) // elevated: owned endpoint
	elevate("198.51.100.9", "monitoring", true)  // its asset was deleted: nothing
	// A connection that was never elevated: nothing.
	if _, err := admin.Exec(`INSERT INTO public.external_connections (tenant_id, source_ip, dest_ip, dest_port, protocol)
		VALUES ($1, '10.0.0.5', '198.51.100.11', 443, 'TLS')`, tenant); err != nil {
		t.Fatalf("seeding plain connection: %v", err)
	}

	got = beat()
	if v := optIn(got); v != true {
		t.Errorf("third_party_tls_enrichment = %v, want true once the tenant opted in", v)
	}
	for field, want := range map[string][]string{
		"prefixes":  {"192.0.2.128/25", "198.0.0.0/8", "203.0.113.0/24"},
		"endpoints": {"198.51.100.7:443"},
		"excluded":  {"10.30.0.0/16", "192.0.2.0/25", "203.0.113.64/26"},
	} {
		if v := owned(got, field); !reflect.DeepEqual(v, want) {
			t.Errorf("owned_networks.%s = %v, want %v", field, v, want)
		}
	}
}
