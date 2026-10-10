package main

// WP7 F12, through the route device-interrogation posts to as deployed:
// the router main() builds, an HMAC-signed request, this service's engine. A
// host's own report carries its complete socket set; the next report that
// drops a socket closes it on THIS side, inside the engine's transaction, and
// says how many it closed. A socket another source recorded is untouched, and
// a virtual interface's address is kept as attribute evidence, never as an
// identifier. Skips without TEST_DATABASE_URL.
//
// MUTATION: drop the reconcile call in identity.Engine.applyToAsset, or the
// EndpointsComplete copy in Intake, and the :443 row stays active.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const (
	hostinvRouteMAC   = "a8:bb:cc:44:55:9a"
	hostinvRouteAddr  = "10.91.0.9"
	hostinvRouteAgent = "agent:5b2e"
)

func hostinvRouteReport(run string, at time.Time, ports ...int) identity.Sighting {
	eps := make([]identity.EndpointObservation, 0, len(ports))
	for _, p := range ports {
		eps = append(eps, identity.EndpointObservation{Address: hostinvRouteAddr, Port: p, Transport: "tcp",
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: hostinvRouteAgent + ":" + run, Mode: identity.ModeActive}})
	}
	return identity.Sighting{
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: hostinvRouteAgent, Mode: identity.ModeActive},
		Channel:    identity.ChannelAuthenticatedSession,
		ObservedAt: at,
		ReceiptID:  hostinvRouteAgent + ":" + run,
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindMACAddress, Value: hostinvRouteMAC},
			{Kind: identity.KindIPAddress, Value: hostinvRouteAddr, Provenance: identity.IdentifierProvenance{SelfReported: true}},
			{Kind: identity.KindIPAddress, Value: "172.17.0.1", Provenance: identity.IdentifierProvenance{VirtualInterface: true}},
		},
		Endpoints:         eps,
		EndpointsComplete: &identity.CompleteEndpointSet{SourcePrefix: hostinvRouteAgent + ":"},
	}
}

func TestIntegration_SightingRoute_ACompleteEndpointSetClosesTheDroppedSocket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	r := gin.New()
	mountSightingRoutes(r, handlers.NewSightingHandler(services.NewAssetService(db)), sourceTestSecret)

	post := func(s identity.Sighting) services.SightingResult {
		t.Helper()
		body, err := json.Marshal(map[string]any{"sightings": []identity.Sighting{s}})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, sightingsPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(serviceauth.HeaderTenantID, tenant.String())
		serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("signed call = %d %s", w.Code, w.Body.String())
		}
		var resp struct {
			Results []services.SightingResult `json:"results"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Results) != 1 {
			t.Fatalf("response %s: %v", w.Body.String(), err)
		}
		return resp.Results[0]
	}
	status := func(assetID string, port int) string {
		t.Helper()
		var s string
		if err := raw.QueryRow(`SELECT status FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2 AND port=$3`, tenant, assetID, port).Scan(&s); err != nil {
			t.Fatalf("endpoint :%d: %v", port, err)
		}
		return s
	}

	at := time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
	first := post(hostinvRouteReport("run1", at, 22, 443))
	if first.Outcome != string(identity.OutcomeCreated) || first.AssetID == "" {
		t.Fatalf("first report = %+v, want created", first)
	}
	// A socket a scan recorded: not the agent's to close.
	if _, err := raw.Exec(`INSERT INTO asset_endpoints (tenant_id, asset_id, address, port, transport, source_kind, source_ref, status, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3::inet, 8443, 'tcp', 'measured', 'scan:run-1', 'active', $4, $4)`, tenant, first.AssetID, hostinvRouteAddr, at); err != nil {
		t.Fatalf("seed a scan endpoint: %v", err)
	}

	second := post(hostinvRouteReport("run2", at.Add(time.Hour), 22))
	if second.Outcome != string(identity.OutcomeMatched) || second.AssetID != first.AssetID {
		t.Fatalf("second report = %+v, want matched on %s", second, first.AssetID)
	}
	if second.EndpointsClosed != 1 {
		t.Errorf("endpoints_closed = %d, want 1", second.EndpointsClosed)
	}
	if got := status(first.AssetID, 443); got != "closed" {
		t.Errorf(":443 is %q after the report dropped it, want closed", got)
	}
	if got := status(first.AssetID, 22); got != "active" {
		t.Errorf(":22 is %q, want active", got)
	}
	if got := status(first.AssetID, 8443); got != "active" {
		t.Errorf("the scan's :8443 is %q; the agent's set says nothing about another source's sockets", got)
	}

	var bridgeOwned int
	if err := raw.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND kind='ip_address' AND value='172.17.0.1'`, tenant).Scan(&bridgeOwned); err != nil {
		t.Fatal(err)
	}
	if bridgeOwned != 0 {
		t.Error("a virtual interface's address became an identifier")
	}
	var kept string
	if err := raw.QueryRow(`SELECT coalesce(attributes->>'virtual_interface_addresses','') FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, first.AssetID).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != `["172.17.0.1"]` {
		t.Errorf("virtual_interface_addresses = %q, want the bridge address kept as evidence", kept)
	}
}
