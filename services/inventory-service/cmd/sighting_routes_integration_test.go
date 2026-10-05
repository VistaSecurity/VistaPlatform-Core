package main

// The internal sightings route end to end: the router main() builds, a real
// AssetService over Postgres, an HMAC-signed request. A call without the
// signature is refused; a signed one is resolved by THIS service's engine —
// the class hint, the endpoints and a self-reported (pinned) address all land
// — and the same sighting again matches the asset it created.
// Skips without TEST_DATABASE_URL.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SightingRoute_SignedCallResolvesThroughTheEngine(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	r := gin.New()
	mountSightingRoutes(r, handlers.NewSightingHandler(services.NewAssetService(db)), sourceTestSecret)

	const mac, addr = "a8:bb:cc:44:55:66", "10.91.0.1"
	body, err := json.Marshal(map[string]any{"sightings": []identity.Sighting{
		{
			Source:  identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation", Mode: identity.ModeActive},
			Channel: identity.ChannelAuthenticatedSession, ReceiptID: "sighting-route-1",
			ClassHint: "router",
			Identifiers: []identity.SightedIdentifier{
				{Kind: identity.KindMACAddress, Value: mac},
				{Kind: identity.KindIPAddress, Value: addr, Provenance: identity.IdentifierProvenance{SelfReported: true}},
			},
			Endpoints: []identity.EndpointObservation{{Address: addr, Port: 443, Transport: "tcp"}},
		},
		// Another tenant's sighting in this tenant's call: refused, not written.
		{TenantID: uuid.NewString(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation"},
			Channel: identity.ChannelL2Frame, Identifiers: []identity.SightedIdentifier{{Kind: identity.KindMACAddress, Value: "a8:bb:cc:44:55:77"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	post := func(sign bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, sightingsPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(serviceauth.HeaderTenantID, tenant.String())
		if sign {
			serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := post(false); w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned call = %d, want 401", w.Code)
	}
	var assets int
	if err := raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant).Scan(&assets); err != nil || assets != 0 {
		t.Fatalf("the refused call wrote %d assets (%v)", assets, err)
	}

	decode := func(w *httptest.ResponseRecorder) []services.SightingResult {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("signed call = %d %s, want 200", w.Code, w.Body.String())
		}
		var resp struct {
			Results []services.SightingResult `json:"results"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Results) != 2 {
			t.Fatalf("response %s: %v", w.Body.String(), err)
		}
		return resp.Results
	}
	first := decode(post(true))
	if first[0].Outcome != string(identity.OutcomeCreated) || first[0].AssetID == "" {
		t.Fatalf("first sighting = %+v, want created", first[0])
	}
	if first[1].Outcome != "rejected" || len(first[1].Reasons) != 1 || first[1].Reasons[0] != services.SightingReasonTenantMismatch {
		t.Fatalf("cross-tenant sighting = %+v, want rejected tenant_mismatch", first[1])
	}

	var class, assignment string
	var ports int
	if err := raw.QueryRow(`SELECT class_key FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, first[0].AssetID).Scan(&class); err != nil {
		t.Fatal(err)
	}
	if class != "router" {
		t.Errorf("class = %q, want the sighting's class hint router", class)
	}
	if err := raw.QueryRow(`SELECT coalesce(address_assignment,'') FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='ip_address' AND value=$3`,
		tenant, first[0].AssetID, addr).Scan(&assignment); err != nil {
		t.Fatal(err)
	}
	if assignment != string(identity.AssignmentStatic) {
		t.Errorf("self-reported address stored as %q, want static (pinned)", assignment)
	}
	if err := raw.QueryRow(`SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2 AND port=443`, tenant, first[0].AssetID).Scan(&ports); err != nil {
		t.Fatal(err)
	}
	if ports != 1 {
		t.Errorf("%d endpoint rows on 443, want the sighting's endpoint", ports)
	}

	second := decode(post(true))
	if second[0].Outcome != string(identity.OutcomeMatched) || second[0].AssetID != first[0].AssetID {
		t.Fatalf("the same sighting again = %+v, want matched on %s", second[0], first[0].AssetID)
	}
}

// TestIntegration_SightingRoute_WritesWhatTheResolutionOwes: what a posting
// collector's own engine wrote beside the resolution before is written
// by the route now — the synthetic names Intake withheld as identifiers (the
// asset's `synthetic_names` attribute) and a first-hand sighting's segment as
// the asset's placement. A hearsay sighting places nothing.
//
// MUTATION: drop the applySightingContext call in IngestSightings and both
// assertions go red.
func TestIntegration_SightingRoute_WritesWhatTheResolutionOwes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	location := uuid.New()
	if _, err := raw.Exec(`INSERT INTO locations(id,tenant_id,name,location_type) VALUES($1,$2,'HQ','site')`, location, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,location_id)
		VALUES($1,'HQ LAN','cidr','10.92.0.0/24','private','production',true,$2)`, tenant, location); err != nil {
		t.Fatal(err)
	}
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := services.NewAssetService(db)

	const synthetic = "0a1b2c3d-1111-2222-3333-444455556666"
	results, err := svc.IngestSightings(context.Background(), tenant, []services.SightingItem{{Sighting: identity.Sighting{
		Source:  identity.Source{Kind: identity.SourceMeasured, Ref: "agent:test", Mode: identity.ModeActive},
		Channel: identity.ChannelAuthenticatedSession, ReceiptID: "owes-1", ObservedAt: time.Now().UTC(),
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindAgentID, Value: uuid.NewString()},
			{Kind: identity.KindIPAddress, Value: "10.92.0.7"},
			{Kind: identity.KindHostname, Value: synthetic},
		},
	}}})
	if err != nil || len(results) != 1 || results[0].AssetID == "" {
		t.Fatalf("results %+v err %v", results, err)
	}
	var names, site string
	if err := raw.QueryRow(`SELECT coalesce(attributes->'synthetic_names','null')::text, coalesce(site,'') FROM assets WHERE tenant_id=$1 AND id=$2`,
		tenant, results[0].AssetID).Scan(&names, &site); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(names, synthetic) {
		t.Errorf("synthetic_names = %s, want the withheld name", names)
	}
	if site != "HQ" {
		t.Errorf("site = %q, want the first-hand sighting's segment placement HQ", site)
	}
}

// TestIntegration_SightingRoute_TargetedDeclaration drives the route's second
// shape: an item with target_asset_id is a declaration FOR that asset
// (Engine.ResolveDeclaredFor, the identifier edit's path), not a question to
// the engine. A typed address lands on the named asset pinned
// (address_assignment static, owner decision 1); one another asset owns
// writes nothing and answers `conflict` with the merge proposal the edit
// opens; a target that is not a live asset of the tenant, and a measured
// sighting naming a target, are rejected. The untargeted item in the same
// call keeps the ordinary shape.
//
// MUTATION: drop the TargetAssetID branch in IngestSightings and the
// declaration resolves through the engine instead: the address in a fresh
// tenant creates a NEW asset and the first assertion goes red.
func TestIntegration_SightingRoute_TargetedDeclaration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	r := gin.New()
	mountSightingRoutes(r, handlers.NewSightingHandler(services.NewAssetService(db)), sourceTestSecret)

	post := func(items []map[string]any) []services.SightingResult {
		t.Helper()
		body, err := json.Marshal(map[string]any{"sightings": items})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, sightingsPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(serviceauth.HeaderTenantID, tenant.String())
		serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var resp struct {
			Results []services.SightingResult `json:"results"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil || len(resp.Results) != len(items) {
			t.Fatalf("call = %d %s", w.Code, w.Body.String())
		}
		return resp.Results
	}
	measured := map[string]any{"kind": "measured", "ref": "interrogation", "mode": "active"}
	declared := map[string]any{"kind": "declared", "ref": "manual"}
	sighting := func(source map[string]any, channel string, ids ...map[string]any) map[string]any {
		return map[string]any{"source": source, "channel": channel, "observed_at": time.Now().UTC(), "identifiers": ids}
	}
	id := func(kind, value string) map[string]any { return map[string]any{"kind": kind, "value": value} }

	// Two assets, by ordinary (untargeted) sightings.
	made := post([]map[string]any{
		sighting(measured, "authenticated_session", id("mac_address", "a8:bb:cc:51:00:01")),
		sighting(measured, "authenticated_session", id("mac_address", "a8:bb:cc:51:00:02"), id("serial_number", "OTHER-SERIAL")),
	})
	device, other := made[0].AssetID, made[1].AssetID
	if made[0].Outcome != "created" || made[1].Outcome != "created" {
		t.Fatalf("setup = %+v", made)
	}

	edit := sighting(declared, "person", id("ip_address", "10.93.0.5"), id("hostname", "fw-edited"))
	edit["target_asset_id"] = device
	clash := sighting(declared, "person", id("serial_number", "OTHER-SERIAL"))
	clash["target_asset_id"] = device
	unknown := sighting(declared, "person", id("hostname", "nobody"))
	unknown["target_asset_id"] = uuid.NewString()
	notDeclared := sighting(measured, "l2_frame", id("hostname", "measured-claim"))
	notDeclared["target_asset_id"] = device
	plain := sighting(measured, "authenticated_session", id("mac_address", "a8:bb:cc:51:00:01"))

	got := post([]map[string]any{edit, clash, unknown, notDeclared, plain})
	if got[0].Outcome != "matched" || got[0].AssetID != device {
		t.Fatalf("targeted edit = %+v, want matched on the named asset %s", got[0], device)
	}
	var assignment, owner string
	if err := raw.QueryRow(`SELECT asset_id::text, coalesce(address_assignment,'') FROM asset_identifiers WHERE tenant_id=$1 AND kind='ip_address' AND value='10.93.0.5'`,
		tenant).Scan(&owner, &assignment); err != nil {
		t.Fatal(err)
	}
	if owner != device || assignment != string(identity.AssignmentStatic) {
		t.Errorf("typed address on %s as %q, want on %s pinned static", owner, assignment, device)
	}
	if got[1].Outcome != "conflict" || got[1].AssetID != device || got[1].ProposalID == "" ||
		len(got[1].Reasons) != 1 || got[1].Reasons[0] != services.SightingReasonDeclaredIdentifierConflict {
		t.Errorf("serial owned by another asset = %+v, want conflict with a proposal", got[1])
	}
	var serialOwner string
	if err := raw.QueryRow(`SELECT asset_id::text FROM asset_identifiers WHERE tenant_id=$1 AND kind='serial_number' AND value='OTHER-SERIAL'`, tenant).Scan(&serialOwner); err != nil || serialOwner != other {
		t.Errorf("the conflicting serial moved to %s (%v); a refused declaration writes nothing", serialOwner, err)
	}
	if got[2].Outcome != "rejected" || got[2].Reasons[0] != services.SightingReasonUnknownTarget {
		t.Errorf("unknown target = %+v", got[2])
	}
	if got[3].Outcome != "rejected" || got[3].Reasons[0] != services.SightingReasonInvalid {
		t.Errorf("a measured sighting naming its asset = %+v, want rejected invalid", got[3])
	}
	if got[4].Outcome != "matched" || got[4].AssetID != device {
		t.Errorf("untargeted item beside them = %+v, want the ordinary match", got[4])
	}
}

// TestIntegration_SightingRoute_HearsayPeerInheritsItsSegmentsSite: a peer a
// controller describes (a UniFi client: l2_frame hearsay, so no first-hand
// placement) is created INSIDE a located segment. It must carry that segment's
// location and site, or the network map draws the segment twice — once under
// the segment's site, once under "No site recorded" (seen live: 14 UniFi
// clients in one /24). An asset already in that state heals on its next
// sighting, and a site somebody stated is never overwritten.
//
// MUTATION: drop the InheritSegmentLocation call in resolveObservationWithRepo
// and the created and healed assertions go red. The other polarity: make the
// placement write ignore a disagreeing site and the curated assertion goes red.
func TestIntegration_SightingRoute_HearsayPeerInheritsItsSegmentsSite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	location := uuid.New()
	if _, err := raw.Exec(`INSERT INTO locations(id,tenant_id,name,location_type) VALUES($1,$2,'Branch','site')`, location, tenant); err != nil {
		t.Fatal(err)
	}
	var segment string
	if err := raw.QueryRow(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,location_id)
		VALUES($1,'Branch LAN','cidr','10.94.0.0/24','private','production',true,$2) RETURNING id::text`, tenant, location).Scan(&segment); err != nil {
		t.Fatal(err)
	}
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	r := gin.New()
	mountSightingRoutes(r, handlers.NewSightingHandler(services.NewAssetService(db)), sourceTestSecret)

	const mac, addr = "a8:bb:cc:94:00:01", "10.94.0.11"
	post := func() services.SightingResult {
		t.Helper()
		body, err := json.Marshal(map[string]any{"sightings": []identity.Sighting{{
			Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:" + uuid.NewString(), Mode: identity.ModeActive},
			Channel:    identity.ChannelL2Frame,
			ObservedAt: time.Now().UTC(),
			Confidence: 0.8,
			Ownership:  identity.OwnershipInternal,
			Identifiers: []identity.SightedIdentifier{
				{Kind: identity.KindMACAddress, Value: mac},
				{Kind: identity.KindIPAddress, Value: addr},
			},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, sightingsPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(serviceauth.HeaderTenantID, tenant.String())
		serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var resp struct {
			Results []services.SightingResult `json:"results"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil || len(resp.Results) != 1 || resp.Results[0].AssetID == "" {
			t.Fatalf("call = %d %s", w.Code, w.Body.String())
		}
		return resp.Results[0]
	}
	placement := func(asset string) (seg, loc, site string) {
		t.Helper()
		if err := raw.QueryRow(`SELECT coalesce(network_segment_id::text,''),coalesce(location_id::text,''),coalesce(site,'') FROM assets WHERE tenant_id=$1 AND id=$2`,
			tenant, asset).Scan(&seg, &loc, &site); err != nil {
			t.Fatal(err)
		}
		return seg, loc, site
	}

	// 1. Created by hearsay inside the located segment: born placed.
	created := post()
	if created.Outcome != string(identity.OutcomeCreated) {
		t.Fatalf("setup outcome = %+v, want created", created)
	}
	if seg, loc, site := placement(created.AssetID); seg != segment || loc != location.String() || site != "Branch" {
		t.Errorf("hearsay-created asset placement = (%s, %s, %q), want (%s, %s, \"Branch\")", seg, loc, site, segment, location)
	}

	// 2. The live state before the fix: in the segment, no location, no site.
	// The next sighting heals it.
	if _, err := raw.Exec(`UPDATE assets SET location_id=NULL, site=NULL WHERE tenant_id=$1 AND id=$2`, tenant, created.AssetID); err != nil {
		t.Fatal(err)
	}
	if again := post(); again.AssetID != created.AssetID {
		t.Fatalf("re-sighting = %+v, want a match on %s", again, created.AssetID)
	}
	if _, loc, site := placement(created.AssetID); loc != location.String() || site != "Branch" {
		t.Errorf("re-sighted asset placement = (%s, %q), want healed to (%s, \"Branch\")", loc, site, location)
	}

	// 3. A site somebody stated wins over the segment's.
	if _, err := raw.Exec(`UPDATE assets SET location_id=NULL, site='Curated' WHERE tenant_id=$1 AND id=$2`, tenant, created.AssetID); err != nil {
		t.Fatal(err)
	}
	post()
	if _, loc, site := placement(created.AssetID); loc != "" || site != "Curated" {
		t.Errorf("curated asset placement = (%s, %q), want it left at (\"\", \"Curated\")", loc, site)
	}
}
