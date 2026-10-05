package main

// slice A on inventory-service's REAL internal sightings route: the
// router main() builds, an HMAC-signed call, this service's engine. Skips
// without TEST_DATABASE_URL.
//
//   - a gateway's claimed address re-homes from a provisional holder, and the
//     claim sighting places nothing (the device's home segment is set by the
//     interrogation, not by whichever network it claimed first);
//   - a host an interrogation reported auto-approves on a segment whose
//     auto-approval is on (D3), and only there, and only for an interrogation.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func postSightings(t *testing.T, r *gin.Engine, tenant uuid.UUID, sightings ...identity.Sighting) []services.SightingResult {
	t.Helper()
	body, err := json.Marshal(map[string]any{"sightings": sightings})
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
		t.Fatalf("sightings call = %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Results []services.SightingResult `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Results) != len(sightings) {
		t.Fatalf("response %s: %v", w.Body.String(), err)
	}
	return resp.Results
}

func TestIntegration_SightingRoute_GatewayClaimRehomesAndPlacesNothing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	location := uuid.New()
	if _, err := raw.Exec(`INSERT INTO locations(id,tenant_id,name,location_type) VALUES($1,$2,'Branch','site')`, location, tenant); err != nil {
		t.Fatal(err)
	}
	var segment string
	if err := raw.QueryRow(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,location_id,metadata)
		VALUES($1,'Branch LAN','cidr','192.0.2.0/24','private','production',true,$2,'{"dynamic":true}') RETURNING id::text`, tenant, location).Scan(&segment); err != nil {
		t.Fatal(err)
	}
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := services.NewAssetService(db)
	r := gin.New()
	mountSightingRoutes(r, handlers.NewSightingHandler(svc), sourceTestSecret)
	ctx := t.Context()
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	interrogation := identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:" + uuid.NewString(), Mode: identity.ModeActive}

	// The gateway, known by its serial, with no segment and no site.
	created := postSightings(t, r, tenant, identity.Sighting{
		Source: interrogation, Channel: identity.ChannelControllerInventory, ObservedAt: at, ClassHint: "router",
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "GW-ROUTE-1"}},
	})
	gateway := created[0].AssetID
	if gateway == "" {
		t.Fatalf("gateway not created: %+v", created[0])
	}
	if _, err := raw.Exec(`UPDATE assets SET network_segment_id=NULL, location_id=NULL, site=NULL WHERE id=$1`, gateway); err != nil {
		t.Fatal(err)
	}
	// A provisional guess holding the gateway's address on that network.
	guessRef, err := pgidentity.New(raw).CreateAsset(ctx, tenant.String(), identity.NewAsset{
		ClassKey: "unknown_host", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: "guess",
		Status: identity.StatusPendingApproval, IdentityStatus: string(identity.IdentityProvisional),
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture"},
		Identifiers: []identity.Identifier{{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: segment, Confidence: 1,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture"}, SeenAt: at.Add(-24 * time.Hour)}},
		FirstSeenAt: at.Add(-24 * time.Hour), LastSeenAt: at.Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("seed the provisional guess: %v", err)
	}
	guess := guessRef.ID

	res := postSightings(t, r, tenant, identity.Sighting{
		Source: interrogation, Channel: identity.ChannelAuthenticatedSession, ObservedAt: at.Add(time.Hour), Confidence: 1,
		Ownership: identity.OwnershipInternal,
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindIPAddress, Value: "192.0.2.1", Provenance: identity.IdentifierProvenance{SelfReported: true, Claimed: true}},
			{Kind: identity.KindSerialNumber, Value: "GW-ROUTE-1", Provenance: identity.IdentifierProvenance{Kind: identity.SourceInferred, Ref: "asset:" + gateway}},
		},
	})
	if res[0].Outcome != string(identity.OutcomeMatched) || res[0].AssetID != gateway {
		t.Fatalf("claim = %+v, want matched on the gateway %s", res[0], gateway)
	}
	var holder, assignment string
	if err := raw.QueryRowContext(ctx, `SELECT asset_id::text, coalesce(address_assignment,'') FROM asset_identifiers WHERE tenant_id=$1 AND kind='ip_address' AND value='192.0.2.1'`,
		tenant).Scan(&holder, &assignment); err != nil {
		t.Fatal(err)
	}
	if holder != gateway || assignment != "static" {
		t.Errorf("192.0.2.1 held by %s (%q), want the gateway, pinned (the guess was %s)", holder, assignment, guess)
	}
	var site string
	if err := raw.QueryRowContext(ctx, `SELECT coalesce(site,'') FROM assets WHERE id=$1`, gateway).Scan(&site); err != nil {
		t.Fatal(err)
	}
	if site != "" {
		t.Errorf("a claim sighting placed the gateway at %q; only its home segment places it", site)
	}
}

func TestIntegration_SightingRoute_InterrogatedHostsAutoApproveOnAutoApproveSegments(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	segSvc := services.NewNetworkSegmentService(db, services.NewLocationService(db))
	for cidr, auto := range map[string]bool{"192.0.2.0/24": true, "198.51.100.0/24": false} {
		if _, err := raw.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,auto_approve_discoveries)
			VALUES($1,$2,'cidr',$2,'private','production',true,$3)`, tenant, cidr, auto); err != nil {
			t.Fatal(err)
		}
	}
	if err := segSvc.ManageAutoApprovalRules(tenant, uuid.Nil); err != nil {
		t.Fatalf("ManageAutoApprovalRules: %v", err)
	}
	svc := services.NewAssetService(db)
	svc.SetEnrichmentServices(segSvc, nil)
	r := gin.New()
	mountSightingRoutes(r, handlers.NewSightingHandler(svc), sourceTestSecret)

	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	peer := func(ref, mac, addr string) identity.Sighting {
		return identity.Sighting{
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: ref, Mode: identity.ModeActive}, Channel: identity.ChannelL2Frame,
			ObservedAt: at, Confidence: 0.8, Ownership: identity.OwnershipInternal,
			Identifiers: []identity.SightedIdentifier{{Kind: identity.KindMACAddress, Value: mac}, {Kind: identity.KindIPAddress, Value: addr}},
		}
	}
	job := "interrogation:" + uuid.NewString()
	res := postSightings(t, r, tenant,
		peer(job, "00:00:5e:00:53:21", "192.0.2.21"),              // interrogation, auto-approve segment
		peer(job, "00:00:5e:00:53:22", "198.51.100.22"),           // interrogation, auto-approve off
		peer("sensor:fixture", "00:00:5e:00:53:23", "192.0.2.23"), // not an interrogation
	)
	want := []string{"monitoring", "pending_approval", "pending_approval"}
	for i, rr := range res {
		if rr.AssetID == "" {
			t.Fatalf("sighting %d created nothing: %+v", i, rr)
		}
		var status string
		if err := raw.QueryRow(`SELECT asset_status FROM assets WHERE id=$1`, rr.AssetID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != want[i] {
			t.Errorf("sighting %d (%s): asset is %q, want %q", i, rr.Outcome, status, want[i])
		}
	}
	var approvals int
	if err := raw.QueryRow(`SELECT count(*) FROM asset_history WHERE asset_id=$1 AND action='approved'`, res[0].AssetID).Scan(&approvals); err != nil {
		t.Fatal(err)
	}
	if approvals != 1 {
		t.Errorf("the auto-approval wrote %d approved history entries, want 1", approvals)
	}

	// A PROVISIONAL asset the interrogation matches is not approved by the
	// segment: a guess consumes no allowance until something promotes it.
	var segment string
	if err := raw.QueryRow(`SELECT id::text FROM network_segments WHERE tenant_id=$1 AND value='192.0.2.0/24'`, tenant).Scan(&segment); err != nil {
		t.Fatal(err)
	}
	guess, err := pgidentity.New(raw).CreateAsset(t.Context(), tenant.String(), identity.NewAsset{
		ClassKey: "unknown_host", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: "guess",
		Status: identity.StatusPendingApproval, IdentityStatus: string(identity.IdentityProvisional), NetworkSegment: segment,
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture"},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:24", Confidence: 1, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture"}, SeenAt: at},
		},
		FirstSeenAt: at, LastSeenAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	matched := postSightings(t, r, tenant, peer(job, "00:00:5e:00:53:24", "192.0.2.24"))
	if matched[0].AssetID != guess.ID {
		t.Fatalf("the interrogation did not match the provisional asset: %+v", matched[0])
	}
	var status, identityStatus string
	if err := raw.QueryRow(`SELECT asset_status, identity_status FROM assets WHERE id=$1`, guess.ID).Scan(&status, &identityStatus); err != nil {
		t.Fatal(err)
	}
	if identityStatus != string(identity.IdentityProvisional) {
		t.Fatalf("fixture: the match promoted the provisional asset (%s), so the case under test never arose", identityStatus)
	}
	if status != "pending_approval" {
		t.Errorf("a provisional asset was auto-approved (%s)", status)
	}
}
