package main

// slice B on inventory-service's REAL internal routes: the router main()
// builds, HMAC-signed calls, this service's engine. The gateway's claimed
// addresses go through POST /internal/sightings exactly as an interrogation
// posts them, then the run's complete list through POST /internal/gateway-links,
// and every read a tenant sees (Network Segments, the asset page, the map) is
// checked against what was written. Skips without TEST_DATABASE_URL.

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
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const gatewayLinksPath = "/api/v1/inventory-service/internal/gateway-links"

func postGatewayLinks(t *testing.T, r *gin.Engine, tenant uuid.UUID, req sightingclient.GatewayLinksRequest) (int, sightingclient.GatewayLinksResult) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	hr := httptest.NewRequest(http.MethodPost, gatewayLinksPath, bytes.NewReader(body))
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set(serviceauth.HeaderTenantID, tenant.String())
	serviceauth.NewSigner(sourceTestSecret).SignRequest(hr)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, hr)
	var out sightingclient.GatewayLinksResult
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("gateway links response %s: %v", w.Body.String(), err)
		}
	}
	return w.Code, out
}

type gatewayFixture struct {
	t        *testing.T
	raw      *sqlx.DB
	r        *gin.Engine
	svc      *services.AssetService
	segSvc   *services.NetworkSegmentService
	tenant   uuid.UUID
	segments map[string]uuid.UUID // cidr → id
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	segSvc := services.NewNetworkSegmentService(db, services.NewLocationService(db))
	svc := services.NewAssetService(db)
	svc.SetEnrichmentServices(segSvc, nil)
	r := gin.New()
	mountSightingRoutes(r, handlers.NewSightingHandler(svc), sourceTestSecret)
	f := &gatewayFixture{t: t, raw: db.DB, r: r, svc: svc, segSvc: segSvc, tenant: tenant, segments: map[string]uuid.UUID{}}
	for name, cidr := range map[string]string{"Branch LAN": "192.0.2.0/24", "Guest": "198.51.100.0/24", "Lab": "203.0.113.0/24"} {
		f.segments[cidr] = f.segment(tenant, name, cidr)
	}
	return f
}

func (f *gatewayFixture) segment(tenant uuid.UUID, name, cidr string) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.raw.QueryRow(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata)
		VALUES($1,$2,'cidr',$3,'private','production',true,'{"dynamic":true}') RETURNING id`, tenant, name, cidr).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// device creates a device known by its serial, as an interrogation's first
// sighting of it does.
func (f *gatewayFixture) device(serial string, at time.Time) uuid.UUID {
	f.t.Helper()
	res := postSightings(f.t, f.r, f.tenant, identity.Sighting{
		Source:  identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:" + uuid.NewString(), Mode: identity.ModeActive},
		Channel: identity.ChannelControllerInventory, ObservedAt: at, ClassHint: "router",
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: serial}},
	})
	id, err := uuid.Parse(res[0].AssetID)
	if err != nil {
		f.t.Fatalf("device %s not created: %+v", serial, res[0])
	}
	return id
}

// claim posts one claimed-address sighting for the device, as
// device-interrogation-service's claimGatewayAddresses does.
func (f *gatewayFixture) claim(device uuid.UUID, serial, job, address string, at time.Time) services.SightingResult {
	f.t.Helper()
	return postSightings(f.t, f.r, f.tenant, identity.Sighting{
		Source:  identity.Source{Kind: identity.SourceMeasured, Ref: job, Mode: identity.ModeActive},
		Channel: identity.ChannelAuthenticatedSession, ObservedAt: at, Confidence: 1, Ownership: identity.OwnershipInternal,
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindIPAddress, Value: address, Provenance: identity.IdentifierProvenance{SelfReported: true, Claimed: true}},
			{Kind: identity.KindSerialNumber, Value: serial, Provenance: identity.IdentifierProvenance{Kind: identity.SourceInferred, Ref: "asset:" + device.String()}},
		},
	})[0]
}

type storedLink struct {
	asset      *uuid.UUID
	address    *string
	ref        *string
	observedAt *time.Time
	updatedAt  time.Time
	candidates string
}

func (f *gatewayFixture) stored(segment uuid.UUID) storedLink {
	f.t.Helper()
	var s storedLink
	if err := f.raw.QueryRow(`SELECT gateway_asset_id, host(gateway_address), gateway_source_ref, gateway_observed_at, updated_at,
		coalesce(metadata->'gateway_candidates','{}'::jsonb)::text FROM network_segments WHERE id=$1`, segment).
		Scan(&s.asset, &s.address, &s.ref, &s.observedAt, &s.updatedAt, &s.candidates); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *gatewayFixture) listed(tenant uuid.UUID) map[uuid.UUID]models.NetworkSegment {
	f.t.Helper()
	list, _, err := f.segSvc.List(tenant, models.NetworkSegmentFilters{PageSize: 100})
	if err != nil {
		f.t.Fatalf("list segments: %v", err)
	}
	out := map[uuid.UUID]models.NetworkSegment{}
	for _, s := range list {
		out[s.ID] = s
	}
	return out
}

func TestIntegration_GatewayLinksRoute_LinkFollowsTheHeldAddress(t *testing.T) {
	f := newGatewayFixture(t)
	lan, guest, lab := f.segments["192.0.2.0/24"], f.segments["198.51.100.0/24"], f.segments["203.0.113.0/24"]
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	gw := f.device("GW-LINK-1", at)

	// An ESTABLISHED asset holds the gateway's address on Lab together with
	// a MAC: the claim is contested, a merge proposal opens, and the gateway
	// does not get the address.
	labHolder, err := pgidentity.New(f.raw.DB).CreateAsset(t.Context(), f.tenant.String(), identity.NewAsset{
		ClassKey: "server", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: "lab-server",
		Status: identity.StatusMonitoring, NetworkSegment: lab.String(),
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture"},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindIPAddress, Value: "203.0.113.1", Scope: lab.String(), Confidence: 1, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture"}, SeenAt: at},
			{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:41", Confidence: 1, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture"}, SeenAt: at},
		},
		FirstSeenAt: at, LastSeenAt: at,
	})
	if err != nil {
		t.Fatalf("seed the established holder: %v", err)
	}

	job := "interrogation:" + uuid.NewString()
	run1 := at.Add(time.Hour)
	for _, a := range []string{"192.0.2.1", "198.51.100.1"} {
		if r := f.claim(gw, "GW-LINK-1", job, a, run1); r.AssetID != gw.String() {
			t.Fatalf("claim %s = %+v, want the gateway", a, r)
		}
	}
	if r := f.claim(gw, "GW-LINK-1", job, "203.0.113.1", run1); r.AssetID == gw.String() {
		t.Fatalf("fixture: the contested claim landed on the gateway (%+v), so the case under test never arose", r)
	}

	all := []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}
	code, res := postGatewayLinks(t, f.r, f.tenant, sightingclient.GatewayLinksRequest{AssetID: gw.String(), SourceRef: job, ObservedAt: run1, Addresses: all})
	if code != http.StatusOK || len(res.Linked) != 2 || len(res.Cleared) != 0 {
		t.Fatalf("first run = %d %+v, want two segments linked", code, res)
	}
	for seg, addr := range map[uuid.UUID]string{lan: "192.0.2.1", guest: "198.51.100.1"} {
		s := f.stored(seg)
		if s.asset == nil || *s.asset != gw || s.address == nil || *s.address != addr || s.ref == nil || *s.ref != job ||
			s.observedAt == nil || !s.observedAt.Equal(run1) {
			t.Errorf("segment %s link = %+v, want the gateway at %s from %s", seg, s, addr, job)
		}
	}
	if s := f.stored(lab); s.asset != nil {
		t.Errorf("the CONTESTED network was linked to %s; the device does not hold its address there", *s.asset)
	}

	// Idempotent: the same run again changes nothing, not even updated_at.
	before := f.stored(lan)
	code, res = postGatewayLinks(t, f.r, f.tenant, sightingclient.GatewayLinksRequest{AssetID: gw.String(), SourceRef: job, ObservedAt: run1, Addresses: all})
	if code != http.StatusOK || len(res.Linked) != 2 {
		t.Fatalf("re-run = %d %+v", code, res)
	}
	if after := f.stored(lan); !after.updatedAt.Equal(before.updatedAt) {
		t.Errorf("an identical re-run rewrote the segment (updated_at %s → %s)", before.updatedAt, after.updatedAt)
	}

	// Reads: the Network Segments page.
	sensor := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_capabilities,reported_dns_interfaces)
		VALUES($1,$2,'branch-collector','linux','test-v1','datacenter_host','active',now(),ARRAY['eth0'],ARRAY['identity_dns_v1'],ARRAY['eth0'])`, sensor, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0','192.0.2.10',24)`, sensor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`UPDATE assets SET display_name='edge-router' WHERE id=$1`, gw); err != nil {
		t.Fatal(err)
	}
	listed := f.listed(f.tenant)
	if g := listed[lan].Gateway; g == nil || g.AssetID != gw || g.DisplayName != "edge-router" || g.Address != "192.0.2.1" || !g.ObservedAt.Equal(run1) {
		t.Errorf("Branch LAN gateway = %+v", g)
	}
	if c := listed[lan].Coverage; c == nil || c.SensorID != sensor || c.SensorName != "branch-collector" {
		t.Errorf("Branch LAN coverage = %+v, want the collector with an interface in it", c)
	}
	if c := listed[guest].Coverage; c != nil {
		t.Errorf("Guest coverage = %+v, want none: no collector has an interface there", c)
	}
	if g := listed[lab].Gateway; g != nil {
		t.Errorf("Lab gateway = %+v, want none", g)
	}

	// Reads: the gateway's own page ("Networks routed") and a host's ("via").
	if _, err := f.raw.Exec(`INSERT INTO asset_facts(tenant_id,asset_id,key,value,source_kind,source_ref)
		VALUES($1,$2,'net.vlans','[{"name":"Branch LAN","subnet":"192.0.2.0/24","gateway":"192.0.2.1"},{"id":20,"name":"Guest","subnet":"198.51.100.0/24","gateway":"198.51.100.1"}]','measured',$3)`,
		f.tenant, gw, job); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`UPDATE assets SET network_segment_id=$2 WHERE id=$1`, gw, lan); err != nil {
		t.Fatal(err)
	}
	host := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,display_name,class_key,class_path,class_source_kind,environment,asset_status,network_segment_id)
		VALUES($1,$2,'host-a','host-a','server','hardware.computer.server','measured','production','monitoring',$3)`, host, f.tenant, lan); err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.GetAssetByID(f.tenant, gw)
	if err != nil {
		t.Fatal(err)
	}
	if page.RoutedSegments == nil || len(*page.RoutedSegments) != 2 {
		t.Fatalf("routed segments = %+v, want Branch LAN and Guest", page.RoutedSegments)
	}
	byID := map[uuid.UUID]models.RoutedSegment{}
	for _, rs := range *page.RoutedSegments {
		byID[rs.SegmentID] = rs
	}
	if rs := byID[lan]; rs.Address != "192.0.2.1" || rs.VLANID != nil || rs.HostCount != 2 || rs.Coverage == nil || rs.Dynamic == nil || !*rs.Dynamic {
		t.Errorf("Branch LAN routed = %+v (want untagged, 2 hosts, covered, dynamic)", rs)
	}
	if rs := byID[guest]; rs.VLANID == nil || *rs.VLANID != 20 || rs.HostCount != 0 || rs.Coverage != nil {
		t.Errorf("Guest routed = %+v (want tag 20, no hosts, uncovered)", rs)
	}
	if page.SegmentGateway != nil {
		t.Errorf("the gateway reads as routed via itself: %+v", page.SegmentGateway)
	}
	hostPage, err := f.svc.GetAssetByID(f.tenant, host)
	if err != nil {
		t.Fatal(err)
	}
	if hostPage.SegmentGateway == nil || hostPage.SegmentGateway.AssetID != gw {
		t.Errorf("host via = %+v, want the gateway", hostPage.SegmentGateway)
	}
	if hostPage.RoutedSegments == nil || len(*hostPage.RoutedSegments) != 0 {
		t.Errorf("a host that routes nothing reads routed_segments %+v, want []", hostPage.RoutedSegments)
	}

	// Reads: the map.
	m, err := f.svc.GetNetworkMap(t.Context(), f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range m.Segments {
		switch s.SegmentID {
		case lan:
			if s.Gateway == nil || s.Gateway.AssetID != gw {
				t.Errorf("map Branch LAN gateway = %+v", s.Gateway)
			}
		case lab:
			if s.Gateway != nil {
				t.Errorf("map Lab gateway = %+v, want none", s.Gateway)
			}
		}
	}

	// The device stops reporting Guest: that link alone is cleared.
	job2 := "interrogation:" + uuid.NewString()
	run2 := run1.Add(time.Hour)
	code, res = postGatewayLinks(t, f.r, f.tenant, sightingclient.GatewayLinksRequest{AssetID: gw.String(), SourceRef: job2, ObservedAt: run2, Addresses: []string{"192.0.2.1", "203.0.113.1"}})
	if code != http.StatusOK || len(res.Linked) != 1 || len(res.Cleared) != 1 || res.Cleared[0] != guest.String() {
		t.Fatalf("run 2 = %d %+v, want Branch LAN kept and Guest cleared", code, res)
	}
	if s := f.stored(guest); s.asset != nil || s.address != nil || s.ref != nil || s.observedAt != nil {
		t.Errorf("Guest after it stopped being reported = %+v, want every column cleared", s)
	}
	if s := f.stored(lan); s.ref == nil || *s.ref != job2 || !s.observedAt.Equal(run2) {
		t.Errorf("Branch LAN after run 2 = %+v, want refreshed to %s", s, job2)
	}

	// A second device reports serving Branch LAN, more recently: it is the
	// gateway now, and the first is kept as a candidate. The first device's
	// later run with an OLDER observation does not take it back.
	gw2 := f.device("GW-LINK-2", at)
	job3 := "interrogation:" + uuid.NewString()
	run3 := run2.Add(time.Hour)
	if r := f.claim(gw2, "GW-LINK-2", job3, "192.0.2.2", run3); r.AssetID != gw2.String() {
		t.Fatalf("second gateway claim = %+v", r)
	}
	if code, res = postGatewayLinks(t, f.r, f.tenant, sightingclient.GatewayLinksRequest{AssetID: gw2.String(), SourceRef: job3, ObservedAt: run3, Addresses: []string{"192.0.2.2"}}); code != http.StatusOK || len(res.Linked) != 1 {
		t.Fatalf("second gateway = %d %+v", code, res)
	}
	s := f.stored(lan)
	if s.asset == nil || *s.asset != gw2 || *s.address != "192.0.2.2" {
		t.Errorf("Branch LAN after the newer claim = %+v, want the second gateway", s)
	}
	var cands map[string]map[string]string
	if err := json.Unmarshal([]byte(s.candidates), &cands); err != nil || cands[gw.String()]["address"] != "192.0.2.1" {
		t.Errorf("candidates = %s, want the first gateway kept at 192.0.2.1", s.candidates)
	}
	if code, res = postGatewayLinks(t, f.r, f.tenant, sightingclient.GatewayLinksRequest{AssetID: gw.String(), SourceRef: job2, ObservedAt: run2, Addresses: []string{"192.0.2.1"}}); code != http.StatusOK || len(res.Candidates) != 1 || len(res.Linked) != 0 {
		t.Fatalf("older run of the first gateway = %d %+v, want a candidate only", code, res)
	}
	if s := f.stored(lan); *s.asset != gw2 {
		t.Errorf("an older observation took Branch LAN back: %+v", s)
	}
	// The first device's run that no longer reports Branch LAN never touches
	// the second device's link; it only withdraws its own candidacy.
	if code, res = postGatewayLinks(t, f.r, f.tenant, sightingclient.GatewayLinksRequest{AssetID: gw.String(), SourceRef: job2, ObservedAt: run3.Add(time.Hour), Addresses: []string{}}); code != http.StatusOK || len(res.Cleared) != 0 {
		t.Fatalf("empty run of the first gateway = %d %+v", code, res)
	}
	if s := f.stored(lan); s.asset == nil || *s.asset != gw2 || s.candidates != "{}" {
		t.Errorf("Branch LAN after the first gateway withdrew = %+v, want the second gateway and no candidates", s)
	}

	// Deleted: a soft-deleted gateway reads as none; a hard delete nulls the
	// column through the foreign key.
	if _, err := f.raw.Exec(`UPDATE assets SET deleted_at=now() WHERE id=$1`, gw2); err != nil {
		t.Fatal(err)
	}
	if g := f.listed(f.tenant)[lan].Gateway; g != nil {
		t.Errorf("a deleted gateway still reads as Branch LAN's: %+v", g)
	}
	if hp, err := f.svc.GetAssetByID(f.tenant, host); err != nil || hp.SegmentGateway != nil {
		t.Errorf("host via a deleted gateway = %+v (%v)", hp.SegmentGateway, err)
	}
	if code, _ := postGatewayLinks(t, f.r, f.tenant, sightingclient.GatewayLinksRequest{AssetID: gw2.String(), SourceRef: job3, ObservedAt: run3, Addresses: []string{"192.0.2.2"}}); code != http.StatusNotFound {
		t.Errorf("links for a deleted device = %d, want 404", code)
	}
	if _, err := f.raw.Exec(`DELETE FROM assets WHERE id=$1`, gw2); err != nil {
		t.Fatal(err)
	}
	if s := f.stored(lan); s.asset != nil {
		t.Errorf("a hard-deleted gateway is still referenced: %+v", s)
	}
	_ = labHolder
}

// Cross-tenant isolation on the route and on every new read.
func TestIntegration_GatewayLinksRoute_TenantIsolation(t *testing.T) {
	f := newGatewayFixture(t)
	lan := f.segments["192.0.2.0/24"]
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	gw := f.device("GW-ISO-1", at)
	job := "interrogation:" + uuid.NewString()
	if r := f.claim(gw, "GW-ISO-1", job, "192.0.2.1", at); r.AssetID != gw.String() {
		t.Fatalf("claim = %+v", r)
	}
	if code, res := postGatewayLinks(t, f.r, f.tenant, sightingclient.GatewayLinksRequest{AssetID: gw.String(), SourceRef: job, ObservedAt: at, Addresses: []string{"192.0.2.1"}}); code != http.StatusOK || len(res.Linked) != 1 {
		t.Fatalf("link = %d %+v", code, res)
	}

	other := testdb.NewTenant(t, f.raw.DB)
	otherLAN := f.segment(other, "Other LAN", "192.0.2.0/24")

	// The route, signed for the other tenant, does not know tenant one's device.
	if code, _ := postGatewayLinks(t, f.r, other, sightingclient.GatewayLinksRequest{AssetID: gw.String(), SourceRef: job, ObservedAt: at.Add(time.Hour), Addresses: []string{}}); code != http.StatusNotFound {
		t.Errorf("another tenant's call for this device = %d, want 404", code)
	}
	if s := f.stored(lan); s.asset == nil || *s.asset != gw {
		t.Errorf("another tenant's call changed this tenant's link: %+v", s)
	}
	// The same CIDR in the other tenant has no gateway.
	listed := f.listed(other)
	if _, leaked := listed[lan]; leaked {
		t.Error("the other tenant lists this tenant's segment")
	}
	if g := listed[otherLAN].Gateway; g != nil {
		t.Errorf("the other tenant's segment reads this tenant's gateway: %+v", g)
	}
	m, err := f.svc.GetNetworkMap(t.Context(), other)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range m.Segments {
		if s.SegmentID == lan || s.Gateway != nil {
			t.Errorf("the other tenant's map shows %+v", s)
		}
	}
	if _, err := f.svc.GetAssetByID(other, gw); err == nil {
		t.Error("the other tenant reads this tenant's gateway asset")
	}
	// A segment cannot even be pointed at another tenant's asset: the foreign
	// key is (tenant_id, gateway_asset_id).
	if _, err := f.raw.Exec(`UPDATE network_segments SET gateway_asset_id=$2 WHERE id=$1`, otherLAN, gw); err == nil {
		t.Error("a segment was linked to another tenant's asset")
	}
}
