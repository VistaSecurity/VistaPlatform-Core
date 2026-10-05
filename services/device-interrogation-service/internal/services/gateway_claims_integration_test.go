package services

// slice A, driven through the REAL interrogation ingest: ObservationSink
// .Persist with the net.vlans fact a gateway reports, posting its claims over
// the sightings route (the reference route by default; set
// SIGHTINGS_TEST_INVENTORY_URL to run against inventory-service itself).

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The gateway in these tests routes four networks. It shares ONE MAC across
// every VLAN interface, which is normal for a small gateway and is what makes
// the floating-address and reflector rules worth re-checking.
const (
	gwMAC    = "00:00:5e:00:53:aa"
	gwSerial = "GW-SLICE-A-1"
)

// gatewayVLANs is the net.vlans value of a gateway routing four networks,
// shaped as the UniFi collector emits it.
func gatewayVLANs() []map[string]any {
	return []map[string]any{
		{"name": "Default", "subnet": "192.0.2.0/24", "gateway": "192.0.2.1", "dhcp_enabled": true},
		{"id": 2, "name": "Lab", "subnet": "198.51.100.0/24", "gateway": "198.51.100.1", "dhcp_enabled": true},
		{"id": 3, "name": "Cameras", "subnet": "203.0.113.0/24", "gateway": "203.0.113.1", "dhcp_enabled": false},
		{"id": 4, "name": "Servers", "subnet": "2001:db8:4::/64", "gateway": "2001:db8:4::1", "dhcp_enabled": true},
		// A Cisco-style row: a VLAN with no prefix contributes nothing.
		{"id": 9, "name": "voice"},
	}
}

type gatewayFixture struct {
	db       *sql.DB
	tenant   uuid.UUID
	gateway  uuid.UUID
	repo     *pgidentity.Repository
	segments map[string]string // cidr → segment id
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	f := &gatewayFixture{db: db, tenant: testdb.NewTenant(t, db), repo: pgidentity.New(db), segments: map[string]string{}}
	ctx := context.Background()

	// The segments exist before the gateway is first interrogated (a seed,
	// an operator, an earlier run): the claims must land inside them.
	if err := NewObservationSink(db).ensureVLANSegments(ctx, f.tenant, uuid.New(), gatewayVLANs()); err != nil {
		t.Fatalf("ensureVLANSegments: %v", err)
	}
	rows, err := db.Query(`SELECT value, id::text FROM network_segments WHERE tenant_id=$1`, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cidr, id string
		if err := rows.Scan(&cidr, &id); err != nil {
			t.Fatal(err)
		}
		f.segments[cidr] = id
	}
	_ = rows.Close()
	if len(f.segments) != 4 {
		t.Fatalf("segments = %v, want the four with a prefix", f.segments)
	}

	// The gateway as the platform first knew it: registered at its address on
	// the Lab network (its management address), known by serial and MAC, and
	// filed — wrongly — under the Default network.
	f.gateway = f.createAsset(t, "gateway", "", f.segments["192.0.2.0/24"],
		identity.Identifier{Kind: identity.KindSerialNumber, Value: gwSerial},
		identity.Identifier{Kind: identity.KindMACAddress, Value: gwMAC},
		identity.Identifier{Kind: identity.KindIPAddress, Value: "198.51.100.1", Scope: f.segments["198.51.100.0/24"],
			Source: identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}},
	)
	if _, err := db.Exec(`INSERT INTO asset_management(tenant_id, asset_id, management_url, management_protocol)
		VALUES ($1, $2, 'https://198.51.100.1', 'https')`, f.tenant, f.gateway); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *gatewayFixture) createAsset(t *testing.T, name, identityStatus, segment string, ids ...identity.Identifier) uuid.UUID {
	t.Helper()
	at := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	for i := range ids {
		ids[i].Confidence = 1
		ids[i].SeenAt = at
		if ids[i].Source.Kind == "" {
			ids[i].Source = identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture"}
		}
	}
	ref, err := f.repo.CreateAsset(context.Background(), f.tenant.String(), identity.NewAsset{
		ClassKey: "unknown_host", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: name,
		Status: identity.StatusMonitoring, IdentityStatus: identityStatus, NetworkSegment: segment,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture"},
		Identifiers: ids, FirstSeenAt: at, LastSeenAt: at,
	})
	if err != nil {
		t.Fatalf("CreateAsset(%s): %v", name, err)
	}
	return uuid.MustParse(ref.ID)
}

func (f *gatewayFixture) interrogate(t *testing.T, job uuid.UUID, at time.Time) {
	t.Helper()
	err := NewObservationSink(f.db).Persist(context.Background(), f.tenant, f.gateway, interrogationSource(job), InterrogationObservations{
		ObservedAt: at,
		Facts:      []di.FactObservation{{Key: facts.KeyNetVlans, Value: gatewayVLANs(), Confidence: 1}},
	})
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
}

// holder returns the asset holding an address, its stored assignment and its
// scope.
func (f *gatewayFixture) holder(t *testing.T, address string) (asset, assignment, scope string) {
	t.Helper()
	err := f.db.QueryRow(`SELECT asset_id::text, coalesce(address_assignment,''), scope FROM asset_identifiers
		WHERE tenant_id=$1 AND kind='ip_address' AND value=$2`, f.tenant, address).Scan(&asset, &assignment, &scope)
	if err == sql.ErrNoRows {
		return "", "", ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return asset, assignment, scope
}

func (f *gatewayFixture) historyCount(t *testing.T, asset uuid.UUID, action, reason string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND action=$3 AND changes_json->>'reason'=$4`,
		f.tenant, asset, action, reason).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIntegration_GatewayClaims_LandOnTheGatewayAndSettleEveryHolder(t *testing.T) {
	f := newGatewayFixture(t)
	seg := f.segments

	// Three records already hold three of the gateway's addresses:
	//   - a PROVISIONAL guess built from a reflected advert (name + address);
	//   - an established record of nothing but the address;
	//   - an established device with its own MAC — the stronger holder.
	guess := f.createAsset(t, "printer guess", string(identity.IdentityProvisional), seg["192.0.2.0/24"],
		identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: seg["192.0.2.0/24"]},
		identity.Identifier{Kind: identity.KindHostname, Value: "printer.local", Scope: seg["192.0.2.0/24"]})
	ipOnly := f.createAsset(t, "203.0.113.1", "", seg["203.0.113.0/24"],
		identity.Identifier{Kind: identity.KindIPAddress, Value: "203.0.113.1", Scope: seg["203.0.113.0/24"]})
	stronger := f.createAsset(t, "other device", "", seg["2001:db8:4::/64"],
		identity.Identifier{Kind: identity.KindIPAddress, Value: "2001:db8:4::1", Scope: seg["2001:db8:4::/64"]},
		identity.Identifier{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:99"})

	f.interrogate(t, uuid.New(), time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC))

	gw := f.gateway.String()
	for address, cidr := range map[string]string{
		"192.0.2.1":    "192.0.2.0/24",    // re-homed from the provisional guess
		"198.51.100.1": "198.51.100.0/24", // the gateway's own, declared
		"203.0.113.1":  "203.0.113.0/24",  // re-homed from the address-only record
	} {
		asset, assignment, scope := f.holder(t, address)
		if asset != gw || assignment != "static" || scope != seg[cidr] {
			t.Errorf("%s: held by %q (%q, scope %q); want the gateway, static, scope %s", address, asset, assignment, scope, seg[cidr])
		}
	}
	// The stronger holder keeps its address and a merge proposal names both.
	if asset, _, _ := f.holder(t, "2001:db8:4::1"); asset != stronger.String() {
		t.Errorf("2001:db8:4::1 is held by %q; the stronger holder %s must keep it", asset, stronger)
	}
	var proposals int
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND changes_json->>'kind'='merge_proposal'
		AND changes_json::text LIKE '%'||$2||'%' AND changes_json::text LIKE '%'||$3||'%'`, f.tenant, gw, stronger.String()).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	if proposals == 0 {
		t.Error("no merge proposal names the gateway and the stronger holder")
	}

	for _, a := range []uuid.UUID{f.gateway, guess, ipOnly} {
		if f.historyCount(t, a, string(identity.ActionIdentifierReassigned), identity.ReasonClaimedByDevice) == 0 {
			t.Errorf("asset %s has no identifier_reassigned entry for the claim", a)
		}
	}
	var guessHostname int
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE asset_id=$1 AND kind='hostname'`, guess).Scan(&guessHostname); err != nil {
		t.Fatal(err)
	}
	if guessHostname != 1 {
		t.Error("the provisional guess lost its own name; only the address was the gateway's")
	}

	// Home segment: the management address's network, not the one it was
	// filed under, recorded in history.
	var home string
	if err := f.db.QueryRow(`SELECT coalesce(network_segment_id::text,'') FROM assets WHERE id=$1`, f.gateway).Scan(&home); err != nil {
		t.Fatal(err)
	}
	if home != seg["198.51.100.0/24"] {
		t.Errorf("home segment = %q, want the management address's segment %s", home, seg["198.51.100.0/24"])
	}
	if f.historyCount(t, f.gateway, string(identity.ActionUpdated), reasonHomeSegment) != 1 {
		t.Error("the move to the home segment was not recorded")
	}

	// A second interrogation changes nothing: no new reassignments, no
	// second home move, the same holders.
	f.interrogate(t, uuid.New(), time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC))
	if n := f.historyCount(t, f.gateway, string(identity.ActionIdentifierReassigned), identity.ReasonClaimedByDevice); n != 2 {
		t.Errorf("gateway has %d reassignment entries after a second run, want the first run's 2", n)
	}
	if f.historyCount(t, f.gateway, string(identity.ActionUpdated), reasonHomeSegment) != 1 {
		t.Error("a second run moved the gateway to its home segment again")
	}
	if asset, _, _ := f.holder(t, "2001:db8:4::1"); asset != stronger.String() {
		t.Error("a second run took the stronger holder's address")
	}
}

// The location follows the HOME segment only: the claim sightings for the
// other networks place nothing, even when they reach the gateway first.
func TestIntegration_GatewayClaims_LocationFollowsTheHomeSegmentOnly(t *testing.T) {
	f := newGatewayFixture(t)
	home, other := uuid.New(), uuid.New()
	for id, name := range map[uuid.UUID]string{home: "Home site", other: "Other site"} {
		if _, err := f.db.Exec(`INSERT INTO locations(id,tenant_id,name,location_type) VALUES($1,$2,$3,'site')`, id, f.tenant, name); err != nil {
			t.Fatal(err)
		}
	}
	for cidr, loc := range map[string]uuid.UUID{"198.51.100.0/24": home, "192.0.2.0/24": other, "203.0.113.0/24": other, "2001:db8:4::/64": other} {
		if _, err := f.db.Exec(`UPDATE network_segments SET location_id=$2 WHERE id=$1`, f.segments[cidr], loc); err != nil {
			t.Fatal(err)
		}
	}
	// No segment yet, so nothing but the rule decides where it lands.
	if _, err := f.db.Exec(`UPDATE assets SET network_segment_id=NULL WHERE id=$1`, f.gateway); err != nil {
		t.Fatal(err)
	}

	f.interrogate(t, uuid.New(), time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC))

	var location, site, segment string
	if err := f.db.QueryRow(`SELECT coalesce(location_id::text,''), coalesce(site,''), coalesce(network_segment_id::text,'') FROM assets WHERE id=$1`,
		f.gateway).Scan(&location, &site, &segment); err != nil {
		t.Fatal(err)
	}
	if segment != f.segments["198.51.100.0/24"] || location != home.String() || site != "Home site" {
		t.Errorf("gateway placed in segment %q at %q (%q); want the home segment %s at the home site",
			segment, location, site, f.segments["198.51.100.0/24"])
	}
}

// A management address in no segment (the gateway was registered at its WAN
// address) asserts no home: the segment is left as it was, and no routed
// network is guessed at.
func TestIntegration_GatewayClaims_ManagementAddressOutsideEverySegmentAssertsNoHome(t *testing.T) {
	f := newGatewayFixture(t)
	if _, err := f.db.Exec(`UPDATE asset_management SET management_url='https://100.64.0.2' WHERE asset_id=$1`, f.gateway); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE assets SET network_segment_id=NULL WHERE id=$1`, f.gateway); err != nil {
		t.Fatal(err)
	}
	f.interrogate(t, uuid.New(), time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC))

	var segment, location string
	if err := f.db.QueryRow(`SELECT coalesce(network_segment_id::text,''), coalesce(location_id::text,'') FROM assets WHERE id=$1`,
		f.gateway).Scan(&segment, &location); err != nil {
		t.Fatal(err)
	}
	if segment != "" || location != "" {
		t.Errorf("a gateway with no home was placed in segment %q at %q", segment, location)
	}
	if asset, _, _ := f.holder(t, "192.0.2.1"); asset != f.gateway.String() {
		t.Error("the claims still have to land when there is no home")
	}
}

// Decision 3 must not regress: once the gateway holds its own addresses, the
// gateway answering ARP for each of them with its one shared MAC is one asset
// seen at its own address — no floating-address pair, no announcement edge,
// no proposal. And: the gateway reflecting another device's mDNS name
// from one of its addresses does not absorb the name.
func TestIntegration_GatewayClaims_SharedMACAndReflectorDoNotRegress(t *testing.T) {
	f := newGatewayFixture(t)
	f.interrogate(t, uuid.New(), time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC))
	ctx := context.Background()
	sensor := identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:fixture", Mode: identity.ModePassive}

	for i, address := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8:4::1"} {
		_, res, err := postSighting(ctx, f.db, identity.Sighting{
			TenantID: f.tenant.String(), Source: sensor, Channel: identity.ChannelL2Frame,
			ObservedAt: time.Date(2026, 10, 3, 11, i, 0, 0, time.UTC), Confidence: 1, Ownership: identity.OwnershipInternal,
			Identifiers: []identity.SightedIdentifier{
				{Kind: identity.KindMACAddress, Value: gwMAC},
				{Kind: identity.KindIPAddress, Value: address},
			},
		})
		if err != nil {
			t.Fatalf("ARP for %s: %v", address, err)
		}
		if res.Asset.ID != f.gateway.String() || res.Outcome == identity.OutcomeConflict {
			t.Errorf("ARP for %s resolved %s on %q; want the gateway", address, res.Outcome, res.Asset.ID)
		}
	}
	var announcements, proposals int
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND attributes->>'mechanism'='l2_announcement'`, f.tenant).Scan(&announcements); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND changes_json->>'kind'='merge_proposal'`, f.tenant).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	if announcements != 0 || proposals != 0 {
		t.Errorf("the gateway answering for its own addresses produced %d announcement edge(s) and %d proposal(s)", announcements, proposals)
	}

	// The reflector: another device's name, re-originated by the gateway on
	// another of its networks. shared/hostobs.DecodeMDNS strips the
	// reflector's MAC and source address from such a response, so the
	// sighting names the printer and the address it ANNOUNCED — and the
	// gateway now owning every one of its own addresses must not draw it in.
	_, res, err := postSighting(ctx, f.db, identity.Sighting{
		TenantID: f.tenant.String(), Source: sensor, Channel: identity.ChannelRelayed,
		ObservedAt: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC), Confidence: 0.5, Ownership: identity.OwnershipInternal,
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindHostname, Value: "office-printer.local", Address: "192.0.2.50"},
			{Kind: identity.KindIPAddress, Value: "192.0.2.50"},
		},
	})
	if err != nil && !isRefusal(err) {
		t.Fatalf("relayed advert: %v", err)
	}
	if res.Asset.ID == f.gateway.String() {
		t.Errorf("the reflected advert resolved onto the gateway (%s)", res.Outcome)
	}
	var absorbed int
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE asset_id=$1 AND kind='hostname' AND value='office-printer.local'`,
		f.gateway).Scan(&absorbed); err != nil {
		t.Fatal(err)
	}
	if absorbed != 0 {
		t.Error("the gateway absorbed a name it only reflected")
	}
}

func isRefusal(err error) bool { return errors.Is(err, errSightingRefused) }
