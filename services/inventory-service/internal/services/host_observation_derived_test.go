package services

// Phase 2 in the host-observation intake: derived MACs (D3) and IPv6
// hygiene (D2).
//
// The unit tests drive hostObservationObservation with no database (every
// address scopes to the tenant default). The TestIntegration_* tests drive the
// real ingest (IngestFindings → engine → Postgres) and skip without
// TEST_DATABASE_URL. Addresses are RFC 5737 / RFC 3849 and ULA; the MACs are
// invented.

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/attrlist"
)

const (
	testEUI64Addr = "fd00::a2b2:c3ff:fed4:e5f6" // IID a2b2:c3ff:fed4:e5f6 → MAC a0:b2:c3:d4:e5:f6
	testEUI64MAC  = "a0:b2:c3:d4:e5:f6"
	testTempAddr  = "fd00::1234:5678:9abc:def0" // random IID: RFC 8981-shaped
)

func identifiersOf(obs identity.Observation, kind identity.Kind) []identity.Identifier {
	var out []identity.Identifier
	for _, id := range obs.Identifiers {
		if id.Kind == kind {
			out = append(out, id)
		}
	}
	return out
}

// TestHostObservationBuilder_D2Vector is the spec's own vector:
// [fe80::1, fd00::a2b2:c3ff:fed4:e5f6, fd00::1234:5678:9abc:def0] with no MAC
// and no segment → one derived MAC a0:b2:c3:d4:e5:f6, one EUI-64 address
// identifier, the temporary address and the (unscopable) link-local address as
// attributes.
// Mutations: drop the MACFromEUI64 append → no derived MAC; drop the
// AddressAttribute `continue` → three address identifiers.
func TestHostObservationBuilder_D2Vector(t *testing.T) {
	ho := &hostobs.HostObservation{
		Source:    hostobs.SourceMDNS,
		Addresses: mustAddrs(t, "fe80::1", testEUI64Addr, testTempAddr),
		Hostnames: []string{"thermostat-4"},
	}
	obs, err := buildHostObs(t, unscopedService(), ho)
	if err != nil {
		t.Fatalf("hostObservationObservation: %v", err)
	}
	macs := identifiersOf(obs, identity.KindMACAddress)
	if len(macs) != 1 || macs[0].Value != testEUI64MAC {
		t.Fatalf("mac identifiers = %+v, want exactly the derived %s", macs, testEUI64MAC)
	}
	if macs[0].Source.Kind != identity.SourceInferred || macs[0].Source.Ref != "derived:eui64:"+testEUI64Addr || macs[0].Confidence != 0.9 {
		t.Errorf("derived MAC = %+v, want inferred / derived:eui64:%s / 0.9", macs[0], testEUI64Addr)
	}
	ips := identifiersOf(obs, identity.KindIPAddress)
	if len(ips) != 1 || ips[0].Value != testEUI64Addr {
		t.Fatalf("ip identifiers = %+v, want exactly the EUI-64 address", ips)
	}
	evidence := hostObsEvidence(t, unscopedService(), ho)
	if !slices.Equal(evidence[attrlist.KeyIPv6Temporary], []string{testTempAddr}) {
		t.Errorf("temporary addresses = %v, want [%s]", evidence[attrlist.KeyIPv6Temporary], testTempAddr)
	}
	if !slices.Equal(evidence[attrlist.KeyLinkLocal], []string{"fe80::1"}) {
		t.Errorf("link-local addresses = %v, want [fe80::1] (no real segment to scope it to)", evidence[attrlist.KeyLinkLocal])
	}
}

// A MAC the sighting STATED — even one dropped as locally administered — is
// better evidence than one worked out from an address, so nothing is derived.
// Mutation: drop `!statedMAC` → a second MAC identifier appears.
func TestHostObservationBuilder_StatedMACSuppressesDerivation(t *testing.T) {
	for _, mac := range []string{"28:cf:da:11:22:50", "02:11:22:33:44:55"} {
		obs, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
			Source:    hostobs.SourceMDNS,
			MAC:       mac,
			Addresses: mustAddrs(t, testEUI64Addr),
		})
		if err != nil {
			t.Fatalf("hostObservationObservation: %v", err)
		}
		for _, id := range identifiersOf(obs, identity.KindMACAddress) {
			if id.Source.Kind == identity.SourceInferred {
				t.Errorf("stated MAC %s: a derived MAC was emitted as well: %+v", mac, id)
			}
		}
	}
}

// A link-local EUI-64 address and a global one built from the same NIC derive
// ONE MAC, referencing the first address it was derived from.
func TestHostObservationBuilder_OneDerivedMACPerNIC(t *testing.T) {
	obs, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
		Source:    hostobs.SourceMDNS,
		Addresses: mustAddrs(t, "fe80::a2b2:c3ff:fed4:e5f6", "2001:db8::a2b2:c3ff:fed4:e5f6"),
		Hostnames: []string{"thermostat-5"},
	})
	if err != nil {
		t.Fatalf("hostObservationObservation: %v", err)
	}
	macs := identifiersOf(obs, identity.KindMACAddress)
	if len(macs) != 1 || macs[0].Value != testEUI64MAC || macs[0].Source.Ref != "derived:eui64:fe80::a2b2:c3ff:fed4:e5f6" {
		t.Fatalf("mac identifiers = %+v, want one derived MAC from the first address", macs)
	}
}

// A statically configured server address is NOT demoted to "temporary": a
// hand-assigned IID is low-entropy (derive.IPv6Role).
// Mutation: drop lowEntropyIID from derive.IPv6Role → the server address
// becomes an attribute and this fails.
func TestHostObservationBuilder_StaticIPv6StaysAnIdentifier(t *testing.T) {
	obs, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
		Source:    hostobs.SourceMDNS,
		Addresses: mustAddrs(t, "2001:db8::10", "2001:db8::dead:beef"),
		Hostnames: []string{"ns-1"},
	})
	if err != nil {
		t.Fatalf("hostObservationObservation: %v", err)
	}
	var got []string
	for _, id := range identifiersOf(obs, identity.KindIPAddress) {
		got = append(got, id.Value)
	}
	if !slices.Equal(got, []string{"2001:db8::10", "2001:db8::dead:beef"}) {
		t.Fatalf("ip identifiers = %v, want both hand-assigned addresses", got)
	}
}

// A sighting whose ONLY evidence is temporary addresses carries nothing to be
// recognised by, and is refused like any sighting with nothing attachable.
func TestHostObservationBuilder_TemporaryOnlyIsRefused(t *testing.T) {
	_, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
		Source:    hostobs.SourceMDNS,
		Addresses: mustAddrs(t, testTempAddr),
	})
	if err == nil {
		t.Fatal("a sighting of nothing but a rotating address produced an observation")
	}
}

// ── against a real database ───────────────────────────────────────────────

// TestIntegration_HostObservation_EUI64DerivedMACJoinsTheLaterReport is D3 end
// to end through the real ingest:
//
//  1. an mDNS sighting of a thermostat carries only a name and IPv6 addresses.
//     Its EUI-64 address yields a derived MAC, stored `inferred` with the
//     address as its evidence; its temporary address is an attribute;
//  2. later a DHCP exchange states that MAC directly. It MATCHES the same
//     asset, decided by mac_address — no duplicate — and the MAC's provenance
//     is upgraded to what was seen.
//
// Mutation: drop the derived-MAC append in hostObservationObservation → step 2
// creates a second asset.
func TestIntegration_HostObservation_EUI64DerivedMACJoinsTheLaterReport(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	first := &hostobs.HostObservation{
		Source:    hostobs.SourceMDNS,
		Addresses: mustAddrs(t, testEUI64Addr, testTempAddr),
		Hostnames: []string{"thermostat-6"},
	}
	res, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, first)})
	if err != nil {
		t.Fatal(err)
	}
	_ = res
	var assetID uuid.UUID
	var temps string
	if err := db.QueryRow(`SELECT id, COALESCE(attributes->>'ipv6_temporary_addresses','') FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant).Scan(&assetID, &temps); err != nil {
		t.Fatalf("expected exactly one asset after the mDNS sighting: %v", err)
	}
	var kind, ref string
	if err := db.QueryRow(`SELECT source_kind, COALESCE(source_ref,'') FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='mac_address' AND value=$3`,
		tenant, assetID, testEUI64MAC).Scan(&kind, &ref); err != nil {
		t.Fatalf("the derived MAC was not stored: %v", err)
	}
	if kind != "inferred" || ref != "derived:eui64:"+testEUI64Addr {
		t.Errorf("derived MAC provenance = %s / %s, want inferred / derived:eui64:%s", kind, ref, testEUI64Addr)
	}
	var tempList []string
	if err := json.Unmarshal([]byte(temps), &tempList); err != nil || !slices.Equal(tempList, []string{testTempAddr}) {
		t.Errorf("ipv6_temporary_addresses = %q (%v), want [%s]", temps, err, testTempAddr)
	}
	var tempIdentifiers int
	if err := db.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND value=$2`, tenant, testTempAddr).Scan(&tempIdentifiers); err != nil {
		t.Fatal(err)
	}
	if tempIdentifiers != 0 {
		t.Errorf("the temporary address became an identifier")
	}

	second := &hostobs.HostObservation{
		Source:    hostobs.SourceDHCP,
		MAC:       testEUI64MAC,
		Addresses: mustAddrs(t, "192.0.2.61"),
		Hostnames: []string{"thermostat-6"},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, second)}); err != nil {
		t.Fatal(err)
	}
	var assets int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if assets != 1 {
		t.Fatalf("%d assets after the DHCP report of the same MAC; want the derived MAC to have joined them", assets)
	}
	// The engine's match entry (other writers add their own `updated` rows,
	// so this reads the one that carries a decision).
	var decidedBy string
	if err := db.QueryRow(`SELECT changes_json->>'decided_by' FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND changes_json ? 'decided_by' ORDER BY seq DESC LIMIT 1`,
		tenant, assetID).Scan(&decidedBy); err != nil {
		t.Fatalf("no history entry records what decided the match: %v", err)
	}
	if decidedBy != string(identity.KindMACAddress) {
		t.Errorf("decided_by = %q, want mac_address", decidedBy)
	}
	if err := db.QueryRow(`SELECT source_kind FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='mac_address' AND value=$3`,
		tenant, assetID, testEUI64MAC).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "measured" {
		t.Errorf("after the MAC was seen directly its source_kind is %q, want measured", kind)
	}
}

// TestIntegration_HostObservation_LinkLocalScopedToTheSegment: a link-local
// address in a sighting whose other address sits in a real segment is an
// identifier in THAT segment — never tenant-wide — and none is recorded as
// the link_local_addresses attribute.
// Mutation: drop the link-local rescope in hostObservationObservation → the
// identifier is tenant-scoped.
func TestIntegration_HostObservation_LinkLocalScopedToTheSegment(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	segment := uuid.New()
	if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'Office','cidr','192.0.2.0/24','production')`, segment, tenant); err != nil {
		t.Fatal(err)
	}
	ho := &hostobs.HostObservation{
		Source:    hostobs.SourceDHCP,
		MAC:       "28:cf:da:11:22:62",
		Addresses: mustAddrs(t, "fe80::1c2d:3e4f:5a6b:7c8d", "192.0.2.62"),
		Hostnames: []string{"desk-62"},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, ho)}); err != nil {
		t.Fatal(err)
	}
	var scope string
	if err := db.QueryRow(`SELECT COALESCE(scope,'') FROM asset_identifiers WHERE tenant_id=$1 AND kind='ip_address' AND value='fe80::1c2d:3e4f:5a6b:7c8d'`, tenant).Scan(&scope); err != nil {
		t.Fatalf("the link-local address is not an identifier: %v", err)
	}
	if scope != segment.String() {
		t.Errorf("link-local scope = %q, want the sighting's segment %s", scope, segment)
	}
	var linkLocals string
	if err := db.QueryRow(`SELECT COALESCE(attributes->>'link_local_addresses','') FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant).Scan(&linkLocals); err != nil {
		t.Fatal(err)
	}
	if linkLocals != "" {
		t.Errorf("link_local_addresses = %s; a scoped link-local address is an identifier, not an attribute", linkLocals)
	}
}
