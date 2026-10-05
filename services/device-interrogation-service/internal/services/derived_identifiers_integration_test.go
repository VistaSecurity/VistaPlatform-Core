package services

// Phase 2 in device-interrogation: derived MACs (B4/D3) and IPv6 hygiene
// (D2), through the real CreateDevice and ObservationSink paths against a real
// Postgres. Skips without TEST_DATABASE_URL.
//
// The serial below spells a MAC under 00:00:0C, a long-standing registered
// prefix in the curated OUI table (derive.MACFromSerialRegistered consults it);
// the rest of the serial is invented. Addresses are RFC 3849 / ULA.

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const (
	testMACSerial   = "00000C7A6B5C"
	testSerialMAC   = "00:00:0c:7a:6b:5c"
	testPeerEUI64   = "2001:db8::a2b2:c3ff:fed4:e5f7" // → a0:b2:c3:d4:e5:f7
	testPeerEUI64MC = "a0:b2:c3:d4:e5:f7"
	testPeerTemp    = "2001:db8::8d3c:4a1f:b27e:9c05"
)

// TestIntegration_ManualDeviceSerialMeetsTheControllerReportByMAC is B4 end to
// end: a person types a device in with a MAC-shaped serial; its record carries
// the derived MAC (`inferred`, derived:serial:<serial>). A controller later
// reports a neighbour by that MAC — and it resolves to the SAME asset, not a
// second one, and the MAC's provenance is upgraded to what was reported.
//
// Mutation: drop the MACFromSerialRegistered append in deviceObservation → the
// controller's report creates a third asset.
func TestIntegration_ManualDeviceSerialMeetsTheControllerReportByMAC(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	svc := NewDeviceServiceWithKey(db, testMasterKey)

	gatewayName := "gw-" + uuid.New().String()[:8] + ".corp.example.test"
	gateway, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco_ios", Hostname: &gatewayName, SerialNumber: strptr(testMACSerial),
	})
	if err != nil {
		t.Fatalf("CreateDevice(gateway): %v", err)
	}
	var kind, ref string
	if err := db.QueryRow(`SELECT source_kind, COALESCE(source_ref,'') FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='mac_address' AND value=$3`,
		tenant, gateway.ID, testSerialMAC).Scan(&kind, &ref); err != nil {
		t.Fatalf("the MAC the serial spells was not recorded on the typed-in device: %v", err)
	}
	if kind != "inferred" || ref != "derived:serial:"+testMACSerial {
		t.Errorf("derived MAC provenance = %s / %s, want inferred / derived:serial:%s", kind, ref, testMACSerial)
	}

	controllerName := "ctrl-" + uuid.New().String()[:8] + ".corp.example.test"
	controller, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: &controllerName})
	if err != nil {
		t.Fatalf("CreateDevice(controller): %v", err)
	}
	peer := di.PeerRef{DisplayName: "Gateway", ClassHint: "router"}
	if !peer.AddIdentifier(di.IdentifierMACAddress, testSerialMAC) {
		t.Fatal("AddIdentifier rejected the MAC")
	}
	if err := NewObservationSink(db).Persist(ctx, tenant, controller.ID, interrogationSource(uuid.New()), InterrogationObservations{
		Relationships: []di.RelationshipObservation{{Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: peer}},
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	assertCount(t, db, 2, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant)
	assertCount(t, db, 1, `SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND to_asset_id=$2`, tenant, gateway.ID)
	if err := db.QueryRow(`SELECT source_kind FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='mac_address' AND value=$3`,
		tenant, gateway.ID, testSerialMAC).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "measured" {
		t.Errorf("after the controller reported the MAC its source_kind is %q, want measured", kind)
	}
}

// TestIntegration_ObservationSink_PeerIPv6Hygiene: a neighbour reported with a
// name, an EUI-64 address and a temporary-shaped address, and no MAC. The
// derived MAC is recorded as such; the temporary address is the
// ipv6_temporary_addresses attribute, not an identifier. A second neighbour
// carrying ONLY a temporary address is skipped, not a failed job.
//
// Mutation: make attrlist.AddressAttribute return "" for RoleTemporary → the
// temporary address becomes an identifier.
func TestIntegration_ObservationSink_PeerIPv6Hygiene(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	controllerName := "ctrl-" + uuid.New().String()[:8] + ".corp.example.test"
	controller, err := NewDeviceServiceWithKey(db, testMasterKey).CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: &controllerName})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	peer := di.PeerRef{DisplayName: "Thermostat"}
	for _, v := range [][2]string{{di.IdentifierHostname, "thermostat-8"}, {di.IdentifierIPAddress, testPeerEUI64}, {di.IdentifierIPAddress, testPeerTemp}} {
		if !peer.AddIdentifier(v[0], v[1]) {
			t.Fatalf("AddIdentifier rejected %v", v)
		}
	}
	onlyTemp := di.PeerRef{DisplayName: "rotating"}
	onlyTemp.AddIdentifier(di.IdentifierIPAddress, "2001:db8::5e1a:77c2:913b:d04f")

	if err := NewObservationSink(db).Persist(ctx, tenant, controller.ID, interrogationSource(uuid.New()), InterrogationObservations{
		Relationships: []di.RelationshipObservation{
			{Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: peer},
			{Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: onlyTemp},
		},
	}); err != nil {
		t.Fatalf("Persist: %v (a peer with nothing but a rotating address must be skipped, not fail the job)", err)
	}

	var peerAsset uuid.UUID
	var kind, ref, temps string
	if err := db.QueryRow(`
		SELECT a.id, i.source_kind, COALESCE(i.source_ref,''), COALESCE(a.attributes->>'ipv6_temporary_addresses','')
		FROM assets a JOIN asset_identifiers i ON i.tenant_id=a.tenant_id AND i.asset_id=a.id
		WHERE a.tenant_id=$1 AND i.kind='mac_address' AND i.value=$2`, tenant, testPeerEUI64MC).Scan(&peerAsset, &kind, &ref, &temps); err != nil {
		t.Fatalf("no asset carries the derived MAC: %v", err)
	}
	if kind != "inferred" || ref != "derived:eui64:"+testPeerEUI64 {
		t.Errorf("derived MAC provenance = %s / %s, want inferred / derived:eui64:%s", kind, ref, testPeerEUI64)
	}
	var got []string
	if err := json.Unmarshal([]byte(temps), &got); err != nil || !slices.Equal(got, []string{testPeerTemp}) {
		t.Errorf("ipv6_temporary_addresses = %q (%v), want [%s]", temps, err, testPeerTemp)
	}
	assertCount(t, db, 1, `SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='ip_address' AND value=$3`, tenant, peerAsset, testPeerEUI64)
	assertCount(t, db, 0, `SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND kind='ip_address' AND value IN ($2, '2001:db8::5e1a:77c2:913b:d04f')`, tenant, testPeerTemp)
	assertCount(t, db, 2, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant)
}

// TestIntegration_ObservationSink_PeerSerialDerivesAMACOnlyWithoutOne: a
// neighbour reported by serial alone gains the MAC its serial spells, recorded
// as derived; one reported WITH a MAC gains nothing — the reported MAC is the
// better evidence.
// Mutation: drop `!statedMAC` on Intake's serial branch (shared/identity/intake.go) → the
// second peer carries two MACs.
func TestIntegration_ObservationSink_PeerSerialDerivesAMACOnlyWithoutOne(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	controllerName := "ctrl-" + uuid.New().String()[:8] + ".corp.example.test"
	controller, err := NewDeviceServiceWithKey(db, testMasterKey).CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: &controllerName})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	bySerial := di.PeerRef{DisplayName: "Switch 3"}
	bySerial.AddIdentifier(di.IdentifierSerialNumber, "00000C4D3E2F")
	withMAC := di.PeerRef{DisplayName: "Switch 4"}
	withMAC.AddIdentifier(di.IdentifierSerialNumber, "00000C4D3E30")
	withMAC.AddIdentifier(di.IdentifierMACAddress, "00:00:0c:99:88:77")

	if err := NewObservationSink(db).Persist(ctx, tenant, controller.ID, interrogationSource(uuid.New()), InterrogationObservations{
		Relationships: []di.RelationshipObservation{
			{Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: bySerial},
			{Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: withMAC},
		},
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	var kind, ref string
	if err := db.QueryRow(`SELECT source_kind, COALESCE(source_ref,'') FROM asset_identifiers WHERE tenant_id=$1 AND kind='mac_address' AND value='00:00:0c:4d:3e:2f'`, tenant).Scan(&kind, &ref); err != nil {
		t.Fatalf("the serial-only peer carries no derived MAC: %v", err)
	}
	if kind != "inferred" || ref != "derived:serial:00000C4D3E2F" {
		t.Errorf("derived MAC provenance = %s / %s, want inferred / derived:serial:00000C4D3E2F", kind, ref)
	}
	assertCount(t, db, 0, `SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND kind='mac_address' AND value='00:00:0c:4d:3e:30'`, tenant)
}
