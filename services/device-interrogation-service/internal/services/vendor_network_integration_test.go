package services

// DCIM row 1.5c through the REAL in-cluster path: the Cisco fake appliance's
// interrogation result goes to DeviceInterrogationService.persistObservations
// (the line that hands result.Network to the sink is part of what is tested),
// the sink posts the device's network as one sighting bound to the device
// record (persistNetwork, shared with SNMP since row 1.5d), and the ARP table
// is evidence about other hosts that never creates an asset.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identifiersql"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The Cisco fixture's ARP table (testdata/vendor_network/cisco): a host the
// tenant already has, and one it does not.
const (
	arpKnownMAC     = "00:50:56:aa:10:50"
	arpKnownAddr    = "10.20.10.50"
	arpUnknownMAC   = "00:50:56:aa:99:01"
	arpUnknownAddr  = "10.20.99.1"
	ciscoSwitchMgmt = "10.20.99.2"
)

type vendorSinkRun struct {
	db     *sql.DB
	tenant uuid.UUID
	device uuid.UUID
	host   uuid.UUID
}

// runCiscoThroughTheService creates the switch's device record (as Discovery →
// Devices does, at its management address) and an established host that owns
// one ARP entry's MAC, then interrogates the fake switch and persists the
// result through the in-cluster service.
func runCiscoThroughTheService(t *testing.T) vendorSinkRun {
	t.Helper()
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	hostname := "access-sw-01-" + uuid.New().String()[:6] + ".corp.example.test"
	ip := ciscoSwitchMgmt
	dev, err := NewDeviceServiceWithKey(db, testMasterKey).CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco", Hostname: &hostname, IPAddress: &ip,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// A host the tenant already has: its agent reported the address the
	// switch later sees in its ARP table (and no MAC).
	_, res, err := postSighting(ctx, db, identity.Sighting{
		TenantID: tenant.String(), Channel: identity.ChannelAuthenticatedSession, ObservedAt: time.Now().UTC().Add(-time.Hour),
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "agent:" + uuid.NewString(), Mode: identity.ModeActive},
		Confidence: 1, Ownership: identity.OwnershipInternal,
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindIPAddress, Value: arpKnownAddr},
			{Kind: identity.KindHostname, Value: "desk-4-12"},
		},
	})
	if err != nil || res.Asset.Zero() {
		t.Fatalf("seeding the known host: %v (%+v)", err, res)
	}
	host := uuid.MustParse(res.Asset.ID)

	result, _ := interrogateVendorAppliance(t, "cisco")
	// The fake listens on loopback; in production this is the address the
	// collector reached the switch at.
	result.Network.ManagementAddress = ciscoSwitchMgmt
	svc := &DeviceInterrogationService{db: db, observations: NewObservationSink(db)}
	if err := svc.persistObservations(ctx, tenant, dev.ID, uuid.New(), result); err != nil {
		t.Fatalf("persistObservations: %v", err)
	}
	return vendorSinkRun{db: db, tenant: tenant, device: dev.ID, host: host}
}

// reinterrogate runs the switch's interrogation again: the next scheduled run,
// when the connected prefixes the first one taught already exist.
func (r vendorSinkRun) reinterrogate(t *testing.T) {
	t.Helper()
	result, _ := interrogateVendorAppliance(t, "cisco")
	result.Network.ManagementAddress = ciscoSwitchMgmt
	svc := &DeviceInterrogationService{db: r.db, observations: NewObservationSink(r.db)}
	if err := svc.persistObservations(context.Background(), r.tenant, r.device, uuid.New(), result); err != nil {
		t.Fatalf("persistObservations (again): %v", err)
	}
}

// TestIntegration_VendorNetwork_InterfacesLandOnTheInterrogatedDevice: the
// interfaces are the device record's, the management address is its primary
// IP, and the retired facts are not written.
//
// Mutation: drop `Network: result.Network` from persistObservations — red (no
// interfaces on the device).
func TestIntegration_VendorNetwork_InterfacesLandOnTheInterrogatedDevice(t *testing.T) {
	r := runCiscoThroughTheService(t)
	// The eight interfaces the switch reported. (The device record's address
	// was first filed on a synthetic `observed-1` interface; the report moves
	// it to Vlan99 and the emptied synthetic interface is left behind — an
	// engine gap recorded as a seed, not this adapter's to close.)
	assertCount(t, r.db, 8, `SELECT count(*) FROM interfaces WHERE tenant_id=$1 AND asset_id=$2 AND status <> 'rejected'
		AND coalesce(source_ref, '') <> 'identity:synthetic'`, r.tenant, r.device)
	// Every reported address sits on the interface that reported it, once —
	// also after the next interrogation.
	r.reinterrogate(t)

	// The identifiers that bind every later self-sighting (serial, interface
	// MACs, the network itself) carry the interface each address and MAC is
	// on. Without the name the engine planned all of a sighting's carried
	// addresses as ONE unnamed group and filed it under whichever interface
	// held any of them: a serial sighting arriving after a learned prefix
	// rescoped the addresses wrote 10.20.99.2 a second time, on Vlan10. A
	// synthetic `observed-<n>` interface is never named, so a later report can
	// still rename it.
	//
	// Mutation: drop the interface name from knownAssetIdentifiers — red.
	known, err := knownAssetIdentifiers(context.Background(), r.db, r.tenant, r.device)
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]string{}
	for _, id := range known {
		named[string(id.Kind)+"="+id.Value] = id.Interface
	}
	if named["ip_address="+ciscoSwitchMgmt] != "Vlan99" || named["ip_address=10.20.10.1"] != "Vlan10" ||
		named["mac_address=00:b0:e1:a2:c0:01"] != "GigabitEthernet1/0/1" {
		t.Errorf("known identifiers are not named by their interfaces: %v", named)
	}
	assertCount(t, r.db, 1, `SELECT count(*) FROM ip_addresses WHERE tenant_id=$1 AND host(address) = $2 AND status <> 'rejected'`, r.tenant, ciscoSwitchMgmt)
	assertCount(t, r.db, 1, `SELECT count(*) FROM ip_addresses ip JOIN interfaces i ON i.tenant_id = ip.tenant_id AND i.id = ip.assigned_id
		WHERE ip.tenant_id=$1 AND host(ip.address) = $2 AND i.name = 'Vlan99'`, r.tenant, ciscoSwitchMgmt)
	assertCount(t, r.db, 1, `SELECT count(*) FROM ip_addresses ip JOIN interfaces i ON i.tenant_id = ip.tenant_id AND i.id = ip.assigned_id
		WHERE ip.tenant_id=$1 AND host(ip.address) = '10.20.10.1' AND i.name = 'Vlan10'`, r.tenant)
	var primary string
	if err := r.db.QueryRow(`
		SELECT coalesce(host(ip.address), '') FROM assets a
		  LEFT JOIN ip_addresses ip ON ip.tenant_id = a.tenant_id AND ip.id = a.primary_ip4_id
		 WHERE a.tenant_id = $1 AND a.id = $2`, r.tenant, r.device).Scan(&primary); err != nil {
		t.Fatal(err)
	}
	if primary != ciscoSwitchMgmt {
		t.Errorf("primary IPv4 = %q, want the device record's management address %s", primary, ciscoSwitchMgmt)
	}
	assertCount(t, r.db, 0, `SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key IN ($3, $4)`,
		r.tenant, r.device, facts.KeyNetInterfaces, facts.KeyNetVlans)
	// The neighbour fact is kept until row 3.3 models neighbours as cables.
	assertCount(t, r.db, 1, `SELECT count(DISTINCT key) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key = $3`,
		r.tenant, r.device, facts.KeyNetNeighbors)
}

// TestIntegration_VendorNetwork_ARPNeverCreatesAnAsset: the switch's ARP table
// names a host the tenant has (by its address) and one it does not. Neither
// creates an asset; the known host's address gains the MAC it answered with;
// the unknown entry is parked as an unresolved termination keyed by its MAC,
// intent `assignment`, against the switch interface that learned it, under
// the collector's own producer name.
//
// Mutations (each red, then restored green): park under `snmp` regardless of
// the observation's Producer; remove the Park in recordSNMPARPEvidence (no
// termination); let ARP create (post every entry as an l2_frame sighting).
func TestIntegration_VendorNetwork_ARPNeverCreatesAnAsset(t *testing.T) {
	r := runCiscoThroughTheService(t)

	// The switch and the host it was seeded with — nothing else.
	assertCount(t, r.db, 2, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, r.tenant)
	assertCount(t, r.db, 0, `SELECT count(*) FROM (`+identifiersql.All+`) ids WHERE tenant_id=$1 AND kind='mac_address' AND value=$2`,
		r.tenant, arpUnknownMAC)

	// The unknown entry is parked against the interface that learned it.
	var (
		producer, intent, originKind, iface string
		far, attrs                          []byte
	)
	if err := r.db.QueryRow(`
		SELECT u.producer, u.intent, u.origin_kind, coalesce(i.name, ''), u.far_identity, u.attributes
		  FROM unresolved_terminations u
		  LEFT JOIN interfaces i ON i.tenant_id = u.tenant_id AND i.id = u.origin_id
		 WHERE u.tenant_id = $1`, r.tenant).Scan(&producer, &intent, &originKind, &iface, &far, &attrs); err != nil {
		t.Fatalf("no unresolved termination for the unknown ARP entry: %v", err)
	}
	var farID map[string]string
	var attr map[string]any
	_ = json.Unmarshal(far, &farID)
	_ = json.Unmarshal(attrs, &attr)
	if producer != "cisco" || intent != "assignment" || originKind != "interface" || iface != "Vlan99" ||
		farID["mac_address"] != arpUnknownMAC || attr["address"] != arpUnknownAddr {
		t.Errorf("parked %s/%s %s:%s far=%v attrs=%v; want cisco/assignment interface:Vlan99 far={mac_address:%s} address %s",
			producer, intent, originKind, iface, farID, attr, arpUnknownMAC, arpUnknownAddr)
	}
	// Exactly one: the known host's entry is not parked, and the switch's own
	// ARP rows (age `-`) are not evidence about anybody.
	assertCount(t, r.db, 1, `SELECT count(*) FROM unresolved_terminations WHERE tenant_id=$1`, r.tenant)

	// The known host's address gained the MAC the switch saw it answer with.
	assertCount(t, r.db, 1, `SELECT count(*) FROM ip_addresses ip JOIN interfaces i ON i.tenant_id = ip.tenant_id AND i.id = ip.assigned_id
		WHERE ip.tenant_id=$1 AND i.asset_id=$2 AND host(ip.address)=$3 AND ip.mac_address = $4::macaddr8`,
		r.tenant, r.host, arpKnownAddr, arpKnownMAC)

	// A second interrogation parks nothing new: the same row, seen twice.
	r.reinterrogate(t)
	assertCount(t, r.db, 2, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, r.tenant)
	assertCount(t, r.db, 1, `SELECT count(*) FROM unresolved_terminations WHERE tenant_id=$1 AND observation_count = 2`, r.tenant)
}
