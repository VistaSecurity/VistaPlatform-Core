package services

// DCIM row 1.5b: the UniFi adapter writes interfaces, VLANs, prefixes and
// client addresses through the intake seam.
//
// The parity tests drive the REAL adapter from a RECORDED controller response
// set (testdata/unifi_parity/site.json): the collector's projection
// (deviceinterrogation.UnifiSiteObservations) → the subject's observed
// network (subjectNetworks) → peerSighting → identity.Intake →
// identity.Engine → the Postgres repository, through
// identitytest.RunAdapterParity, one subject per adapter. The persist test
// drives ObservationSink.Persist end to end, posting to the reference
// sighting route, and checks where the rows land and which facts are no
// longer stored.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// unifiParityAdapter is the UniFi adapter for one subject of the recording.
func unifiParityAdapter(role, mac string) identitytest.ParityAdapter {
	return identitytest.ParityAdapterFunc{
		AdapterName: "unifi/" + role,
		Fn: func(tenantID string, response []byte, at time.Time) (identity.Sighting, error) {
			return unifiSubjectSighting(tenantID, response, at, mac)
		},
	}
}

func unifiParityFixture(t *testing.T, name string, want identitytest.ParityWant) []identitytest.ParityFixture {
	return []identitytest.ParityFixture{{
		Name:     name,
		Response: unifiParityRecording(t),
		Secrets:  unifiParitySecrets,
		Want:     want,
	}}
}

func boolRef(b bool) *bool { return &b }

// unifiSwitchWant is the 24-port switch as the recording describes it.
func unifiSwitchWant() identitytest.ParityWant {
	ge := func(n int) string { return "Port " + strconv.Itoa(n) }
	var ifs []identitytest.WantInterface
	ifs = append(ifs,
		identitytest.WantInterface{Name: ge(1), Type: "1000base-t", SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up",
			Mode: "tagged", TaggedVLANs: []int{20, 30}},
		identitytest.WantInterface{Name: ge(2), Type: "1000base-t", SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up",
			Mode: "tagged", TaggedVLANs: []int{30}},
		identitytest.WantInterface{Name: ge(3), Type: "100base-tx", SpeedKbps: 100_000, OperStatus: "up", AdminStatus: "up",
			Mode: "access", UntaggedVLAN: 20},
		identitytest.WantInterface{Name: ge(4), Type: "1000base-t", SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up",
			Mode: "access", UntaggedVLAN: 20},
	)
	for n := 5; n <= 8; n++ {
		ifs = append(ifs, identitytest.WantInterface{Name: ge(n), Type: "1000base-t", OperStatus: "down", AdminStatus: "up",
			Mode: "access", UntaggedVLAN: 20})
	}
	ifs = append(ifs,
		identitytest.WantInterface{Name: ge(9), Type: "1000base-t", SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up", Mode: "access"},
		identitytest.WantInterface{Name: ge(10), Type: "1000base-t", OperStatus: "down", AdminStatus: "down"},
	)
	for n := 11; n <= 24; n++ {
		ifs = append(ifs, identitytest.WantInterface{Name: ge(n), Type: "1000base-t", OperStatus: "down", AdminStatus: "up", Mode: "tagged-all"})
	}
	ifs = append(ifs,
		identitytest.WantInterface{Name: "SFP+ 1", Type: "10gbase-x-sfpp", SpeedKbps: 10_000_000, OperStatus: "up", AdminStatus: "up", LAG: "LAG 25"},
		identitytest.WantInterface{Name: "SFP+ 2", Type: "10gbase-x-sfpp", SpeedKbps: 10_000_000, OperStatus: "up", AdminStatus: "up", LAG: "LAG 25"},
		identitytest.WantInterface{Name: "LAG 25", Type: "lag", OperStatus: "up", AdminStatus: "up", Mode: "tagged", TaggedVLANs: []int{20, 30}},
		identitytest.WantInterface{Name: "eth0", MAC: unifiParitySwitch, Addresses: []string{"10.20.0.11/32"}},
	)
	return identitytest.ParityWant{
		Interfaces: ifs,
		VLANs:      []identitytest.WantVLAN{{VID: 20, Name: "VLAN 20"}, {VID: 30, Name: "VLAN 30"}},
		PrimaryIP4: "10.20.0.11",
	}
}

// TestIntegration_UniFi_AdapterParity: the recorded site's 24-port switch
// (trunks, an access port with an excluded VLAN, IoT access ports, a port
// with an operator's label, a shut port, an SFP+ LAG), its UDM (three
// networks as bridges with the gateway's own addresses, the prefixes with
// their VLAN and DHCP posture, the WAN on the port it is), its access point
// (two SSIDs on two radios) and a wired client each become exactly the
// interfaces, addresses, prefixes and VLANs the controller described —
// idempotently, with the wireless PSKs and the SMTP / PPPoE passwords
// planted in the recording nowhere.
//
// Mutations (each red, then restored green): drop the untagged VLAN from
// setUnifiVLANs (`entry["vlan"]`) — Port 3's untagged VLAN is NULL; remove
// the name canonicalisation in unifiPortName (return the configured name) —
// `sfp+2` and `Printer` become interface names; drop `static_addresses` from
// the gateway projection — see TestIntegration_UniFi_GatewayAddressesStayStatic.
func TestIntegration_UniFi_AdapterParity(t *testing.T) {
	t.Run("switch", func(t *testing.T) {
		identitytest.RunAdapterParity(t, unifiParityAdapter("switch", unifiParitySwitch),
			unifiParityFixture(t, "usw-24-lag-trunks", unifiSwitchWant()))
	})
	t.Run("gateway", func(t *testing.T) {
		identitytest.RunAdapterParity(t, unifiParityAdapter("gateway", unifiParityUDM),
			unifiParityFixture(t, "udm-three-networks", identitytest.ParityWant{
				Interfaces: []identitytest.WantInterface{
					{Name: "Port 1", Type: "1000base-t", MAC: "74:ac:b9:10:00:02", SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up", Mode: "tagged-all"},
					{Name: "Port 9", Type: "1000base-t", MAC: "74:ac:b9:10:00:09", SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up",
						Addresses: []string{"203.0.113.10/24"}},
					{Name: "eth0", MAC: unifiParityUDM},
					{Name: "br0", Type: "bridge", OperStatus: "up", Addresses: []string{"10.20.0.1/24"}},
					{Name: "br20", Type: "bridge", OperStatus: "up", Mode: "access", UntaggedVLAN: 20, Addresses: []string{"10.20.20.1/24"}},
					{Name: "br30", Type: "bridge", OperStatus: "up", Mode: "access", UntaggedVLAN: 30, Addresses: []string{"10.20.30.1/24"}},
				},
				Prefixes: []identitytest.WantPrefix{
					{Prefix: "10.20.0.0/24", DHCPManaged: boolRef(true)},
					{Prefix: "10.20.20.0/24", VLAN: 20, DHCPManaged: boolRef(false)},
					{Prefix: "10.20.30.0/24", VLAN: 30, DHCPManaged: boolRef(true)},
				},
				VLANs:      []identitytest.WantVLAN{{VID: 20, Name: "IoT"}, {VID: 30, Name: "Guest"}},
				PrimaryIP4: "10.20.0.1",
			}))
	})
	t.Run("access-point", func(t *testing.T) {
		identitytest.RunAdapterParity(t, unifiParityAdapter("access-point", unifiParityAP),
			unifiParityFixture(t, "u6-two-ssids-two-radios", identitytest.ParityWant{
				Interfaces: []identitytest.WantInterface{
					{Name: "Port 1", Type: "1000base-t", SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up", Mode: "tagged-all"},
					{Name: "eth0", MAC: unifiParityAP, Addresses: []string{"10.20.0.21/32"}},
					{Name: "ra0", Type: "ieee802.11n", MAC: "f4:92:bf:30:00:02", OperStatus: "up"},
					{Name: "rai0", Type: "ieee802.11ac", MAC: "f4:92:bf:30:00:03", OperStatus: "up"},
					// The guest SSID's BSSIDs are locally administered
					// (f6:…): software-assigned, never identity, so the
					// interface is recorded without one.
					{Name: "ra1", Type: "ieee802.11n", OperStatus: "up"},
					{Name: "rai1", Type: "ieee802.11ac", OperStatus: "down"},
				},
				// Row 4.4: the two SSIDs as wireless LANs, scored through the
				// catalogue (Corp AES-CCMP; Guest TKIP, weak) and served by the
				// radios that broadcast them. The passphrase planted on both is
				// in no table (Secrets), only that one exists.
				WirelessLANs: []identitytest.WantWirelessLAN{
					{SSID: "Corp", AuthType: "wpa-personal", AuthCipher: "aes", Algorithm: "WIFI-CCMP", PSKPresent: true, Serving: []string{"ra0", "rai0"}},
					{SSID: "Guest", AuthType: "wpa-personal", AuthCipher: "tkip", Algorithm: "WIFI-TKIP", PSKPresent: true, Serving: []string{"ra1", "rai1"}},
				},
				VLANs:      []identitytest.WantVLAN{{VID: 30, Name: "VLAN 30"}},
				PrimaryIP4: "10.20.0.21",
			}))
	})
	t.Run("client", func(t *testing.T) {
		identitytest.RunAdapterParity(t, unifiParityAdapter("client", unifiParityLaptop),
			unifiParityFixture(t, "wired-laptop", identitytest.ParityWant{
				Interfaces: []identitytest.WantInterface{
					{Name: "observed-1", MAC: unifiParityLaptop, Addresses: []string{"10.20.0.101/32"}},
				},
				PrimaryIP4: "10.20.0.101",
			}))
	})
}

// unifiAssetByMAC is the asset holding mac as an identifier.
func unifiAssetByMAC(t *testing.T, db *sql.DB, tenant uuid.UUID, mac string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`SELECT asset_id FROM asset_identifiers WHERE tenant_id = $1 AND kind = 'mac_address' AND value = $2`,
		tenant, mac).Scan(&id); err != nil {
		t.Fatalf("asset with MAC %s: %v", mac, err)
	}
	return id
}

// TestIntegration_UniFi_PersistRecordsInterfacesNotFacts drives the whole
// receiving path — ObservationSink.Persist over the recorded site, every
// sighting posted to the reference route — for a UniFi OS console (the
// controller IS the site's UDM, the common deployment):
//
//   - each managed device holds its interfaces (28 on the switch, 6 on the
//     UDM and the AP) and the tenant holds the site's three prefixes;
//   - a client's address lands on the CLIENT's interface, never on the AP or
//     switch it is attached to;
//   - no net.interfaces or net.vlans fact is stored, while the rest of the
//     devices' facts still are;
//   - no planted secret reaches any tenant table.
//
// Mutations (each red, then restored green): bind the client's net.interfaces
// fact to the access point instead of the client (unifiEmitClientObservations
// `addSubjectFact(peer, …)` → the infra peer) — 10.20.30.77 lands on the AP;
// remove the isSubjectNetworkFact `continue` in persist — net.interfaces facts
// are stored again.
func TestIntegration_UniFi_PersistRecordsInterfacesNotFacts(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	controller := seedHexLocalHost(t, db, tenant, unifiParityUDM, "udm-console")

	result, err := unifiSiteResult(unifiParityRecording(t))
	if err != nil {
		t.Fatal(err)
	}
	sink := NewObservationSink(db)
	source := identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:" + uuid.NewString(), Mode: identity.ModeActive}
	if err := sink.Persist(context.Background(), tenant, controller, source, InterrogationObservations{
		ObservedAt:    time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC),
		Facts:         result.Facts,
		Relationships: result.Relationships,
	}); err != nil {
		t.Fatalf("persist: %v", err)
	}

	interfacesOf := func(asset uuid.UUID) int {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM interfaces WHERE tenant_id = $1 AND asset_id = $2`, tenant, asset).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	udm := unifiAssetByMAC(t, db, tenant, unifiParityUDM)
	if udm != controller {
		t.Errorf("the UDM's subject resolved to %s, not the console it is (%s)", udm, controller)
	}
	for mac, want := range map[string]int{unifiParitySwitch: 28, unifiParityUDM: 6, unifiParityAP: 6} {
		if got := interfacesOf(unifiAssetByMAC(t, db, tenant, mac)); got != want {
			t.Errorf("device %s holds %d interfaces, want %d", mac, got, want)
		}
	}
	var prefixes int
	if err := db.QueryRow(`SELECT count(*) FROM prefixes WHERE tenant_id = $1`, tenant).Scan(&prefixes); err != nil {
		t.Fatal(err)
	}
	if prefixes != 3 {
		t.Errorf("tenant holds %d prefixes, want the site's three", prefixes)
	}

	// Every client's address is on the client.
	ap := unifiAssetByMAC(t, db, tenant, unifiParityAP)
	sw := unifiAssetByMAC(t, db, tenant, unifiParitySwitch)
	for addr, mac := range map[string]string{"10.20.0.101": unifiParityLaptop, "10.20.20.50": unifiParityCamera, "10.20.30.77": "a4:83:e7:00:00:04"} {
		var holder uuid.UUID
		if err := db.QueryRow(`
			SELECT i.asset_id FROM ip_addresses ip
			  JOIN interfaces i ON i.tenant_id = ip.tenant_id AND i.id = ip.assigned_id
			 WHERE ip.tenant_id = $1 AND ip.assigned_kind = 'interface' AND host(ip.address) = $2`, tenant, addr).Scan(&holder); err != nil {
			t.Errorf("client address %s is on no interface: %v", addr, err)
			continue
		}
		if holder == ap || holder == sw {
			t.Errorf("client address %s landed on the infrastructure it is attached to (asset %s)", addr, holder)
		}
		if want := unifiAssetByMAC(t, db, tenant, mac); holder != want {
			t.Errorf("client address %s is on asset %s, want the client %s", addr, holder, want)
		}
	}

	var stored, kept int
	if err := db.QueryRow(`SELECT count(*) FILTER (WHERE key IN ('net.interfaces', 'net.vlans')), count(*) FILTER (WHERE key = 'hw.model')
		FROM asset_facts WHERE tenant_id = $1`, tenant).Scan(&stored, &kept); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Errorf("%d net.interfaces / net.vlans facts stored; the UniFi path records interfaces and prefixes instead", stored)
	}
	if kept != 3 {
		t.Errorf("%d hw.model facts, want one per managed device: the rest of the run must still land", kept)
	}

	unifiCheckNoSecrets(t, db, tenant)
}

// TestIntegration_UniFi_SeparateControllerDoesNotContestTheGateway: a
// controller that is NOT the site's gateway (a Cloud Key, or the Network
// application on a VM, reached at its own address in front of the UDM) claims
// none of the gateway's addresses. Before row 1.5b only the controller
// claimed them; now the gateway's own sighting reports them on its
// bridge interfaces, and a claim by the controller made the second run
// contest the gateway and drop its facts.
//
// Mutation (red, then restored green): make unifiControllerIsGateway return
// true — the second persist fails with the gateway contested, and the LAN
// addresses sit on the controller.
func TestIntegration_UniFi_SeparateControllerDoesNotContestTheGateway(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	controller := seedHexLocalHost(t, db, tenant, "00:1a:2b:3c:4d:5e", "cloud-key")

	result, err := unifiSiteResultAt(unifiParityRecording(t), "10.20.0.250")
	if err != nil {
		t.Fatal(err)
	}
	sink := NewObservationSink(db)
	for run := 0; run < 2; run++ {
		source := identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:" + uuid.NewString(), Mode: identity.ModeActive}
		if err := sink.Persist(context.Background(), tenant, controller, source, InterrogationObservations{
			ObservedAt:    time.Date(2026, 10, 15, 9+run, 0, 0, 0, time.UTC),
			Facts:         result.Facts,
			Relationships: result.Relationships,
		}); err != nil {
			t.Fatalf("persist run %d: %v", run+1, err)
		}
	}
	udm := unifiAssetByMAC(t, db, tenant, unifiParityUDM)
	if udm == controller {
		t.Fatal("the gateway resolved onto the separate controller")
	}
	for _, addr := range []string{"10.20.0.1", "10.20.20.1", "10.20.30.1"} {
		var holder uuid.UUID
		if err := db.QueryRow(`
			SELECT i.asset_id FROM ip_addresses ip
			  JOIN interfaces i ON i.tenant_id = ip.tenant_id AND i.id = ip.assigned_id
			 WHERE ip.tenant_id = $1 AND ip.assigned_kind = 'interface' AND host(ip.address) = $2`, tenant, addr).Scan(&holder); err != nil {
			t.Errorf("gateway address %s is on no interface: %v", addr, err)
			continue
		}
		if holder != udm {
			t.Errorf("gateway address %s is on asset %s, want the gateway %s (controller %s)", addr, holder, udm, controller)
		}
	}
}

// unifiCheckNoSecrets searches every row of every tenant table for the
// planted secrets.
func unifiCheckNoSecrets(t *testing.T, db *sql.DB, tenant uuid.UUID) {
	t.Helper()
	rows, err := db.Query(`
		SELECT c.table_name FROM information_schema.columns c
		  JOIN information_schema.tables tb ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
		 WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id' AND tb.table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	_ = rows.Close()
	if len(tables) == 0 {
		t.Fatal("no tenant tables to search")
	}
	for _, table := range tables {
		for _, secret := range unifiParitySecrets {
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM public."`+table+`" t WHERE t.tenant_id = $1 AND strpos(to_jsonb(t)::text, $2) > 0`,
				tenant, secret).Scan(&n); err != nil {
				t.Fatalf("searching %s: %v", table, err)
			}
			if n > 0 {
				t.Errorf("planted secret %q reached %d row(s) of %s", secret, n, table)
			}
		}
	}
}
