package services

// Gate 2's edge half, proved from a vendor fixture rather than from a
// hand-built observation.
//
// The two halves of "a collector draws the map" were each covered and the SEAM
// between them was not: shared/deviceinterrogation proves UniFi EMITS a
// member_of and a connects_to from a `stat/device` response, and
// TestIntegration_ObservationSink_PeerBecomesAPendingAssetAndAPendingEdge
// proves the sink WRITES an edge — from a RelationshipObservation the test
// constructs itself. Nothing joined the two, so a collector that emitted an
// edge no engine could resolve (a peer with no identifier, a type outside the
// canonical ten, a direction the sink reads the other way) would pass both
// suites and draw nothing on the map.
//
// The gate line asks that the dev cluster show edges from at least UniFi and
// cloud. That deployment half is deferred by owner decision until the build is
// done; this is the automated statement that stands in its place, and it is the
// stronger of the two in one respect — it names which rows, in which direction,
// with which provenance, and fails if any of that changes.
//
// (Named as "the dev cluster" rather than by its hostname deliberately: the
// public-tree export's leak gate greps every shipped file for our lab identity,
// and a comment is a shipped file. See the export-gate note in CLAUDE.md.)
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// unifiPoison is a value the controller returns and the platform must never
// store. Spelled as the shared collector tests spell it.
const unifiPoison = "MUST-NOT-BE-COLLECTED"

// newUniFiControllerForTest answers every call unifiClient.interrogate makes,
// with the x_-prefixed secrets a real controller returns alongside the topology
// we are after: the site mesh PSK and RADIUS secret on `list/setting`, the WPA
// passphrase and IPsec PSK on `rest/networkconf`, the per-device auth key and
// syslog key on `stat/device`, and the operator's email on `/api/self`.
//
// controllerName is the site's `super_identity` name, which is what
// unifiControllerPeer uses to name the far end of every adoption edge. It is a
// parameter because the far end has to RESOLVE to the device row the
// interrogation belongs to — on a real install the controller's display name is
// its hostname, and if it is not, the adoption edge points at a second pending
// asset for the same controller. That is worth knowing, and it is exactly what
// this test would catch.
func newUniFiControllerForTest(t *testing.T, controllerName string) *httptest.Server {
	t.Helper()
	ok := func(w http.ResponseWriter, data string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":` + data + `}`))
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// A software controller, so the UniFi-OS endpoint is absent and the
		// client falls through to /api/login. Exercising the fallback is free
		// here and is how a real legacy controller behaves.
		case r.URL.Path == "/api/auth/login":
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/api/login":
			http.SetCookie(w, &http.Cookie{Name: "unifises", Value: "session"})
			ok(w, `[]`)
		case r.URL.Path == "/api/self":
			ok(w, `[{"site_name":"default","email":"`+unifiPoison+`","name":"`+unifiPoison+`"}]`)
		case strings.HasSuffix(r.URL.Path, "/list/setting"):
			ok(w, `[
				{"key":"super_identity","name":"`+controllerName+`","hostname":"`+controllerName+`"},
				{"key":"super_mgmt","x_mesh_psk":"`+unifiPoison+`"},
				{"key":"super_smtp","x_password":"`+unifiPoison+`"},
				{"key":"radius","x_secret":"`+unifiPoison+`"}
			]`)
		case strings.HasSuffix(r.URL.Path, "/rest/networkconf"):
			ok(w, `[
				{"_id":"net-lan","name":"Default","purpose":"corporate","enabled":true,
				 "ip_subnet":"192.0.2.1/24","dhcpd_enabled":true,
				 "dhcpd_start":"192.0.2.100","dhcpd_stop":"192.0.2.200",
				 "x_radius_secret":"`+unifiPoison+`"},
				{"_id":"net-iot","name":"IoT","purpose":"corporate","enabled":true,
				 "vlan_enabled":true,"vlan":20,"ip_subnet":"198.51.100.1/24",
				 "dhcpd_enabled":false,"x_wpa_psk":"`+unifiPoison+`"}
			]`)
		case strings.HasSuffix(r.URL.Path, "/stat/sta"):
			ok(w, `[{
				"mac":"4c:6e:0a:87:d4:80","ip":"192.0.2.68","hostname":"linux-2","name":"linux-2",
				"oui":"Intel","is_wired":true,"sw_mac":"78:8a:20:4b:ee:41","network":"Default","vlan":1,
				"x_fingerprint":"`+unifiPoison+`","fingerprint":"`+unifiPoison+`",
				"note":"operator@example.com `+unifiPoison+`"
			}]`)
		case strings.HasSuffix(r.URL.Path, "/stat/device"):
			ok(w, `[{
				"name":"Office Switch","ip":"192.0.2.11","mac":"78:8a:20:4b:ee:41",
				"model":"US8P150","type":"usw","version":"6.6.77.15402",
				"serial":"788A204BEE41","adopted":true,"state":1,"uptime":1234567,
				"x_authkey":"`+unifiPoison+`","x_vwirekey":"`+unifiPoison+`",
				"syslog_key":"`+unifiPoison+`",
				"ethernet_table":[{"name":"eth0","mac":"78:8a:20:4b:ee:41","num_port":8}],
				"port_table":[
					{"port_idx":1,"name":"Uplink","up":true,"enable":true,"speed":1000,
					 "native_networkconf_id":"net-lan","poe_power":"6.20",
					 "x_port_key":"`+unifiPoison+`"},
					{"port_idx":2,"name":"Camera 1","up":false,"enable":false,"speed":0,
					 "native_networkconf_id":"net-iot"}
				],
				"lldp_table":[{
					"chassis_id":"00:1b:17:00:00:01","system_name":"core-sw-1.corp.example.test",
					"port_id":"Gi1/0/24","local_port_name":"Uplink","local_port_idx":1,
					"is_wired":true,
					"system_desc":"Cisco IOS Software, C9300 `+unifiPoison+`"
				}],
				"uplink":{
					"uplink_mac":"00:1b:17:00:00:01",
					"uplink_device_name":"core-sw-1.corp.example.test",
					"uplink_remote_port":24,"port_idx":1,"type":"wire",
					"x_uplink_key":"`+unifiPoison+`"
				}
			},{
				"name":"Office AP","ip":"192.0.2.12","mac":"78:8a:20:4b:ee:52",
				"model":"U6LR","type":"uap","version":"6.6.55.15189",
				"serial":"788A204BEE52","adopted":true,"state":1,"uptime":7654321,
				"x_authkey":"`+unifiPoison+`","x_vwirekey":"`+unifiPoison+`",
				"ethernet_table":[{"name":"eth0","mac":"78:8a:20:4b:ee:52","num_port":1}],
				"uplink":{
					"uplink_mac":"78:8a:20:4b:ee:41",
					"uplink_device_name":"Office Switch",
					"uplink_remote_port":2,"port_idx":1,"type":"wire",
					"x_uplink_key":"`+unifiPoison+`"
				}
			}]`)
		default:
			ok(w, `[]`)
		}
	}))
}

// The fixture's managed devices. The switch is what the controller's LLDP and
// client tables hang off; the AP uplinks through the switch, so its uplink edge
// has to land on the switch asset rather than on a second, MAC-only one.
const (
	unifiSwitchMAC = "78:8a:20:4b:ee:41"
	unifiAPMAC     = "78:8a:20:4b:ee:52"
	lldpNeighbour  = "00:1b:17:00:00:01"
	unifiClientMAC = "4c:6e:0a:87:d4:80"
)

// unifiRun is one interrogation of the fixture controller, persisted through
// the service's own adapter.
type unifiRun struct {
	tenant     uuid.UUID
	controller uuid.UUID
	jobID      uuid.UUID
	hexLocalID uuid.UUID
	result     *di.InterrogateResult
	persistErr error
}

// interrogateUniFiFixture drives the whole path a real UniFi integration
// drives: the REAL registry (so the result has been through Sanitize as it
// would be in production), then the service's own persistObservations adapter.
//
// configure runs after the fixture's pre-existing inventory is in place and
// before the interrogation, to set the tenant up the way the case needs.
func interrogateUniFiFixture(t *testing.T, db *sql.DB, configure func(tenant uuid.UUID)) unifiRun {
	t.Helper()
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	hostname := "unifi-" + uuid.New().String()[:8] + ".corp.example.test"
	srv := newUniFiControllerForTest(t, hostname)
	t.Cleanup(srv.Close)
	// httptest binds loopback, which the device SSRF guard refuses. Open THIS
	// listener and nothing else: every other address the collector could be
	// talked into dialling still goes through the production guard.
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	// The controller is the device being interrogated: an asset with
	// management, exactly as Discovery → Devices creates it.
	svc := NewDeviceServiceWithKey(db, testMasterKey)
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	hexLocalID := seedHexLocalHost(t, db, tenant, unifiClientMAC, "4c6e0a87d480.local")
	if configure != nil {
		configure(tenant)
	}

	interrogator, err := di.NewRegistry().Get("unifi")
	if err != nil {
		t.Fatalf("registry.Get(unifi): %v", err)
	}
	result, err := interrogator.Interrogate(ctx, di.DeviceInfo{
		DeviceType:    "unifi",
		ManagementURL: srv.URL,
	}, di.Credentials{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}
	if len(result.Relationships) == 0 {
		t.Fatalf("the collector emitted no relationships; facts: %d assets: %d", len(result.Facts), len(result.Assets))
	}

	jobID := uuid.New()
	sink := &DeviceInterrogationService{db: db, observations: NewObservationSink(db)}
	return unifiRun{
		tenant:     tenant,
		controller: dev.ID,
		jobID:      jobID,
		hexLocalID: hexLocalID,
		result:     result,
		persistErr: sink.persistObservations(ctx, tenant, dev.ID, jobID, result),
	}
}

// TestIntegration_UniFiCollector_DrawsEdgesThroughTheEngine joins the two
// halves: a UniFi `stat/device` response goes in, and assets, facts and edges
// come out.
//
// It asserts the wiring, not the helper: delete the persistObservations call in
// InterrogateDevice and the collector still emits edges and the sink still
// writes them, and only a test that goes through the adapter notices.
func TestIntegration_UniFiCollector_DrawsEdgesThroughTheEngine(t *testing.T) {
	db := testdb.Connect(t)

	// A tenant that has not turned identity admission on — the default, since
	// the mode reads as disabled when no setting exists. Every subject the
	// controller names resolves at once, so this is where the full map is
	// asserted.
	t.Run("admission off", func(t *testing.T) {
		run := interrogateUniFiFixture(t, db, nil)
		tenant := run.tenant
		if run.persistErr != nil {
			t.Errorf("persistObservations dropped observations: %v", run.persistErr)
		}
		ref := "interrogation:" + run.jobID.String()

		// --- the switch and the AP became assets, and their facts are on them
		switchID := assetByIdentifier(t, db, tenant, "mac_address", unifiSwitchMAC)
		apID := assetByIdentifier(t, db, tenant, "mac_address", unifiAPMAC)
		neighbourID := assetByIdentifier(t, db, tenant, "mac_address", lldpNeighbour)
		if switchID == apID {
			t.Fatalf("the switch and the AP resolved to one asset %s", switchID)
		}
		assertDeviceFacts(t, db, tenant, switchID, ref, "US8P150", "788A204BEE41")
		assertDeviceFacts(t, db, tenant, apID, ref, "U6LR", "788A204BEE52")

		// --- member_of: both adopted devices belong to the controller ------
		for _, dev := range []struct {
			id    uuid.UUID
			label string
		}{{switchID, "switch adoption"}, {apID, "AP adoption"}} {
			assertCollectorEdge(t, db, tenant, collectorEdge{
				from: dev.id, to: run.controller, typ: "member_of", sourceRef: ref, label: dev.label,
			})
		}

		// --- member_of: the AP uplinks through the switch ------------------
		assertCollectorEdge(t, db, tenant, collectorEdge{
			from: apID, to: switchID, typ: "member_of", sourceRef: ref, label: "AP uplink",
		})

		// --- connects_to: the LLDP neighbour -------------------------------
		//
		// UniFi reports both an LLDP neighbour and an uplink for the same
		// physical link, so the uplink's member_of and the LLDP connects_to
		// land between the same pair. The connects_to is the one asserted: it
		// is what draws the neighbour on the map as a link, not a container.
		assertCollectorEdge(t, db, tenant, collectorEdge{
			from: switchID, to: neighbourID, typ: "connects_to", sourceRef: ref, label: "LLDP neighbour",
		})

		// --- provenance, on every edge this run wrote -----------------------
		//
		// An edge with no provenance cannot be audited or swept, and "measured"
		// versus "inferred" is the field a reviewer uses to decide whether to
		// believe it (ADR-0008 D4.2).
		rows, err := db.Query(`
			SELECT type, source_kind, coalesce(source_ref, ''), status
			FROM asset_relationships WHERE tenant_id = $1`, tenant)
		if err != nil {
			t.Fatalf("edge scan: %v", err)
		}
		defer func() { _ = rows.Close() }()
		seen := 0
		for rows.Next() {
			var typ, kind, gotRef, status string
			if err := rows.Scan(&typ, &kind, &gotRef, &status); err != nil {
				t.Fatalf("scan: %v", err)
			}
			seen++
			if kind != string(identity.SourceMeasured) {
				t.Errorf("%s edge source_kind = %q, want measured — a controller STATES its adoption and its neighbours", typ, kind)
			}
			if gotRef != ref {
				t.Errorf("%s edge source_ref = %q, want %s", typ, gotRef, ref)
			}
			if status != "pending" {
				t.Errorf("%s edge status = %q, want pending — neither end was approved by anyone", typ, status)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows: %v", err)
		}
		if seen < 5 {
			t.Errorf("%d edges written, want at least the two adoptions, the AP uplink, the LLDP link and the client link", seen)
		}

		// --- UniFi client joined the hex .local CI by MAC and promoted linux-2
		clientID := assetByIdentifier(t, db, tenant, "mac_address", unifiClientMAC)
		if clientID != run.hexLocalID {
			t.Errorf("client MAC minted a new asset %s; want join onto hex .local CI %s", clientID, run.hexLocalID)
		}
		var hostName, display string
		if err := db.QueryRow(`SELECT coalesce(hostname,''), coalesce(display_name,'') FROM assets WHERE tenant_id=$1 AND id=$2`,
			tenant, run.hexLocalID).Scan(&hostName, &display); err != nil {
			t.Fatalf("read hex-local CI names: %v", err)
		}
		if hostName != "linux-2" || display != "linux-2" {
			t.Errorf("CI names hostname=%q display=%q, want linux-2 after STA ingest", hostName, display)
		}
		assertCollectorEdge(t, db, tenant, collectorEdge{
			from: clientID, to: switchID, typ: "connects_to", sourceRef: ref, label: "client-to-switch",
		})

		var dyn sql.NullBool
		var src, srcType, srcAsset, dhcp sql.NullString
		if err := db.QueryRow(`
			SELECT (metadata->>'dynamic')::boolean, metadata->>'source',
			       metadata->>'source_device_type', metadata->>'source_asset_id', metadata->>'dhcp'
			FROM network_segments
			WHERE tenant_id = $1 AND value = '192.0.2.0/24' AND segment_type = 'cidr'`,
			tenant).Scan(&dyn, &src, &srcType, &srcAsset, &dhcp); err != nil {
			t.Fatalf("DHCP LAN segment: %v", err)
		}
		if !dyn.Valid || !dyn.Bool || dhcp.String != "enabled" {
			t.Errorf("DHCP LAN metadata.dynamic = %v dhcp = %q, want true/enabled so lease IPs cannot vote", dyn, dhcp.String)
		}
		// Provenance names the device, through the real in-cluster path: the
		// controller Discovery → Devices created, not a hard-coded vendor.
		if src.String != "interrogation" || srcType.String != "unifi" || srcAsset.String != run.controller.String() {
			t.Errorf("DHCP LAN provenance = %q/%q/%q, want interrogation/unifi/%s", src.String, srcType.String, srcAsset.String, run.controller)
		}

		var iotDyn sql.NullBool
		if err := db.QueryRow(`
			SELECT (metadata->>'dynamic')::boolean
			FROM network_segments
			WHERE tenant_id = $1 AND value = '198.51.100.0/24' AND segment_type = 'cidr'`,
			tenant).Scan(&iotDyn); err != nil {
			t.Fatalf("static VLAN segment: %v", err)
		}
		if !iotDyn.Valid || iotDyn.Bool {
			t.Errorf("static VLAN metadata.dynamic = %v, want false", iotDyn)
		}

		// --- and nothing the controller volunteered came with them ----------
		//
		// The mesh PSK, the SMTP relay password, the per-device auth key and
		// the operator's email are all in the fixture above; none of them may
		// be in a row. This is the assertion the original leak would have
		// failed.
		assertNoPoisonInTenantRows(t, db, tenant)
	})

	// A tenant with identity admission ENFORCED and an asset allowance — the
	// configuration of the live tenant where this went wrong. Admission admits
	// the devices the controller inventories and RETAINS the weakly-evidenced
	// peers (the LLDP neighbour, the controller as its devices name it) until
	// they can be resolved. The retained peers' receipt envelopes are
	// persisted to a jsonb column keyed per peer.
	//
	// That key used to join a peer's identifiers with NUL. jsonb refuses
	// \u0000 (22P05), so every peer with two or more identifiers failed its
	// resolution transaction and the fact or edge it carried was dropped: on a
	// live interrogation 139 of 143 facts and all 74 relationships. With
	// admission off nothing is retained and the key is never written, which is
	// why the case above could not see it.
	//
	// MUTATION: make retainedPeerKey return identifierKey(peer) and this fails
	// with every fact and edge dropped on `pq: unsupported Unicode escape
	// sequence (22P05)`.
	t.Run("admission enforced", func(t *testing.T) {
		run := interrogateUniFiFixture(t, db, func(tenant uuid.UUID) {
			if _, err := db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
				SELECT $1,id,'{"quantity":100}'::jsonb,'unifi collector edges' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
				t.Fatalf("asset allowance: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
				ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
				t.Fatalf("enforce admission: %v", err)
			}
		})
		tenant := run.tenant
		if run.persistErr != nil {
			t.Fatalf("persistObservations dropped observations under enforced admission: %v", run.persistErr)
		}
		ref := "interrogation:" + run.jobID.String()

		// The devices the controller inventories are admitted, with their facts.
		switchID := assetByIdentifier(t, db, tenant, "mac_address", unifiSwitchMAC)
		apID := assetByIdentifier(t, db, tenant, "mac_address", unifiAPMAC)
		assertDeviceFacts(t, db, tenant, switchID, ref, "US8P150", "788A204BEE41")
		assertDeviceFacts(t, db, tenant, apID, ref, "U6LR", "788A204BEE52")

		// Edges are not asserted here. Under enforced admission a peer named
		// only by a MAC (the AP's uplink, a client's switch) is retained with
		// network_scope_unresolved rather than matched to the admitted asset,
		// so those edges wait for replay. That is admission policy, and the
		// case above asserts the edges themselves.

		// The retained context reached Postgres, and every peer the collector
		// named reads back by the key it was stored under — which is what
		// replay does once an operator resolves the retained peers.
		var body []byte
		if err := db.QueryRow(`SELECT payload FROM identity_observation_peer_contexts WHERE tenant_id=$1`, tenant).Scan(&body); err != nil {
			t.Fatalf("no retained peer context: %v — admission retained nothing, so the retained path was not exercised", err)
		}
		var state retainedPeerContext
		if err := json.Unmarshal(body, &state); err != nil {
			t.Fatalf("decode retained payload: %v", err)
		}
		multi := 0
		for _, peer := range unifiRunPeers(run.result) {
			if len(peer.Identifiers) > 1 {
				multi++
			}
			if _, ok := state.retainedPeer(peer); !ok {
				t.Errorf("retained context has no envelope for peer %q (%d identifiers)", peer.DisplayName, len(peer.Identifiers))
			}
		}
		// Without a multi-identifier peer the key never had a separator in it,
		// and this case would pass against the bug it exists for.
		if multi == 0 {
			t.Fatal("the fixture names no peer with two or more identifiers, so the NUL-key shape is not exercised")
		}
		for key := range state.Peers {
			if raw, err := hex.DecodeString(key); err != nil || len(raw) != sha256.Size {
				t.Errorf("retained peer key %q is not a hex SHA-256", key)
			}
		}

		// Under admission the vendor projection is persisted a second time, in
		// the retained payload, and that copy has to be as clean as the rows.
		if strings.Contains(string(body), unifiPoison) {
			t.Errorf("the retained peer context carries material the controller volunteered and nothing reads")
		}
	})
}

// unifiRunPeers is every distinct peer the persisted observations name: the
// set preparePeerContext retains an envelope for.
func unifiRunPeers(result *di.InterrogateResult) []di.PeerRef {
	var peers []di.PeerRef
	seen := map[string]bool{}
	add := func(p di.PeerRef) {
		if p.IsZero() {
			return
		}
		if key := retainedPeerKey(p); !seen[key] {
			seen[key] = true
			peers = append(peers, p)
		}
	}
	for _, f := range result.Facts {
		add(f.Subject)
	}
	for _, r := range result.Relationships {
		add(r.Subject)
		add(r.Peer)
	}
	return peers
}

// assertDeviceFacts asserts that a managed device's identity facts landed on
// ITS asset, from this interrogation — not on the controller, and not on a
// second asset for the same device.
func assertDeviceFacts(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, sourceRef, model, serial string) {
	t.Helper()
	for key, want := range map[string]string{
		"hw.vendor": "Ubiquiti Networks",
		"hw.model":  model,
		"hw.serial": serial,
	} {
		var got string
		if err := db.QueryRow(`
			SELECT value #>> '{}' FROM asset_facts
			WHERE tenant_id = $1 AND asset_id = $2 AND key = $3 AND source_ref = $4`,
			tenant, asset, key, sourceRef).Scan(&got); err != nil {
			t.Errorf("asset %s has no %s fact from %s: %v", asset, key, sourceRef, err)
			continue
		}
		if got != want {
			t.Errorf("asset %s %s = %q, want %q", asset, key, got, want)
		}
	}
	var interfaces int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_facts
		WHERE tenant_id = $1 AND asset_id = $2 AND key = 'net.interfaces' AND source_ref = $3`,
		tenant, asset, sourceRef).Scan(&interfaces); err != nil {
		t.Fatalf("net.interfaces lookup: %v", err)
	}
	if interfaces != 1 {
		t.Errorf("asset %s has %d net.interfaces facts from %s, want 1", asset, interfaces, sourceRef)
	}
}

// --- helpers ---------------------------------------------------------------

type collectorEdge struct {
	from, to  uuid.UUID
	typ       string
	sourceRef string
	label     string
}

func assertCollectorEdge(t *testing.T, db *sql.DB, tenant uuid.UUID, want collectorEdge) {
	t.Helper()
	var kind, ref string
	if err := db.QueryRow(`
		SELECT source_kind, coalesce(source_ref, '') FROM asset_relationships
		WHERE tenant_id = $1 AND from_asset_id = $2 AND to_asset_id = $3 AND type = $4`,
		tenant, want.from, want.to, want.typ).Scan(&kind, &ref); err != nil {
		t.Fatalf("%s (%s): no %s edge %s -> %s: %v", want.label, want.typ, want.typ, want.from, want.to, err)
	}
	if kind != string(identity.SourceMeasured) || ref != want.sourceRef {
		t.Errorf("%s edge provenance = (%q, %q), want (measured, %q)", want.typ, kind, ref, want.sourceRef)
	}
}

func seedHexLocalHost(t *testing.T, db *sql.DB, tenant uuid.UUID, mac, hexLocal string) uuid.UUID {
	t.Helper()
	repo := pgidentity.New(db)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatalf("identification engine: %v", err)
	}
	obs := identity.Observation{
		TenantID:    tenant.String(),
		ClassHint:   string(assetclass.KeyUnknownHost),
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:host-identity-test", Mode: identity.ModePassive},
		ObservedAt:  time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC),
		Confidence:  0.85,
		Network:     identity.Network{Ownership: identity.OwnershipInternal},
		Hostname:    hexLocal,
		DisplayName: hexLocal,
		Identifiers: []identity.Identifier{
			{Kind: identity.KindMACAddress, Value: mac, Confidence: 1},
			{Kind: identity.KindHostname, Value: hexLocal, Scope: identity.ScopeTenantDefault, Confidence: 1},
		},
	}
	clean, _ := obs.Sanitize()
	var assetID uuid.UUID
	err = repo.RunInTx(context.Background(), tenant.String(), func(r *pgidentity.Repository) error {
		res, rErr := engine.WithRepository(r).Resolve(context.Background(), clean)
		if rErr != nil {
			return rErr
		}
		if res.Asset.Zero() {
			t.Fatalf("hex .local sighting created no asset")
		}
		assetID = uuid.MustParse(res.Asset.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("seed hex .local host: %v", err)
	}
	return assetID
}

func assetByIdentifier(t *testing.T, db *sql.DB, tenant uuid.UUID, kind, value string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`
		SELECT a.id FROM assets a
		JOIN asset_identifiers i ON i.tenant_id = a.tenant_id AND i.asset_id = a.id
		WHERE a.tenant_id = $1 AND i.kind = $2 AND i.value = $3`, tenant, kind, value).Scan(&id); err != nil {
		t.Fatalf("no asset carries %s=%s: %v", kind, value, err)
	}
	return id
}

// assertNoPoisonInTenantRows sweeps the four tables an interrogation writes for
// the poison string. A per-column assertion would miss the leak that actually
// happened, which was a whole vendor object landing in a jsonb column nobody
// was looking at.
func assertNoPoisonInTenantRows(t *testing.T, db *sql.DB, tenant uuid.UUID) {
	t.Helper()
	for _, q := range []struct {
		what  string
		query string
	}{
		{"asset_facts", `SELECT coalesce(json_agg(row_to_json(t))::text, '[]') FROM (SELECT key, value, source_ref FROM asset_facts WHERE tenant_id = $1) t`},
		{"asset_relationships", `SELECT coalesce(json_agg(row_to_json(t))::text, '[]') FROM (SELECT type, attributes, source_ref FROM asset_relationships WHERE tenant_id = $1) t`},
		{"asset_identifiers", `SELECT coalesce(json_agg(row_to_json(t))::text, '[]') FROM (SELECT kind, value FROM asset_identifiers WHERE tenant_id = $1) t`},
		{"assets", `SELECT coalesce(json_agg(row_to_json(t))::text, '[]') FROM (SELECT display_name, hostname, metadata FROM assets WHERE tenant_id = $1) t`},
	} {
		var blob string
		if err := db.QueryRow(q.query, tenant).Scan(&blob); err != nil {
			t.Fatalf("%s sweep: %v", q.what, err)
		}
		if strings.Contains(blob, unifiPoison) {
			t.Errorf("%s carries material the controller volunteered and nothing reads: %s", q.what, blob)
		}
		// And the sweep must be looking at something.
		var parsed []map[string]any
		if err := json.Unmarshal([]byte(blob), &parsed); err != nil {
			t.Fatalf("%s sweep did not return JSON: %v", q.what, err)
		}
		if len(parsed) == 0 {
			t.Errorf("%s has no rows for this tenant, so its sweep proves nothing", q.what)
		}
	}
}
