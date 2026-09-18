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
	"database/sql"
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
			}]`)
		default:
			ok(w, `[]`)
		}
	}))
}

// TestIntegration_UniFiCollector_DrawsEdgesThroughTheEngine drives the whole
// path a real UniFi integration drives: the REAL registry (so the result has
// been through Sanitize as it would be in production), then the service's own
// persistObservations adapter, then the rows.
//
// It asserts the wiring, not the helper: delete the persistObservations call in
// InterrogateDevice and the collector still emits edges and the sink still
// writes them, and only a test that goes through the adapter notices.
func TestIntegration_UniFiCollector_DrawsEdgesThroughTheEngine(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	hostname := "unifi-" + uuid.New().String()[:8] + ".corp.example.test"
	srv := newUniFiControllerForTest(t, hostname)
	defer srv.Close()

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

	hexLocalID := seedHexLocalHost(t, db, tenant, "4c:6e:0a:87:d4:80", "4c6e0a87d480.local")

	registry := di.NewRegistry()
	interrogator, err := registry.Get("unifi")
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
	sink.persistObservations(ctx, tenant, dev.ID, jobID, result)

	// --- the switch became an asset ---------------------------------------
	switchID := assetByIdentifier(t, db, tenant, "mac_address", "78:8a:20:4b:ee:41")
	neighbourID := assetByIdentifier(t, db, tenant, "mac_address", "00:1b:17:00:00:01")

	// --- member_of: the adopted switch belongs to the controller ----------
	assertCollectorEdge(t, db, tenant, collectorEdge{
		from: switchID, to: dev.ID, typ: "member_of",
		sourceRef: "interrogation:" + jobID.String(),
		label:     "adoption",
	})

	// --- connects_to: the LLDP neighbour ----------------------------------
	//
	// UniFi reports both an LLDP neighbour and an uplink for the same physical
	// link, so the two edges land between the same pair. What matters for the
	// map is that the neighbour became an asset and at least one edge joins it
	// to the switch.
	var joined int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_relationships
		WHERE tenant_id = $1
		  AND ((from_asset_id = $2 AND to_asset_id = $3) OR (from_asset_id = $3 AND to_asset_id = $2))`,
		tenant, switchID, neighbourID).Scan(&joined); err != nil {
		t.Fatalf("neighbour edge lookup: %v", err)
	}
	if joined == 0 {
		t.Error("the LLDP neighbour became an asset but no edge joins it to the switch; the map would show two unconnected nodes")
	}

	// --- provenance, on every edge this run wrote -------------------------
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
		var typ, kind, ref, status string
		if err := rows.Scan(&typ, &kind, &ref, &status); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen++
		if kind != string(identity.SourceMeasured) {
			t.Errorf("%s edge source_kind = %q, want measured — a controller STATES its adoption and its neighbours", typ, kind)
		}
		if ref != "interrogation:"+jobID.String() {
			t.Errorf("%s edge source_ref = %q, want interrogation:%s", typ, ref, jobID)
		}
		if status != "pending" {
			t.Errorf("%s edge status = %q, want pending — neither end was approved by anyone", typ, status)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if seen < 2 {
		t.Errorf("%d edges written, want at least the adoption and the neighbour link", seen)
	}

	// --- UniFi client joined the hex .local CI by MAC and promoted linux-2 --
	clientID := assetByIdentifier(t, db, tenant, "mac_address", "4c:6e:0a:87:d4:80")
	if clientID != hexLocalID {
		t.Errorf("client MAC minted a new asset %s; want join onto hex .local CI %s", clientID, hexLocalID)
	}
	var hostName, display string
	if err := db.QueryRow(`SELECT coalesce(hostname,''), coalesce(display_name,'') FROM assets WHERE tenant_id=$1 AND id=$2`,
		tenant, hexLocalID).Scan(&hostName, &display); err != nil {
		t.Fatalf("read hex-local CI names: %v", err)
	}
	if hostName != "linux-2" || display != "linux-2" {
		t.Errorf("CI names hostname=%q display=%q, want linux-2 after STA ingest", hostName, display)
	}
	assertCollectorEdge(t, db, tenant, collectorEdge{
		from: clientID, to: switchID, typ: "connects_to",
		sourceRef: "interrogation:" + jobID.String(),
		label:     "client-to-switch",
	})

	var dyn sql.NullBool
	var src sql.NullString
	if err := db.QueryRow(`
		SELECT (metadata->>'dynamic')::boolean, metadata->>'source'
		FROM network_segments
		WHERE tenant_id = $1 AND value = '192.0.2.0/24' AND segment_type = 'cidr'`,
		tenant).Scan(&dyn, &src); err != nil {
		t.Fatalf("DHCP LAN segment: %v", err)
	}
	if !dyn.Valid || !dyn.Bool {
		t.Errorf("DHCP LAN metadata.dynamic = %v, want true so lease IPs cannot vote", dyn)
	}
	if src.String != "unifi" {
		t.Errorf("DHCP LAN metadata.source = %q, want unifi", src.String)
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

	// --- and nothing the controller volunteered came with them ------------
	//
	// The mesh PSK, the SMTP relay password, the per-device auth key and the
	// operator's email are all in the fixture above; none of them may be in a
	// row. This is the assertion the original leak would have failed.
	assertNoPoisonInTenantRows(t, db, tenant)
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
