package services

// Sensor self-observation, end to end against a real Postgres (asset-inventory
// decision 9, morning notes).
//
// The gap this closes was verified in the lab: a sensor's own host asset
// showed up as `<its LAN address> · unknown_host · monitoring`, carrying only
// a MAC and an IP, while the `sensors` row for that same sensor knew its name,
// platform and profile. These tests pin both halves of the fix — a self-report becomes a
// named, classed asset through the SAME host-observation ingest path every
// other observation uses, and the retro-link case: an asset that already
// exists ANONYMOUSLY (seen only passively, by some other sensor, before this
// one ever self-reported) gains the sensor's identity rather than duplicating.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

// selfObservationFinding builds the finding sensor-manager's
// services/self_observation.go produces (see selfObservationDiscovery there):
// discovery_method "sensor_self_report", the observation carrying AgentID.
func selfObservationFinding(t *testing.T, sensorID uuid.UUID, ho *hostobs.HostObservation) IngestFinding {
	t.Helper()
	ho.AgentID = sensorID.String()
	f := observationFinding(t, ho)
	sensorRef := sensorID.String()
	f.SourceSensorID = &sensorRef
	f.RawData["discovery_method"] = "sensor_self_report"
	f.RawData["confidence_score"] = 1.0
	return f
}

func TestIntegration_SelfObservation_BecomesNamedClassedAssetAndLinksSensor(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	sensorID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status)
		VALUES ($1, $2, 'xps16-sensor', 'linux', '1.0.0', 'datacenter_host', 'active')`,
		sensorID, tenant); err != nil {
		t.Fatalf("insert sensor fixture: %v", err)
	}

	f := selfObservationFinding(t, sensorID, &hostobs.HostObservation{
		Platform:  "linux",
		Profile:   "datacenter_host",
		Hostnames: []string{"xps16-sensor"},
		Addresses: addrsFor(t, "192.0.2.173"),
	})

	imported, err := svc.IngestFindings(tenant, []IngestFinding{f})
	if err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want 1", imported)
	}

	var assetID uuid.UUID
	var classKey, hostname string
	if err := db.QueryRow(`
		SELECT id, class_key, COALESCE(hostname, '')
		  FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).
		Scan(&assetID, &classKey, &hostname); err != nil {
		t.Fatalf("read the asset back: %v", err)
	}

	if classKey != "server" {
		t.Errorf("class_key = %q, want server (linux + datacenter_host profile)", classKey)
	}
	if hostname != "xps16-sensor" {
		t.Errorf("hostname = %q, want xps16-sensor — no longer an anonymous unknown_host", hostname)
	}

	var sensorIDValue string
	if err := db.QueryRow(`
		SELECT value FROM asset_identifiers
		 WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'sensor_id'`, tenant, assetID).
		Scan(&sensorIDValue); err != nil {
		t.Fatalf("sensor_id identifier missing: %v", err)
	}
	if sensorIDValue != sensorID.String() {
		t.Errorf("sensor_id identifier = %q, want %q", sensorIDValue, sensorID.String())
	}

	var linkedAssetID uuid.UUID
	if err := db.QueryRow(`SELECT asset_id FROM sensors WHERE id = $1`, sensorID).Scan(&linkedAssetID); err != nil {
		t.Fatalf("read sensors.asset_id: %v", err)
	}
	if linkedAssetID != assetID {
		t.Errorf("sensors.asset_id = %s, want %s", linkedAssetID, assetID)
	}
}

// TestIntegration_SelfObservation_RetroLinksAnonymousUnknownHost is the
// real-deployment case: the sensor's own host was seen PASSIVELY (by some other
// sensor's ARP/mDNS capture) before this sensor ever self-reported, so an
// anonymous unknown_host asset already exists holding only its MAC and IP. The
// self-report must MATCH that asset (same MAC/IP resolve it) rather than
// create a second one, and the match must upgrade it: hostname, class, and the
// sensor_id identifier all land on the asset that already existed.
func TestIntegration_SelfObservation_RetroLinksAnonymousUnknownHost(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	sensorID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status)
		VALUES ($1, $2, 'xps16-sensor', 'linux', '1.0.0', 'datacenter_host', 'active')`,
		sensorID, tenant); err != nil {
		t.Fatalf("insert sensor fixture: %v", err)
	}

	// Step 1: an anonymous passive observation of the same host, from a
	// DIFFERENT (other) sensor's capture — MAC + IP only, no name. This is
	// exactly what leaves a sensor's own host as an anonymous unknown_host
	// in real deployments.
	passive := observationFinding(t, &hostobs.HostObservation{
		Source:    hostobs.SourceARP,
		MAC:       "28:cf:da:aa:bb:cc",
		Addresses: addrsFor(t, "192.0.2.173"),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{passive}); err != nil {
		t.Fatalf("IngestFindings(passive): %v", err)
	}

	var anonAssetID uuid.UUID
	var anonClass, anonHostname string
	if err := db.QueryRow(`
		SELECT id, class_key, COALESCE(hostname, '')
		  FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).
		Scan(&anonAssetID, &anonClass, &anonHostname); err != nil {
		t.Fatalf("read the anonymous asset back: %v", err)
	}
	if anonClass != "unknown_host" {
		t.Fatalf("precondition failed: anonymous asset class_key = %q, want unknown_host", anonClass)
	}
	if anonHostname != "" {
		t.Fatalf("precondition failed: anonymous asset already has a hostname %q", anonHostname)
	}

	// Step 2: the sensor's OWN self-report of the SAME host (same MAC/IP —
	// the retro-link signal) arrives.
	self := selfObservationFinding(t, sensorID, &hostobs.HostObservation{
		Platform:  "linux",
		Profile:   "datacenter_host",
		MAC:       "28:cf:da:aa:bb:cc",
		Hostnames: []string{"xps16-sensor"},
		Addresses: addrsFor(t, "192.0.2.173"),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{self}); err != nil {
		t.Fatalf("IngestFindings(self): %v", err)
	}

	var assetCount int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).
		Scan(&assetCount); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if assetCount != 1 {
		t.Fatalf("asset count = %d, want 1 — the self-report must MATCH the existing MAC/IP asset, not create a second one", assetCount)
	}

	var classKey, hostname string
	if err := db.QueryRow(`
		SELECT class_key, COALESCE(hostname, '') FROM assets WHERE id = $1`, anonAssetID).
		Scan(&classKey, &hostname); err != nil {
		t.Fatalf("read the upgraded asset: %v", err)
	}
	if hostname != "xps16-sensor" {
		t.Errorf("hostname = %q after retro-link, want xps16-sensor", hostname)
	}
	if classKey != "server" {
		t.Errorf("class_key = %q after retro-link, want server", classKey)
	}

	var sensorIDValue string
	if err := db.QueryRow(`
		SELECT value FROM asset_identifiers
		 WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'sensor_id'`, tenant, anonAssetID).
		Scan(&sensorIDValue); err != nil {
		t.Fatalf("sensor_id identifier missing after retro-link: %v", err)
	}
	if sensorIDValue != sensorID.String() {
		t.Errorf("sensor_id = %q, want %q", sensorIDValue, sensorID.String())
	}

	var linkedAssetID uuid.UUID
	if err := db.QueryRow(`SELECT asset_id FROM sensors WHERE id = $1`, sensorID).Scan(&linkedAssetID); err != nil {
		t.Fatalf("read sensors.asset_id: %v", err)
	}
	if linkedAssetID != anonAssetID {
		t.Errorf("sensors.asset_id = %s, want the SAME (retro-linked) asset %s", linkedAssetID, anonAssetID)
	}
}

// TestIntegration_SelfObservation_NeverOverwritesAnAlreadyClassifiedAsset is
// the guard the retro-link case above trusts: a self-report may only fill the
// unknown_host FLOOR, never argue with a class a rule, a human or an import
// already decided. Without this, an asset a reviewer approved as
// (say) `network_device` — matched on MAC because it happens to share one
// with a NIC the sensor also reports (a container host bridging its own
// interface, for instance) — would have its class silently rewritten on the
// next self-report heartbeat.
//
// Mutation check: dropping the `AND class_key = 'unknown_host'` predicate
// from upgradeUnknownHostClass's UPDATE makes this test fail (class_key
// becomes "server").
func TestIntegration_SelfObservation_NeverOverwritesAnAlreadyClassifiedAsset(t *testing.T) {
	for _, declaredClass := range []string{"network_device", "unknown_host"} {
		t.Run(declaredClass, func(t *testing.T) {
			svc, db, tenant := newHostObsFixture(t)

			sensorID := uuid.New()
			if _, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status)
		VALUES ($1, $2, 'xps16-sensor', 'linux', '1.0.0', 'datacenter_host', 'active')`,
				sensorID, tenant); err != nil {
				t.Fatalf("insert sensor fixture: %v", err)
			}

			// An asset a human (or a rule) already classified, sharing the MAC the
			// self-report will carry.
			passive := observationFinding(t, &hostobs.HostObservation{
				Source:    hostobs.SourceARP,
				MAC:       "28:cf:da:11:aa:bb",
				Addresses: addrsFor(t, "192.0.2.174"),
			})
			if _, err := svc.IngestFindings(tenant, []IngestFinding{passive}); err != nil {
				t.Fatalf("IngestFindings(passive): %v", err)
			}
			var existingID uuid.UUID
			if err := db.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).
				Scan(&existingID); err != nil {
				t.Fatalf("read the pre-existing asset: %v", err)
			}
			if _, err := db.Exec(`UPDATE assets SET class_key = $2, class_source_kind = 'declared' WHERE id = $1`, existingID, declaredClass); err != nil {
				t.Fatalf("simulate a human-approved class: %v", err)
			}

			self := selfObservationFinding(t, sensorID, &hostobs.HostObservation{
				Platform:  "linux",
				Profile:   "datacenter_host",
				MAC:       "28:cf:da:11:aa:bb",
				Hostnames: []string{"xps16-sensor"},
				Addresses: addrsFor(t, "192.0.2.174"),
			})
			if _, err := svc.IngestFindings(tenant, []IngestFinding{self}); err != nil {
				t.Fatalf("IngestFindings(self): %v", err)
			}

			var classKey string
			if err := db.QueryRow(`SELECT class_key FROM assets WHERE id = $1`, existingID).Scan(&classKey); err != nil {
				t.Fatalf("read the asset back: %v", err)
			}
			if classKey != declaredClass {
				t.Errorf("class_key = %q after a self-report, want the declared class %s UNCHANGED", classKey, declaredClass)
			}
		})
	}
}

// TestIntegration_SelfObservation_NeverDemotesAnExistingHostname is the
// hostname analogue of the class test above: a later self-report of a worse
// (synthetic) name must not revert a better measured hostname. Equal-or-better
// names still promote via the identity engine's ranker.
//
// Mutation check: last-write-wins on hostname makes this fail.
func TestIntegration_SelfObservation_NeverDemotesAnExistingHostname(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	sensorID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status)
		VALUES ($1, $2, 'xps16-sensor', 'linux', '1.0.0', 'datacenter_host', 'active')`,
		sensorID, tenant); err != nil {
		t.Fatalf("insert sensor fixture: %v", err)
	}

	passive := observationFinding(t, &hostobs.HostObservation{
		Source:    hostobs.SourceDHCP,
		MAC:       "28:cf:da:22:33:44",
		Addresses: addrsFor(t, "192.0.2.175"),
		Hostnames: []string{"already-named-host"},
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{passive}); err != nil {
		t.Fatalf("IngestFindings(passive): %v", err)
	}
	var existingID uuid.UUID
	var existingHostname string
	if err := db.QueryRow(`SELECT id, COALESCE(hostname, '') FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).
		Scan(&existingID, &existingHostname); err != nil {
		t.Fatalf("read the pre-existing asset: %v", err)
	}
	if existingHostname != "already-named-host" {
		t.Fatalf("precondition failed: hostname = %q", existingHostname)
	}

	self := selfObservationFinding(t, sensorID, &hostobs.HostObservation{
		Platform:  "linux",
		Profile:   "datacenter_host",
		MAC:       "28:cf:da:22:33:44",
		Hostnames: []string{"4c6e0a87d480.local"},
		Addresses: addrsFor(t, "192.0.2.175"),
	})
	if _, err := svc.IngestFindings(tenant, []IngestFinding{self}); err != nil {
		t.Fatalf("IngestFindings(self): %v", err)
	}

	var hostname string
	if err := db.QueryRow(`SELECT COALESCE(hostname, '') FROM assets WHERE id = $1`, existingID).Scan(&hostname); err != nil {
		t.Fatalf("read the asset back: %v", err)
	}
	if hostname != "already-named-host" {
		t.Errorf("hostname = %q after a worse self-report, want the pre-existing name UNCHANGED", hostname)
	}
}

// TestIntegration_SelfObservation_SecondNICOpensAProposalAndStaysMatched is
// the first two-sensor deployment's shape: a laptop running a sensor has an
// Ethernet NIC (its primary) and a Wi-Fi NIC on another network. Passive
// capture met the Wi-Fi NIC first and recorded it as its own asset. The
// sensor's self-report names both MACs.
//
// Before: the report carried one MAC, so the two records never met — or, with
// both MACs, the walk's conflict path attached the report to NEITHER asset.
// Now the report stays matched to the sensor's asset and ONE merge proposal
// names both records; nothing moves, neither asset's status changes, and the
// next hourly report re-asks nothing.
func TestIntegration_SelfObservation_SecondNICOpensAProposalAndStaysMatched(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	const ethernetMAC, wifiMAC = "00:1a:2b:3c:4d:01", "00:1a:2b:3c:4d:02"

	sensorID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status)
		VALUES ($1, $2, 'laptop-sensor', 'windows', '4.5.0', 'datacenter_host', 'active')`,
		sensorID, tenant); err != nil {
		t.Fatalf("insert sensor fixture: %v", err)
	}
	ingest := func(f IngestFinding) {
		t.Helper()
		if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
			t.Fatalf("IngestFindings: %v", err)
		}
	}
	assetHolding := func(kind, value string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := db.QueryRow(`SELECT asset_id FROM asset_identifiers WHERE tenant_id=$1 AND kind=$2 AND value=$3`,
			tenant, kind, value).Scan(&id); err != nil {
			t.Fatalf("who holds %s=%s: %v", kind, value, err)
		}
		return id
	}
	status := func(id uuid.UUID) string {
		t.Helper()
		var s string
		if err := db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&s); err != nil {
			t.Fatalf("status of %s: %v", id, err)
		}
		return s
	}
	proposals := func() []string {
		t.Helper()
		rows, err := db.Query(`
			SELECT changes_json->'candidates' FROM asset_history
			 WHERE tenant_id=$1 AND action='merge_proposed' AND changes_json->>'kind'='merge_proposal'`, tenant)
		if err != nil {
			t.Fatalf("read proposals: %v", err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return out
	}

	// The Wi-Fi NIC, seen passively on its own network.
	ingest(observationFinding(t, &hostobs.HostObservation{
		Source:    hostobs.SourceARP,
		MAC:       wifiMAC,
		Addresses: addrsFor(t, "198.51.100.172"),
	}))
	// The sensor's first self-report: the Ethernet NIC only.
	ingest(selfObservationFinding(t, sensorID, &hostobs.HostObservation{
		Platform: "windows", Profile: "datacenter_host", Hostnames: []string{"laptop-7"},
		MAC: ethernetMAC, Addresses: addrsFor(t, "192.0.2.173"),
	}))
	wifiAsset, hostAsset := assetHolding("mac_address", wifiMAC), assetHolding("sensor_id", sensorID.String())
	if wifiAsset == hostAsset {
		t.Fatal("setup: the Ethernet self-report landed on the Wi-Fi record")
	}
	wifiStatus, hostStatus := status(wifiAsset), status(hostAsset)

	report := func() IngestFinding {
		return selfObservationFinding(t, sensorID, &hostobs.HostObservation{
			Platform: "windows", Profile: "datacenter_host", Hostnames: []string{"laptop-7"},
			MAC: ethernetMAC, OtherMACs: []string{wifiMAC}, Addresses: addrsFor(t, "192.0.2.173"),
		})
	}
	ingest(report())

	got := proposals()
	if len(got) != 1 {
		t.Fatalf("%d merge proposals, want one naming both records: %v", len(got), got)
	}
	for _, want := range []uuid.UUID{hostAsset, wifiAsset} {
		if !strings.Contains(got[0], want.String()) {
			t.Fatalf("proposal candidates %s do not name %s", got[0], want)
		}
	}
	// Still the sensor's asset, refreshed by its own report.
	var linked uuid.UUID
	if err := db.QueryRow(`SELECT asset_id FROM sensors WHERE id=$1`, sensorID).Scan(&linked); err != nil || linked != hostAsset {
		t.Fatalf("sensors.asset_id = %s (%v), want the sensor's own asset %s", linked, err, hostAsset)
	}
	// ADR-0002 D5: nothing moved, nothing left service.
	if holder := assetHolding("mac_address", wifiMAC); holder != wifiAsset {
		t.Fatalf("the Wi-Fi MAC moved to %s without a person deciding", holder)
	}
	if status(wifiAsset) != wifiStatus || status(hostAsset) != hostStatus {
		t.Fatalf("statuses changed: wifi %s→%s, host %s→%s", wifiStatus, status(wifiAsset), hostStatus, status(hostAsset))
	}

	// The next hourly report asks nothing new.
	ingest(report())
	if n := len(proposals()); n != 1 {
		t.Fatalf("%d merge proposals after the repeat report, want the one pending question", n)
	}
}
