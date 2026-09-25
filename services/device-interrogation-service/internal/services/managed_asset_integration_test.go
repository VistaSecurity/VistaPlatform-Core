package services

// A device is an asset with management configured (ADR-0002 D5), and these are
// the statements that only a real database can make about it.
//
// Every assertion here is about which ROWS exist afterwards. That is the point:
// the change these guard is "devices stopped being a second asset table", and
// nothing short of querying assets / asset_management / asset_credentials /
// asset_facts / asset_identifiers / asset_relationships can tell the fixed
// behaviour from the broken one.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func strptr(s string) *string { return &s }

// TestIntegration_CreateDevice_IsAnAssetWithManagement is the shape of the
// whole change in one test: creating a device writes an ASSET, a management row
// and a credentials row — not a `devices` row, which no longer exists.
func TestIntegration_CreateDevice_IsAnAssetWithManagement(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	hostname := "fw1-" + uuid.New().String()[:8] + ".corp.example.test"
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType:    "palo_alto",
		Hostname:      &hostname,
		ManagementURL: strptr("https://" + hostname),
		Vendor:        strptr("Palo Alto Networks"),
		Model:         strptr("PA-440"),
		Username:      strptr("admin"),
		Password:      strptr("s3cr3t-p@ssw0rd"),
		Metadata:      map[string]interface{}{"site_id": "default"},
		Tags:          map[string]interface{}{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// The id IS the asset id, and asset_id says so rather than making a client
	// infer it.
	if dev.AssetID != dev.ID {
		t.Errorf("asset_id %s != id %s — there is no separate device id any more", dev.AssetID, dev.ID)
	}

	// The class is what the device IS; device_type is which interrogator drives
	// it. Both are present because they answer different questions.
	if dev.ClassKey != "firewall" {
		t.Errorf("class = %q, want firewall — a PAN-OS appliance is a firewall", dev.ClassKey)
	}
	if dev.DeviceType != "palo_alto" {
		t.Errorf("device_type = %q, want palo_alto", dev.DeviceType)
	}

	// The asset row.
	var classKey, classPath, status string
	var assetHostname sql.NullString
	if err := db.QueryRow(`
		SELECT class_key, class_path, asset_status, hostname
		FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, dev.ID).
		Scan(&classKey, &classPath, &status, &assetHostname); err != nil {
		t.Fatalf("read asset: %v", err)
	}
	if classKey != "firewall" || !strings.HasSuffix(classPath, "firewall") {
		t.Errorf("asset class = %q path %q, want firewall", classKey, classPath)
	}
	if assetHostname.String != hostname {
		t.Errorf("asset hostname = %q, want %q", assetHostname.String, hostname)
	}
	// The engine never approves its own creations (ADR-0002 D3), so a new
	// device's asset waits in Approvals exactly like any other discovery. The
	// Devices page shows it regardless: that page is a filter on
	// asset_management and does not look at approval status.
	if status != identity.StatusPendingApproval {
		t.Errorf("asset_status = %q, want %q — the identification engine must not approve what it creates",
			status, identity.StatusPendingApproval)
	}

	// The management row. Its existence is what makes the asset a device.
	var mgmtURL, protocol, connStatus string
	if err := db.QueryRow(`
		SELECT management_url, management_protocol, connection_status
		FROM asset_management WHERE tenant_id = $1 AND asset_id = $2`, tenant, dev.ID).
		Scan(&mgmtURL, &protocol, &connStatus); err != nil {
		t.Fatalf("read asset_management: %v", err)
	}
	if mgmtURL != "https://"+hostname || protocol != "https" || connStatus != "unknown" {
		t.Errorf("asset_management = (%q, %q, %q), want (https://%s, https, unknown)",
			mgmtURL, protocol, connStatus, hostname)
	}

	// The declared hardware identity, as FACTS with provenance — not columns.
	// That is what lets a later interrogation's measured value and this
	// operator's declared one coexist and be reconciled rather than one
	// silently overwriting the other.
	wantFacts := map[string]string{
		facts.KeyHWVendor: "Palo Alto Networks",
		facts.KeyHWModel:  "PA-440",
	}
	for key, want := range wantFacts {
		var raw []byte
		var sourceKind, sourceRef string
		if err := db.QueryRow(`
			SELECT value, source_kind, source_ref FROM asset_facts
			WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`, tenant, dev.ID, key).
			Scan(&raw, &sourceKind, &sourceRef); err != nil {
			t.Fatalf("read fact %s: %v", key, err)
		}
		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("fact %s is not a JSON string: %v", key, err)
		}
		if got != want {
			t.Errorf("fact %s = %q, want %q", key, got, want)
		}
		if sourceKind != string(identity.SourceDeclared) {
			t.Errorf("fact %s source_kind = %q, want declared — a person typed it, nothing measured it", key, sourceKind)
		}
		if sourceRef != sourceManual {
			t.Errorf("fact %s source_ref = %q, want %q", key, sourceRef, sourceManual)
		}
	}

	// And they read back through the API shape.
	if dev.Vendor == nil || *dev.Vendor != "Palo Alto Networks" {
		t.Errorf("Device.vendor = %v, want the declared fact", dev.Vendor)
	}

	// The identifiers the engine recorded. The FQDN is what lets this device
	// and the same host seen by the sensor resolve to ONE asset.
	var fqdnCount int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_identifiers
		WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'fqdn' AND value = $3`,
		tenant, dev.ID, hostname).Scan(&fqdnCount); err != nil {
		t.Fatalf("read identifiers: %v", err)
	}
	if fqdnCount != 1 {
		t.Errorf("fqdn identifier rows = %d, want 1", fqdnCount)
	}

	// The vendor-specific addressing the collectors need is preserved.
	if dev.Metadata == nil || dev.Metadata["site_id"] != "default" {
		t.Errorf("Device.metadata = %v, want site_id preserved", dev.Metadata)
	}
	if dev.Tags == nil || dev.Tags["env"] != "prod" {
		t.Errorf("Device.tags = %v, want env preserved", dev.Tags)
	}

	// It appears on the Devices page, which is the assets ⋈ asset_management
	// join and nothing else.
	listed, err := svc.ListDevices(ctx, tenant)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != dev.ID {
		t.Fatalf("ListDevices returned %d rows, want the one device just created", len(listed))
	}
}

// TestIntegration_CreateDevice_IsOneUnitOfWork.
//
// The engine's writes (asset, identifiers, last-seen, history) and this
// service's (management, credentials, declared facts) run on ONE transaction,
// via Repository.Tx(). One observation is one fact about the world: an asset
// whose history says it was created and whose management configuration is
// absent is a state no later run repairs, because the next observation MATCHES
// the asset that exists and never takes the create path again.
//
// The failure is injected at the configuration half — a metadata value that
// cannot be marshalled — and the assertion is that NOTHING survived, not even
// the asset the engine had already written.
func TestIntegration_CreateDevice_IsOneUnitOfWork(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	hostname := "half-" + uuid.New().String()[:8] + ".corp.example.test"
	_, err := NewDeviceServiceWithKey(db, testMasterKey).CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "f5",
		Hostname:   &hostname,
		// A channel cannot be marshalled to JSON, so mergeAssetMetadata fails —
		// after Resolve has already written the asset and its identifiers.
		Metadata: map[string]interface{}{"unmarshalable": make(chan int)},
	})
	if err == nil {
		t.Fatal("CreateDevice succeeded with unmarshalable metadata")
	}

	assertCount(t, db, 0, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tenant)
	assertCount(t, db, 0, `SELECT count(*) FROM asset_identifiers WHERE tenant_id = $1`, tenant)
	assertCount(t, db, 0, `SELECT count(*) FROM asset_history WHERE tenant_id = $1`, tenant)
	assertCount(t, db, 0, `SELECT count(*) FROM asset_management WHERE tenant_id = $1`, tenant)
}

// TestIntegration_CreateDevice_NormalisesTheCloudConnectionStatus.
//
// `devices.connection_status` was free text and the cloud collectors used a
// fifth value, "discovered", which asset_management's CHECK rejects. Unmapped,
// that aborts the whole discovery run at the first bucket. It means "we
// enumerated this through the provider API and never tested a connection to
// it", which is `unknown` — mapping it to `connected` would claim a measurement
// nothing took.
func TestIntegration_CreateDevice_NormalisesTheCloudConnectionStatus(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	hostname := "bucket-" + uuid.New().String()[:8]
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "aws_s3_bucket",
		Hostname:   &hostname,
		Metadata:   map[string]interface{}{"arn": "arn:aws:s3:::" + hostname},
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	// A cloud collector's status comes in through the same path on update.
	if _, err := svc.UpdateDevice(ctx, tenant, dev.ID, models.UpdateDeviceRequest{
		ConnectionStatus: strptr("discovered"),
	}); err != nil {
		t.Fatalf("UpdateDevice with the collectors' status: %v", err)
	}

	var status string
	if err := db.QueryRow(`
		SELECT connection_status FROM asset_management WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, dev.ID).Scan(&status); err != nil {
		t.Fatalf("read asset_management: %v", err)
	}
	if status != "unknown" {
		t.Errorf("connection_status = %q, want unknown — nothing tested a connection to this resource", status)
	}

	// Positive polarity: a status the CHECK does allow survives untouched.
	if _, err := svc.UpdateDevice(ctx, tenant, dev.ID, models.UpdateDeviceRequest{
		ConnectionStatus: strptr("connected"),
	}); err != nil {
		t.Fatalf("UpdateDevice(connected): %v", err)
	}
	if err := db.QueryRow(`
		SELECT connection_status FROM asset_management WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, dev.ID).Scan(&status); err != nil {
		t.Fatalf("read asset_management: %v", err)
	}
	if status != "connected" {
		t.Errorf("connection_status = %q, want connected", status)
	}
}

// TestIntegration_CreateDevice_AnAddressTypedAsAHostnameStaysAnAddress.
//
// The Devices form has one "name" field and operators routinely type an IP into
// it. `assets.hostname` is what the UI renders as "hostname" and what a hostname
// search looks at, so putting an address there makes the column lie in both
// directions. The address still identifies the asset — as an ip_address
// identifier, which is where an address belongs.
func TestIntegration_CreateDevice_AnAddressTypedAsAHostnameStaysAnAddress(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	dev, err := NewDeviceServiceWithKey(db, testMasterKey).CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "f5",
		Hostname:   strptr("198.51.100.77"), // an address, in the name field
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	var hostname sql.NullString
	var primary sql.NullString
	if err := db.QueryRow(`
		SELECT hostname, host(primary_address) FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenant, dev.ID).Scan(&hostname, &primary); err != nil {
		t.Fatalf("read asset: %v", err)
	}
	if hostname.Valid && hostname.String != "" {
		t.Errorf("assets.hostname = %q, want empty — that value is an address", hostname.String)
	}
	if primary.String != "198.51.100.77" {
		t.Errorf("assets.primary_address = %q, want 198.51.100.77", primary.String)
	}
	assertCount(t, db, 1, `
		SELECT count(*) FROM asset_identifiers
		WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'ip_address' AND value = '198.51.100.77'`,
		tenant, dev.ID)
	// And no hostname identifier was minted from it.
	assertCount(t, db, 0, `
		SELECT count(*) FROM asset_identifiers
		WHERE tenant_id = $1 AND asset_id = $2 AND kind IN ('hostname', 'fqdn')`, tenant, dev.ID)
}

// TestIntegration_CreateDevice_PasswordIsCiphertextAtRest asserts on the RAW
// COLUMN BYTES, which is the only way to catch an "encrypt" that returns its
// input — a round-trip test passes such a bug perfectly.
func TestIntegration_CreateDevice_PasswordIsCiphertextAtRest(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	const plaintext = "correct-horse-battery-staple"
	svc := NewDeviceServiceWithKey(db, testMasterKey)
	hostname := "sw1-" + uuid.New().String()[:8] + ".corp.example.test"
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco",
		Hostname:   &hostname,
		Username:   strptr("netadmin"),
		Password:   strptr(plaintext),
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	var stored string
	if err := db.QueryRow(`
		SELECT password_enc FROM asset_credentials WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, dev.ID).Scan(&stored); err != nil {
		t.Fatalf("read asset_credentials: %v", err)
	}
	if strings.Contains(stored, plaintext) {
		t.Fatal("password_enc contains the plaintext password — the column name is the contract")
	}
	if !strings.HasPrefix(stored, credentials.Prefix) {
		t.Fatalf("password_enc = %q, want the %q tag the shared helper writes; an untagged value "+
			"forces every reader to guess whether it is encrypted, which is what devices.password did",
			stored, credentials.Prefix)
	}

	// The API response masks it; the stored value must never leave this way.
	if dev.Password == nil || *dev.Password == plaintext || *dev.Password == stored {
		t.Errorf("Device.password = %v, want a mask", dev.Password)
	}

	// And the unmasked reader gets the real ciphertext, because that is what
	// the job hand-off re-seals for one agent.
	creds, err := svc.GetStoredDeviceCredentials(ctx, tenant, dev.ID)
	if err != nil {
		t.Fatalf("GetStoredDeviceCredentials: %v", err)
	}
	if creds.EncryptedPassword != stored {
		t.Errorf("GetStoredDeviceCredentials returned %q, want the stored ciphertext", creds.EncryptedPassword)
	}
	if creds.DeviceType != "cisco" {
		t.Errorf("stored device_type = %q, want cisco", creds.DeviceType)
	}
}

// TestIntegration_CreateDevice_DedupesOntoAnExistingAsset is the reason any of
// this changed: a device an operator adds and the same host already in
// inventory must be ONE asset.
//
// Before phase 1 they could not be: `devices` was a second table with its own
// id and no link to the first, so a FortiGate the sensor saw and the FortiGate
// the operator added were two rows and nothing in the product could say they
// were one thing.
func TestIntegration_CreateDevice_DedupesOntoAnExistingAsset(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	// An asset that already exists, carrying the FQDN — the shape sensor ingest
	// leaves behind.
	existing := uuid.New()
	fqdn := "fw2-" + uuid.New().String()[:8] + ".corp.example.test"
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, class_key, class_path, hostname, asset_status)
		VALUES ($1, $2, 'unknown_host', 'unknown_host', $3, 'monitoring')`,
		existing, tenant, fqdn); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value)
		VALUES ($1, $2, 'fqdn', $3)`, tenant, existing, fqdn); err != nil {
		t.Fatalf("seed identifier: %v", err)
	}

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "fortinet",
		Hostname:   &fqdn,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if dev.ID != existing {
		t.Fatalf("CreateDevice made a new asset %s; the host was already known as %s — "+
			"this is exactly the duplication the identification engine exists to end", dev.ID, existing)
	}

	// Negative polarity: a DIFFERENT host must still create its own asset, or
	// the assertion above would pass for a function that always returns the
	// first asset it finds.
	other := "fw3-" + uuid.New().String()[:8] + ".corp.example.test"
	dev2, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "fortinet",
		Hostname:   &other,
	})
	if err != nil {
		t.Fatalf("CreateDevice (second host): %v", err)
	}
	if dev2.ID == existing {
		t.Fatal("a different hostname resolved onto the existing asset")
	}
}

// TestIntegration_DeleteDevice_UnmanagesRatherThanDeletingTheAsset pins a
// deliberate change of meaning.
//
// "Delete device" used to soft-delete a `devices` row. The asset it maps to now
// is the HOST — with its endpoints, crypto configurations, findings and history
// — and the host did not cease to exist because an operator removed its
// management configuration. So the management and credential rows go and the
// asset stays.
func TestIntegration_DeleteDevice_UnmanagesRatherThanDeletingTheAsset(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	hostname := "ap1-" + uuid.New().String()[:8] + ".corp.example.test"
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
		Username:   strptr("admin"),
		Password:   strptr("p@ss"),
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	if err := svc.DeleteDevice(ctx, tenant, dev.ID); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}

	assertCount(t, db, 0, `SELECT count(*) FROM asset_management WHERE tenant_id = $1 AND asset_id = $2`, tenant, dev.ID)
	assertCount(t, db, 0, `SELECT count(*) FROM asset_credentials WHERE tenant_id = $1 AND asset_id = $2`, tenant, dev.ID)
	assertCount(t, db, 1, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenant, dev.ID)

	// Off the Devices page, because that page IS the join.
	listed, err := svc.ListDevices(ctx, tenant)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("ListDevices returned %d rows after unmanaging, want 0", len(listed))
	}

	// Nothing is decided silently: unmanaging changes what the platform will do
	// with the asset, so it is in the history.
	assertCount(t, db, 1, `
		SELECT count(*) FROM asset_history
		WHERE tenant_id = $1 AND asset_id = $2 AND changes_json->>'management' = 'removed'`, tenant, dev.ID)

	// Repeated delete is not found, not a silent success.
	if err := svc.DeleteDevice(ctx, tenant, dev.ID); err == nil {
		t.Error("DeleteDevice on an unmanaged asset = nil, want not-found")
	}
}

func assertCount(t *testing.T, db *sql.DB, want int, query string, args ...interface{}) {
	t.Helper()
	var got int
	if err := db.QueryRow(query, args...).Scan(&got); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if got != want {
		t.Errorf("count = %d, want %d (%s)", got, want, strings.Join(strings.Fields(query), " "))
	}
}

// ---------------------------------------------------------------------------
// Interrogation observations: facts, peers, edges
// ---------------------------------------------------------------------------

// TestIntegration_ObservationSink_PersistsFactsAndIdentity covers the identity
// half: measured hardware facts under the job's own source_ref, and the serial
// as an IDENTIFIER rather than a column.
func TestIntegration_ObservationSink_PersistsFactsAndIdentity(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	hostname := "sw2-" + uuid.New().String()[:8] + ".corp.example.test"
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
		Vendor:     strptr("Typed By A Person"),
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	jobID := uuid.New()
	sink := NewObservationSink(db)
	obs := InterrogationObservations{
		DeviceIdentity: &di.DeviceIdentity{
			Vendor:          "Ubiquiti",
			Model:           "USW-24-POE",
			FirmwareVersion: "6.6.65",
			SerialNumber:    "F4E2C6" + uuid.New().String()[:6],
			OSVersion:       "UniFi OS 3.2.12",
		},
		Facts: []di.FactObservation{
			{Key: facts.KeyNetUptimeSeconds, Value: 864000, Confidence: di.ConfidenceReported},
		},
	}
	if err := sink.Persist(ctx, tenant, dev.ID, interrogationSource(jobID), obs); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	// A MEASURED fact under this job's own source_ref, beside the declared one
	// — per source, so the disagreement survives to be reconciled rather than
	// the last writer silently winning.
	var rows int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_facts
		WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`, tenant, dev.ID, facts.KeyHWVendor).Scan(&rows); err != nil {
		t.Fatalf("count hw.vendor facts: %v", err)
	}
	if rows != 2 {
		t.Errorf("hw.vendor rows = %d, want 2 (one declared, one measured) — asset_facts is keyed PER SOURCE "+
			"precisely so two sources can disagree", rows)
	}

	var kind, ref string
	if err := db.QueryRow(`
		SELECT source_kind, source_ref FROM asset_facts
		WHERE tenant_id = $1 AND asset_id = $2 AND key = $3 AND source_kind = 'measured'`,
		tenant, dev.ID, facts.KeyHWVendor).Scan(&kind, &ref); err != nil {
		t.Fatalf("read measured hw.vendor: %v", err)
	}
	if ref != "interrogation:"+jobID.String() {
		t.Errorf("measured hw.vendor source_ref = %q, want interrogation:%s", ref, jobID)
	}

	// The ops fact the collector emitted, validated against the registry.
	var uptime []byte
	if err := db.QueryRow(`
		SELECT value FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`,
		tenant, dev.ID, facts.KeyNetUptimeSeconds).Scan(&uptime); err != nil {
		t.Fatalf("read net.uptime_seconds: %v", err)
	}
	if string(uptime) != "864000" {
		t.Errorf("net.uptime_seconds = %s, want 864000", uptime)
	}

	// The serial is an IDENTIFIER: it is how the asset is recognised, and
	// `devices.serial_number` being a plain column is a large part of why an
	// interrogated device and the same host seen elsewhere were two rows.
	assertCount(t, db, 1, `
		SELECT count(*) FROM asset_identifiers
		WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'serial_number' AND value = $3`,
		tenant, dev.ID, obs.DeviceIdentity.SerialNumber)

	// The declared vendor still wins on the way out: ADR-0002 D4 ranks a
	// human's correction above a probe for identity facts too, and an edit
	// field the next scan silently reverts is a control that reports success
	// and does nothing.
	reread, err := svc.GetDevice(ctx, tenant, dev.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if reread.Vendor == nil || *reread.Vendor != "Typed By A Person" {
		t.Errorf("Device.vendor after an interrogation = %v, want the declared value to stand", reread.Vendor)
	}
	// But a key nobody declared takes the measured value.
	if reread.FirmwareVersion == nil || *reread.FirmwareVersion != "6.6.65" {
		t.Errorf("Device.firmware_version = %v, want the measured 6.6.65", reread.FirmwareVersion)
	}
}

// TestIntegration_ObservationSink_PeerBecomesAPendingAssetAndAPendingEdge is
// what makes an interrogation produce a MAP: a neighbour the device told us
// about becomes an asset, and the edge to it is written.
//
// Both halves of ADR-0003 D3 are checked: the peer is created pending (nobody
// has approved it), and the edge is therefore pending too — "approving the
// asset approves what was observed about it".
func TestIntegration_ObservationSink_PeerBecomesAPendingAssetAndAPendingEdge(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	hostname := "ctrl-" + uuid.New().String()[:8] + ".corp.example.test"
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	peerMAC := "aa:bb:cc:dd:ee:01"
	peer := di.PeerRef{DisplayName: "Access Point 1", ClassHint: "access_point"}
	if !peer.AddIdentifier(di.IdentifierMACAddress, peerMAC) {
		t.Fatal("AddIdentifier rejected a valid MAC")
	}

	jobID := uuid.New()
	sink := NewObservationSink(db)
	if err := sink.Persist(ctx, tenant, dev.ID, interrogationSource(jobID), InterrogationObservations{
		Relationships: []di.RelationshipObservation{{
			Type:       string(relationships.MemberOf),
			Direction:  di.PeerToSubject,
			Peer:       peer,
			Attributes: map[string]any{"adopted": true},
		}},
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	// The peer is an asset now — created from identifiers alone, which is the
	// only thing a collector can supply about a neighbour.
	var peerAsset uuid.UUID
	var peerStatus, peerClass string
	if err := db.QueryRow(`
		SELECT a.id, a.asset_status, a.class_key
		FROM assets a
		JOIN asset_identifiers i ON i.tenant_id = a.tenant_id AND i.asset_id = a.id
		WHERE a.tenant_id = $1 AND i.kind = 'mac_address' AND i.value = $2`, tenant, peerMAC).
		Scan(&peerAsset, &peerStatus, &peerClass); err != nil {
		t.Fatalf("read peer asset: %v", err)
	}
	if peerStatus != identity.StatusPendingApproval {
		t.Errorf("peer asset_status = %q, want pending_approval — nobody approved this neighbour", peerStatus)
	}
	if peerClass != "access_point" {
		t.Errorf("peer class = %q, want access_point (the collector's hint)", peerClass)
	}

	// The edge, in the direction the collector reported: PeerToSubject means
	// the canonical direction runs peer -> subject, and the reverse of a type
	// is a label, never a second type (ADR-0003 D2).
	var from, to uuid.UUID
	var edgeStatus, edgeSourceKind, edgeSourceRef string
	var attrs []byte
	if err := db.QueryRow(`
		SELECT from_asset_id, to_asset_id, status, source_kind, source_ref, attributes
		FROM asset_relationships
		WHERE tenant_id = $1 AND type = 'member_of'`, tenant).
		Scan(&from, &to, &edgeStatus, &edgeSourceKind, &edgeSourceRef, &attrs); err != nil {
		t.Fatalf("read edge: %v", err)
	}
	if from != peerAsset || to != dev.ID {
		t.Errorf("edge %s -> %s, want peer %s -> device %s", from, to, peerAsset, dev.ID)
	}
	if edgeStatus != "pending" {
		t.Errorf("edge status = %q, want pending — an endpoint is unapproved, so the edge resolves with it", edgeStatus)
	}
	if edgeSourceKind != string(identity.SourceMeasured) || edgeSourceRef != "interrogation:"+jobID.String() {
		t.Errorf("edge provenance = (%q, %q), want (measured, interrogation:%s)", edgeSourceKind, edgeSourceRef, jobID)
	}
	if !strings.Contains(string(attrs), `"adopted"`) {
		t.Errorf("edge attributes = %s, want the collector's detail carried", attrs)
	}

	// Re-observing the same edge is an UPDATE, not a second row.
	if err := sink.Persist(ctx, tenant, dev.ID, interrogationSource(uuid.New()), InterrogationObservations{
		Relationships: []di.RelationshipObservation{{
			Type:      string(relationships.MemberOf),
			Direction: di.PeerToSubject,
			Peer:      peer,
		}},
	}); err != nil {
		t.Fatalf("Persist (second run): %v", err)
	}
	var edges, observations int
	if err := db.QueryRow(`
		SELECT count(*), max(observation_count) FROM asset_relationships
		WHERE tenant_id = $1 AND type = 'member_of'`, tenant).Scan(&edges, &observations); err != nil {
		t.Fatalf("recount edges: %v", err)
	}
	if edges != 1 {
		t.Errorf("member_of edges = %d, want 1 — re-observing an edge must not append", edges)
	}
	if observations != 2 {
		t.Errorf("observation_count = %d, want 2", observations)
	}
}

// TestIntegration_ObservationSink_EdgeIsActiveWhenBothEndsAreApproved is the
// other row of ADR-0003 D3's table, and the negative polarity the test above
// needs: an edge between two APPROVED assets enters active, because observing
// two approved assets needs no second approval.
func TestIntegration_ObservationSink_EdgeIsActiveWhenBothEndsAreApproved(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	hostname := "ctrl2-" + uuid.New().String()[:8] + ".corp.example.test"
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: &hostname})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	peerMAC := "aa:bb:cc:dd:ee:02"
	peerAsset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, class_key, class_path, asset_status)
		VALUES ($1, $2, 'access_point', 'hardware.network_device.access_point', 'monitoring')`,
		peerAsset, tenant); err != nil {
		t.Fatalf("seed peer asset: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value)
		VALUES ($1, $2, 'mac_address', $3)`, tenant, peerAsset, peerMAC); err != nil {
		t.Fatalf("seed peer identifier: %v", err)
	}
	// Approve the device's own asset too — both ends have to be approved.
	if _, err := db.Exec(`UPDATE assets SET asset_status = 'monitoring' WHERE tenant_id = $1 AND id = $2`,
		tenant, dev.ID); err != nil {
		t.Fatalf("approve device asset: %v", err)
	}

	peer := di.PeerRef{DisplayName: "Access Point 2"}
	peer.AddIdentifier(di.IdentifierMACAddress, peerMAC)

	sink := NewObservationSink(db)
	if err := sink.Persist(ctx, tenant, dev.ID, interrogationSource(uuid.New()), InterrogationObservations{
		Relationships: []di.RelationshipObservation{{
			Type: string(relationships.MemberOf), Direction: di.PeerToSubject, Peer: peer,
		}},
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	var status string
	var from, to uuid.UUID
	if err := db.QueryRow(`
		SELECT status, from_asset_id, to_asset_id FROM asset_relationships
		WHERE tenant_id = $1 AND type = 'member_of'`, tenant).Scan(&status, &from, &to); err != nil {
		t.Fatalf("read edge: %v", err)
	}
	if status != "active" {
		t.Errorf("edge status = %q, want active — both endpoints are approved", status)
	}
	if from != peerAsset {
		t.Errorf("edge resolved to a new peer asset %s instead of the existing %s", from, peerAsset)
	}
}

// TestIntegration_ObservationSink_SecretsNeverReachAssetFacts is the one that
// matters most.
//
// "Collect posture, never key material" cannot be delegated to the customer's
// agent binary: on the agent path the collector-boundary redactor ran in a
// process we do not control the version of, and the result arrived over HTTP.
// The sink re-runs it, so a PSK in a fact value or an edge attribute is masked
// by the platform's own guarantee.
func TestIntegration_ObservationSink_SecretsNeverReachAssetFacts(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	hostname := "gw-" + uuid.New().String()[:8] + ".corp.example.test"
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: &hostname})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// The concrete case from the UniFi collector: the controller's mesh PSK and
	// a per-device auth key, which used to be persisted verbatim on every run.
	const psk = "sup3r-s3cret-mesh-psk"
	peer := di.PeerRef{DisplayName: "neighbour"}
	peer.AddIdentifier(di.IdentifierMACAddress, "aa:bb:cc:dd:ee:03")

	sink := NewObservationSink(db)
	if err := sink.Persist(ctx, tenant, dev.ID, interrogationSource(uuid.New()), InterrogationObservations{
		Facts: []di.FactObservation{{
			Key: facts.KeyNetVlans,
			Value: []map[string]any{
				{"vlan_id": 10, "name": "corp", "x_passphrase": psk, "auth_key": psk},
			},
			Confidence: di.ConfidenceReported,
		}},
		Relationships: []di.RelationshipObservation{{
			Type: string(relationships.MemberOf), Direction: di.PeerToSubject, Peer: peer,
			Attributes: map[string]any{"vlan": 10, "psk": psk},
		}},
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	var factValue []byte
	if err := db.QueryRow(`
		SELECT value FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`,
		tenant, dev.ID, facts.KeyNetVlans).Scan(&factValue); err != nil {
		t.Fatalf("read net.vlans: %v", err)
	}
	if strings.Contains(string(factValue), psk) {
		t.Fatalf("asset_facts carries the PSK verbatim: %s", factValue)
	}
	// Positive polarity: the posture we DO want is still there, so the
	// assertion above is about redaction and not about the fact being dropped.
	if !strings.Contains(string(factValue), `"corp"`) {
		t.Errorf("net.vlans = %s, want the VLAN name kept", factValue)
	}

	var edgeAttrs []byte
	if err := db.QueryRow(`
		SELECT attributes FROM asset_relationships WHERE tenant_id = $1 AND type = 'member_of'`, tenant).
		Scan(&edgeAttrs); err != nil {
		t.Fatalf("read edge attributes: %v", err)
	}
	if strings.Contains(string(edgeAttrs), psk) {
		t.Fatalf("asset_relationships.attributes carries the PSK verbatim: %s", edgeAttrs)
	}
	if !strings.Contains(string(edgeAttrs), `"vlan"`) {
		t.Errorf("edge attributes = %s, want the VLAN id kept", edgeAttrs)
	}
}

// TestIntegration_ObservationSink_RejectsAnUnregisteredFactKey pins the
// registry check. A key nobody declared is a key no consumer can type, and
// asset_facts has no CHECK constraint to catch it later.
func TestIntegration_ObservationSink_RejectsAnUnregisteredFactKey(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	hostname := "gw2-" + uuid.New().String()[:8] + ".corp.example.test"
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: &hostname})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	sink := NewObservationSink(db)
	err = sink.Persist(ctx, tenant, dev.ID, interrogationSource(uuid.New()), InterrogationObservations{
		Facts: []di.FactObservation{{Key: "nobody.declared.this", Value: "x", Confidence: 1}},
	})
	if err == nil {
		t.Fatal("Persist accepted an unregistered fact key")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error = %v, want it to name the registry", err)
	}
	assertCount(t, db, 0, `SELECT count(*) FROM asset_facts WHERE tenant_id = $1 AND key = 'nobody.declared.this'`, tenant)
}

// TestIntegration_WeakIdentifiersAreScopedToTheSegment is the mechanism that
// makes the dedupe above work for the identifiers that need it.
//
// A hostname and an IP identify only WITHIN a segment (ADR-0002 D3): "printer-2"
// and 10.0.0.5 are answers to a question only once you say where you were
// standing. Unscoped they are still recorded — they are true — but they do not
// decide a match, so a device would dedupe only on a serial, a cloud id or an
// FQDN. Both intakes in this package resolve the scope from the same
// `network_segments` rows inventory-service reads, so a device an operator adds
// and the same host the sensor saw land in ONE scope and therefore on one asset.
func TestIntegration_WeakIdentifiersAreScopedToTheSegment(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	var segmentID uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO network_segments (tenant_id, name, segment_type, value, environment)
		VALUES ($1, 'lab', 'cidr', '198.51.100.0/24', 'production')
		RETURNING id`, tenant).Scan(&segmentID); err != nil {
		t.Fatalf("seed segment: %v", err)
	}

	svc := NewDeviceServiceWithKey(db, testMasterKey)
	// A SHORT hostname, deliberately: a dotted name would be an FQDN, which is
	// globally unique and needs no scope, so it would not exercise this at all.
	shortName := "sw" + uuid.New().String()[:6]
	dev, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco",
		Hostname:   &shortName,
		IPAddress:  strptr("198.51.100.20"),
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	for _, kind := range []string{"hostname", "ip_address"} {
		var scope sql.NullString
		if err := db.QueryRow(`
			SELECT scope FROM asset_identifiers
			WHERE tenant_id = $1 AND asset_id = $2 AND kind = $3`, tenant, dev.ID, kind).Scan(&scope); err != nil {
			t.Fatalf("read %s identifier: %v", kind, err)
		}
		if scope.String != segmentID.String() {
			t.Errorf("%s identifier scope = %q, want the segment %s — unscoped it cannot decide a match",
				kind, scope.String, segmentID)
		}
	}

	// The same resolver on the peer path: a neighbour reported with an address
	// inside the segment gets the same scope, which is what lets a peer and a
	// directly-managed device resolve to one asset.
	peer := di.PeerRef{DisplayName: "neighbour"}
	peer.AddIdentifier(di.IdentifierIPAddress, "198.51.100.30")
	if err := NewObservationSink(db).Persist(ctx, tenant, dev.ID, interrogationSource(uuid.New()),
		InterrogationObservations{Relationships: []di.RelationshipObservation{{
			Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: peer,
		}}}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	var peerScope sql.NullString
	if err := db.QueryRow(`
		SELECT scope FROM asset_identifiers
		WHERE tenant_id = $1 AND kind = 'ip_address' AND value = '198.51.100.30'`, tenant).Scan(&peerScope); err != nil {
		t.Fatalf("read peer identifier: %v", err)
	}
	if peerScope.String != segmentID.String() {
		t.Errorf("peer ip_address scope = %q, want the segment %s", peerScope.String, segmentID)
	}

	// Negative polarity: an address OUTSIDE every segment is unscoped, not
	// scoped to whichever segment happened to be first. A wrong scope silently
	// splits one host into two assets, which is worse than no scope.
	outside := di.PeerRef{DisplayName: "elsewhere"}
	outside.AddIdentifier(di.IdentifierIPAddress, "203.0.113.5")
	if err := NewObservationSink(db).Persist(ctx, tenant, dev.ID, interrogationSource(uuid.New()),
		InterrogationObservations{Relationships: []di.RelationshipObservation{{
			Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: outside,
		}}}); err != nil {
		t.Fatalf("Persist (outside): %v", err)
	}
	var outsideScope sql.NullString
	if err := db.QueryRow(`
		SELECT scope FROM asset_identifiers
		WHERE tenant_id = $1 AND kind = 'ip_address' AND value = '203.0.113.5'`, tenant).Scan(&outsideScope); err != nil {
		t.Fatalf("read outside identifier: %v", err)
	}
	if outsideScope.Valid && outsideScope.String == segmentID.String() {
		t.Errorf("an address outside every segment was scoped to %s anyway", segmentID)
	}
	// ...and it is the TENANT-WIDE DEFAULT, not nothing. "Not the wrong segment"
	// is satisfied by an empty scope too, and an empty scope is the defect this
	// whole mechanism exists to prevent: an unscoped ip_address cannot vote, so
	// one host observed three times becomes three assets. Asserting the positive
	// is what makes this check able to fail in the direction that matters.
	if !outsideScope.Valid || outsideScope.String != identity.ScopeTenantDefault {
		t.Errorf("outside-segment ip_address scope = %q (valid=%t), want the tenant-wide default %q",
			outsideScope.String, outsideScope.Valid, identity.ScopeTenantDefault)
	}
}

// TestIntegration_SubmitJobResult_PersistsObservationsWithoutCryptoAssets is the
// guard for the agent-path gate.
//
// A result's facts and relationships are not a by-product of its crypto assets.
// A switch can report a full port table and six LLDP neighbours while presenting
// no certificate at all, and the in-cluster path persists those observations
// unconditionally. The agent path reaches the same sink through
// SubmitJobResult, which skipped results with an empty asset list — so the two
// runtimes, which share ObservationSink precisely so they cannot diverge,
// persisted different things from the same interrogation.
func TestIntegration_SubmitJobResult_PersistsObservationsWithoutCryptoAssets(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	agentID := insertDeviceAgent(t, db, tenant)
	svc := NewAgentService(db, db, nil) // SubmitJobResult never touches Redis
	jobQueue := NewJobQueueService(db, db, nil)

	hostname := "sw-" + uuid.New().String()[:8] + ".corp.example.test"
	dev, err := NewDeviceServiceWithKey(db, testMasterKey).CreateDevice(ctx, tenant,
		models.CreateDeviceRequest{DeviceType: "cisco_ios", Hostname: &hostname})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenant,
		JobType:  models.JobTypeDeviceInterrogation,
		AssetID:  &dev.ID,
		AgentID:  &agentID,
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	// The agent picked the job up (GetNextJob marks it in_progress); only a
	// running job this agent claimed accepts a result.
	if err := jobQueue.UpdateJobStatus(ctx, job.ID, models.JobStatusInProgress, nil, nil); err != nil {
		t.Fatalf("start job: %v", err)
	}

	peer := di.PeerRef{DisplayName: "neighbour-sw2"}
	peer.AddIdentifier(di.IdentifierMACAddress, "aa:bb:cc:dd:ee:07")

	// No Assets: the device presented no cryptography this run.
	if err := svc.SubmitJobResult(ctx, agentID, &models.JobResult{
		JobID:   job.ID,
		Success: true,
		Facts: []di.FactObservation{{
			Key:        facts.KeyNetVlans,
			Value:      []map[string]any{{"vlan_id": 40, "name": "voice"}},
			Confidence: di.ConfidenceReported,
		}},
		Relationships: []di.RelationshipObservation{{
			Type:      string(relationships.ConnectsTo),
			Direction: di.SubjectToPeer,
			Peer:      peer,
		}},
	}); err != nil {
		t.Fatalf("SubmitJobResult: %v", err)
	}

	assertCount(t, db, 1, `
		SELECT count(*) FROM asset_facts
		WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`, tenant, dev.ID, facts.KeyNetVlans)
	assertCount(t, db, 1, `
		SELECT count(*) FROM asset_relationships
		WHERE tenant_id = $1 AND from_asset_id = $2 AND type = 'connects_to'`, tenant, dev.ID)
	// The peer became an asset of its own, which is what makes it a node on the
	// map rather than a string in a payload.
	assertCount(t, db, 1, `
		SELECT count(*) FROM asset_identifiers
		WHERE tenant_id = $1 AND kind = 'mac_address' AND value = 'aa:bb:cc:dd:ee:07'`, tenant)
}
