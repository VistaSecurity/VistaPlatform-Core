package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The net.vlans shape FortiGate emits (fortinetVLANs): a tagged subinterface
// with the firewall's own address on it, and no DHCP posture. The third entry
// is a VLAN with no address, which is a name and not a network.
func fortinetShapedVLANs() []map[string]any {
	return []map[string]any{
		{"id": 100, "name": "port1.100", "subnet": "10.20.30.0/24", "gateway": "10.20.30.1"},
		{"id": 200, "name": "dmz", "subnet": "198.51.100.0/24", "gateway": "198.51.100.1"},
		{"id": 300, "name": "voice"},
	}
}

// seedInterrogatedDevice is an asset the way a managed device is one: an asset
// whose metadata names its interrogation driver.
func seedInterrogatedDevice(t *testing.T, db *sql.DB, tenant uuid.UUID, deviceType, mac, name string) uuid.UUID {
	t.Helper()
	id := seedHexLocalHost(t, db, tenant, mac, name)
	if _, err := db.Exec(`UPDATE assets SET metadata = coalesce(metadata, '{}'::jsonb) || jsonb_build_object('device_type', $3::text) WHERE tenant_id = $1 AND id = $2`, tenant, id, deviceType); err != nil {
		t.Fatalf("stamp device_type: %v", err)
	}
	return id
}

type learnedSegment struct {
	Name        string
	NetworkType string
	Metadata    map[string]any
}

func segmentByCIDR(t *testing.T, db *sql.DB, tenant uuid.UUID, cidr string) (learnedSegment, bool) {
	t.Helper()
	var seg learnedSegment
	var raw []byte
	err := db.QueryRow(`SELECT name, network_type, coalesce(metadata, '{}'::jsonb) FROM network_segments WHERE tenant_id = $1 AND value = $2 AND segment_type = 'cidr'`, tenant, cidr).Scan(&seg.Name, &seg.NetworkType, &raw)
	if err == sql.ErrNoRows {
		return seg, false
	}
	if err != nil {
		t.Fatalf("read segment %s: %v", cidr, err)
	}
	if err := json.Unmarshal(raw, &seg.Metadata); err != nil {
		t.Fatalf("segment %s metadata: %v", cidr, err)
	}
	return seg, true
}

func persistVLANs(t *testing.T, sink *ObservationSink, tenant, device uuid.UUID, vlans []map[string]any, extra ...di.FactObservation) {
	t.Helper()
	obs := InterrogationObservations{Facts: append([]di.FactObservation{{Key: facts.KeyNetVlans, Value: vlans}}, extra...)}
	if err := sink.Persist(context.Background(), tenant, device, identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:test", Mode: identity.ModeActive}, obs); err != nil {
		t.Fatalf("persist: %v", err)
	}
}

// (a) A FortiGate's VLANs become segments, labelled with the device that
// reported them, typed by their prefix, and honest about DHCP.
//
// The sink runs as the application role, so the source-device read and the
// segment writes are proven under RLS rather than as the table owner.
func TestIntegration_VendorNeutralSegments_FortinetVLANsBecomeSegments(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	firewall := seedInterrogatedDevice(t, owner, tenant, "fortinet", "00:09:0f:00:00:01", "fw-edge")

	sink := NewObservationSink(testdb.ConnectAsAppRole(t, owner))
	persistVLANs(t, sink, tenant, firewall, fortinetShapedVLANs())

	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM network_segments WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("segments = %d, want 2 (the address-less VLAN is not a network)", n)
	}
	for cidr, want := range map[string]learnedSegment{
		"10.20.30.0/24":   {Name: "port1.100", NetworkType: "private"},
		"198.51.100.0/24": {Name: "dmz", NetworkType: "public"},
	} {
		got, ok := segmentByCIDR(t, owner, tenant, cidr)
		if !ok {
			t.Fatalf("no segment for %s", cidr)
		}
		if got.Name != want.Name || got.NetworkType != want.NetworkType {
			t.Errorf("%s = %s/%s, want %s/%s", cidr, got.Name, got.NetworkType, want.Name, want.NetworkType)
		}
		m := got.Metadata
		if m["source"] != "interrogation" || m["source_device_type"] != "fortinet" || m["source_asset_id"] != firewall.String() {
			t.Errorf("%s provenance = %v", cidr, m)
		}
		if m["dhcp"] != "unknown" {
			t.Errorf("%s dhcp = %v, want unknown", cidr, m["dhcp"])
		}
		if _, has := m["dynamic"]; has {
			t.Errorf("%s recorded a DHCP answer nobody gave: %v", cidr, m)
		}
	}

	// Stored as unknown, READ as dynamic for identity by every later intake:
	// the conservative reading of "nobody measured whether leases are handed
	// out here" belongs to the scope resolver, not only to the learning run.
	scope, dynamic, err := pgidentity.New(owner).ScopeForAddress(context.Background(), tenant.String(), netip.MustParseAddr("10.20.30.40"), "")
	if err != nil {
		t.Fatal(err)
	}
	if scope == identity.ScopeTenantDefault || !dynamic {
		t.Fatalf("ScopeForAddress = %q dynamic=%v, want the learned segment, read as dynamic", scope, dynamic)
	}
}

// (b) An operator-declared segment with the same CIDR wins: its name, network
// type and metadata are untouched.
func TestIntegration_VendorNeutralSegments_DeclaredSegmentWins(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata) VALUES($1,'Operator DMZ','cidr','198.51.100.0/24','vpn','production',true,'{"operator":"keep"}')`, tenant); err != nil {
		t.Fatal(err)
	}
	firewall := seedInterrogatedDevice(t, db, tenant, "fortinet", "00:09:0f:00:00:02", "fw-branch")
	persistVLANs(t, NewObservationSink(db), tenant, firewall, fortinetShapedVLANs())

	got, ok := segmentByCIDR(t, db, tenant, "198.51.100.0/24")
	if !ok {
		t.Fatal("declared segment vanished")
	}
	if got.Name != "Operator DMZ" || got.NetworkType != "vpn" || got.Metadata["operator"] != "keep" || len(got.Metadata) != 1 {
		t.Fatalf("declared segment overwritten: %+v", got)
	}
}

// (c) A row a previous release labelled `unifi` is still ours: the next
// interrogation refreshes it and relabels it. An unknown posture from another
// device does not erase the answer it holds.
func TestIntegration_VendorNeutralSegments_LegacyUniFiRowsStillRefresh(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	for _, cidr := range []string{"192.168.10.0/24", "10.20.30.0/24"} {
		if _, err := db.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata) VALUES($1,$2,'cidr',$2,'private','production',true,'{"source":"unifi","dynamic":true}')`, tenant, cidr); err != nil {
			t.Fatal(err)
		}
	}
	sink := NewObservationSink(db)

	// A UniFi controller now reports DHCP off on the first network.
	controller := seedInterrogatedDevice(t, db, tenant, "unifi", "00:1a:2b:3c:4d:01", "controller")
	persistVLANs(t, sink, tenant, controller, []map[string]any{{"name": "LAN", "subnet": "192.168.10.0/24", "dhcp_enabled": false}})
	got, _ := segmentByCIDR(t, db, tenant, "192.168.10.0/24")
	if got.Metadata["source"] != "interrogation" || got.Metadata["dynamic"] != false || got.Metadata["dhcp"] != "disabled" ||
		got.Metadata["source_device_type"] != "unifi" || got.Metadata["source_asset_id"] != controller.String() {
		t.Fatalf("legacy unifi row not refreshed: %v", got.Metadata)
	}

	// A FortiGate that routes the second network cannot say whether it serves
	// DHCP. The row keeps the measured answer, and the label that goes with it.
	firewall := seedInterrogatedDevice(t, db, tenant, "fortinet", "00:09:0f:00:00:03", "fw-core")
	persistVLANs(t, sink, tenant, firewall, fortinetShapedVLANs())
	got, _ = segmentByCIDR(t, db, tenant, "10.20.30.0/24")
	if got.Metadata["dynamic"] != true || got.Metadata["source"] != "unifi" || got.Metadata["dhcp"] != nil {
		t.Fatalf("unknown posture overwrote a measured one: %v", got.Metadata)
	}
}

// (d) Lease reuse on a network whose DHCP posture is unknown: two different
// clients seen at the same address are not joined. Mirrors
// TestIntegration_UniFiLeaseReuseDoesNotJoinClients, with a Fortinet-shaped
// entry that carries no dhcp_enabled at all.
func TestIntegration_VendorNeutralSegments_LeaseReuseInUnknownDHCPDoesNotJoin(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	sink := NewObservationSink(db)
	firewall := seedInterrogatedDevice(t, db, tenant, "fortinet", "00:09:0f:00:00:04", "fw-lease")
	for _, host := range []string{"client-a", "client-b"} {
		peer := di.PeerRef{DisplayName: "Shared alias"}
		peer.AddIdentifier(di.IdentifierHostname, host)
		peer.AddIdentifier(di.IdentifierIPAddress, "10.20.30.68")
		persistVLANs(t, sink, tenant, firewall, fortinetShapedVLANs(),
			di.FactObservation{Key: facts.KeyHWVendor, Value: "Example", Confidence: 1, Subject: peer})
	}
	var n int
	if err := db.QueryRow(`SELECT count(DISTINCT asset_id) FROM asset_identifiers WHERE tenant_id=$1 AND kind='hostname' AND value IN ('client-a','client-b')`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("lease reuse joined clients on a DHCP-unknown network: %d identities", n)
	}
}

// (d2) The in-run half of the DHCP-unknown rule. An operator declared the
// network first, with no DHCP posture, so declared-wins leaves the persisted
// segment saying nothing and ScopeForAddress reads it as static. The firewall's
// report in THIS run that it does not know is what keeps a reused lease from
// joining two clients here.
func TestIntegration_VendorNeutralSegments_LeaseReuseUnderDeclaredSegmentDoesNotJoin(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active) VALUES($1,'Operator LAN','cidr','10.20.30.0/24','private','production',true)`, tenant); err != nil {
		t.Fatal(err)
	}
	sink := NewObservationSink(db)
	firewall := seedInterrogatedDevice(t, db, tenant, "fortinet", "00:09:0f:00:00:0b", "fw-declared")
	for _, host := range []string{"client-a", "client-b"} {
		peer := di.PeerRef{DisplayName: "Shared alias"}
		peer.AddIdentifier(di.IdentifierHostname, host)
		peer.AddIdentifier(di.IdentifierIPAddress, "10.20.30.68")
		persistVLANs(t, sink, tenant, firewall, fortinetShapedVLANs(),
			di.FactObservation{Key: facts.KeyHWVendor, Value: "Example", Confidence: 1, Subject: peer})
	}
	var n int
	if err := db.QueryRow(`SELECT count(DISTINCT asset_id) FROM asset_identifiers WHERE tenant_id=$1 AND kind='hostname' AND value IN ('client-a','client-b')`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("lease reuse joined clients under a declared segment: %d identities", n)
	}
}

// (e) The DHCP-unknown protection is the SEGMENT's, not only the learning
// run's: a later interrogation of a different device, carrying no net.vlans
// at all, still cannot join two clients that held the same address.
func TestIntegration_VendorNeutralSegments_LeaseReuseAcrossRunsDoesNotJoin(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	sink := NewObservationSink(db)
	firewall := seedInterrogatedDevice(t, db, tenant, "fortinet", "00:09:0f:00:00:05", "fw-learns")
	persistVLANs(t, sink, tenant, firewall, fortinetShapedVLANs())

	controller := seedInterrogatedDevice(t, db, tenant, "unifi", "00:1a:2b:3c:4d:05", "controller-later")
	for _, host := range []string{"client-a", "client-b"} {
		peer := di.PeerRef{DisplayName: "Shared alias"}
		peer.AddIdentifier(di.IdentifierHostname, host)
		peer.AddIdentifier(di.IdentifierIPAddress, "10.20.30.68")
		obs := InterrogationObservations{Facts: []di.FactObservation{{Key: facts.KeyHWVendor, Value: "Example", Confidence: 1, Subject: peer}}}
		if err := sink.Persist(context.Background(), tenant, controller, identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:later", Mode: identity.ModeActive}, obs); err != nil {
			t.Fatalf("persist: %v", err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(DISTINCT asset_id) FROM asset_identifiers WHERE tenant_id=$1 AND kind='hostname' AND value IN ('client-a','client-b')`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("a later run joined two clients on a DHCP-unknown network: %d identities", n)
	}
}

// (f) Under enforce admission, an address-only sighting on a DHCP-unknown
// network is NOT admitted as `direct_scoped_address` — before this change the
// learned segment made the scope "resolved and not dynamic", which was
// strictly more permissive than the `network_scope_unresolved` it replaced.
// The static network beside it is the other polarity: there a direct,
// address-only sighting IS admitted, so the assertion cannot pass by refusing
// everything.
func TestIntegration_VendorNeutralSegments_EnforceAdmissionOnUnknownDHCP(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	firewall := seedInterrogatedDevice(t, owner, tenant, "fortinet", "00:09:0f:00:00:06", "fw-enforce")
	controller := seedInterrogatedDevice(t, owner, tenant, "unifi", "00:1a:2b:3c:4d:06", "controller-enforce")
	if _, err := owner.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}

	app := testdb.ConnectAsAppRole(t, owner)
	app.SetMaxOpenConns(1)
	sink := NewObservationSink(app)
	_, repo, err := sink.engine()
	if err != nil {
		t.Fatal(err)
	}
	// Force admission on whatever this build's capabilities say, as the
	// retained-peer tests do.
	if sink.eng, err = identity.New(identity.Config{Repo: repo, AdmissionEnabled: true}); err != nil {
		t.Fatal(err)
	}

	// Run 1: the networks are learned — one with DHCP unknown, one static.
	persistVLANs(t, sink, tenant, firewall, fortinetShapedVLANs())
	persistVLANs(t, sink, tenant, controller, []map[string]any{{"name": "Servers", "subnet": "192.168.40.0/24", "dhcp_enabled": false}})

	// Run 2, a different interrogation with no net.vlans: two directly
	// connected, address-only peers.
	for _, addr := range []string{"10.20.30.77", "192.168.40.77"} {
		peer := di.PeerRef{DisplayName: "peer " + addr}
		peer.AddIdentifier(di.IdentifierIPAddress, addr)
		peer.IdentityEvidence.ConnectedInterface = true
		obs := InterrogationObservations{Facts: []di.FactObservation{{Key: facts.KeyHWVendor, Value: "Example", Confidence: 1, Subject: peer}}}
		if err := sink.Persist(context.Background(), tenant, controller, peerSource("interrogation:enforce-"+addr), obs); err != nil {
			t.Fatalf("persist %s: %v", addr, err)
		}
	}

	reasons := func(cidr string) []string {
		t.Helper()
		var out []string
		rows, err := owner.Query(`
			SELECT unnest(o.admission_reasons)
			FROM identity_observations o
			JOIN network_segments s ON s.tenant_id = o.tenant_id AND s.id::text = o.network_scope
			WHERE o.tenant_id = $1 AND s.value = $2`, tenant, cidr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	unknown, static := reasons("10.20.30.0/24"), reasons("192.168.40.0/24")
	if !slices.Contains(static, "direct_scoped_address") {
		t.Fatalf("static network: admission reasons %v, want direct_scoped_address (the control polarity)", static)
	}
	if slices.Contains(unknown, "direct_scoped_address") || !slices.Contains(unknown, "dynamic_address_without_device_binding") {
		t.Fatalf("DHCP-unknown network: admission reasons %v, want dynamic_address_without_device_binding and never direct_scoped_address", unknown)
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND kind='ip_address' AND value='10.20.30.77'`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("an address-only sighting on a DHCP-unknown network established an asset (%d identifiers)", n)
	}
}

// (g) A carrier-grade-NAT prefix a firewall reports — its ISP-facing VLAN —
// is learned as PUBLIC and does not put its range in scope for an unattended
// scan: shared/autoscan refuses CGNAT unless the tenant DECLARES it. The
// declared segment on a second tenant is the other polarity.
func TestIntegration_VendorNeutralSegments_LearnedCGNATIsNotAutoScanScope(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	learnedTenant, declaredTenant := testdb.NewTenant(t, db), testdb.NewTenant(t, db)
	firewall := seedInterrogatedDevice(t, db, learnedTenant, "fortinet", "00:09:0f:00:00:07", "fw-wan")
	persistVLANs(t, NewObservationSink(db), learnedTenant, firewall, []map[string]any{
		{"id": 900, "name": "wan1.900", "subnet": "100.72.14.0/24", "gateway": "100.72.14.1"},
	})
	if got, ok := segmentByCIDR(t, db, learnedTenant, "100.72.14.0/24"); !ok || got.NetworkType != "public" {
		t.Fatalf("learned CGNAT segment = %+v (found %v), want network_type public", got, ok)
	}
	if _, err := db.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active) VALUES($1,'Our CGNAT estate','cidr','100.72.14.0/24','private','production',true)`, declaredTenant); err != nil {
		t.Fatal(err)
	}

	target := netip.MustParseAddr("100.72.14.23")
	for _, tc := range []struct {
		tenant     uuid.UUID
		wantOK     bool
		wantReason autoscan.Reason
	}{
		{learnedTenant, false, autoscan.ReasonCarrierGradeNAT},
		{declaredTenant, true, autoscan.ReasonSegment},
	} {
		prefixes := automaticScopePrefixes(t, db, tc.tenant)
		if ok, reason := autoscan.Classify(target, prefixes, nil); ok != tc.wantOK || reason != tc.wantReason {
			t.Errorf("tenant %s: Classify(%s) = %v/%s, want %v/%s", tc.tenant, target, ok, reason, tc.wantOK, tc.wantReason)
		}
		err := withTx(t, db, func(tx *sql.Tx) error {
			return dispatchguard.AuthorizeAutomaticScan(tx, sensordispatch.Payload{
				TenantID: tc.tenant.String(), Targets: []string{target.String()},
				Protocols: autoscan.DefaultPolicy().Protocols[:1], Ports: autoscan.DefaultPolicy().Ports[:1],
				Options: map[string]interface{}{"origin": "auto_scan"},
			})
		})
		outOfScope := err != nil && strings.Contains(err.Error(), "outside authorized scope")
		if outOfScope == tc.wantOK {
			t.Errorf("tenant %s: AuthorizeAutomaticScan(%s) = %v, want out-of-scope=%v", tc.tenant, target, err, !tc.wantOK)
		}
	}
}

// (h) A LEARNED public segment is not a claim of ownership for a scan a person
// asks for either — a firewall's ISP transit network tells us where it is
// connected, not that the far end is the tenant's. A DECLARED public segment
// still is, which is the case the segment registry exists to permit.
func TestIntegration_VendorNeutralSegments_LearnedPublicIsNotManualScanScope(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	firewall := seedInterrogatedDevice(t, db, tenant, "fortinet", "00:09:0f:00:00:08", "fw-transit")
	persistVLANs(t, NewObservationSink(db), tenant, firewall, []map[string]any{
		{"id": 901, "name": "transit", "subnet": "198.18.0.0/30", "gateway": "198.18.0.1"},
	})
	for _, stmt := range []string{
		`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata) VALUES($1,'Legacy learned','cidr','198.18.1.0/24','public','production',true,'{"source":"unifi","dynamic":false}')`,
		`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata) VALUES($1,'Our public estate','cidr','198.19.0.0/24','public','production',true,'{}')`,
	} {
		if _, err := db.Exec(stmt, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var scope dispatchguard.TargetScope
	if err := withTx(t, db, func(tx *sql.Tx) error {
		var err error
		scope, err = dispatchguard.LoadTargetScope(tx, tenant.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for target, wantAllowed := range map[string]bool{
		"198.18.0.2":  false, // learned from the firewall's transit VLAN
		"198.18.1.9":  false, // learned under the legacy label
		"198.19.0.9":  true,  // declared by an operator
		"10.20.30.40": true,  // private space, always
	} {
		if err := scope.Authorize(target); (err == nil) != wantAllowed {
			t.Errorf("Authorize(%s) = %v, want allowed=%v", target, err, wantAllowed)
		}
	}
}

// (i) The source-device lookup is tenant-scoped in the query itself, not only
// by RLS: a connection that bypasses RLS (the table owner here) must still not
// read another tenant's asset. Called with tenant A and an asset that belongs
// to tenant B, the segment records no device type.
func TestIntegration_VendorNeutralSegments_DeviceTypeLookupIsTenantScoped(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantA, tenantB := testdb.NewTenant(t, db), testdb.NewTenant(t, db)
	foreign := seedInterrogatedDevice(t, db, tenantB, "fortinet", "00:09:0f:00:00:09", "fw-other-tenant")
	if err := NewObservationSink(db).ensureVLANSegments(context.Background(), tenantA, foreign, fortinetShapedVLANs()); err != nil {
		t.Fatal(err)
	}
	got, ok := segmentByCIDR(t, db, tenantA, "10.20.30.0/24")
	if !ok {
		t.Fatal("no segment written")
	}
	if dt, has := got.Metadata["source_device_type"]; has {
		t.Fatalf("read tenant B's device type (%v) while writing tenant A's segment", dt)
	}
}

// (j) The identity-enrichment probe gate — the third dispatch path, the one
// that is unattended but not an auto_scan — refuses a probe scoped to a learned
// public segment. The declared public segment beside it passes the segment
// check and is refused only later, for the unrelated reason that this fixture
// has no reachable collector: that is the polarity proving the first refusal
// is the learned-public rule and not the fixture.
func TestIntegration_VendorNeutralSegments_EnrichmentProbeRefusesLearnedPublic(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	firewall := seedInterrogatedDevice(t, db, tenant, "fortinet", "00:09:0f:00:00:0a", "fw-probe")
	persistVLANs(t, NewObservationSink(db), tenant, firewall, []map[string]any{
		{"id": 902, "name": "transit", "subnet": "198.18.0.0/30", "gateway": "198.18.0.1"},
	})
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	var learned, declared string
	if err := db.QueryRow(`SELECT id::text FROM network_segments WHERE tenant_id=$1 AND value='198.18.0.0/30'`, tenant).Scan(&learned); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata) VALUES($1,'Our public estate','cidr','198.19.0.0/24','public','production',true,'{}') RETURNING id::text`, tenant).Scan(&declared); err != nil {
		t.Fatal(err)
	}

	sensor := uuid.New()
	probe := func(segment, addr string) error {
		t.Helper()
		evidence := identity.Observation{
			TenantID:    tenant.String(),
			Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:probe-test:" + sensor.String(), Mode: identity.ModePassive},
			ObservedAt:  time.Now().UTC(),
			Network:     identity.Network{SegmentID: segment},
			Identifiers: []identity.Identifier{{Kind: identity.KindIPAddress, Value: addr, Scope: segment, Confidence: 1}},
		}
		raw, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		observation := uuid.New()
		if _, err := db.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,collector_version,network_scope,evidence,admission_reasons,state,enrichment_state,enrichment_reason,first_seen_at,last_seen_at)
			VALUES($1,$2,$3,'measured',$4,'test-v1',$5,$6,ARRAY['insufficient_identity_evidence'],'unresolved','blocked','test',now(),now())`,
			tenant, observation, identity.ObservationFingerprint(evidence), evidence.Source.Ref, segment, string(raw)); err != nil {
			t.Fatal(err)
		}
		return withTx(t, db, func(tx *sql.Tx) error {
			return dispatchguard.AuthorizeProbe(tx, sensordispatch.Payload{
				TenantID: tenant.String(), Targets: []string{addr},
				Protocols: autoscan.DefaultPolicy().Protocols[:1], Ports: autoscan.DefaultPolicy().Ports[:1],
				Options: map[string]interface{}{
					"identity_enrichment_request_id": uuid.NewString(),
					"identity_observation_id":        observation.String(),
					"identity_network_scope":         segment,
				},
			}, sensor)
		})
	}

	if err := probe(learned, "198.18.0.2"); err == nil || !strings.Contains(err.Error(), "learned public network") {
		t.Errorf("probe into a learned public segment = %v, want refused as a learned public network", err)
	}
	if err := probe(declared, "198.19.0.9"); err == nil || strings.Contains(err.Error(), "learned public network") || !strings.Contains(err.Error(), "no longer reachable") {
		t.Errorf("probe into a declared public segment = %v, want it past the segment check (refused only for the unreachable collector)", err)
	}
}

// automaticScopePrefixes loads a tenant's segments the way the automatic-scan
// gates do and keeps the ones that grant ownership to an unattended scan.
func automaticScopePrefixes(t *testing.T, db *sql.DB, tenant uuid.UUID) []netip.Prefix {
	t.Helper()
	rows, err := db.Query(`SELECT value, network_type, COALESCE(metadata->>'source','') IN ('interrogation','unifi') FROM network_segments WHERE tenant_id=$1 AND is_active AND segment_type='cidr'`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []netip.Prefix
	for rows.Next() {
		var value, networkType string
		var learned bool
		if err := rows.Scan(&value, &networkType, &learned); err != nil {
			t.Fatal(err)
		}
		if p, err := netip.ParsePrefix(value); err == nil && dispatchguard.SegmentGrantsOwnership(networkType, learned, true) {
			out = append(out, p)
		}
	}
	return out
}

func withTx(t *testing.T, db *sql.DB, fn func(*sql.Tx) error) error {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	return fn(tx)
}
