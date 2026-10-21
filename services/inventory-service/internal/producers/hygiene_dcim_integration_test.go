package producers

// The hygiene producer's DCIM kinds (DCIM gap 6) end to end, against a real
// Postgres under RLS: each of the nine fires on exactly the asset its
// condition names, NOT on the compliant twin beside it, NOT on the asset whose
// record holds nothing to judge (the three-valued half), and resolves when the
// condition is fixed.
//
// The compliance half — that the seeded IH-007 to IH-015 controls turn these
// findings into a pass / fail / not assessed through EvaluateFramework — is
// services/compliance-engine/internal/services/
// hygiene_dcim_controls_integration_test.go.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type dcimHygieneFixture struct {
	*hygieneFixture
	assets map[string]uuid.UUID
	ifaces map[string]uuid.UUID
	cables map[string]uuid.UUID
	ips    map[string]uuid.UUID
	rack   uuid.UUID
	dt2U   uuid.UUID
}

func newDCIMHygieneFixture(t *testing.T) *dcimHygieneFixture {
	t.Helper()
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	p, err := NewHygieneProducer(app)
	if err != nil {
		t.Fatalf("NewHygieneProducer: %v", err)
	}
	f := &dcimHygieneFixture{
		hygieneFixture: &hygieneFixture{owner: owner, app: app, tenant: tenant, producer: p},
		assets:         map[string]uuid.UUID{},
		ifaces:         map[string]uuid.UUID{},
		cables:         map[string]uuid.UUID{},
		ips:            map[string]uuid.UUID{},
	}
	sfx := uuid.NewString()[:8]
	site := testdb.EnsureSite(t, owner, tenant, "DC-"+sfx)

	mfr := uuid.New()
	exec(t, owner, `INSERT INTO manufacturers (id, tenant_id, name, slug) VALUES ($1, $2, $3, $4)`,
		mfr, tenant, "Acme "+sfx, "acme-"+sfx)
	f.dt2U = uuid.New()
	dt0U, dtOld, dtNew := uuid.New(), uuid.New(), uuid.New()
	for _, dt := range []struct {
		id     uuid.UUID
		model  string
		height float64
		eos    any
	}{
		{f.dt2U, "R2", 2, nil},
		{dt0U, "PDU0", 0, nil},
		{dtOld, "OLD1", 1, daysFromNow(-30)},
		{dtNew, "NEW1", 1, daysFromNow(5 * 365)},
	} {
		exec(t, owner, `INSERT INTO device_types (id, tenant_id, manufacturer_id, model, slug, u_height, end_of_support)
		                VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			dt.id, tenant, mfr, dt.model, "dt-"+sfx+"-"+uuid.NewString()[:6], dt.height, dt.eos)
	}
	// A platform whose end of support comes from the end-of-life catalogue,
	// six months out: the "within 12 months" rung, by the catalogue fallback.
	cat := catalogueRow(t, owner, "os", "Acme", "acmeos-"+sfx, "9", daysFromNow(180))
	platSoon := uuid.New()
	exec(t, owner, `INSERT INTO platforms (id, tenant_id, name, slug, eol_catalogue_id) VALUES ($1, $2, $3, $4, $5)`,
		platSoon, tenant, "AcmeOS "+sfx, "acmeos-"+sfx, cat)

	f.rack = uuid.New()
	exec(t, owner, `INSERT INTO racks (id, tenant_id, name, site_id) VALUES ($1, $2, 'R-01', $3)`, f.rack, tenant, site)

	asset := func(name string, cols map[string]any) {
		id := uuid.New()
		f.assets[name] = id
		exec(t, owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path,
		                    asset_status, last_seen_at, owner_email, site_id)
		                VALUES ($1, $2, $3, $3, 'server', 'hardware.computer.server', 'monitoring', now(),
		                        'ops@example.com', $4)`, id, tenant, name, site)
		for col, v := range cols {
			// Column names are test literals, never input.
			exec(t, owner, `UPDATE assets SET `+col+` = $1 WHERE tenant_id = $2 AND id = $3`, v, tenant, id)
		}
	}
	// Placement.
	asset("unracked", map[string]any{"device_type_id": f.dt2U})
	asset("racked", map[string]any{"device_type_id": f.dt2U, "rack_id": f.rack})
	exec(t, owner, `UPDATE assets SET position = 10, face = 'front' WHERE tenant_id = $1 AND id = $2`, tenant, f.assets["racked"])
	asset("zero-u-loose", map[string]any{"device_type_id": dt0U})
	asset("no-type", nil)
	// A virtual machine is not rack-mountable whatever device type it was given.
	asset("vm-typed", map[string]any{"device_type_id": f.dt2U, "class_key": "virtual_machine", "class_path": "virtual.virtual_machine"})
	asset("unpositioned", map[string]any{"device_type_id": f.dt2U, "rack_id": f.rack})
	asset("zero-u-in-rack", map[string]any{"device_type_id": dt0U, "rack_id": f.rack})
	// Lifecycle.
	asset("warranty-gone", map[string]any{"warranty_end": daysFromNow(-10)})
	asset("warranty-ok", map[string]any{"warranty_end": daysFromNow(200)})
	asset("eos-past", map[string]any{"device_type_id": dtOld, "rack_id": f.rack})
	exec(t, owner, `UPDATE assets SET position = 20, face = 'front' WHERE tenant_id = $1 AND id = $2`, tenant, f.assets["eos-past"])
	asset("eos-soon", map[string]any{"platform_id": platSoon})
	asset("eos-far", map[string]any{"device_type_id": dtNew, "rack_id": f.rack})
	exec(t, owner, `UPDATE assets SET position = 30, face = 'front' WHERE tenant_id = $1 AND id = $2`, tenant, f.assets["eos-far"])
	asset("decommissioned", map[string]any{"device_type_id": dtOld, "warranty_end": daysFromNow(-10),
		"decommissioned_at": daysFromNow(-1)})
	// Cabling and addressing.
	for _, n := range []string{"sw-heard", "sw-quiet", "host-a", "host-b", "host-c", "host-d", "planner", "sw-parked", "sw-drift", "sw-measured", "host-p", "host-q", "host-r", "host-s", "dup-1", "dup-2", "dup-global", "vip-1", "vip-2", "synthetic-only", "collected-untyped"} {
		asset(n, nil)
	}

	iface := func(key, assetName, typ string) {
		id := uuid.New()
		f.ifaces[key] = id
		exec(t, owner, `INSERT INTO interfaces (id, tenant_id, asset_id, name, type) VALUES ($1, $2, $3, $4, $5)`,
			id, tenant, f.assets[assetName], key, typ)
	}
	for _, k := range []struct{ key, asset string }{
		{"sw-heard:1", "sw-heard"}, {"sw-heard:2", "sw-heard"},
		{"sw-parked:1", "sw-parked"}, {"sw-parked:2", "sw-parked"}, {"sw-drift:1", "sw-drift"},
		{"sw-measured:1", "sw-measured"}, {"sw-measured:2", "sw-measured"},
		{"host-p:0", "host-p"}, {"host-q:0", "host-q"}, {"host-r:0", "host-r"}, {"host-s:0", "host-s"},
		{"sw-quiet:1", "sw-quiet"}, {"sw-quiet:2", "sw-quiet"},
		{"host-a:0", "host-a"}, {"host-b:0", "host-b"}, {"host-c:0", "host-c"}, {"host-d:0", "host-d"}, {"planner:1", "planner"}, {"planner:2", "planner"},
		{"dup-1:0", "dup-1"}, {"dup-2:0", "dup-2"}, {"dup-global:0", "dup-global"},
		{"vip-1:0", "vip-1"}, {"vip-2:0", "vip-2"},
	} {
		iface(k.key, k.asset, "1000base-t")
	}
	iface("host-a:1", "host-a", "other") // the one untyped interface
	// The identity engine's placeholder for an address no collector named an
	// interface for: invented, so there is nothing for a person to type. Not
	// a finding (IH-011 counts only interfaces something reported).
	measuredIface := func(key, assetName, name, sourceRef string) {
		id := uuid.New()
		f.ifaces[key] = id
		exec(t, owner, `INSERT INTO interfaces (id, tenant_id, asset_id, name, type, source_kind, source_ref)
		                VALUES ($1, $2, $3, $4, 'other', 'measured', $5)`, id, tenant, f.assets[assetName], name, sourceRef)
	}
	measuredIface("synthetic-only:0", "synthetic-only", identity.SyntheticInterfacePrefix+"1", identity.SyntheticInterfaceSourceRef)
	// A NIC a collector reported but could not type: real, and a person can
	// set its type, so it is a finding.
	measuredIface("collected-untyped:0", "collected-untyped", "eth0", "agent:qa-collector")

	cable := func(key, status, sourceKind string, created time.Time, confirmed any, a, b string) {
		id := uuid.New()
		f.cables[key] = id
		exec(t, owner, `INSERT INTO cables (id, tenant_id, operational_status, source_kind, label, created_at, lldp_confirmed_at)
		                VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, tenant, status, sourceKind, key, created, confirmed)
		for end, ifk := range map[string]string{"A": a, "B": b} {
			assetName := ifk[:len(ifk)-2]
			exec(t, owner, `INSERT INTO cable_terminations (tenant_id, cable_id, cable_end, termination_kind, termination_id, asset_id)
			                VALUES ($1, $2, $3, 'interface', $4, $5)`, tenant, id, end, f.ifaces[ifk], f.assets[assetName])
		}
	}
	// Four switches that report neighbours, each through ONE of the four traces
	// an LLDP/CDP observation leaves (services/cable_intake.go), each with a
	// declared cable no neighbour has confirmed: every one is a finding.
	//   sw-heard     a cable the network confirmed two days ago (that cable
	//                itself is fine and must not be listed);
	//   sw-parked    a parked LLDP termination seen yesterday;
	//   sw-drift     an open topology cable_drift finding seen yesterday;
	//   sw-measured  an LLDP-proposed (measured) cable seen yesterday.
	cable("unconfirmed", "connected", "declared", daysFromNow(-40), nil, "sw-heard:1", "host-a:0")
	cable("confirmed", "connected", "declared", daysFromNow(-40), daysFromNow(-2), "sw-heard:2", "host-b:0")
	cable("unconfirmed-parked", "connected", "imported", daysFromNow(-40), nil, "sw-parked:1", "host-p:0")
	exec(t, owner, `INSERT INTO unresolved_terminations (tenant_id, producer, origin_kind, origin_id, far_identity, intent,
	                    first_seen_at, last_seen_at, expires_at)
	                VALUES ($1, 'lldp', 'interface', $2, '{"system_name": "far-switch"}', 'cable', $3, $3, $4)`,
		tenant, f.ifaces["sw-parked:2"], daysFromNow(-1), daysFromNow(29))
	cable("unconfirmed-drift", "connected", "declared", daysFromNow(-40), nil, "sw-drift:1", "host-q:0")
	exec(t, owner, `INSERT INTO findings (tenant_id, producer, kind, subject_type, subject_id, severity, score, summary,
	                    detection_state, workflow_status, first_seen, last_seen)
	                VALUES ($1, 'topology', 'cable_drift', 'asset', $2, 'medium', 0, 'drift', 'ACTIVE', 'NEW', $3, $3)`,
		tenant, f.assets["sw-drift"], daysFromNow(-1))
	cable("unconfirmed-measured", "connected", "declared", daysFromNow(-40), nil, "sw-measured:1", "host-r:0")
	cable("lldp-proposal", "connected", "measured", daysFromNow(-40), nil, "sw-measured:2", "host-s:0")
	exec(t, owner, `UPDATE cables SET last_seen_at = $1 WHERE tenant_id = $2 AND id = $3`, daysFromNow(-1), tenant, f.cables["lldp-proposal"])
	// sw-quiet reports nothing: its unconfirmed cable is not judged.
	cable("quiet", "connected", "declared", daysFromNow(-40), nil, "sw-quiet:1", "host-c:0")
	// Planned cables: one abandoned for 100 days (A end sw-quiet), one fresh.
	cable("planned-old", "planned", "declared", daysFromNow(-100), nil, "sw-quiet:2", "host-d:0")
	cable("planned-new", "planned", "declared", daysFromNow(-10), nil, "planner:1", "planner:2")

	// Addressing: dup-1 and dup-2 share 10.20.30.40 in one VRF; dup-global
	// holds the same address in the global table (a different VRF: fine);
	// vip-1 and vip-2 share an address whose role allows it.
	vrf := uuid.New()
	exec(t, owner, `INSERT INTO vrfs (id, tenant_id, name) VALUES ($1, $2, 'blue')`, vrf, tenant)
	ip := func(key, address string, vrfID any, role any, ifk string) {
		id := uuid.New()
		f.ips[key] = id
		exec(t, owner, `INSERT INTO ip_addresses (id, tenant_id, address, vrf_id, role, assigned_kind, assigned_id)
		                VALUES ($1, $2, $3, $4, $5, 'interface', $6)`, id, tenant, address, vrfID, role, f.ifaces[ifk])
	}
	ip("dup-1", "10.20.30.40/24", vrf, nil, "dup-1:0")
	ip("dup-2", "10.20.30.40/25", vrf, nil, "dup-2:0")
	ip("dup-global", "10.20.30.40/24", nil, nil, "dup-global:0")
	ip("vip-1", "10.20.30.99/24", vrf, "vrrp", "vip-1:0")
	ip("vip-2", "10.20.30.99/24", vrf, "vrrp", "vip-2:0")
	return f
}

// openSubjects is the asset subjects holding an open hygiene finding of kind.
func (f *dcimHygieneFixture) openSubjects(t *testing.T, kind string) []string {
	t.Helper()
	rows, err := f.owner.Query(`SELECT a.hostname FROM findings fi
		JOIN assets a ON a.tenant_id = fi.tenant_id AND a.id = fi.subject_id
		WHERE fi.tenant_id = $1 AND fi.producer = $2 AND fi.kind = $3
		  AND fi.subject_type = 'asset' AND fi.detection_state = 'ACTIVE'
		ORDER BY a.hostname`, f.tenant, findings.ProducerHygiene, kind)
	if err != nil {
		t.Fatalf("open findings %s: %v", kind, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		out = append(out, h)
	}
	return out
}

func equalStrings(a, b []string) bool {
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestIntegration_HygieneDCIM_EachKindLandsOnItsAsset(t *testing.T) {
	f := newDCIMHygieneFixture(t)
	ctx := context.Background()
	run := f.run(t, ctx)
	if run.Assessed == 0 {
		t.Fatal("the pass claimed coverage of no asset")
	}

	want := map[string][]string{
		// zero-u-loose (0 U) and no-type (no device type) are not rack-mountable
		// as far as the record knows; vm-typed is not hardware; decommissioned
		// has left service.
		findings.KindNotRacked: {"unracked"},
		// zero-u-in-rack has no position by design.
		findings.KindNoRackPosition: {"unpositioned"},
		// On the A end only: host-d is the B end of the same cable.
		findings.KindPlannedCableStale: {"sw-quiet"},
		// sw-quiet's cable is just as unconfirmed, but sw-quiet reports no
		// neighbours; the hosts on the far ends report none either (host-s is
		// heard, through the proposal, but holds no declared cable).
		findings.KindCableUnconfirmed: {"sw-drift", "sw-heard", "sw-measured", "sw-parked"},
		// synthetic-only's one interface is the identity engine's placeholder.
		findings.KindInterfaceNoType: {"collected-untyped", "host-a"},
		// Both ends of the pair; not dup-global (another VRF), not the VRRP pair.
		findings.KindDuplicateAddress: {"dup-1", "dup-2"},
		// warranty-ok is in the future; every asset with NO warranty date is
		// unknown, not expired; decommissioned is out of scope.
		findings.KindWarrantyExpired:  {"warranty-gone"},
		findings.KindPastEndOfSupport: {"eos-past"},
		// The catalogue fallback through the platform; eos-past is past, not
		// "soon" as well.
		findings.KindEndOfSupportSoon: {"eos-soon"},
	}
	for kind, hosts := range want {
		if got := f.openSubjects(t, kind); !equalStrings(got, hosts) {
			t.Errorf("%s: open on %v, want %v", kind, got, hosts)
		}
	}

	// The evidence a person starts from: the cable on the port, and the
	// summary names the address rather than a count.
	var evidence, summary string
	if err := f.owner.QueryRow(`SELECT evidence::text, summary FROM findings
		WHERE tenant_id = $1 AND producer = 'hygiene' AND kind = $2 AND subject_id = $3`,
		f.tenant, findings.KindCableUnconfirmed, f.assets["sw-heard"]).Scan(&evidence, &summary); err != nil {
		t.Fatalf("read cable_unconfirmed: %v", err)
	}
	if !containsAll(evidence, f.cables["unconfirmed"].String(), `"interface": "sw-heard:1"`) ||
		containsAll(evidence, f.cables["confirmed"].String()) {
		t.Errorf("cable_unconfirmed evidence = %s; want the unconfirmed cable only", evidence)
	}
	if err := f.owner.QueryRow(`SELECT summary FROM findings
		WHERE tenant_id = $1 AND producer = 'hygiene' AND kind = $2 AND subject_id = $3`,
		f.tenant, findings.KindDuplicateAddress, f.assets["dup-1"]).Scan(&summary); err != nil {
		t.Fatalf("read duplicate_address: %v", err)
	}
	if !containsAll(summary, "10.20.30.40") {
		t.Errorf("duplicate_address summary %q does not name the address", summary)
	}

	// Fix every condition; the next pass resolves every finding it raised.
	o, tn := f.owner, f.tenant
	exec(t, o, `UPDATE assets SET rack_id = $1, position = 40, face = 'front' WHERE tenant_id = $2 AND id = $3`, f.rack, tn, f.assets["unracked"])
	exec(t, o, `UPDATE assets SET position = 1, face = 'rear' WHERE tenant_id = $1 AND id = $2`, tn, f.assets["unpositioned"])
	exec(t, o, `UPDATE cables SET operational_status = 'connected' WHERE tenant_id = $1 AND id = $2`, tn, f.cables["planned-old"])
	exec(t, o, `UPDATE cables SET lldp_confirmed_at = now() WHERE tenant_id = $1 AND source_kind <> 'measured' AND operational_status = 'connected'`, tn)
	exec(t, o, `UPDATE interfaces SET type = '10gbase-x-sfpp' WHERE tenant_id = $1 AND id = $2`, tn, f.ifaces["host-a:1"])
	exec(t, o, `UPDATE interfaces SET type = '1000base-t' WHERE tenant_id = $1 AND id = $2`, tn, f.ifaces["collected-untyped:0"])
	exec(t, o, `UPDATE ip_addresses SET address = '10.20.30.41/24' WHERE tenant_id = $1 AND id = $2`, tn, f.ips["dup-2"])
	exec(t, o, `UPDATE assets SET warranty_end = $1 WHERE tenant_id = $2 AND id = $3`, daysFromNow(400), tn, f.assets["warranty-gone"])
	exec(t, o, `UPDATE device_types SET end_of_support = $1 WHERE tenant_id = $2 AND model = 'OLD1'`, daysFromNow(3*365), tn)
	exec(t, o, `UPDATE eol_catalogue SET eol_date = $1 WHERE id = (SELECT eol_catalogue_id FROM platforms WHERE tenant_id = $2 AND name LIKE 'AcmeOS%')`,
		daysFromNow(3*365), tn)

	second := f.run(t, ctx)
	for kind := range want {
		if got := f.openSubjects(t, kind); len(got) != 0 {
			t.Errorf("%s still open on %v after the condition was fixed", kind, got)
		}
	}
	if second.Resolved < 10 {
		t.Errorf("second pass resolved %d findings, want at least 10 (one per DCIM finding raised)", second.Resolved)
	}
}

// The coverage claim is what turns IH-007..IH-015 from NOT ASSESSED into a
// number: every monitored asset the pass read, including the ones that raised
// nothing.
func TestIntegration_HygieneDCIM_ClaimsCoverageOfCompliantAssets(t *testing.T) {
	f := newDCIMHygieneFixture(t)
	f.run(t, context.Background())
	for _, name := range []string{"racked", "warranty-ok", "eos-far", "sw-quiet"} {
		var n int
		if err := f.owner.QueryRow(`SELECT count(*) FROM producer_assessments
			WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'hygiene'`, f.tenant, f.assets[name]).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("%s: %d hygiene coverage rows, want 1", name, n)
		}
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
