package services

// The faceplate's per-interface crypto posture (DCIM BUILD_PLAN row 3.4)
// against Postgres on the app role: a configuration measured on an endpoint
// bound to an interface's address lands on THAT interface (through
// ip_address_id, or the address's host when the resolver has not set it); the
// same address on another asset's endpoint does not; a certified score is the
// worst score, a stored zero with no numeric corroboration is "not assessed"
// rather than clean; a weak protocol version is flagged; an interface with
// nothing behind it reads 0 configurations; the asset's worst OPEN finding is
// returned; another tenant reads not-found.
//
// Mutations: drop the host-equality branch of the endpoint join → eth0 reads
// 0 configurations; drop the two asset predicates (endpoint and
// configuration) → eth0 reads 2 configurations;
// replace the assessed expression with TRUE → eth1's worst score is 0; drop
// findings.OpenSQL → the resolved critical becomes the top finding.

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_InterfacePosture(t *testing.T) {
	f := newCableFix(t)
	sw := f.asset(t)
	other := f.asset(t)
	eth0 := f.iface(t, sw, "eth0", "1000base-t")
	eth1 := f.iface(t, sw, "eth1", "1000base-t")
	eth2 := f.iface(t, sw, "eth2", "1000base-t")

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.owner.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	addr := func(iface uuid.UUID, a string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO ip_addresses(id,tenant_id,address,assigned_kind,assigned_id) VALUES($1,$2,$3,'interface',$4)`, id, f.tenant, a, iface)
		return id
	}
	addr(eth0, "192.0.2.10/24")
	a1 := addr(eth1, "192.0.2.11/24")

	endpoint := func(asset uuid.UUID, a string, ipID *uuid.UUID) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO asset_endpoints(id,tenant_id,asset_id,address,port,transport,ip_address_id) VALUES($1,$2,$3,$4,443,'tcp',$5)`, id, f.tenant, asset, a, ipID)
		return id
	}
	config := func(asset, ep uuid.UUID, version string, score int, codes ...string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO crypto_implementations(id,tenant_id,asset_id,endpoint_id,protocol,protocol_version,discovery_method,risk_score,created_at,updated_at)
			VALUES($1,$2,$3,$4,'TLS',$5,'passive',$6,NOW(),NOW())`, id, f.tenant, asset, ep, version, score)
		for _, c := range codes {
			exec(`INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type)
				SELECT $1, a.id, a.category FROM algorithms a WHERE a.code = $2`, id, c)
		}
		return id
	}
	// eth0: resolved by host only (no ip_address_id), TLS 1.0 with RC4: weak, scored 90.
	weak := config(sw, endpoint(sw, "192.0.2.10", nil), "TLS1.0", 90, "TLS1.0", "TLS_RSA_WITH_RC4_128_SHA")
	// eth1: resolved by ip_address_id, TLS 1.3 stored 0 while the catalogue says 10: not certified.
	modern := config(sw, endpoint(sw, "192.0.2.11", &a1), "TLS1.3", 0, "TLS1.3", "TLS_AES_256_GCM_SHA384")
	// The same address on another asset is not behind this switch's port.
	config(other, endpoint(other, "192.0.2.10", nil), "TLS1.1", 70, "TLS1.1")

	finding := func(kind, sev string, score int, workflow string) {
		exec(`INSERT INTO findings(tenant_id,producer,kind,subject_type,subject_id,severity,score,summary,evidence,workflow_status)
			VALUES($1,'hygiene',$2,'asset',$3,$4,$5,'s','{}'::jsonb,$6)`, f.tenant, kind, sw, sev, score, workflow)
	}
	finding("no_owner", "high", 80, "NEW")
	finding("stale", "low", 10, "NEW")
	finding("unmanaged", "critical", 95, "RESOLVED")

	got, err := f.cables.InterfacePosture(f.ctx, f.tenant, sw)
	if err != nil {
		t.Fatal(err)
	}
	by := map[uuid.UUID]InterfacePosture{}
	for _, p := range got.Interfaces {
		by[p.InterfaceID] = p
	}
	if len(by) != 3 {
		t.Fatalf("posture for %d interfaces, want 3", len(by))
	}
	p0 := by[eth0]
	if p0.Configurations != 1 || !p0.Assessed || p0.WorstScore == nil || *p0.WorstScore != 90 || !p0.WeakProtocol ||
		p0.WeakestStrength == nil || *p0.WeakestStrength != "weak" || p0.Worst == nil || p0.Worst.ID != weak {
		t.Fatalf("eth0 posture %+v (worst %+v): want 1 configuration, assessed 90, weak protocol, weakest weak", p0, p0.Worst)
	}
	p1 := by[eth1]
	if p1.Configurations != 1 || p1.Assessed || p1.WorstScore != nil || p1.WeakProtocol ||
		p1.WeakestStrength == nil || *p1.WeakestStrength != "recommended" || p1.Worst == nil || p1.Worst.ID != modern {
		t.Fatalf("eth1 posture %+v (worst %+v): want 1 configuration, not assessed, weakest recommended", p1, p1.Worst)
	}
	if p2 := by[eth2]; p2.Configurations != 0 || p2.Assessed || p2.Worst != nil {
		t.Fatalf("eth2 posture %+v: want nothing observed", p2)
	}
	if got.OpenFindings != 2 || got.TopFinding == nil || got.TopFinding.Severity != "high" {
		t.Fatalf("asset findings %d top %+v: want 2 open, top = high", got.OpenFindings, got.TopFinding)
	}

	stranger := testdb.NewTenant(t, f.owner)
	if _, err := f.cables.InterfacePosture(f.ctx, stranger, sw); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("another tenant: %v, want not found", err)
	}
}

// The Cabling lens's Site / Rack column (row 3.4): each named termination
// carries the site and rack its asset was at when cabled.
//
// Mutation: drop 'site_name', tsi.name from cableEndSQL → the name is empty.
func TestIntegration_CableTerminationRef_SiteAndRack(t *testing.T) {
	f := newCableFix(t)
	a, b := f.asset(t), f.asset(t)
	site, rack := uuid.New(), uuid.New()
	if _, err := f.owner.Exec(`INSERT INTO sites(id,tenant_id,name,slug) VALUES($1,$2,'DC-East','dc-east')`, site, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(`INSERT INTO racks(id,tenant_id,name,site_id) VALUES($1,$2,'R12',$3)`, rack, f.tenant, site); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(`UPDATE assets SET site_id = $1, rack_id = $2 WHERE id = $3`, site, rack, a); err != nil {
		t.Fatal(err)
	}
	ia, ib := f.iface(t, a, "eth0", "1000base-t"), f.iface(t, b, "eth0", "1000base-t")
	m, err := f.tryCable(term("interface", ia), term("interface", ib), nil)
	if err != nil {
		t.Fatal(err)
	}
	aEnd := m["a_terminations"].([]any)[0].(map[string]any)
	bEnd := m["b_terminations"].([]any)[0].(map[string]any)
	if aEnd["site_name"] != "DC-East" || aEnd["rack_name"] != "R12" || aEnd["site_id"] != site.String() {
		t.Fatalf("A end %v: want site DC-East, rack R12", aEnd)
	}
	if bEnd["site_name"] != nil || bEnd["rack_name"] != nil {
		t.Fatalf("B end %v: an unplaced asset has no site or rack", bEnd)
	}
}
