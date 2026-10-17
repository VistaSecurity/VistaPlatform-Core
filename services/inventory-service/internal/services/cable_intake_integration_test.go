package services

// DB-integration tests for the LLDP / CDP cable intake (DCIM BUILD_PLAN row
// 3.3). Every scenario goes through the REAL internal sightings intake
// (IngestSightings → identity engine → CableIntake) and, for parked
// neighbours, the REAL resolver it runs after the batch. Skipped unless
// TEST_DATABASE_URL is set (make test-integration-db).
//
// Mutations (each turns a named test red):
//   - cable_resolver.go: MatchTermination always answers ok=false
//     → ParkedThenResolved (the cable never materialises).
//   - cable_intake.go: drop the parkTx call → ParkedThenResolved (no row parked).
//   - cable_intake.go: drop the writeCableDrift call → ContradictionRaisesDrift.
//   - cable_proposals.go: decide("active") → decide("pending") / drop the
//     PGGraph pending filter → ApproveActivatesAndComputesPaths.
//   - internal_sightings.go: drop the RecordNeighbors call → TwoKnownSwitches.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type lldpFix struct {
	raw    *sql.DB
	tenant uuid.UUID
	svc    *AssetService
	cables *CableService
	n      int
}

func newLLDPFix(t *testing.T) *lldpFix {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	svc := NewAssetService(&database.DB{DB: sqlx.NewDb(raw, "postgres")})
	cables := NewCableService(raw)
	svc.SetCableIntake(NewCableIntake(raw, cables))
	return &lldpFix{raw: raw, tenant: testdb.NewTenant(t, raw), svc: svc, cables: cables}
}

// sw describes one switch's sighting: serial, management address, a base
// MAC carried by its Vlan1 interface, its ports and its neighbour table.
type sw struct {
	serial, addr, mac string
	ports             []string
	neighbors         []identity.ObservedNeighbor
}

func (f *lldpFix) ingest(t *testing.T, s sw) uuid.UUID {
	t.Helper()
	f.n++
	ifaces := []identity.ObservedInterface{{Name: "Vlan1", Type: "virtual", MAC: s.mac,
		Addresses: []identity.ObservedAddress{{Address: s.addr, PrefixLen: 24}}}}
	for _, p := range s.ports {
		ifaces = append(ifaces, identity.ObservedInterface{Name: p, Type: "1000base-t"})
	}
	sg := identity.Sighting{
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: interrogationSourcePrefix + s.serial, Mode: identity.ModeActive},
		Channel:     identity.ChannelAuthenticatedSession,
		ObservedAt:  time.Now().UTC(),
		ReceiptID:   fmt.Sprintf("lldp-%s-%d", s.serial, f.n),
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: s.serial}},
		Interfaces:  ifaces,
		Neighbors:   s.neighbors,
	}
	res, err := f.svc.IngestSightings(context.Background(), f.tenant, []SightingItem{{Sighting: sg}})
	if err != nil {
		t.Fatalf("IngestSightings %s: %v", s.serial, err)
	}
	if res[0].AssetID == "" {
		t.Fatalf("%s resolved to no asset: %+v", s.serial, res[0])
	}
	return uuid.MustParse(res[0].AssetID)
}

func (f *lldpFix) iface(t *testing.T, asset uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.raw.QueryRow(`SELECT id FROM interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = $3`, f.tenant, asset, name).Scan(&id); err != nil {
		t.Fatalf("interface %s on %s: %v", name, asset, err)
	}
	return id
}

type cableRow struct {
	id                    uuid.UUID
	status, source, label string
	observations          int
	confirmed             sql.NullTime
}

func (f *lldpFix) cablesOn(t *testing.T, iface uuid.UUID) []cableRow {
	t.Helper()
	rows, err := f.raw.Query(`SELECT c.id, c.status, c.source_kind, COALESCE(c.label, ''), c.observation_count, c.lldp_confirmed_at
		FROM cables c JOIN cable_terminations ct ON ct.cable_id = c.id
		WHERE c.tenant_id = $1 AND ct.termination_id = $2`, f.tenant, iface)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []cableRow
	for rows.Next() {
		var c cableRow
		if err := rows.Scan(&c.id, &c.status, &c.source, &c.label, &c.observations, &c.confirmed); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func (f *lldpFix) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(q, append([]any{f.tenant}, args...)...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func lldp(local, chassis, port, name string) identity.ObservedNeighbor {
	return identity.ObservedNeighbor{Protocol: "lldp", LocalInterface: local, RemoteChassisID: chassis, RemotePortID: port, RemoteSystemName: name}
}

var (
	sw1 = sw{serial: "LLDP-SW-1", addr: "10.33.0.1", mac: "00:00:5e:33:00:01", ports: []string{"GigabitEthernet1/0/1", "GigabitEthernet1/0/2"}}
	sw2 = sw{serial: "LLDP-SW-2", addr: "10.33.0.2", mac: "00:00:5e:33:00:02", ports: []string{"Ethernet1/1", "Ethernet1/2"}}
	sw3 = sw{serial: "LLDP-SW-3", addr: "10.33.0.3", mac: "00:00:5e:33:00:03", ports: []string{"GigabitEthernet0/1"}}
)

func with(s sw, n ...identity.ObservedNeighbor) sw { s.neighbors = n; return s }

// Two known switches: sw2's LLDP names sw1's port → ONE pending, measured
// cable labelled lldp, no path yet. Re-observing it (from either side) counts
// observations on the same cable.
func TestIntegration_LLDP_TwoKnownSwitchesProposeOnePendingCable(t *testing.T) {
	f := newLLDPFix(t)
	a1 := f.ingest(t, sw1)
	a2 := f.ingest(t, with(sw2, lldp("Ethernet1/1", sw1.mac, "Gi1/0/1", "lldp-sw-1")))
	gi1, eth1 := f.iface(t, a1, "GigabitEthernet1/0/1"), f.iface(t, a2, "Ethernet1/1")

	got := f.cablesOn(t, eth1)
	if len(got) != 1 {
		t.Fatalf("cables on Ethernet1/1 = %d, want 1 proposed cable", len(got))
	}
	c := got[0]
	if c.status != "pending" || c.source != "measured" || c.label != "lldp" || c.observations != 1 {
		t.Fatalf("proposed cable = %+v, want pending / measured / lldp / 1 observation", c)
	}
	if far := f.cablesOn(t, gi1); len(far) != 1 || far[0].id != c.id {
		t.Fatalf("the far end Gi1/0/1 is not on the proposed cable: %+v", far)
	}
	if n := f.count(t, `SELECT count(*) FROM cable_paths WHERE tenant_id = $1 AND origin_id = $2 AND is_complete`, eth1); n != 0 {
		t.Fatalf("a pending cable carries a complete path (%d); paths wait for approval", n)
	}

	// Idempotent: sw2 again, then sw1's own view of the same link.
	f.ingest(t, with(sw2, lldp("Ethernet1/1", sw1.mac, "Gi1/0/1", "lldp-sw-1")))
	f.ingest(t, with(sw1, lldp("GigabitEthernet1/0/1", sw2.mac, "Ethernet1/1", "lldp-sw-2")))
	if n := f.count(t, `SELECT count(*) FROM cables WHERE tenant_id = $1`); n != 1 {
		t.Fatalf("cables after re-observation = %d, want still 1", n)
	}
	if c2 := f.cablesOn(t, eth1)[0]; c2.id != c.id || c2.observations != 3 || !c2.confirmed.Valid {
		t.Fatalf("re-observed cable = %+v, want the same cable with 3 observations, confirmed", c2)
	}
}

// An unknown neighbour is parked (producer lldp, intent cable, the far
// identity), and becomes the proposed cable when the far switch arrives — by
// the resolver IngestSightings runs after the batch that filed it.
func TestIntegration_LLDP_UnknownNeighbourParkedThenResolved(t *testing.T) {
	f := newLLDPFix(t)
	a2 := f.ingest(t, with(sw2, lldp("Ethernet1/2", sw1.mac, "Gi1/0/2", "lldp-sw-1")))
	eth2 := f.iface(t, a2, "Ethernet1/2")

	var far []byte
	var producer, intent string
	if err := f.raw.QueryRow(`SELECT producer, intent, far_identity FROM unresolved_terminations
		WHERE tenant_id = $1 AND origin_kind = 'interface' AND origin_id = $2`, f.tenant, eth2).Scan(&producer, &intent, &far); err != nil {
		t.Fatalf("the unknown neighbour was not parked: %v", err)
	}
	var ident map[string]string
	_ = json.Unmarshal(far, &ident)
	if producer != "lldp" || intent != "cable" || ident["chassis_id"] != sw1.mac || ident["port_id"] != "Gi1/0/2" || ident["system_name"] != "lldp-sw-1" {
		t.Fatalf("parked row = %s / %s / %v", producer, intent, ident)
	}
	if len(f.cablesOn(t, eth2)) != 0 {
		t.Fatal("a cable was proposed to a far end that does not exist")
	}

	a1 := f.ingest(t, sw1) // the far switch arrives, with no neighbours of its own
	gi2 := f.iface(t, a1, "GigabitEthernet1/0/2")
	got := f.cablesOn(t, eth2)
	if len(got) != 1 || got[0].status != "pending" || got[0].source != "measured" {
		t.Fatalf("after the far switch arrived: cables on Ethernet1/2 = %+v, want one pending measured cable", got)
	}
	if far := f.cablesOn(t, gi2); len(far) != 1 || far[0].id != got[0].id {
		t.Fatalf("the materialised cable does not end on Gi1/0/2: %+v", far)
	}
	if n := f.count(t, `SELECT count(*) FROM unresolved_terminations WHERE tenant_id = $1 AND intent = 'cable'`); n != 0 {
		t.Fatalf("%d parked row(s) left after the resolver applied them", n)
	}
}

// A declared, active cable that LLDP contradicts raises topology/cable_drift on
// the observing asset, with both ends in evidence; it resolves when the
// network agrees again, and when the cable is changed.
func TestIntegration_LLDP_ContradictionRaisesDriftThenResolves(t *testing.T) {
	f := newLLDPFix(t)
	a1, a3 := f.ingest(t, sw1), f.ingest(t, sw3)
	a2 := f.ingest(t, sw2)
	eth1, gi01 := f.iface(t, a2, "Ethernet1/1"), f.iface(t, a3, "GigabitEthernet0/1")
	declared, err := f.cables.Create(ifaceActorCtx(), f.tenant, lldpJSON(t, map[string]any{
		"a_terminations": []any{map[string]any{"termination_kind": "interface", "termination_id": eth1}},
		"b_terminations": []any{map[string]any{"termination_kind": "interface", "termination_id": gi01}},
		"type":           "cat6",
	}))
	if err != nil {
		t.Fatal(err)
	}
	cableID := uuid.MustParse(fmt.Sprint(lldpDecode(t, declared)["id"]))

	drift := func() (state string, evidence map[string]any) {
		t.Helper()
		var ev []byte
		err := f.raw.QueryRow(`SELECT detection_state, evidence FROM findings
			WHERE tenant_id = $1 AND producer = 'topology' AND kind = 'cable_drift' AND subject_type = 'asset' AND subject_id = $2`,
			f.tenant, a2).Scan(&state, &ev)
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(ev, &evidence)
		return state, evidence
	}

	// LLDP on Ethernet1/1 names sw1's Gi1/0/1, not sw3's Gi0/1.
	f.ingest(t, with(sw2, lldp("Ethernet1/1", sw1.mac, "Gi1/0/1", "lldp-sw-1")))
	state, ev := drift()
	if state != "ACTIVE" {
		t.Fatalf("drift finding state = %q, want ACTIVE", state)
	}
	cs, _ := ev["contradictions"].([]any)
	if len(cs) != 1 {
		t.Fatalf("evidence = %v, want one contradicted port", ev)
	}
	c0, _ := cs[0].(map[string]any)
	observed, _ := c0["observed"].(map[string]any)
	cableFar, _ := c0["cable_far"].([]any)
	if c0["local_interface"] != "Ethernet1/1" || c0["cable_id"] != cableID.String() ||
		observed["asset_id"] != a1.String() || len(cableFar) != 1 || cableFar[0].(map[string]any)["interface_id"] != gi01.String() {
		t.Fatalf("evidence does not carry both ends: %v", c0)
	}
	if n := f.count(t, `SELECT count(*) FROM cables WHERE tenant_id = $1`); n != 1 {
		t.Fatalf("a contradicted port got a proposed cable too (%d cables)", n)
	}

	// The network agrees again → resolved, and the declared cable is confirmed.
	f.ingest(t, with(sw2, lldp("Ethernet1/1", sw3.mac, "Gi0/1", "lldp-sw-3")))
	if state, _ := drift(); state != "INACTIVE" {
		t.Fatalf("after agreement the drift finding is %q, want INACTIVE", state)
	}
	if c := f.cablesOn(t, eth1)[0]; !c.confirmed.Valid || c.observations < 1 {
		t.Fatalf("the declared cable was not confirmed: %+v", c)
	}

	// Contradicted again, then the cable is edited → resolved by the change.
	f.ingest(t, with(sw2, lldp("Ethernet1/1", sw1.mac, "Gi1/0/1", "lldp-sw-1")))
	if state, _ := drift(); state != "ACTIVE" {
		t.Fatalf("re-contradiction: state %q, want ACTIVE", state)
	}
	if _, err := f.cables.Update(ifaceActorCtx(), f.tenant, cableID, lldpJSON(t, map[string]any{"label": "re-patched"})); err != nil {
		t.Fatal(err)
	}
	if state, _ := drift(); state != "INACTIVE" {
		t.Fatalf("after the cable changed the drift finding is %q, want INACTIVE", state)
	}
}

// Approving a proposal makes it active (approved_at stamped) and computes the
// path end to end; a second approve is refused; rejecting a proposal keeps
// its ports and suppresses re-proposal.
func TestIntegration_LLDP_ApproveActivatesAndComputesPaths(t *testing.T) {
	f := newLLDPFix(t)
	a1 := f.ingest(t, sw1)
	a2 := f.ingest(t, with(sw2,
		lldp("Ethernet1/1", sw1.mac, "Gi1/0/1", "lldp-sw-1"),
		lldp("Ethernet1/2", sw1.mac, "Gi1/0/2", "lldp-sw-1")))
	eth1, eth2 := f.iface(t, a2, "Ethernet1/1"), f.iface(t, a2, "Ethernet1/2")
	gi1 := f.iface(t, a1, "GigabitEthernet1/0/1")
	approve, reject := f.cablesOn(t, eth1)[0].id, f.cablesOn(t, eth2)[0].id

	ctx := ifaceActorCtx()
	if _, err := f.cables.Approve(ctx, f.tenant, approve); err != nil {
		t.Fatalf("approve: %v", err)
	}
	var status string
	var approvedAt sql.NullTime
	if err := f.raw.QueryRow(`SELECT status, approved_at FROM cables WHERE id = $1`, approve).Scan(&status, &approvedAt); err != nil {
		t.Fatal(err)
	}
	if status != "active" || !approvedAt.Valid {
		t.Fatalf("approved cable: status %q approved_at %v", status, approvedAt)
	}
	var dest uuid.NullUUID
	var complete bool
	if err := f.raw.QueryRow(`SELECT destination_id, is_complete FROM cable_paths WHERE tenant_id = $1 AND origin_kind = 'interface' AND origin_id = $2`,
		f.tenant, eth1).Scan(&dest, &complete); err != nil {
		t.Fatalf("no path for the approved cable's origin: %v", err)
	}
	if !complete || dest.UUID != gi1 {
		t.Fatalf("path after approval: complete=%v destination=%v, want complete to Gi1/0/1", complete, dest)
	}
	if _, err := f.cables.Approve(ctx, f.tenant, approve); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("approving an active cable: %v, want a conflict", err)
	}

	if _, err := f.cables.Reject(ctx, f.tenant, reject); err != nil {
		t.Fatalf("reject: %v", err)
	}
	f.ingest(t, with(sw2, lldp("Ethernet1/2", sw1.mac, "Gi1/0/2", "lldp-sw-1")))
	got := f.cablesOn(t, eth2)
	if len(got) != 1 || got[0].id != reject || got[0].status != "rejected" {
		t.Fatalf("after re-observing a rejected pairing: %+v, want the one rejected cable", got)
	}
}

// RLS: the intake on the app role finds far ends in the tenant's own
// inventory only, and its rows are invisible to another tenant.
func TestIntegration_LLDP_TenantIsolation(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	ifaces := NewInterfaceService(app)
	intake := NewCableIntake(app, NewCableService(app))

	mac := "00:00:5e:33:00:99"
	assetA := ifaceSeedAsset(t, owner, tenantA, "monitoring")
	assetB := ifaceSeedAsset(t, owner, tenantB, "monitoring")
	localA, err := ifaces.Create(ctx, tenantA, uuid.Nil, InterfaceInput{AssetID: assetA, Name: "Ethernet1/1", Type: "1000base-t"})
	if err != nil {
		t.Fatal(err)
	}
	// Tenant B owns the device the neighbour names.
	if _, err := ifaces.Create(ctx, tenantB, uuid.Nil, InterfaceInput{AssetID: assetB, Name: "GigabitEthernet1/0/1", Type: "1000base-t", MACAddress: ifaceStrp(mac)}); err != nil {
		t.Fatal(err)
	}
	res, err := intake.RecordNeighbors(context.Background(), tenantA, assetA,
		[]identity.ObservedNeighbor{lldp("Ethernet1/1", mac, "Gi1/0/1", "other-tenant-sw")},
		identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:test"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposed != 0 || res.Parked != 1 {
		t.Fatalf("tenant A's neighbour matched across tenants: %+v, want parked", res)
	}
	var visibleToB int
	if err := database.WithTenantTx(context.Background(), &database.DB{DB: sqlx.NewDb(app, "postgres")}, tenantB, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM unresolved_terminations WHERE origin_id = $1`, localA.ID).Scan(&visibleToB)
	}); err != nil {
		t.Fatal(err)
	}
	if visibleToB != 0 {
		t.Fatalf("tenant B sees tenant A's parked neighbour (%d rows)", visibleToB)
	}
}

func lldpDecode(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func lldpJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
