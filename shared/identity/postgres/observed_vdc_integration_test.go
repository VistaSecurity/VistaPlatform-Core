package postgres_test

// DCIM gap 1, part 2: a sighting's virtual device contexts, through the REAL
// identity path — Intake builds the observation, the Engine resolves it, the
// networkWriter records the contexts and each interface's membership on the
// engine's transaction — against a real Postgres.
//
// Mutations (each red, then restored green):
//   - "declared wins": drop the `cur.sourceKind == measured` condition in
//     refreshContext → the declared context's identifier is overwritten;
//   - drop the `measured[u]` arm in contextMemberships (every other
//     membership is kept) → eth2 stays in vsys2 after moving to vsys1;
//     make it drop every other membership → the person's link to mgmt goes;
//   - drop the `c.sourceKind != measured` skip in staleContexts → the
//     declared mgmt context goes stale;
//   - drop the `!c.lastSeen.Before(cutoff)` window → vsys2 goes stale on the
//     next day's sighting;
//   - drop the identifierFree check in refreshContext → the transaction fails
//     on virtual_device_contexts_identifier_uniq;
//   - drop the w.virtualDeviceContexts call from RecordObservedNetwork → no
//     rows at all.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

type vdcRow struct {
	name, identifier, sourceKind, status, description string
	observations                                      int
	members                                           []string
}

func (r vdcRow) String() string {
	return fmt.Sprintf("%s id=%s %s/%s obs=%d desc=%q members=%v", r.name, r.identifier, r.sourceKind, r.status, r.observations, r.description, r.members)
}

func readVDCs(t *testing.T, db *sql.DB, tenant, asset string) map[string]vdcRow {
	t.Helper()
	rows, err := db.Query(`
		SELECT c.name, coalesce(c.identifier::text, ''), c.source_kind, c.status, coalesce(c.description, ''), c.observation_count,
		       ARRAY(SELECT i.name FROM public.interface_virtual_device_contexts j
		              JOIN public.interfaces i ON i.tenant_id = j.tenant_id AND i.id = j.interface_id
		             WHERE j.tenant_id = c.tenant_id AND j.virtual_device_context_id = c.id ORDER BY i.name)
		  FROM public.virtual_device_contexts c WHERE c.tenant_id = $1 AND c.asset_id = $2`, tenant, asset)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]vdcRow{}
	for rows.Next() {
		var r vdcRow
		if err := rows.Scan(&r.name, &r.identifier, &r.sourceKind, &r.status, &r.description, &r.observations, pq.Array(&r.members)); err != nil {
			t.Fatal(err)
		}
		sort.Strings(r.members)
		out[r.name] = r
	}
	return out
}

func TestIntegration_Identity_VirtualDeviceContexts(t *testing.T) {
	h := newIfaceHarness(t)
	h.at = time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	firewall := func(ifcs []identity.ObservedInterface, ctxs ...identity.ObservedVirtualDeviceContext) identity.Sighting {
		return identity.Sighting{
			TenantID: h.tenant, Channel: identity.ChannelAuthenticatedSession, ObservedAt: h.at,
			Source:                identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:vdc-it", Mode: identity.ModeActive},
			Identifiers:           []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "VDC-IT-0001"}},
			Interfaces:            ifcs,
			VirtualDeviceContexts: ctxs,
		}
	}
	id := func(v int) *int { return &v }
	ifc := func(name, ctx string) identity.ObservedInterface {
		return identity.ObservedInterface{Name: name, VirtualDeviceContext: ctx}
	}

	// 1. Two contexts, three interfaces.
	first := h.resolve(firewall([]identity.ObservedInterface{ifc("eth1", "vsys1"), ifc("eth2", "vsys2"), ifc("eth3", "vsys2")},
		identity.ObservedVirtualDeviceContext{Name: "vsys1", Identifier: id(1)}, identity.ObservedVirtualDeviceContext{Name: "vsys2", Identifier: id(2)}))
	if first.Asset.Zero() {
		t.Fatalf("resolved to no asset (%s)", first.Outcome)
	}
	asset := first.Asset.ID
	var assetStatus string
	if err := h.db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2`, h.tenant, asset).Scan(&assetStatus); err != nil {
		t.Fatal(err)
	}
	follows := "pending"
	if assetStatus == identity.StatusMonitoring {
		follows = "active"
	}
	got := readVDCs(t, h.db, h.tenant, asset)
	want := map[string]string{
		"vsys1": vdcRow{name: "vsys1", identifier: "1", sourceKind: "measured", status: follows, observations: 1, members: []string{"eth1"}}.String(),
		"vsys2": vdcRow{name: "vsys2", identifier: "2", sourceKind: "measured", status: follows, observations: 1, members: []string{"eth2", "eth3"}}.String(),
	}
	checkVDCs(t, "first sighting", got, want)
	var created int
	if err := h.db.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'virtual_device_context' AND action = 'create'`,
		h.tenant).Scan(&created); err != nil || created != 2 {
		t.Errorf("%d context creates recorded (%v), want 2", created, err)
	}

	// The asset is approved; a person declares two contexts of their own and
	// puts eth1 in one and eth3 in the other.
	if _, err := h.db.Exec(`UPDATE assets SET asset_status = $3 WHERE tenant_id = $1 AND id = $2`, h.tenant, asset, identity.StatusMonitoring); err != nil {
		t.Fatal(err)
	}
	declare := func(name string, identifier int, description string) uuid.UUID {
		var cid uuid.UUID
		// Declared at the time of the first sighting (the column defaults to
		// the wall clock, which this test's observation times precede).
		if err := h.db.QueryRow(`INSERT INTO virtual_device_contexts (tenant_id, asset_id, name, identifier, description, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id`, h.tenant, asset, name, identifier, description, h.at).Scan(&cid); err != nil {
			t.Fatal(err)
		}
		return cid
	}
	join := func(iface string, cid uuid.UUID) {
		if _, err := h.db.Exec(`INSERT INTO interface_virtual_device_contexts (tenant_id, interface_id, virtual_device_context_id)
			SELECT tenant_id, id, $3 FROM interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = $4`, h.tenant, asset, cid, iface); err != nil {
			t.Fatal(err)
		}
	}
	mgmt := declare("mgmt", 9, "a person's")
	vsys3 := declare("vsys3", 3, "declared by hand")
	join("eth1", mgmt)
	join("eth3", vsys3)

	// 2. A month later the device reports vsys1 (now also owning eth2) and
	// vsys3 under a different identifier; vsys2 is gone.
	h.at = h.at.AddDate(0, 0, 31)
	h.resolve(firewall([]identity.ObservedInterface{ifc("eth1", "vsys1"), ifc("eth2", "vsys1"), ifc("eth3", "vsys3")},
		identity.ObservedVirtualDeviceContext{Name: "vsys1", Identifier: id(1)}, identity.ObservedVirtualDeviceContext{Name: "vsys3", Identifier: id(33)}))
	got = readVDCs(t, h.db, h.tenant, asset)
	want = map[string]string{
		// Promoted with its approved asset; gained eth2.
		"vsys1": vdcRow{name: "vsys1", identifier: "1", sourceKind: "measured", status: "active", observations: 2, members: []string{"eth1", "eth2"}}.String(),
		// Unseen past the window: stale, not deleted; the interfaces it lost
		// left it (eth2 moved, eth3 named a declared context instead).
		"vsys2": vdcRow{name: "vsys2", identifier: "2", sourceKind: "measured", status: "stale", observations: 1}.String(),
		// The person's context: matched, never overwritten — identifier 3
		// stays, only the sighting counter moves.
		"vsys3": vdcRow{name: "vsys3", identifier: "3", sourceKind: "declared", status: "active", observations: 1, description: "declared by hand", members: []string{"eth3"}}.String(),
		// Not reported, but declared: never stale; the person's membership of
		// eth1 survives the device naming vsys1 for it.
		"mgmt": vdcRow{name: "mgmt", identifier: "9", sourceKind: "declared", status: "active", description: "a person's", members: []string{"eth1"}}.String(),
	}
	checkVDCs(t, "a month later", got, want)

	// 3. The next day vsys2 is back, claiming identifier 3 — the declared
	// vsys3's. It returns from stale and keeps its own identifier (the claim
	// is skipped, not a failed transaction).
	h.at = h.at.AddDate(0, 0, 1)
	h.resolve(firewall([]identity.ObservedInterface{ifc("eth2", "vsys2")},
		identity.ObservedVirtualDeviceContext{Name: "vsys2", Identifier: id(3)}))
	got = readVDCs(t, h.db, h.tenant, asset)
	want["vsys2"] = vdcRow{name: "vsys2", identifier: "2", sourceKind: "measured", status: "active", observations: 2, members: []string{"eth2"}}.String()
	// eth2 left vsys1 (measured) for vsys2; vsys1, seen yesterday, is inside
	// the window and stays active.
	want["vsys1"] = vdcRow{name: "vsys1", identifier: "1", sourceKind: "measured", status: "active", observations: 2, members: []string{"eth1"}}.String()
	checkVDCs(t, "the next day", got, want)
}

func checkVDCs(t *testing.T, when string, got map[string]vdcRow, want map[string]string) {
	t.Helper()
	var gotNames, wantNames []string
	for n := range got {
		gotNames = append(gotNames, n)
	}
	for n := range want {
		wantNames = append(wantNames, n)
	}
	sort.Strings(gotNames)
	sort.Strings(wantNames)
	if strings.Join(gotNames, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("%s: contexts %v, want %v", when, gotNames, wantNames)
	}
	for _, n := range wantNames {
		if g := got[n].String(); g != want[n] {
			t.Errorf("%s:\n got  %s\n want %s", when, g, want[n])
		}
	}
}
