package services

// Physical cabling on the map against a real Postgres (DCIM BUILD_PLAN row
// 3.6). Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// mapCableFixture: a switch cabled to a server through two patch panels, and
// to a second server over a direct cable that is still a proposal. The switch
// has an LLDP-observed relationship to each server; only the first names its
// ports.
type mapCableFixture struct {
	*cableFix
	sw, srv, srv2, pa, pb uuid.UUID
	gi1, gi2, eth0, eth1  uuid.UUID
	direct                uuid.UUID
}

func newMapCableFixture(t *testing.T) *mapCableFixture {
	t.Helper()
	f := &mapCableFixture{cableFix: newCableFix(t)}
	f.sw, f.srv, f.srv2, f.pa, f.pb = f.asset(t), f.asset(t), f.asset(t), f.asset(t), f.asset(t)
	f.gi1 = f.iface(t, f.sw, "GigabitEthernet1/0/1", "1000base-t")
	f.gi2 = f.iface(t, f.sw, "GigabitEthernet1/0/2", "1000base-t")
	f.eth0 = f.iface(t, f.srv, "eth0", "1000base-t")
	f.eth1 = f.iface(t, f.srv2, "eth1", "1000base-t")
	fa, ra := f.panel(t, f.pa)
	fb, rb := f.panel(t, f.pb)
	f.cable(t, term(dcim.ObjectKindInterface, f.gi1), term(dcim.ObjectKindFrontPort, fa))
	f.cable(t, term(dcim.ObjectKindRearPort, ra), term(dcim.ObjectKindRearPort, rb))
	f.cable(t, term(dcim.ObjectKindFrontPort, fb), term(dcim.ObjectKindInterface, f.eth0))
	f.direct = f.cable(t, term(dcim.ObjectKindInterface, f.gi2), term(dcim.ObjectKindInterface, f.eth1))
	if _, err := f.owner.Exec(`UPDATE cables SET status = 'pending' WHERE id = $1`, f.direct); err != nil {
		t.Fatal(err)
	}
	f.edge(t, f.sw, f.srv, `{"discovery_protocol":"lldp","local_port":"GigabitEthernet1/0/1","remote_port":"eth0"}`)
	f.edge(t, f.sw, f.srv2, `{"discovery_protocol":"lldp"}`)
	return f
}

func (f *mapCableFixture) edge(t *testing.T, from, to uuid.UUID, attrs string) {
	t.Helper()
	if _, err := f.owner.Exec(`
		INSERT INTO asset_relationships (tenant_id, from_asset_id, to_asset_id, type, source_kind, status, attributes)
		VALUES ($1, $2, $3, 'connects_to', 'measured', 'active', $4::jsonb)`, f.tenant, from, to, attrs); err != nil {
		t.Fatalf("edge: %v", err)
	}
}

func (f *mapCableFixture) db() *database.DB { return &database.DB{DB: sqlx.NewDb(f.app, "postgres")} }

// The neighbourhood's logical edges carry the interfaces their observation
// names, and its cable runs are listed once per pair with their shape and
// lifecycle.
//
// Mutations: drop the resolveEdgeInterfaces call from Neighbourhood → the
// LLDP edge has no from_interface_id, red. Drop the neighbourhoodCablePaths
// call → no cable paths, red. Drop the `c.status == pending` branch → the
// proposed cable reads active, red.
func TestIntegration_Neighbourhood_CablePathsAndEdgeInterfaces(t *testing.T) {
	f := newMapCableFixture(t)
	nbh, err := NewRelationshipService(f.db()).Neighbourhood(f.ctx, f.tenant, f.sw, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	var named, bare *RelationshipEdge
	for i := range nbh.Edges {
		switch nbh.Edges[i].ToAssetID {
		case f.srv:
			named = &nbh.Edges[i]
		case f.srv2:
			bare = &nbh.Edges[i]
		}
	}
	if named == nil || bare == nil {
		t.Fatalf("edges: %+v", nbh.Edges)
	}
	if named.FromInterfaceID == nil || *named.FromInterfaceID != f.gi1 || named.FromInterfaceName != "GigabitEthernet1/0/1" {
		t.Fatalf("LLDP edge from interface = %v %q, want Gi1", named.FromInterfaceID, named.FromInterfaceName)
	}
	if named.ToInterfaceID == nil || *named.ToInterfaceID != f.eth0 {
		t.Fatalf("LLDP edge to interface = %v, want eth0", named.ToInterfaceID)
	}
	if bare.FromInterfaceID != nil || bare.ToInterfaceID != nil {
		t.Fatalf("an edge naming no port got interfaces %v / %v", bare.FromInterfaceID, bare.ToInterfaceID)
	}

	if len(nbh.CablePaths) != 2 || nbh.TotalCablePaths != 2 {
		t.Fatalf("cable paths = %d (total %d), want 2 (one per pair of interfaces, not per direction): %+v", len(nbh.CablePaths), nbh.TotalCablePaths, nbh.CablePaths)
	}
	byPeer := map[uuid.UUID]NeighbourhoodCablePath{}
	for _, p := range nbh.CablePaths {
		peer := p.ToAssetID
		if peer == f.sw {
			peer = p.FromAssetID
		}
		byPeer[peer] = p
	}
	patched, ok := byPeer[f.srv]
	if !ok {
		t.Fatalf("no run to the patched server: %+v", nbh.CablePaths)
	}
	if patched.CableCount != 3 || patched.PatchPanelCount != 2 || patched.CircuitCount != 0 || patched.Status != EdgeStatusActive || patched.OperationalStatus != "connected" {
		t.Fatalf("patched run = %+v, want 3 cables through 2 patch panels, active, connected", patched)
	}
	forward := patched.FromInterfaceID == f.gi1 && patched.ToInterfaceID == f.eth0
	backward := patched.FromInterfaceID == f.eth0 && patched.ToInterfaceID == f.gi1
	if !forward && !backward {
		t.Fatalf("patched run interfaces %s -> %s", patched.FromInterfaceID, patched.ToInterfaceID)
	}
	proposed, ok := byPeer[f.srv2]
	if !ok || proposed.Status != EdgeStatusPending || proposed.CableID != f.direct || proposed.CableCount != 1 || proposed.PatchPanelCount != 0 {
		t.Fatalf("proposed run = %+v (found %v), want pending over the direct cable", proposed, ok)
	}

	// The patch panels are not graph nodes, and a run between assets the walk
	// did not reach is not drawn: around the second server alone (depth 1)
	// only its own run appears.
	alone, err := NewRelationshipService(f.db()).Neighbourhood(f.ctx, f.tenant, f.srv2, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(alone.CablePaths) != 1 || alone.CablePaths[0].CableID != f.direct {
		t.Fatalf("around srv2: %+v", alone.CablePaths)
	}

	// Another tenant sees none of it.
	other := newCableFix(t)
	nb2, err := NewRelationshipService(&database.DB{DB: sqlx.NewDb(other.app, "postgres")}).Neighbourhood(f.ctx, other.tenant, f.sw, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(nb2.CablePaths) != 0 || len(nb2.Edges) != 0 {
		t.Fatalf("another tenant sees %d runs, %d edges", len(nb2.CablePaths), len(nb2.Edges))
	}
}

// The topology aggregates cable runs per unordered prefix pair, counting the
// proposed ones separately; a run inside one prefix is not a cross-prefix
// summary.
//
// Mutation: drop the topologyCablePaths call from GetTopology → red.
func TestIntegration_Topology_CablePaths(t *testing.T) {
	f := newMapCableFixture(t)
	db := f.db()
	ownerDB := &database.DB{DB: sqlx.NewDb(f.owner, "postgres")}
	p1 := seedPrefix(t, ownerDB, f.tenant, "core", "10.0.0.0/24")
	p2 := seedPrefix(t, ownerDB, f.tenant, "servers", "10.0.1.0/24")
	for asset, prefix := range map[uuid.UUID]uuid.UUID{f.sw: p1, f.srv: p2, f.srv2: p2} {
		if _, err := f.owner.Exec(`UPDATE assets SET prefix_id = $1 WHERE id = $2`, prefix, asset); err != nil {
			t.Fatal(err)
		}
	}
	tp, err := (&AssetService{db: db}).GetTopology(f.ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(tp.CablePaths) != 1 || tp.TotalCablePaths != 1 {
		t.Fatalf("topology cable paths = %+v, want one prefix pair", tp.CablePaths)
	}
	got := tp.CablePaths[0]
	if got.Count != 2 || got.PendingCount != 1 || got.FromPrefixName != "10.0.0.0/24" || got.ToPrefixName != "10.0.1.0/24" {
		t.Fatalf("pair = %+v, want 10.0.0.0/24 <-> 10.0.1.0/24, 2 runs, 1 pending", got)
	}

	if _, err := f.owner.Exec(`UPDATE assets SET prefix_id = $1 WHERE id = ANY($2)`, p1, "{"+f.srv.String()+","+f.srv2.String()+"}"); err != nil {
		t.Fatal(err)
	}
	tp, err = (&AssetService{db: db}).GetTopology(f.ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(tp.CablePaths) != 0 {
		t.Fatalf("same-prefix runs reported as cross-prefix: %+v", tp.CablePaths)
	}
}
