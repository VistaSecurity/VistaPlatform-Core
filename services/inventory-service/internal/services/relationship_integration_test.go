package services

// The relationship surface against a real Postgres — ADR-0003.
//
// These are the tests that matter for this workstream. Every endpoint here is a
// recursive CTE or a multi-statement transaction, and neither shape can be
// checked by a unit test: a cycle that never terminates, a cap that does not
// cap, a walk that goes the wrong way, and an RLS policy that is not actually
// the boundary all look identical from outside the database.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// relFixture is a service over a fresh schema plus one tenant.
func relFixture(t *testing.T) (*RelationshipService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	return NewRelationshipService(db), db, tenant
}

// seedRelAsset writes one monitored asset with one identifier.
func seedRelAsset(t *testing.T, db *database.DB, tenant uuid.UUID, name, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path,
		                    asset_status, risk_score, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,$3,'server','hardware.computer.server',$4,10,NOW(),NOW(),NOW(),NOW())`,
		id, tenant, name, status); err != nil {
		t.Fatalf("insert asset %s: %v", name, err)
	}
	if _, err := db.Exec(`
		INSERT INTO asset_identifiers (id, tenant_id, asset_id, kind, value, source_kind, confidence,
		                               first_seen_at, last_seen_at, created_at, updated_at)
		VALUES ($1,$2,$3,'fqdn',$4,'measured',1,NOW(),NOW(),NOW(),NOW())`,
		uuid.New(), tenant, id, name); err != nil {
		t.Fatalf("insert identifier for %s: %v", name, err)
	}
	return id
}

// seedEdge writes one edge directly, bypassing the service, so a test can set
// up a provenance and status the API would not produce.
func seedEdge(t *testing.T, db *database.DB, tenant, from, to uuid.UUID, edgeType relationships.Type, sourceKind, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO asset_relationships (id, tenant_id, from_asset_id, to_asset_id, type,
		                                 source_kind, source_ref, confidence, status, attributes,
		                                 first_seen_at, last_seen_at, observation_count, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,'test',1,$7,'{}'::jsonb,NOW(),NOW(),1,NOW(),NOW())`,
		id, tenant, from, to, string(edgeType), sourceKind, status); err != nil {
		t.Fatalf("insert edge %s: %v", edgeType, err)
	}
	return id
}

func seedRelReviewer(t *testing.T, db *database.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO users (id, tenant_id, email, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, true, NOW(), NOW())`,
		id, tenant, "rel-reviewer-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// TestIntegration_Relationships_BothDirections: one row, read from both ends,
// with the direction and the reverse LABEL stamped per reader.
//
// The label is the half that is easy to get wrong. An edge is stored once
// (ADR-0003 D1), so the app's page and the server's page are reading the SAME
// row — and it has to read "runs_on" on one and "runs" on the other. A single
// stored label would make one of those two pages say the opposite of the truth.
func TestIntegration_Relationships_BothDirections(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	app := seedRelAsset(t, db, tenant, "app-01.example.test", "monitoring")
	server := seedRelAsset(t, db, tenant, "server-01.example.test", "monitoring")
	seedEdge(t, db, tenant, app, server, relationships.RunsOn, SourceKindMeasured, EdgeStatusActive)

	t.Run("from the app the edge is outbound", func(t *testing.T) {
		edges, total, err := svc.ListForAsset(ctx, tenant, app, RelationshipListOptions{})
		if err != nil {
			t.Fatalf("ListForAsset: %v", err)
		}
		if total != 1 || len(edges) != 1 {
			t.Fatalf("total=%d rows=%d, want 1/1", total, len(edges))
		}
		e := edges[0]
		if e.Direction != DirectionOut {
			t.Errorf("direction = %q, want out", e.Direction)
		}
		if e.Label != string(relationships.RunsOn) {
			t.Errorf("label = %q, want runs_on", e.Label)
		}
		if e.Peer == nil || e.Peer.AssetID != server {
			t.Fatalf("peer must be the server, got %+v", e.Peer)
		}
		if e.Peer.DisplayName != "server-01.example.test" {
			t.Errorf("peer display name = %q; a peer rendered as a bare uuid is undecidable", e.Peer.DisplayName)
		}
		if e.Peer.PrimaryIdentifier != "fqdn:server-01.example.test" {
			t.Errorf("peer identifier = %q, want the strongest identifier", e.Peer.PrimaryIdentifier)
		}
	})

	t.Run("from the server the SAME row is inbound and reads reversed", func(t *testing.T) {
		edges, total, err := svc.ListForAsset(ctx, tenant, server, RelationshipListOptions{})
		if err != nil {
			t.Fatalf("ListForAsset: %v", err)
		}
		if total != 1 || len(edges) != 1 {
			t.Fatalf("total=%d rows=%d, want 1/1", total, len(edges))
		}
		e := edges[0]
		if e.Direction != DirectionIn {
			t.Errorf("direction = %q, want in", e.Direction)
		}
		if e.Label != "runs" {
			t.Errorf("label = %q, want the reverse label 'runs'", e.Label)
		}
		if e.Peer == nil || e.Peer.AssetID != app {
			t.Fatalf("peer must be the app, got %+v", e.Peer)
		}
	})

	t.Run("direction filters select one side", func(t *testing.T) {
		out, _, err := svc.ListForAsset(ctx, tenant, app, RelationshipListOptions{Direction: DirectionOut})
		if err != nil {
			t.Fatalf("out: %v", err)
		}
		in, _, err := svc.ListForAsset(ctx, tenant, app, RelationshipListOptions{Direction: DirectionIn})
		if err != nil {
			t.Fatalf("in: %v", err)
		}
		if len(out) != 1 || len(in) != 0 {
			t.Errorf("from the app: out=%d in=%d, want 1/0", len(out), len(in))
		}
	})

	t.Run("a rejected edge is not on the tab by default", func(t *testing.T) {
		other := seedRelAsset(t, db, tenant, "rejected-peer.example.test", "monitoring")
		seedEdge(t, db, tenant, app, other, relationships.DependsOn, SourceKindInferred, EdgeStatusRejected)

		edges, total, err := svc.ListForAsset(ctx, tenant, app, RelationshipListOptions{})
		if err != nil {
			t.Fatalf("ListForAsset: %v", err)
		}
		if total != 1 || len(edges) != 1 {
			t.Fatalf("a rejected edge must not reappear on the tab: total=%d rows=%d", total, len(edges))
		}
		// …but it is still reachable when explicitly asked for, because
		// "somebody rejected this" is a real thing to be able to look up.
		rejected, rejectedTotal, err := svc.ListForAsset(ctx, tenant, app, RelationshipListOptions{Status: EdgeStatusRejected})
		if err != nil {
			t.Fatalf("ListForAsset(rejected): %v", err)
		}
		if rejectedTotal != 1 || len(rejected) != 1 {
			t.Errorf("status=rejected must return it: total=%d rows=%d", rejectedTotal, len(rejected))
		}
	})
}

// TestIntegration_Relationships_RLSIsolation drives the reads as the
// UNPRIVILEGED app role, which is the only way the RLS policy is actually the
// thing under test.
//
// As the owner (or any BYPASSRLS role) every policy in the database is inert
// and a missing `tenant_id` predicate passes silently — which is exactly how a
// cross-tenant read ships. testdb.ConnectAsAppRole is the harness for this.
func TestIntegration_Relationships_RLSIsolation(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	ownerDB := &database.DB{DB: sqlx.NewDb(owner, "postgres")}
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)

	aFrom := seedRelAsset(t, ownerDB, tenantA, "a-from.example.test", "monitoring")
	aTo := seedRelAsset(t, ownerDB, tenantA, "a-to.example.test", "monitoring")
	seedEdge(t, ownerDB, tenantA, aFrom, aTo, relationships.DependsOn, SourceKindMeasured, EdgeStatusActive)

	bFrom := seedRelAsset(t, ownerDB, tenantB, "b-from.example.test", "monitoring")
	bTo := seedRelAsset(t, ownerDB, tenantB, "b-to.example.test", "monitoring")
	seedEdge(t, ownerDB, tenantB, bFrom, bTo, relationships.DependsOn, SourceKindMeasured, EdgeStatusActive)

	appRole := testdb.ConnectAsAppRole(t, owner)
	svc := NewRelationshipService(&database.DB{DB: sqlx.NewDb(appRole, "postgres")})
	ctx := context.Background()

	t.Run("tenant A sees its own edge", func(t *testing.T) {
		edges, total, err := svc.ListForAsset(ctx, tenantA, aFrom, RelationshipListOptions{})
		if err != nil {
			t.Fatalf("ListForAsset: %v", err)
		}
		if total != 1 || len(edges) != 1 {
			t.Fatalf("tenant A must see its own edge: total=%d rows=%d", total, len(edges))
		}
	})

	t.Run("tenant A asking about tenant B's asset gets nothing", func(t *testing.T) {
		edges, total, err := svc.ListForAsset(ctx, tenantA, bFrom, RelationshipListOptions{})
		if err != nil {
			t.Fatalf("ListForAsset: %v", err)
		}
		if total != 0 || len(edges) != 0 {
			t.Fatalf("CROSS-TENANT LEAK: tenant A read %d of tenant B's edges", len(edges))
		}
	})

	t.Run("the neighbourhood does not cross the boundary either", func(t *testing.T) {
		g, err := svc.Neighbourhood(ctx, tenantA, bFrom, 3, true)
		if err != nil {
			t.Fatalf("Neighbourhood: %v", err)
		}
		// The root itself is not tenant A's, so it does not survive the `live`
		// join: the graph comes back empty rather than with a foreign node in it.
		for _, n := range g.Nodes {
			if n.AssetID == bFrom || n.AssetID == bTo {
				t.Fatalf("CROSS-TENANT LEAK: tenant A's neighbourhood contains tenant B's asset %s", n.AssetID)
			}
		}
		if len(g.Edges) != 0 {
			t.Fatalf("CROSS-TENANT LEAK: %d of tenant B's edges in tenant A's graph", len(g.Edges))
		}
	})

	t.Run("declaring an edge to ANOTHER tenant's asset is a peer-not-found", func(t *testing.T) {
		// Not a 500, and above all not an edge. `bTo` exists — it is simply not
		// tenant A's, and the only honest answer to "relate my asset to that
		// one" is that there is no such asset here. A leak in the other
		// direction would let one tenant WRITE a row naming another's asset,
		// which the composite FK would then anchor.
		_, err := svc.Declare(ctx, tenantA, aFrom, uuid.New(), DeclaredEdgeInput{
			Type: string(relationships.DependsOn), PeerAssetID: bTo,
		})
		if !errors.Is(err, ErrRelationshipPeerNotFound) {
			t.Fatalf("error = %v, want ErrRelationshipPeerNotFound", err)
		}
		var n int
		if err := owner.QueryRow(
			`SELECT count(*) FROM asset_relationships WHERE from_asset_id = $1 AND to_asset_id = $2`,
			aFrom, bTo).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 0 {
			t.Fatalf("CROSS-TENANT LEAK: %d edge(s) written from tenant A's asset to tenant B's", n)
		}
	})

	t.Run("the proposal queue is per tenant", func(t *testing.T) {
		seedEdge(t, ownerDB, tenantB, bTo, bFrom, relationships.Manages, SourceKindInferred, EdgeStatusPending)
		proposals, total, err := svc.ListProposals(ctx, tenantA, 0, 0)
		if err != nil {
			t.Fatalf("ListProposals: %v", err)
		}
		if total != 0 || len(proposals) != 0 {
			t.Fatalf("CROSS-TENANT LEAK: tenant A sees %d of tenant B's proposals", len(proposals))
		}
	})
}

// TestIntegration_Impact_CycleSafe is the cycle guard.
//
// Three assets in a ring, each depending on the next. A traversal without a
// depth bound never returns, so this hanging IS the assertion for termination:
// the depth bound is the only thing that stops the walk, because the recursion
// dedupes on `(asset_id, depth)` and every lap around a cycle is a new pair.
//
// What it does NOT see is how the recursion itself deduplicates. The `reached`
// CTE groups by `asset_id` a second time, so the RESULT below is identical
// whether the recursion says `UNION` or `UNION ALL` — measured, not assumed:
// the `UNION ALL` mutant passes this test unchanged while the working table
// goes exponential on any graph with several routes between two nodes
// (QUERY_LANGUAGE A7 measured 340 rows for 16 nodes). That property is pinned
// by TestRelationshipWalksDeduplicateAndBoundDepth instead, which reads the SQL.
func TestIntegration_Impact_CycleSafe(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	a := seedRelAsset(t, db, tenant, "ring-a.example.test", "monitoring")
	b := seedRelAsset(t, db, tenant, "ring-b.example.test", "monitoring")
	c := seedRelAsset(t, db, tenant, "ring-c.example.test", "monitoring")
	seedEdge(t, db, tenant, a, b, relationships.DependsOn, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, b, c, relationships.DependsOn, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, c, a, relationships.DependsOn, SourceKindMeasured, EdgeStatusActive)

	// If the walk does not terminate this call hangs and the test times out,
	// which is the failure mode being guarded.
	res, err := svc.Impact(ctx, tenant, a, ImpactDownstream, MaxImpactDepth)
	if err != nil {
		t.Fatalf("Impact: %v", err)
	}
	// Two other nodes in the ring. The ROOT is excluded from its own closure
	// even though the cycle reaches it — "a change to A affects A" is true and
	// useless, and reporting it would make every cyclic graph's impact count
	// one too many.
	if res.Total != 2 {
		t.Fatalf("impact total = %d, want 2 (the ring's other two nodes, root excluded); nodes=%+v", res.Total, res.Nodes)
	}
	for _, n := range res.Nodes {
		if n.AssetID == a {
			t.Errorf("the root must be excluded from its own impact closure")
		}
		if n.Depth < 1 || n.Depth > 2 {
			t.Errorf("node %s at depth %d; a 3-ring places the others at 1 and 2", n.AssetID, n.Depth)
		}
	}
	if len(res.Nodes) != 2 {
		t.Errorf("a node reachable by several routes must appear ONCE, got %d rows for 2 nodes", len(res.Nodes))
	}
	_ = b
	_ = c
}

// TestIntegration_Impact_DirectionAndVocabulary pins the two things about the
// impact walk that are easy to get backwards.
func TestIntegration_Impact_DirectionAndVocabulary(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	// app runs_on vm, vm hosted_on hypervisor. Canonical direction points from
	// the dependent to the thing it rests on.
	app := seedRelAsset(t, db, tenant, "imp-app.example.test", "monitoring")
	vm := seedRelAsset(t, db, tenant, "imp-vm.example.test", "monitoring")
	hyp := seedRelAsset(t, db, tenant, "imp-hyp.example.test", "monitoring")
	seedEdge(t, db, tenant, app, vm, relationships.RunsOn, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, vm, hyp, relationships.HostedOn, SourceKindMeasured, EdgeStatusActive)

	t.Run("downstream from the hypervisor reaches the vm then the app", func(t *testing.T) {
		res, err := svc.Impact(ctx, tenant, hyp, ImpactDownstream, DefaultImpactDepth)
		if err != nil {
			t.Fatalf("Impact: %v", err)
		}
		if res.Total != 2 {
			t.Fatalf("total = %d, want 2 — taking the hypervisor down takes the vm and the app with it", res.Total)
		}
		depth := map[uuid.UUID]int{}
		for _, n := range res.Nodes {
			depth[n.AssetID] = n.Depth
		}
		if depth[vm] != 1 {
			t.Errorf("vm at depth %d, want 1", depth[vm])
		}
		if depth[app] != 2 {
			t.Errorf("app at depth %d, want 2", depth[app])
		}
		if len(res.CountsByDepth) != 2 {
			t.Errorf("counts_by_depth = %+v, want one entry per occupied depth", res.CountsByDepth)
		}
	})

	t.Run("upstream from the app reaches what it rests on", func(t *testing.T) {
		res, err := svc.Impact(ctx, tenant, app, ImpactUpstream, DefaultImpactDepth)
		if err != nil {
			t.Fatalf("Impact: %v", err)
		}
		if res.Total != 2 {
			t.Fatalf("total = %d, want 2 (the vm and the hypervisor)", res.Total)
		}
	})

	t.Run("connects_to is NOT impact-bearing", func(t *testing.T) {
		// A flow is not a dependency. If `connects_to` were walked, the closure
		// of almost any asset would be the whole tenant, because every external
		// connection upserts one.
		chatty := seedRelAsset(t, db, tenant, "imp-chatty.example.test", "monitoring")
		seedEdge(t, db, tenant, chatty, hyp, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusActive)

		res, err := svc.Impact(ctx, tenant, hyp, ImpactDownstream, DefaultImpactDepth)
		if err != nil {
			t.Fatalf("Impact: %v", err)
		}
		for _, n := range res.Nodes {
			if n.AssetID == chatty {
				t.Fatalf("a connects_to peer must not appear in the impact closure")
			}
		}
		if res.Total != 2 {
			t.Errorf("total = %d, want 2 — the connects_to edge must not widen it", res.Total)
		}
		if len(res.Types) != 9 {
			t.Errorf("the echoed vocabulary is %d types, want the 9 impact-bearing ones: %v", len(res.Types), res.Types)
		}
	})

	t.Run("a pending edge does not carry impact", func(t *testing.T) {
		// Impact walks ACTIVE edges only. A belief nobody has agreed to must
		// not appear in a blast-radius answer someone plans a change around.
		ghost := seedRelAsset(t, db, tenant, "imp-ghost.example.test", "monitoring")
		seedEdge(t, db, tenant, ghost, hyp, relationships.RunsOn, SourceKindInferred, EdgeStatusPending)

		res, err := svc.Impact(ctx, tenant, hyp, ImpactDownstream, DefaultImpactDepth)
		if err != nil {
			t.Fatalf("Impact: %v", err)
		}
		for _, n := range res.Nodes {
			if n.AssetID == ghost {
				t.Fatalf("a PENDING edge must not contribute to the impact closure")
			}
		}
	})
}

// TestIntegration_Neighbourhood_DepthAndPending walks out N hops and pins the
// pending opt-in.
func TestIntegration_Neighbourhood_DepthAndPending(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	root := seedRelAsset(t, db, tenant, "nb-root.example.test", "monitoring")
	one := seedRelAsset(t, db, tenant, "nb-one.example.test", "monitoring")
	two := seedRelAsset(t, db, tenant, "nb-two.example.test", "monitoring")
	three := seedRelAsset(t, db, tenant, "nb-three.example.test", "monitoring")
	seedEdge(t, db, tenant, root, one, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, one, two, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, two, three, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusActive)

	t.Run("depth 1 stops at the first hop", func(t *testing.T) {
		g, err := svc.Neighbourhood(ctx, tenant, root, 1, false)
		if err != nil {
			t.Fatalf("Neighbourhood: %v", err)
		}
		if g.TotalNodes != 2 {
			t.Fatalf("depth 1 = root + 1 neighbour = 2 nodes, got %d", g.TotalNodes)
		}
		if len(g.Edges) != 1 {
			t.Errorf("edges = %d, want 1", len(g.Edges))
		}
	})

	t.Run("depth 2 reaches two hops and marks the root", func(t *testing.T) {
		g, err := svc.Neighbourhood(ctx, tenant, root, 2, false)
		if err != nil {
			t.Fatalf("Neighbourhood: %v", err)
		}
		if g.TotalNodes != 3 {
			t.Fatalf("depth 2 = 3 nodes, got %d", g.TotalNodes)
		}
		roots := 0
		byID := map[uuid.UUID]int{}
		for _, n := range g.Nodes {
			byID[n.AssetID] = n.Depth
			if n.IsRoot {
				roots++
			}
		}
		if roots != 1 {
			t.Errorf("exactly one node is the root, got %d", roots)
		}
		if byID[root] != 0 || byID[one] != 1 || byID[two] != 2 {
			t.Errorf("depths wrong: root=%d one=%d two=%d", byID[root], byID[one], byID[two])
		}
		if _, reached := byID[three]; reached {
			t.Errorf("depth 2 must not reach the third hop")
		}
	})

	t.Run("pending edges are opt-in", func(t *testing.T) {
		pendingPeer := seedRelAsset(t, db, tenant, "nb-pending.example.test", "monitoring")
		seedEdge(t, db, tenant, root, pendingPeer, relationships.DependsOn, SourceKindInferred, EdgeStatusPending)

		closed, err := svc.Neighbourhood(ctx, tenant, root, 1, false)
		if err != nil {
			t.Fatalf("Neighbourhood: %v", err)
		}
		for _, n := range closed.Nodes {
			if n.AssetID == pendingPeer {
				t.Fatalf("a pending edge must not be drawn unless asked for")
			}
		}

		open, err := svc.Neighbourhood(ctx, tenant, root, 1, true)
		if err != nil {
			t.Fatalf("Neighbourhood(include_pending): %v", err)
		}
		found := false
		for _, n := range open.Nodes {
			if n.AssetID == pendingPeer {
				found = true
			}
		}
		if !found {
			t.Errorf("include_pending=true must draw the pending peer")
		}
	})
}

// TestIntegration_Neighbourhood_CapIsReported is the cap's mutation guard.
//
// A cap that silently shortens is worse than no cap: the map looks complete and
// the node somebody was looking for is simply absent. This seeds past the EDGE
// cap and asserts the flag and the honest totals, not just the shorter list.
func TestIntegration_Neighbourhood_CapIsReported(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	root := seedRelAsset(t, db, tenant, "cap-root.example.test", "monitoring")
	// Two peers with many typed edges between them would need the whole
	// vocabulary; instead fan out past the node cap, which caps the edge set too.
	const peers = NeighbourhoodNodeCap + 25
	for i := 0; i < peers; i++ {
		p := seedRelAsset(t, db, tenant, "cap-peer-"+uuid.New().String()[:8]+".example.test", "monitoring")
		seedEdge(t, db, tenant, root, p, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusActive)
	}

	g, err := svc.Neighbourhood(ctx, tenant, root, 1, false)
	if err != nil {
		t.Fatalf("Neighbourhood: %v", err)
	}
	if !g.Truncated {
		t.Fatalf("truncated must be true past the cap; got nodes=%d total=%d", len(g.Nodes), g.TotalNodes)
	}
	if len(g.Nodes) != NeighbourhoodNodeCap {
		t.Errorf("returned %d nodes, want exactly the cap %d", len(g.Nodes), NeighbourhoodNodeCap)
	}
	// The honest total, not the capped length. This is the assertion the cap
	// exists for: a caller must be able to see how much it is NOT being shown.
	if g.TotalNodes != peers+1 {
		t.Errorf("total_nodes = %d, want the real %d — a capped answer must still report the true size", g.TotalNodes, peers+1)
	}
	if g.NodeCap != NeighbourhoodNodeCap || g.EdgeCap != NeighbourhoodEdgeCap {
		t.Errorf("the caps must be echoed: node=%d edge=%d", g.NodeCap, g.EdgeCap)
	}
}

// TestIntegration_Relationships_DeclareAndDelete covers the write path and the
// declared-only delete rule.
func TestIntegration_Relationships_DeclareAndDelete(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()
	actor := seedRelReviewer(t, db, tenant)

	app := seedRelAsset(t, db, tenant, "decl-app.example.test", "monitoring")
	server := seedRelAsset(t, db, tenant, "decl-server.example.test", "monitoring")
	waiting := seedRelAsset(t, db, tenant, "decl-pending.example.test", "pending_approval")

	t.Run("declared between two monitored assets is active at once", func(t *testing.T) {
		e, err := svc.Declare(ctx, tenant, app, actor, DeclaredEdgeInput{
			Type: string(relationships.RunsOn), PeerAssetID: server,
		})
		if err != nil {
			t.Fatalf("Declare: %v", err)
		}
		if e.Status != EdgeStatusActive {
			t.Errorf("status = %q; a user with assets.update asserting an edge is the same as editing an attribute (ADR-0003 D3)", e.Status)
		}
		if e.SourceKind != SourceKindDeclared {
			t.Errorf("source_kind = %q, want declared", e.SourceKind)
		}
		if e.FromAssetID != app || e.ToAssetID != server {
			t.Errorf("canonical direction wrong: %s -> %s", e.FromAssetID, e.ToAssetID)
		}
		if e.ApprovedAt == nil {
			t.Errorf("an edge that entered active must carry approved_at")
		}
	})

	t.Run("history records the declaration on the from asset", func(t *testing.T) {
		var n int
		if err := db.QueryRow(`
			SELECT count(*) FROM asset_history
			 WHERE tenant_id=$1 AND asset_id=$2 AND action='edge_added'
			   AND changes_json->>'kind' = 'relationship'`, tenant, app).Scan(&n); err != nil {
			t.Fatalf("read history: %v", err)
		}
		if n != 1 {
			t.Errorf("edge_added rows on the from asset = %d, want 1", n)
		}
	})

	t.Run("direction=in flips the canonical ends", func(t *testing.T) {
		e, err := svc.Declare(ctx, tenant, server, actor, DeclaredEdgeInput{
			Type: string(relationships.Manages), PeerAssetID: app, Direction: DirectionIn,
		})
		if err != nil {
			t.Fatalf("Declare(in): %v", err)
		}
		if e.FromAssetID != app || e.ToAssetID != server {
			t.Errorf("direction=in must store app -> server, got %s -> %s", e.FromAssetID, e.ToAssetID)
		}
	})

	t.Run("declared against a pending end enters pending", func(t *testing.T) {
		e, err := svc.Declare(ctx, tenant, app, actor, DeclaredEdgeInput{
			Type: string(relationships.DependsOn), PeerAssetID: waiting,
		})
		if err != nil {
			t.Fatalf("Declare: %v", err)
		}
		if e.Status != EdgeStatusPending {
			t.Errorf("status = %q, want pending — an edge is active only when BOTH ends are monitored", e.Status)
		}
	})

	t.Run("the same triple twice is a conflict, not a second row", func(t *testing.T) {
		_, err := svc.Declare(ctx, tenant, app, actor, DeclaredEdgeInput{
			Type: string(relationships.RunsOn), PeerAssetID: server,
		})
		if err == nil {
			t.Fatalf("a duplicate (from, to, type) must be refused")
		}
		if !errors.Is(err, ErrRelationshipExists) {
			t.Errorf("error = %v, want ErrRelationshipExists", err)
		}
	})

	t.Run("a self-edge is refused", func(t *testing.T) {
		_, err := svc.Declare(ctx, tenant, app, actor, DeclaredEdgeInput{
			Type: string(relationships.DependsOn), PeerAssetID: app,
		})
		if !errors.Is(err, ErrRelationshipSelfEdge) {
			t.Errorf("error = %v, want ErrRelationshipSelfEdge", err)
		}
	})

	t.Run("an unknown peer is refused", func(t *testing.T) {
		_, err := svc.Declare(ctx, tenant, app, actor, DeclaredEdgeInput{
			Type: string(relationships.DependsOn), PeerAssetID: uuid.New(),
		})
		if !errors.Is(err, ErrRelationshipPeerNotFound) {
			t.Errorf("error = %v, want ErrRelationshipPeerNotFound", err)
		}
	})

	t.Run("a declared edge deletes; a measured one does not", func(t *testing.T) {
		declared, err := svc.Declare(ctx, tenant, app, actor, DeclaredEdgeInput{
			Type: string(relationships.SendsDataTo), PeerAssetID: server,
		})
		if err != nil {
			t.Fatalf("Declare: %v", err)
		}
		if err := svc.Delete(ctx, tenant, app, declared.ID, actor); err != nil {
			t.Fatalf("Delete(declared): %v", err)
		}

		measured := seedEdge(t, db, tenant, app, server, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusActive)
		err = svc.Delete(ctx, tenant, app, measured, actor)
		if !errors.Is(err, ErrRelationshipNotDeclared) {
			t.Fatalf("deleting a MEASURED edge must be refused, got %v", err)
		}
		// And it is still there — a refusal that deleted anyway would be the
		// worst of both answers.
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND id=$2`,
			tenant, measured).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 1 {
			t.Errorf("the refused delete removed the row anyway")
		}
	})
}

// TestIntegration_RelationshipProposals_AcceptRejectAndHistory covers the
// Approvals half: which pending edges are proposals, the decision, the actor,
// and the history.
func TestIntegration_RelationshipProposals_AcceptRejectAndHistory(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()
	actor := seedRelReviewer(t, db, tenant)

	live1 := seedRelAsset(t, db, tenant, "prop-live-1.example.test", "monitoring")
	live2 := seedRelAsset(t, db, tenant, "prop-live-2.example.test", "monitoring")
	live3 := seedRelAsset(t, db, tenant, "prop-live-3.example.test", "monitoring")
	waiting := seedRelAsset(t, db, tenant, "prop-waiting.example.test", "pending_approval")

	// A reviewable proposal: inferred, both ends monitored.
	reviewable := seedEdge(t, db, tenant, live1, live2, relationships.DependsOn, SourceKindInferred, EdgeStatusPending)
	// NOT a proposal: an end is still pending its own approval, so approving
	// the ASSET resolves this edge. Listing it here would ask the same question
	// twice and let a reviewer answer it two ways.
	seedEdge(t, db, tenant, live1, waiting, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusPending)
	// NOT a proposal: already active.
	seedEdge(t, db, tenant, live2, live3, relationships.RunsOn, SourceKindMeasured, EdgeStatusActive)

	t.Run("only the stuck pending edge is a proposal", func(t *testing.T) {
		proposals, total, err := svc.ListProposals(ctx, tenant, 0, 0)
		if err != nil {
			t.Fatalf("ListProposals: %v", err)
		}
		if total != 1 || len(proposals) != 1 {
			t.Fatalf("total=%d rows=%d, want 1/1; got %+v", total, len(proposals), proposals)
		}
		p := proposals[0]
		if p.ID != reviewable {
			t.Fatalf("wrong proposal: %s", p.ID)
		}
		// Both ends decorated — the reviewer is on Approvals with no asset page
		// around them, and "<something> depends on <something>" is not a
		// reviewable sentence.
		if p.From == nil || p.To == nil {
			t.Fatalf("a proposal must decorate BOTH ends: from=%v to=%v", p.From, p.To)
		}
		if p.From.DisplayName == "" || p.To.DisplayName == "" {
			t.Errorf("both ends need a readable name: %q / %q", p.From.DisplayName, p.To.DisplayName)
		}
	})

	t.Run("accept activates, stamps the actor, and writes history", func(t *testing.T) {
		e, err := svc.Decide(ctx, tenant, reviewable, actor, true)
		if err != nil {
			t.Fatalf("Decide(accept): %v", err)
		}
		if e.Status != EdgeStatusActive {
			t.Errorf("status = %q, want active", e.Status)
		}
		if e.ApprovedBy == nil || *e.ApprovedBy != actor {
			t.Errorf("approved_by = %v, want the reviewer %s", e.ApprovedBy, actor)
		}
		if e.ApprovedAt == nil {
			t.Errorf("approved_at must be stamped")
		}
		var n int
		if err := db.QueryRow(`
			SELECT count(*) FROM asset_history
			 WHERE tenant_id=$1 AND asset_id=$2 AND action='edge_accepted' AND actor_user_id=$3`,
			tenant, live1, actor).Scan(&n); err != nil {
			t.Fatalf("read history: %v", err)
		}
		if n != 1 {
			t.Errorf("edge_accepted history rows = %d, want 1", n)
		}
	})

	t.Run("deciding it twice is a conflict, not a silent re-decision", func(t *testing.T) {
		_, err := svc.Decide(ctx, tenant, reviewable, actor, false)
		if !errors.Is(err, ErrRelationshipDecided) {
			t.Fatalf("a second decision must be refused, got %v", err)
		}
	})

	t.Run("reject records the decision and keeps the row", func(t *testing.T) {
		toReject := seedEdge(t, db, tenant, live2, live1, relationships.Manages, SourceKindInferred, EdgeStatusPending)
		e, err := svc.Decide(ctx, tenant, toReject, actor, false)
		if err != nil {
			t.Fatalf("Decide(reject): %v", err)
		}
		if e.Status != EdgeStatusRejected {
			t.Errorf("status = %q, want rejected", e.Status)
		}
		// The row survives. A rejection is a decision somebody made, and
		// deleting it would let the same inference be proposed again tomorrow
		// with nothing recording that it was already answered.
		var status string
		if err := db.QueryRow(`SELECT status FROM asset_relationships WHERE tenant_id=$1 AND id=$2`,
			tenant, toReject).Scan(&status); err != nil {
			t.Fatalf("the rejected row must survive: %v", err)
		}
		if status != EdgeStatusRejected {
			t.Errorf("stored status = %q", status)
		}
		var n int
		if err := db.QueryRow(`
			SELECT count(*) FROM asset_history
			 WHERE tenant_id=$1 AND asset_id=$2 AND action='edge_rejected' AND actor_user_id=$3`,
			tenant, live2, actor).Scan(&n); err != nil {
			t.Fatalf("read history: %v", err)
		}
		if n != 1 {
			t.Errorf("edge_rejected history rows = %d, want 1", n)
		}
	})

	t.Run("an unknown edge is 404, not a silent success", func(t *testing.T) {
		_, err := svc.Decide(ctx, tenant, uuid.New(), actor, true)
		if !errors.Is(err, ErrRelationshipNotFound) {
			t.Errorf("error = %v, want ErrRelationshipNotFound", err)
		}
	})
}

// TestIntegration_Decide_RefusesToActivateAgainstAPendingEnd.
//
// ADR-0003 D1: "An edge whose either endpoint is pending is itself pending."
// `Decide` used to check only that the edge was pending, so accepting one whose
// end was still awaiting approval produced an `active` relationship to an asset
// nobody had admitted — and the impact closure walks active edges, so that
// asset then turned up in a blast-radius answer someone plans a change around.
//
// It was reachable: the proposal QUEUE filters to "both ends monitored", but
// the asset page's Relationships tab lists the same edge from the pending
// asset's own side and offers Accept there, because the only end the list
// endpoint decorates is the monitored peer.
//
// Mutation check: delete the `if accept { ... assetStatuses ... }` block in
// Decide and the first subtest fails with the edge active.
func TestIntegration_Decide_RefusesToActivateAgainstAPendingEnd(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()
	actor := seedRelReviewer(t, db, tenant)

	live := seedRelAsset(t, db, tenant, "decide-live.example.test", "monitoring")
	waiting := seedRelAsset(t, db, tenant, "decide-waiting.example.test", "pending_approval")
	edgeID := seedEdge(t, db, tenant, waiting, live, relationships.DependsOn, SourceKindInferred, EdgeStatusPending)

	status := func(id uuid.UUID) string {
		t.Helper()
		var st string
		if err := db.QueryRow(`SELECT status FROM asset_relationships WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&st); err != nil {
			t.Fatalf("read edge status: %v", err)
		}
		return st
	}

	t.Run("accept is refused while an end is pending, and changes nothing", func(t *testing.T) {
		_, err := svc.Decide(ctx, tenant, edgeID, actor, true)
		if !errors.Is(err, ErrRelationshipEndPending) {
			t.Fatalf("error = %v, want ErrRelationshipEndPending", err)
		}
		if got := status(edgeID); got != EdgeStatusPending {
			t.Fatalf("edge is %q after a refused accept, want pending — a refusal that wrote anyway "+
				"is the worst of both answers", got)
		}
	})

	t.Run("the refusal names the asset to go and approve", func(t *testing.T) {
		_, err := svc.Decide(ctx, tenant, edgeID, actor, true)
		if err == nil || !strings.Contains(err.Error(), waiting.String()) {
			t.Fatalf("error = %v, want it to name the pending asset %s", err, waiting)
		}
	})

	t.Run("REJECT is allowed whatever the ends are doing", func(t *testing.T) {
		// "This claim is wrong" is answerable regardless, and refusing it would
		// leave the edge with no way out of the queue.
		rejected := seedEdge(t, db, tenant, waiting, live, relationships.Manages, SourceKindInferred, EdgeStatusPending)
		if _, err := svc.Decide(ctx, tenant, rejected, actor, false); err != nil {
			t.Fatalf("Decide(reject): %v", err)
		}
		if got := status(rejected); got != EdgeStatusRejected {
			t.Fatalf("edge is %q, want rejected", got)
		}
	})

	t.Run("once the end is approved the same accept works", func(t *testing.T) {
		assets := &AssetService{db: db}
		if err := assets.ApproveAssets(tenant, []uuid.UUID{waiting}, actor); err != nil {
			t.Fatalf("ApproveAssets: %v", err)
		}
		// The inferred edge is still pending (promotion excludes inferred), so
		// this is the SAME decision, now legitimately available.
		out, err := svc.Decide(ctx, tenant, edgeID, actor, true)
		if err != nil {
			t.Fatalf("Decide(accept) after approval: %v", err)
		}
		if out.Status != EdgeStatusActive {
			t.Fatalf("edge is %q, want active", out.Status)
		}
	})
}

// TestIntegration_InferredEdge_SurvivesAssetApproval is the regression guard on
// the promotion rule.
//
// `promoteEdgesForApprovedAssets` activates the pending edges of a
// newly approved asset. It used to activate INFERRED ones too, which made the
// relationship-proposal queue nearly unreachable: an inference drawn while an
// end was pending became a fact the moment that asset was accepted, with nobody
// ever asked. ADR-0003 D3 says an inferred edge "appears in Approvals as a
// relationship proposal" — this is the test that it does.
//
// Mutation check: drop `AND r.source_kind <> 'inferred'` from the UPDATE in
// asset_service.go and the first subtest fails.
func TestIntegration_InferredEdge_SurvivesAssetApproval(t *testing.T) {
	svc, db, tenant := relFixture(t)
	assets := &AssetService{db: db}
	ctx := context.Background()
	actor := seedRelReviewer(t, db, tenant)

	live := seedRelAsset(t, db, tenant, "promo-live.example.test", "monitoring")
	waiting := seedRelAsset(t, db, tenant, "promo-waiting.example.test", "pending_approval")

	inferred := seedEdge(t, db, tenant, waiting, live, relationships.DependsOn, SourceKindInferred, EdgeStatusPending)
	measured := seedEdge(t, db, tenant, waiting, live, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusPending)
	// The other two provenances the exclusion must NOT catch. Without them the
	// predicate could be narrowed to `source_kind = 'measured'` and every test
	// here would stay green while an imported CMDB edge sat pending forever in
	// a queue whose own predicate (both ends monitored) never lists it.
	declared := seedEdge(t, db, tenant, waiting, live, relationships.Manages, SourceKindDeclared, EdgeStatusPending)
	imported := seedEdge(t, db, tenant, waiting, live, relationships.MemberOf, SourceKindImported, EdgeStatusPending)

	if err := assets.ApproveAssets(tenant, []uuid.UUID{waiting}, actor); err != nil {
		t.Fatalf("ApproveAssets: %v", err)
	}

	status := func(id uuid.UUID) string {
		t.Helper()
		var s string
		if err := db.QueryRow(`SELECT status FROM asset_relationships WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&s); err != nil {
			t.Fatalf("read edge status: %v", err)
		}
		return s
	}

	t.Run("the inferred edge stays pending and becomes a proposal", func(t *testing.T) {
		if got := status(inferred); got != EdgeStatusPending {
			t.Fatalf("inferred edge is %q after the asset was approved, want pending — "+
				"approving an asset approves what was OBSERVED about it, not what was inferred", got)
		}
		proposals, total, err := svc.ListProposals(ctx, tenant, 0, 0)
		if err != nil {
			t.Fatalf("ListProposals: %v", err)
		}
		if total != 1 || len(proposals) != 1 || proposals[0].ID != inferred {
			t.Fatalf("the inferred edge must now be a reviewable proposal: total=%d rows=%d", total, len(proposals))
		}
	})

	t.Run("the measured edge is promoted, as it always was", func(t *testing.T) {
		if got := status(measured); got != EdgeStatusActive {
			t.Fatalf("measured edge is %q, want active — approving the asset approves the observation", got)
		}
	})

	t.Run("declared and imported are promoted too", func(t *testing.T) {
		// ADR-0003 D3 grants promotion to everything that is a record rather
		// than a belief: an observation, a user's assertion, a system of
		// record. Only `inferred` is carved out.
		for name, id := range map[string]uuid.UUID{"declared": declared, "imported": imported} {
			if got := status(id); got != EdgeStatusActive {
				t.Errorf("%s edge is %q, want active — only `inferred` waits for a person", name, got)
			}
		}
	})
}

// TestIntegration_Impact_PerTypeDirection is ADR-0003 D5's amendment
// as a test, and it is the regression guard for the bug the
// amendment was written for.
//
// D5 originally said "the downstream closure over [eight types], reversed" —
// one uniform rule. Six of the types point from the dependent to the thing it
// rests on, so reverse is right for them. `contains` and `manages` point the
// other way, and walking those in reverse inverted them: a demonstration on
// PG17 against the shipped CTE returned NOTHING for "what breaks if this
// wireless controller dies" and returned the controller for "what breaks if
// this access point dies". That is the ops persona's headline question
// (ADR-0006: "a switch is being replaced Friday; what is behind it?") answered
// backwards, for exactly the class of asset the question is usually about.
//
// Each subtest below is one of those demonstrations, turned into an assertion.
//
// Mutation check: set `Contains` or `Manages` to ImpactReverse in
// shared/relationships and the matching subtest fails with "(nothing)".
func TestIntegration_Impact_PerTypeDirection(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	// The two container/manager shapes, and one dependent shape for contrast.
	controller := seedRelAsset(t, db, tenant, "dir-wlc.example.test", "monitoring")
	ap := seedRelAsset(t, db, tenant, "dir-ap.example.test", "monitoring")
	vnet := seedRelAsset(t, db, tenant, "dir-vnet.example.test", "monitoring")
	subnet := seedRelAsset(t, db, tenant, "dir-subnet.example.test", "monitoring")
	cluster := seedRelAsset(t, db, tenant, "dir-cluster.example.test", "monitoring")
	node := seedRelAsset(t, db, tenant, "dir-node.example.test", "monitoring")

	// Canonical directions straight out of the ADR-0003 D2 table.
	seedEdge(t, db, tenant, controller, ap, relationships.Manages, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, vnet, subnet, relationships.Contains, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, node, cluster, relationships.MemberOf, SourceKindMeasured, EdgeStatusActive)

	reached := func(t *testing.T, root uuid.UUID, direction string) map[uuid.UUID]int {
		t.Helper()
		res, err := svc.Impact(ctx, tenant, root, direction, DefaultImpactDepth)
		if err != nil {
			t.Fatalf("Impact(%s): %v", direction, err)
		}
		out := map[uuid.UUID]int{}
		for _, n := range res.Nodes {
			out[n.AssetID] = n.Depth
		}
		return out
	}

	t.Run("manages walks FORWARD: the controller's blast radius is its access points", func(t *testing.T) {
		got := reached(t, controller, ImpactDownstream)
		if _, ok := got[ap]; !ok {
			t.Fatalf("downstream(controller) = %v, want the access point — a controller whose "+
				"blast radius is empty is this endpoint answering the ops question backwards", got)
		}
		if len(got) != 1 {
			t.Errorf("downstream(controller) reached %d assets, want exactly the access point", len(got))
		}
		// And the mirror: the AP rests on the controller, not the other way.
		if _, ok := reached(t, ap, ImpactDownstream)[controller]; ok {
			t.Error("downstream(access point) must NOT contain the controller — the controller " +
				"does not stop working when an access point does")
		}
		if _, ok := reached(t, ap, ImpactUpstream)[controller]; !ok {
			t.Error("upstream(access point) must contain the controller it depends on")
		}
	})

	t.Run("contains walks FORWARD: the network's blast radius is its subnets", func(t *testing.T) {
		got := reached(t, vnet, ImpactDownstream)
		if _, ok := got[subnet]; !ok {
			t.Fatalf("downstream(virtual network) = %v, want the subnet", got)
		}
		if _, ok := reached(t, subnet, ImpactDownstream)[vnet]; ok {
			t.Error("downstream(subnet) must NOT contain the virtual network that contains it")
		}
	})

	t.Run("member_of still walks REVERSE, unchanged", func(t *testing.T) {
		// The contrast case. The amendment changes two types; a fix that
		// flipped all of them would break this one and nothing else would say so.
		if _, ok := reached(t, cluster, ImpactDownstream)[node]; !ok {
			t.Error("downstream(cluster) must contain its member node — member_of points " +
				"member → group, so this one IS walked in reverse")
		}
		if _, ok := reached(t, node, ImpactDownstream)[cluster]; ok {
			t.Error("downstream(node) must not contain the cluster it is a member of")
		}
	})
}

// TestIntegration_Impact_UpstreamIsTheExactMirror.
//
// The property the two questions are defined by: Y is in downstream(X) iff X is
// in upstream(Y). It is asserted over a graph that mixes both walk directions
// AND the terminal type, because that is where a mirror breaks — a hand-written
// second spelling of the walk drifts one type at a time and each drift looks
// like a plausible answer on its own.
func TestIntegration_Impact_UpstreamIsTheExactMirror(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	app := seedRelAsset(t, db, tenant, "mir-app.example.test", "monitoring")
	vm := seedRelAsset(t, db, tenant, "mir-vm.example.test", "monitoring")
	hv := seedRelAsset(t, db, tenant, "mir-hv.example.test", "monitoring")
	ctrl := seedRelAsset(t, db, tenant, "mir-ctrl.example.test", "monitoring")
	svc2 := seedRelAsset(t, db, tenant, "mir-service.example.test", "monitoring")

	seedEdge(t, db, tenant, app, vm, relationships.RunsOn, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, vm, hv, relationships.HostedOn, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, ctrl, vm, relationships.Manages, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, app, svc2, relationships.Impacts, SourceKindDeclared, EdgeStatusActive)

	all := []uuid.UUID{app, vm, hv, ctrl, svc2}
	closure := func(root uuid.UUID, direction string) map[uuid.UUID]bool {
		res, err := svc.Impact(ctx, tenant, root, direction, MaxImpactDepth)
		if err != nil {
			t.Fatalf("Impact(%s): %v", direction, err)
		}
		out := map[uuid.UUID]bool{}
		for _, n := range res.Nodes {
			out[n.AssetID] = true
		}
		return out
	}

	down := map[uuid.UUID]map[uuid.UUID]bool{}
	up := map[uuid.UUID]map[uuid.UUID]bool{}
	for _, id := range all {
		down[id] = closure(id, ImpactDownstream)
		up[id] = closure(id, ImpactUpstream)
	}
	for _, x := range all {
		for _, y := range all {
			if x == y {
				continue
			}
			if down[x][y] != up[y][x] {
				t.Errorf("mirror broken: %s in downstream(%s) = %v, but %s in upstream(%s) = %v",
					y, x, down[x][y], x, y, up[y][x])
			}
		}
	}
}

// TestIntegration_Impact_DeclaredImpactsIsWalkedOnce.
//
// ADR-0003 D5 originally excluded `impacts` entirely on the grounds that the
// traversal DERIVES it, so walking it would read the cache back into the
// computation that fills it. That reasoning holds for a derived edge and not for
// one a USER declared: D2 lists `impacts` as declared as well as derived, and a
// tenant saying "this database backs payroll" is an assertion, not a cached
// result. It is crossed ONCE — the business service is where a blast-radius
// sentence ends, and continuing through it turns a specific answer into a vague
// one.
//
// Mutation check: remove `impacts` from the registry's direction map and the
// first subtest fails; remove it from the terminal set and the second does.
func TestIntegration_Impact_DeclaredImpactsIsWalkedOnce(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	database := seedRelAsset(t, db, tenant, "imp-db.example.test", "monitoring")
	payroll := seedRelAsset(t, db, tenant, "imp-payroll.example.test", "monitoring")
	// Something hanging off the far side of the business service, which the
	// terminal rule must NOT reach.
	beyond := seedRelAsset(t, db, tenant, "imp-beyond.example.test", "monitoring")

	seedEdge(t, db, tenant, database, payroll, relationships.Impacts, SourceKindDeclared, EdgeStatusActive)
	seedEdge(t, db, tenant, payroll, beyond, relationships.Contains, SourceKindDeclared, EdgeStatusActive)

	t.Run("the declared business service is in the blast radius", func(t *testing.T) {
		res, err := svc.Impact(ctx, tenant, database, ImpactDownstream, DefaultImpactDepth)
		if err != nil {
			t.Fatalf("Impact: %v", err)
		}
		found := false
		for _, n := range res.Nodes {
			if n.AssetID == payroll {
				found = true
			}
		}
		if !found {
			t.Fatalf("downstream(database) = %+v, want the payroll service it was DECLARED to impact", res.Nodes)
		}
	})

	t.Run("and the walk stops there", func(t *testing.T) {
		res, err := svc.Impact(ctx, tenant, database, ImpactDownstream, DefaultImpactDepth)
		if err != nil {
			t.Fatalf("Impact: %v", err)
		}
		for _, n := range res.Nodes {
			if n.AssetID == beyond {
				t.Fatalf("the walk continued THROUGH the business service to %s; `impacts` is "+
					"crossed once, or a blast-radius answer becomes everything the service touches", beyond)
			}
		}
	})

	t.Run("the vocabulary echoed is the nine impact-bearing types", func(t *testing.T) {
		res, err := svc.Impact(ctx, tenant, database, ImpactDownstream, DefaultImpactDepth)
		if err != nil {
			t.Fatalf("Impact: %v", err)
		}
		if len(res.Types) != 9 {
			t.Errorf("echoed %d types, want the 9 impact-bearing ones: %v", len(res.Types), res.Types)
		}
		for _, typ := range res.Types {
			if typ == string(relationships.ConnectsTo) {
				t.Error("connects_to must not be in the impact vocabulary")
			}
		}
	})
}
