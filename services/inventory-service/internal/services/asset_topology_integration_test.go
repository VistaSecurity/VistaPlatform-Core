package services

// The tenant-wide topology against a real Postgres (ADR-0006 D4 second half,
// workstream 3.8).
//
// The assertions that matter are the ones about what is NOT dropped. A grouping
// query is easy to write so that the interesting rows fall out of it — an INNER
// JOIN to `prefixes` instead of a LEFT one, `<>` instead of
// `IS DISTINCT FROM` — and every such mistake produces a tidy, plausible,
// WRONG diagram that nothing on screen contradicts. So each test seeds the
// awkward row first and asserts it is there.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newTopologyFixture(t *testing.T) (*AssetService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return &AssetService{db: db}, db, testdb.NewTenant(t, raw)
}

// seedPrefix writes one prefix and returns its id.
func seedPrefix(t *testing.T, db *database.DB, tenant uuid.UUID, name, cidr string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO prefixes (id, tenant_id, description, prefix, environment, source_kind, status)
		VALUES ($1, $2, $3, $4::cidr, 'production', 'declared', 'active')`, id, tenant, name, cidr); err != nil {
		t.Fatalf("insert prefix %s: %v", name, err)
	}
	return id
}

// seedTopologyAsset writes one asset with an optional site and prefix.
func seedTopologyAsset(
	t *testing.T, db *database.DB, tenant uuid.UUID,
	hostname, classKey, classPath string, site *string, prefix *uuid.UUID,
) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var siteID any
	if site != nil {
		siteID = testdb.EnsureSite(t, db, tenant, *site)
	}
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path,
		                    asset_status, site_id, prefix_id,
		                    last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,$3,$4,$5,'monitoring',$6,$7,NOW(),NOW(),NOW(),NOW())`,
		id, tenant, hostname, classKey, classPath, siteID, prefix); err != nil {
		t.Fatalf("insert asset %s: %v", hostname, err)
	}
	return id
}

func siteNamed(t *testing.T, tp *Topology, name string) TopologySite {
	t.Helper()
	for _, s := range tp.Sites {
		if s.Site == name {
			return s
		}
	}
	t.Fatalf("no site %q in %d sites", name, len(tp.Sites))
	return TopologySite{}
}

func prefixNamed(t *testing.T, site TopologySite, name string) TopologyPrefix {
	t.Helper()
	for _, s := range site.Prefixes {
		if s.PrefixName == name {
			return s
		}
	}
	t.Fatalf("no prefix %q under site %q", name, site.Site)
	return TopologyPrefix{}
}

// The headline: an asset with no site and no prefix is IN the tree, under
// explicit nodes, and the independent total proves the tree did not lose it.
//
// On a fresh inventory almost every asset is in that state. A topology that
// dropped them would draw the curated minority and read as complete, which is
// the failure this endpoint exists to not commit.
func TestIntegration_Topology_NothingIsDropped(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	east := "DC-East"
	core := seedPrefix(t, db, tenant, "Core VLAN", "10.0.0.0/16")

	seedTopologyAsset(t, db, tenant, "web-01", "server", "hardware.computer.server", &east, &core)
	seedTopologyAsset(t, db, tenant, "web-02", "server", "hardware.computer.server", &east, &core)
	seedTopologyAsset(t, db, tenant, "db-01", "managed_database", "service.data.managed_database", &east, &core)
	// Sited but prefix-less.
	seedTopologyAsset(t, db, tenant, "printer-01", "network_device", "hardware.network_device", &east, nil)
	// Neither.
	seedTopologyAsset(t, db, tenant, "mystery-01", "server", "hardware.computer.server", nil, nil)

	tp, err := svc.GetTopology(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}

	if tp.TotalAssets != 5 {
		t.Fatalf("total_assets = %d, want 5", tp.TotalAssets)
	}
	if tp.UnassignedAssets != 1 {
		t.Errorf("unassigned_assets = %d, want 1", tp.UnassignedAssets)
	}

	// The tree adds up. This is the check the independent total exists for.
	summed := 0
	for _, s := range tp.Sites {
		siteSum := 0
		for _, g := range s.Prefixes {
			segSum := 0
			for _, c := range g.Classes {
				segSum += c.AssetCount
			}
			if segSum != g.AssetCount {
				t.Errorf("prefix %q sums to %d over its classes but reports %d", g.PrefixName, segSum, g.AssetCount)
			}
			siteSum += g.AssetCount
		}
		if siteSum != s.AssetCount {
			t.Errorf("site %q sums to %d over its prefixes but reports %d", s.Site, siteSum, s.AssetCount)
		}
		summed += s.AssetCount
	}
	if summed != tp.TotalAssets {
		t.Fatalf("the tree holds %d assets and the tenant has %d — a branch was lost", summed, tp.TotalAssets)
	}

	east0 := siteNamed(t, tp, "DC-East")
	if east0.AssetCount != 4 {
		t.Errorf("DC-East holds %d assets, want 4", east0.AssetCount)
	}
	coreSeg := prefixNamed(t, east0, "10.0.0.0/16")
	if coreSeg.PrefixID == nil || *coreSeg.PrefixID != core {
		t.Errorf("Core VLAN carries prefix_id %v, want %s — without it the drill-through cannot be written", coreSeg.PrefixID, core)
	}
	if coreSeg.AssetCount != 3 || len(coreSeg.Classes) != 2 {
		t.Errorf("Core VLAN = %d assets over %d classes, want 3 over 2", coreSeg.AssetCount, len(coreSeg.Classes))
	}
	unseg := prefixNamed(t, east0, TopologyNoPrefix)
	if unseg.PrefixID != nil {
		t.Errorf("the No prefix bucket carries a prefix_id (%v); a client would write a query that matches nothing", unseg.PrefixID)
	}
	if unseg.AssetCount != 1 {
		t.Errorf("DC-East's No prefix bucket = %d, want 1", unseg.AssetCount)
	}

	unassigned := siteNamed(t, tp, TopologyUnassignedSite)
	if unassigned.AssetCount != 1 {
		t.Errorf("the Unassigned site = %d assets, want 1", unassigned.AssetCount)
	}
	if len(unassigned.Prefixes) != 1 || unassigned.Prefixes[0].PrefixName != TopologyNoPrefix {
		t.Errorf("the Unassigned site's prefixes = %+v, want one No prefix bucket", unassigned.Prefixes)
	}
}

// A site recorded in `tags` rather than in the column still groups.
//
// Sites arrived as tags before the column existed, so a tenant whose CMDB
// import wrote them there would otherwise see one enormous "Unassigned" node
// over an estate that is fully labelled. The `site` FACET already reads them
// that way, and the tree has to agree with the rail it sits beside.
func TestIntegration_Topology_SiteFallsBackToTags(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	id := seedTopologyAsset(t, db, tenant, "tagged-01", "server", "hardware.computer.server", nil, nil)
	if _, err := db.Exec(
		`UPDATE assets SET tags = '{"location":{"site":"DC-West"}}'::jsonb WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	tp, err := svc.GetTopology(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if tp.UnassignedAssets != 0 {
		t.Errorf("unassigned_assets = %d; an asset whose site is in tags is not unassigned", tp.UnassignedAssets)
	}
	s := siteNamed(t, tp, "DC-West")
	if s.AssetCount != 1 {
		t.Errorf("DC-West = %d assets, want 1", s.AssetCount)
	}
}

// Cross-prefix edges, aggregated, per type — and the pairs that must NOT be
// there.
func TestIntegration_Topology_EdgesAreCrossPrefixAndActiveOnly(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	east := "DC-East"
	core := seedPrefix(t, db, tenant, "Core VLAN", "10.0.0.0/16")
	dmz := seedPrefix(t, db, tenant, "DMZ", "10.1.0.0/16")

	a := seedTopologyAsset(t, db, tenant, "core-a", "server", "hardware.computer.server", &east, &core)
	b := seedTopologyAsset(t, db, tenant, "core-b", "server", "hardware.computer.server", &east, &core)
	c := seedTopologyAsset(t, db, tenant, "dmz-a", "server", "hardware.computer.server", &east, &dmz)
	loose := seedTopologyAsset(t, db, tenant, "loose", "server", "hardware.computer.server", &east, nil)

	// Two counted types across the same pair.
	seedEdge(t, db, tenant, a, c, relationships.ConnectsTo, "measured", EdgeStatusActive)
	seedEdge(t, db, tenant, b, c, relationships.DependsOn, "declared", EdgeStatusActive)
	// Into the prefix-less bucket. `IS DISTINCT FROM` is what keeps this one:
	// with `<>` the NULL side makes the predicate UNKNOWN and the edge vanishes.
	seedEdge(t, db, tenant, a, loose, relationships.ConnectsTo, "measured", EdgeStatusActive)
	// Same prefix: not a CROSS-prefix connection, so not here.
	seedEdge(t, db, tenant, a, b, relationships.ConnectsTo, "measured", EdgeStatusActive)
	// Pending: nobody has agreed it is true.
	seedEdge(t, db, tenant, b, c, relationships.ConnectsTo, "inferred", EdgeStatusPending)
	// A containment type: one thing described twice, not a connection.
	seedEdge(t, db, tenant, c, a, relationships.RunsOn, "measured", EdgeStatusActive)

	tp, err := svc.GetTopology(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}

	byPair := map[string]TopologyEdge{}
	for _, e := range tp.Edges {
		byPair[e.FromPrefixName+"->"+e.ToPrefixName] = e
	}
	coreToDMZ, ok := byPair["10.0.0.0/16->10.1.0.0/16"]
	if !ok {
		t.Fatalf("no Core VLAN->DMZ edge in %+v", tp.Edges)
	}
	if coreToDMZ.Count != 2 {
		t.Errorf("Core VLAN->DMZ count = %d, want 2 (one connects_to + one depends_on)", coreToDMZ.Count)
	}
	if coreToDMZ.ByType["connects_to"] != 1 || coreToDMZ.ByType["depends_on"] != 1 {
		t.Errorf("by_type = %v, want one of each — the breakdown is what says which claim a line represents", coreToDMZ.ByType)
	}
	if _, ok := byPair["10.0.0.0/16->"+TopologyNoPrefix]; !ok {
		t.Errorf("the edge into the No prefix bucket was dropped; `<>` instead of IS DISTINCT FROM loses every "+
			"edge with an prefix-less end, which on a fresh tenant is all of them. Edges: %+v", tp.Edges)
	}
	if _, ok := byPair["10.0.0.0/16->10.0.0.0/16"]; ok {
		t.Error("a same-prefix edge was returned; the question is cross-prefix connections")
	}
	// The pending edge and the containment edge are the same pair as one that
	// IS counted, so their absence shows in the count, not in the pair list.
	if coreToDMZ.ByType["runs_on"] != 0 {
		t.Errorf("a containment edge was counted: %v", coreToDMZ.ByType)
	}
	total := 0
	for _, e := range tp.Edges {
		total += e.Count
	}
	if total != 3 {
		t.Errorf("%d edges counted in total, want 3 — pending, same-prefix and containment edges must all be out", total)
	}
	if tp.TotalEdges != 3 {
		t.Errorf("total_edges = %d, want 3", tp.TotalEdges)
	}
}

// A tenant with nothing gets empty arrays and zeroes, not an error.
func TestIntegration_Topology_EmptyEstate(t *testing.T) {
	svc, _, tenant := newTopologyFixture(t)
	tp, err := svc.GetTopology(context.Background(), tenant)
	if err != nil {
		t.Fatalf("an empty inventory must be an answer, not an error: %v", err)
	}
	if len(tp.Sites) != 0 || len(tp.Edges) != 0 || tp.TotalAssets != 0 {
		t.Errorf("an empty tenant reported %d sites / %d edges / %d assets", len(tp.Sites), len(tp.Edges), tp.TotalAssets)
	}
	if tp.Truncated {
		t.Error("an empty estate reported itself truncated")
	}
}

// A soft-deleted asset is out of the tree AND out of the total, so the two
// still agree. Counting it in one and not the other is how the sum check above
// would start failing for a reason that is not a lost branch.
func TestIntegration_Topology_ExcludesDeletedAssets(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	east := "DC-East"
	seedTopologyAsset(t, db, tenant, "live-01", "server", "hardware.computer.server", &east, nil)
	gone := seedTopologyAsset(t, db, tenant, "gone-01", "server", "hardware.computer.server", &east, nil)
	if _, err := db.Exec(`UPDATE assets SET deleted_at = NOW() WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}

	tp, err := svc.GetTopology(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if tp.TotalAssets != 1 {
		t.Errorf("total_assets = %d, want 1", tp.TotalAssets)
	}
	if got := siteNamed(t, tp, "DC-East").AssetCount; got != 1 {
		t.Errorf("DC-East = %d, want 1 — a deleted asset is still in the tree", got)
	}
}

// Another tenant's estate must not appear, through the app role RLS actually
// applies to. The owner role in the other tests BYPASSES policies, so a query
// that leaked across tenants would pass every one of them.
func TestIntegration_Topology_RLSIsolatesTenants(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)

	ownerDB := &database.DB{DB: sqlx.NewDb(owner, "postgres")}
	east := "DC-East"
	seg := seedPrefix(t, ownerDB, tenantA, "A Core", "10.0.0.0/16")
	seedTopologyAsset(t, ownerDB, tenantA, "a-only", "server", "hardware.computer.server", &east, &seg)

	appRole := testdb.ConnectAsAppRole(t, owner)
	svc := &AssetService{db: &database.DB{DB: sqlx.NewDb(appRole, "postgres")}}

	tp, err := svc.GetTopology(context.Background(), tenantB)
	if err != nil {
		t.Fatal(err)
	}
	if tp.TotalAssets != 0 || len(tp.Sites) != 0 {
		t.Fatalf("tenant B sees %d of tenant A's assets across %d sites", tp.TotalAssets, len(tp.Sites))
	}

	own, err := svc.GetTopology(context.Background(), tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if own.TotalAssets != 1 {
		t.Fatalf("tenant A cannot see its OWN estate through the app role (%d assets) — "+
			"an over-tight predicate is the same bug pointed the other way", own.TotalAssets)
	}
}

// The count and the click are the same question.
//
// Every class chip in the topology is a LINK into the asset list, carrying the
// query `topology-model.ts` builds — and the tree is only worth having if that
// link opens exactly the rows the chip counted. The two halves are written in
// different languages (a Go grouping query and a TypeScript query string), so
// nothing but a test like this one holds them together.
//
// The operator is the whole point. QUERY_LANGUAGE §5.3 gives `class:` and
// `class=` different meanings — `:` matches the class and every descendant by
// materialised path, `=` matches the class itself — while the topology groups
// by `class_key`, which is exact. Plenty of classes are NOT leaves:
// `standards/classification-rules.yaml` assigns `network_device` to anything it
// cannot narrow further, and switches, routers and firewalls sit beneath it.
// So the subtree form makes a chip reading 1 open a list of 3 here, and by the
// same factor of three on a real estate.
//
// Both polarities: the exact form agrees, and the subtree form is asserted to
// DISAGREE, so this cannot pass by accident on a fixture with only leaf classes.
func TestIntegration_Topology_ClassDrillThroughSelectsWhatItCounted(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	east := "DC-East"
	seg := seedPrefix(t, db, tenant, "Core VLAN", "10.20.0.0/16")

	// One asset at the NON-LEAF class, two at classes beneath it.
	seedTopologyAsset(t, db, tenant, "unknown-box", "network_device", "hardware.network_device", &east, &seg)
	seedTopologyAsset(t, db, tenant, "sw-01", "switch", "hardware.network_device.switch", &east, &seg)
	seedTopologyAsset(t, db, tenant, "rtr-01", "router", "hardware.network_device.router", &east, &seg)

	tp, err := svc.GetTopology(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	prefix := prefixNamed(t, siteNamed(t, tp, east), "10.20.0.0/16")

	var node *TopologyClass
	for i := range prefix.Classes {
		if prefix.Classes[i].ClassKey == "network_device" {
			node = &prefix.Classes[i]
		}
	}
	if node == nil {
		t.Fatalf("no network_device class node in %+v", prefix.Classes)
	}
	if node.AssetCount != 1 {
		t.Fatalf("the node counts %d assets, want 1 — it groups by class_key, which is exact", node.AssetCount)
	}

	// The query topology-model.ts writes for this node (pinned verbatim there by
	// its "matches the class EXACTLY, because that is what the node counted" case).
	exact := "prefix_id:" + prefix.PrefixID.String() + " and class=network_device"
	_, total, err := svc.GetAssets(tenant, models.AssetFilters{Query: exact})
	if err != nil {
		t.Fatalf("the drill-through query did not run: %v", err)
	}
	if total != node.AssetCount {
		t.Errorf("the chip says %d and its link opens %d rows (%q) — the count and the click "+
			"are the same question and must have the same answer", node.AssetCount, total, exact)
	}

	// The other polarity: the subtree form, which this link used to carry, must
	// be measurably wrong here. Without this the test would pass on a fixture
	// whose classes were all leaves, which is exactly how the bug survived.
	subtree := "prefix_id:" + prefix.PrefixID.String() + " and class:network_device"
	_, subtreeTotal, err := svc.GetAssets(tenant, models.AssetFilters{Query: subtree})
	if err != nil {
		t.Fatalf("the subtree query did not run: %v", err)
	}
	if subtreeTotal != 3 {
		t.Fatalf("the subtree form selects %d, want 3 (the class and its two descendants) — "+
			"the fixture no longer distinguishes the two operators, so the assertion above proves nothing", subtreeTotal)
	}
}
