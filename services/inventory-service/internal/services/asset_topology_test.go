package services

// The tree assembly, as a pure function (workstream 3.8).
//
// `assembleTopology` folds flat (site, segment, class) triples into the nested
// shape, and the nesting is where an off-by-one silently loses a branch. It
// takes rows and returns a tree, so it is testable without a database — and the
// two cases below are exactly the ones an integration test on ordinary data
// would not produce.

import (
	"testing"

	"github.com/google/uuid"
)

// A tenant that NAMES a segment "Unsegmented" must not have it merged with the
// bucket for assets that have none.
//
// Nothing stops them: `network_segments.name` is free text. Keying the fold on
// the NAME rather than the id moves those assets into the bucket, where the
// drill-through query is `not segment_id exists` — so clicking the node returns
// a different set from the one the count described, and the real segment
// disappears from the tree entirely.
func TestAssembleTopology_RealSegmentNamedUnsegmentedIsNotMerged(t *testing.T) {
	awkward := uuid.New()
	rows := []topologyRow{
		{Site: "DC-East", SegmentID: &awkward, SegmentName: TopologyUnsegmented,
			ClassKey: "server", ClassPath: "hardware.computer.server", AssetCount: 7},
		{Site: "DC-East", SegmentID: nil, SegmentName: TopologyUnsegmented,
			ClassKey: "server", ClassPath: "hardware.computer.server", AssetCount: 2},
	}

	sites := assembleTopology(rows)
	if len(sites) != 1 {
		t.Fatalf("%d sites, want 1", len(sites))
	}
	if len(sites[0].Segments) != 2 {
		t.Fatalf("%d segments, want 2 — a segment a tenant NAMED \"Unsegmented\" was merged with the "+
			"bucket for assets that have none; the fold must key on the id, not the name", len(sites[0].Segments))
	}
	var named, bucket *TopologySegment
	for i := range sites[0].Segments {
		if sites[0].Segments[i].SegmentID == nil {
			bucket = &sites[0].Segments[i]
		} else {
			named = &sites[0].Segments[i]
		}
	}
	if named == nil || bucket == nil {
		t.Fatalf("expected one segment with an id and one without: %+v", sites[0].Segments)
	}
	if named.AssetCount != 7 || bucket.AssetCount != 2 {
		t.Errorf("counts crossed over: named=%d bucket=%d, want 7 and 2", named.AssetCount, bucket.AssetCount)
	}
	if sites[0].AssetCount != 9 {
		t.Errorf("site total = %d, want 9", sites[0].AssetCount)
	}
}

// Two sites, two segments each, several classes — the ordinary fold, asserted
// on the sums at all three levels.
//
// The rows arrive flat and in the query's order (biggest first), and every
// level's total is accumulated rather than taken from any one row, so a fold
// that dropped a row would show up as a total that no longer adds up.
func TestAssembleTopology_SumsAtEveryLevel(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	rows := []topologyRow{
		{Site: "DC-East", SegmentID: &a, SegmentName: "Core", ClassKey: "server", ClassPath: "hardware.computer.server", AssetCount: 10},
		{Site: "DC-East", SegmentID: &a, SegmentName: "Core", ClassKey: "managed_database", ClassPath: "service.data.managed_database", AssetCount: 4},
		{Site: "DC-East", SegmentID: &b, SegmentName: "DMZ", ClassKey: "server", ClassPath: "hardware.computer.server", AssetCount: 3},
		{Site: TopologyUnassignedSite, SegmentID: nil, SegmentName: TopologyUnsegmented, ClassKey: "network_device", ClassPath: "hardware.network_device", AssetCount: 2},
	}

	sites := assembleTopology(rows)
	if len(sites) != 2 {
		t.Fatalf("%d sites, want 2", len(sites))
	}
	// Insertion order is the query's order, which is what puts the biggest
	// branch at the top of the view.
	if sites[0].Site != "DC-East" || sites[1].Site != TopologyUnassignedSite {
		t.Errorf("site order = %s, %s; the query's order must survive the fold", sites[0].Site, sites[1].Site)
	}
	if sites[0].AssetCount != 17 || sites[1].AssetCount != 2 {
		t.Errorf("site totals = %d, %d; want 17 and 2", sites[0].AssetCount, sites[1].AssetCount)
	}
	if len(sites[0].Segments) != 2 {
		t.Fatalf("DC-East has %d segments, want 2", len(sites[0].Segments))
	}
	if sites[0].Segments[0].AssetCount != 14 || len(sites[0].Segments[0].Classes) != 2 {
		t.Errorf("Core = %d assets over %d classes, want 14 over 2",
			sites[0].Segments[0].AssetCount, len(sites[0].Segments[0].Classes))
	}
}

// No rows is an empty slice, never nil: a nil slice marshals to JSON `null`,
// and a client reading `sites.length` on it throws.
func TestAssembleTopology_EmptyIsASlice(t *testing.T) {
	sites := assembleTopology(nil)
	if sites == nil {
		t.Fatal("assembleTopology(nil) returned nil; it marshals to `null` and breaks the client")
	}
	if len(sites) != 0 {
		t.Fatalf("%d sites from no rows", len(sites))
	}
}

// The edge fold: one entry per DIRECTED pair, with the per-type breakdown
// preserved.
//
// The two directions of a pair are separate entries on purpose — `depends_on`
// is not symmetric, and merging them loses which side is the dependant.
func TestAssembleTopologyEdges_DirectedPairsWithBreakdown(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	rows := []topologyEdgeRow{
		{FromSegmentID: &a, FromSegmentName: "Core", ToSegmentID: &b, ToSegmentName: "DMZ", Type: "connects_to", Count: 7},
		{FromSegmentID: &a, FromSegmentName: "Core", ToSegmentID: &b, ToSegmentName: "DMZ", Type: "depends_on", Count: 2},
		{FromSegmentID: &b, FromSegmentName: "DMZ", ToSegmentID: &a, ToSegmentName: "Core", Type: "connects_to", Count: 1},
		{FromSegmentID: &a, FromSegmentName: "Core", ToSegmentID: nil, ToSegmentName: TopologyUnsegmented, Type: "connects_to", Count: 4},
	}

	edges := assembleTopologyEdges(rows)
	if len(edges) != 3 {
		t.Fatalf("%d edges, want 3 directed pairs: %+v", len(edges), edges)
	}
	if edges[0].Count != 9 {
		t.Errorf("Core->DMZ count = %d, want 9 (7 + 2)", edges[0].Count)
	}
	if edges[0].ByType["connects_to"] != 7 || edges[0].ByType["depends_on"] != 2 {
		t.Errorf("Core->DMZ by_type = %v, want connects_to:7 depends_on:2", edges[0].ByType)
	}
	if edges[1].Count != 1 || edges[1].FromSegmentName != "DMZ" {
		t.Errorf("the reverse direction was merged into the forward one: %+v", edges[1])
	}
	if edges[2].ToSegmentID != nil || edges[2].ToSegmentName != TopologyUnsegmented {
		t.Errorf("the edge into the Unsegmented bucket lost its null id: %+v", edges[2])
	}
}

func TestAssembleTopologyEdges_EmptyIsASlice(t *testing.T) {
	if edges := assembleTopologyEdges(nil); edges == nil {
		t.Fatal("assembleTopologyEdges(nil) returned nil; it marshals to `null`")
	}
}

// The counted edge types come from the `relationships` constants, so a rename
// there is a compile error rather than a type that silently stops being
// counted. This pins the FORMAT of the array literal, which no compiler checks.
func TestTopologyEdgeTypes_IsAPostgresArrayLiteral(t *testing.T) {
	if got := topologyEdgeTypes(); got != "{connects_to,depends_on}" {
		t.Fatalf("topologyEdgeTypes() = %q, want {connects_to,depends_on} — "+
			"a malformed array literal makes `type = ANY(...)` match nothing and the map draws no edges", got)
	}
}
