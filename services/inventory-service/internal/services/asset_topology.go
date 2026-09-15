package services

// The tenant-wide topology (ADR-0006 D4, second half — workstream 3.8).
//
// The map's OTHER view. The neighbourhood answers "what does this one thing
// touch"; this answers "where is everything", and D4 is explicit that the second
// question must not be answered with a force graph:
//
//	"not a force graph of thousands of nodes, which is unreadable everywhere it
//	 is tried. A hierarchical view by site → segment → class with counts,
//	 expandable to the assets in a segment, with cross-segment connection
//	 summaries drawn as aggregated edges."
//
// So this endpoint returns a TREE of counts plus a small set of aggregated
// edges, and the client draws it with the components it already has. Nothing
// here returns an asset row: the tree is the index, and a click on a class node
// runs the ordinary asset list with a `segment_id:… and class:…` query — which
// keeps the counts and the list the same question asked twice, rather than two
// answers a user gets to reconcile.
//
// # Nothing is dropped
//
// An asset with no site appears under an explicit "Unassigned" site, and one
// with no segment under an explicit "Unsegmented" segment. This is the whole
// reason the endpoint is worth having on a real tenant: on a fresh inventory
// MOST assets are in exactly that state, and a topology that quietly omitted
// them would show a tidy diagram of the small minority that had been curated
// and read as complete. `TotalAssets` is the check — it is counted
// independently of the tree, so a client can assert the tree adds up to it.

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// Labels for the two "nobody has said" buckets. They are VALUES in the
// response, not a client-side fallback, so every consumer — the topology view,
// an export, an agent reading the API — names them the same way.
const (
	// TopologyUnassignedSite is the site of an asset whose `site` is null.
	TopologyUnassignedSite = "Unassigned"
	// TopologyUnsegmented is the segment of an asset with no network segment.
	TopologyUnsegmented = "Unsegmented"
)

// TopologyNodeCap bounds the (site, segment, class) triples one response
// carries.
//
// A REFUSAL TO GUESS rather than a tuning knob, the same as the neighbourhood
// caps: past the cap the answer reports itself truncated with the real total,
// never silently shortened. The tree is grouped, so reaching this needs a
// genuinely enormous estate — a thousand distinct triples is a thousand rows in
// the expanded view, at which point the page is not readable anyway.
const TopologyNodeCap = 2000

// TopologyEdgeCap bounds the aggregated segment-pair edges.
const TopologyEdgeCap = 500

// TopologyClass is one class node: a leaf of the tree.
type TopologyClass struct {
	ClassKey string `json:"class_key" db:"class_key"`
	// ClassPath is the materialised ancestry (`hardware.computer.server`). The
	// client labels from it and, more importantly, the drill-through query uses
	// the KEY — `class:` matches a subtree, so a key is the exact node.
	ClassPath  string `json:"class_path" db:"class_path"`
	AssetCount int    `json:"asset_count" db:"asset_count"`
}

// TopologySegment is one segment node, with its classes.
type TopologySegment struct {
	// SegmentID is nil for the "Unsegmented" bucket. A client must branch on
	// this rather than on the name: a tenant is free to NAME a segment
	// "Unsegmented", and the drill-through query for the bucket is
	// `not exists(segment_id)` while for a real segment it is `segment_id:<id>`.
	SegmentID   *uuid.UUID      `json:"segment_id"`
	SegmentName string          `json:"segment_name"`
	AssetCount  int             `json:"asset_count"`
	Classes     []TopologyClass `json:"classes"`
}

// TopologySite is one site node, with its segments.
type TopologySite struct {
	// Site is TopologyUnassignedSite when the asset records none.
	Site       string            `json:"site"`
	AssetCount int               `json:"asset_count"`
	Segments   []TopologySegment `json:"segments"`
}

// TopologyEdge is the aggregate of every ACTIVE relationship crossing from one
// segment into another.
//
// Directed, and deliberately: `depends_on` is not symmetric, and folding the
// two directions together would lose which side is the dependant. Same-segment
// edges are NOT here — "cross-segment connection summaries" is what D4 asks for,
// and an intra-segment count would be a different statistic wearing the same
// shape.
type TopologyEdge struct {
	FromSegmentID   *uuid.UUID `json:"from_segment_id"`
	FromSegmentName string     `json:"from_segment_name"`
	ToSegmentID     *uuid.UUID `json:"to_segment_id"`
	ToSegmentName   string     `json:"to_segment_name"`
	// Count is every edge of any counted type between the pair.
	Count int `json:"count"`
	// ByType breaks it down — `connects_to` (observed traffic) and
	// `depends_on` (a declared dependency) are different claims and a single
	// number would hide which one a line represents.
	ByType map[string]int `json:"by_type"`
}

// Topology is the whole answer.
type Topology struct {
	Sites []TopologySite `json:"sites"`
	Edges []TopologyEdge `json:"edges"`
	// TotalAssets is counted INDEPENDENTLY of the tree, so a client can check
	// that the tree adds up to it. A tree that silently lost a branch is the
	// failure this number exists to make visible.
	TotalAssets int `json:"total_assets"`
	// UnassignedAssets is how many have no site — the number that says whether
	// the diagram above is the estate or a curated corner of it.
	UnassignedAssets int `json:"unassigned_assets"`
	// TotalNodes / TotalEdges are the untruncated totals.
	TotalNodes int  `json:"total_nodes"`
	TotalEdges int  `json:"total_edges"`
	Truncated  bool `json:"truncated"`
	NodeCap    int  `json:"node_cap"`
	EdgeCap    int  `json:"edge_cap"`
}

// topologyRow is one (site, segment, class) triple as the grouping returns it.
type topologyRow struct {
	Site        string     `db:"site"`
	SegmentID   *uuid.UUID `db:"segment_id"`
	SegmentName string     `db:"segment_name"`
	ClassKey    string     `db:"class_key"`
	ClassPath   string     `db:"class_path"`
	AssetCount  int        `db:"asset_count"`
}

// topologyEdgeRow is one aggregated segment pair.
type topologyEdgeRow struct {
	FromSegmentID   *uuid.UUID `db:"from_segment_id"`
	FromSegmentName string     `db:"from_segment_name"`
	ToSegmentID     *uuid.UUID `db:"to_segment_id"`
	ToSegmentName   string     `db:"to_segment_name"`
	Type            string     `db:"type"`
	Count           int        `db:"count"`
}

// topologySiteSQL is the site expression, shared with the `site` facet so the
// tree's headings and the rail's buckets cannot name a site differently.
//
// It falls back through `tags.location.site` and `tags.site` for the same
// reason the facet does: sites arrived as tags before the column existed, and a
// tenant whose CMDB import wrote them there would otherwise see one enormous
// "Unassigned" node over an estate that is fully labelled.
const topologySiteSQL = "COALESCE(a.site, a.tags->'location'->>'site', a.tags->>'site', '" +
	TopologyUnassignedSite + "')"

// GetTopology returns the site → segment → class tree with cross-segment edge
// counts, for one tenant.
//
// RLS is the isolation boundary — everything runs inside
// `database.WithTenantTx`, which sets `app.tenant_id` — and the explicit
// `tenant_id = $1` predicates are the house belt-and-braces on top of it.
func (s *AssetService) GetTopology(ctx context.Context, tenantID uuid.UUID) (*Topology, error) {
	out := &Topology{
		Sites:   []TopologySite{},
		Edges:   []TopologyEdge{},
		NodeCap: TopologyNodeCap,
		EdgeCap: TopologyEdgeCap,
	}

	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// The independent totals, first. They are what makes the tree
		// checkable, so they are not derived from it.
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*),
			       count(*) FILTER (WHERE `+topologySiteSQL+` = $2)
			  FROM assets a
			 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL`,
			tenantID, TopologyUnassignedSite).Scan(&out.TotalAssets, &out.UnassignedAssets); err != nil {
			return fmt.Errorf("topology totals: %w", err)
		}

		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM (
				SELECT 1
				  FROM assets a
				  LEFT JOIN network_segments ns ON ns.id = a.network_segment_id AND ns.tenant_id = a.tenant_id
				 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
				 GROUP BY `+topologySiteSQL+`, a.network_segment_id, ns.name, a.class_key, a.class_path
			) t`, tenantID).Scan(&out.TotalNodes); err != nil {
			return fmt.Errorf("topology node count: %w", err)
		}

		var rows []topologyRow
		// ORDER BY ends in the three grouping keys so the ordering is TOTAL:
		// asset_count ties constantly (every segment with one server), and
		// LIMIT over a partial ordering does not partition deterministically.
		if err := tx.SelectContext(ctx, &rows, `
			SELECT `+topologySiteSQL+`                      AS site,
			       a.network_segment_id                     AS segment_id,
			       COALESCE(ns.name, $3)                    AS segment_name,
			       a.class_key,
			       a.class_path,
			       count(*)                                 AS asset_count
			  FROM assets a
			  LEFT JOIN network_segments ns ON ns.id = a.network_segment_id AND ns.tenant_id = a.tenant_id
			 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
			 GROUP BY 1, 2, 3, 4, 5
			 ORDER BY asset_count DESC, site ASC, segment_name ASC, a.class_key ASC
			 LIMIT $2`, tenantID, TopologyNodeCap, TopologyUnsegmented); err != nil {
			return fmt.Errorf("topology tree: %w", err)
		}
		out.Sites = assembleTopology(rows)
		if out.TotalNodes > len(rows) {
			out.Truncated = true
		}

		// The edges. ACTIVE only — a pending edge is something nobody has
		// agreed is true, and an aggregate count is the one place a single
		// unconfirmed observation is invisible, so drawing it as a line would
		// state it as fact with nothing on screen to qualify it.
		//
		// Two types, both named by D4: `connects_to` is observed traffic and
		// `depends_on` is a declared dependency. The containment types
		// (`runs_on`, `hosted_on`, …) are excluded on purpose: a VM and its
		// hypervisor being in two segments is not a connection between those
		// segments, it is one thing described twice.
		var edgeRows []topologyEdgeRow
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM (
				SELECT 1
				  FROM asset_relationships r
				  JOIN assets fa ON fa.id = r.from_asset_id AND fa.tenant_id = r.tenant_id AND fa.deleted_at IS NULL
				  JOIN assets ta ON ta.id = r.to_asset_id   AND ta.tenant_id = r.tenant_id AND ta.deleted_at IS NULL
				 WHERE r.tenant_id = $1
				   AND r.status = $2
				   AND r.type = ANY($3)
				   AND fa.network_segment_id IS DISTINCT FROM ta.network_segment_id
				 GROUP BY fa.network_segment_id, ta.network_segment_id, r.type
			) t`, tenantID, EdgeStatusActive, topologyEdgeTypes()).Scan(&out.TotalEdges); err != nil {
			return fmt.Errorf("topology edge count: %w", err)
		}
		if err := tx.SelectContext(ctx, &edgeRows, `
			SELECT fa.network_segment_id     AS from_segment_id,
			       COALESCE(fns.name, $4)    AS from_segment_name,
			       ta.network_segment_id     AS to_segment_id,
			       COALESCE(tns.name, $4)    AS to_segment_name,
			       r.type,
			       count(*)                  AS count
			  FROM asset_relationships r
			  JOIN assets fa ON fa.id = r.from_asset_id AND fa.tenant_id = r.tenant_id AND fa.deleted_at IS NULL
			  JOIN assets ta ON ta.id = r.to_asset_id   AND ta.tenant_id = r.tenant_id AND ta.deleted_at IS NULL
			  LEFT JOIN network_segments fns ON fns.id = fa.network_segment_id AND fns.tenant_id = r.tenant_id
			  LEFT JOIN network_segments tns ON tns.id = ta.network_segment_id AND tns.tenant_id = r.tenant_id
			 WHERE r.tenant_id = $1
			   AND r.status = $2
			   AND r.type = ANY($5)
			   -- IS DISTINCT FROM, not <>: two NULLs are ONE bucket
			   -- ("Unsegmented"), while <> evaluates NULL and would drop every
			   -- edge with an unsegmented end — which on a fresh tenant is all
			   -- of them.
			   AND fa.network_segment_id IS DISTINCT FROM ta.network_segment_id
			 GROUP BY 1, 2, 3, 4, 5
			 ORDER BY count DESC, from_segment_name ASC, to_segment_name ASC, r.type ASC
			 LIMIT $3`,
			tenantID, EdgeStatusActive, TopologyEdgeCap, TopologyUnsegmented, topologyEdgeTypes()); err != nil {
			return fmt.Errorf("topology edges: %w", err)
		}
		out.Edges = assembleTopologyEdges(edgeRows)
		if out.TotalEdges > len(edgeRows) {
			out.Truncated = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// topologyEdgeTypes is the pair D4 names, as a Postgres text array literal.
//
// Built from the `relationships` constants rather than spelled out, so a rename
// there is a compile error here instead of an edge type that silently stops
// being counted.
func topologyEdgeTypes() string {
	return "{" + string(relationships.ConnectsTo) + "," + string(relationships.DependsOn) + "}"
}

// assembleTopology folds the flat triples into the tree, preserving the order
// the query returned (biggest first) at every level.
//
// Written as a pure function over rows so it is unit-testable without a
// database: the nesting is where an off-by-one loses a branch, and that is
// exactly the class of bug a count-only integration test would not notice.
func assembleTopology(rows []topologyRow) []TopologySite {
	sites := []TopologySite{}
	siteIdx := map[string]int{}
	// Keyed on the segment ID's string form, with "" for the unsegmented
	// bucket — NOT on the name, because a tenant may legitimately name a
	// segment "Unsegmented" and merging it with the real bucket would move
	// assets between nodes.
	segIdx := map[string]map[string]int{}

	for _, r := range rows {
		si, ok := siteIdx[r.Site]
		if !ok {
			si = len(sites)
			siteIdx[r.Site] = si
			sites = append(sites, TopologySite{Site: r.Site, Segments: []TopologySegment{}})
			segIdx[r.Site] = map[string]int{}
		}
		sites[si].AssetCount += r.AssetCount

		segKey := ""
		if r.SegmentID != nil {
			segKey = r.SegmentID.String()
		}
		gi, ok := segIdx[r.Site][segKey]
		if !ok {
			gi = len(sites[si].Segments)
			segIdx[r.Site][segKey] = gi
			sites[si].Segments = append(sites[si].Segments, TopologySegment{
				SegmentID:   r.SegmentID,
				SegmentName: r.SegmentName,
				Classes:     []TopologyClass{},
			})
		}
		sites[si].Segments[gi].AssetCount += r.AssetCount
		sites[si].Segments[gi].Classes = append(sites[si].Segments[gi].Classes, TopologyClass{
			ClassKey:   r.ClassKey,
			ClassPath:  r.ClassPath,
			AssetCount: r.AssetCount,
		})
	}
	return sites
}

// assembleTopologyEdges folds the per-type rows into one entry per directed
// segment pair.
func assembleTopologyEdges(rows []topologyEdgeRow) []TopologyEdge {
	out := []TopologyEdge{}
	idx := map[string]int{}
	for _, r := range rows {
		from, to := "", ""
		if r.FromSegmentID != nil {
			from = r.FromSegmentID.String()
		}
		if r.ToSegmentID != nil {
			to = r.ToSegmentID.String()
		}
		key := from + "->" + to
		i, ok := idx[key]
		if !ok {
			i = len(out)
			idx[key] = i
			out = append(out, TopologyEdge{
				FromSegmentID: r.FromSegmentID, FromSegmentName: r.FromSegmentName,
				ToSegmentID: r.ToSegmentID, ToSegmentName: r.ToSegmentName,
				ByType: map[string]int{},
			})
		}
		out[i].Count += r.Count
		out[i].ByType[r.Type] += r.Count
	}
	return out
}
