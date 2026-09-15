// Package services: the relationship read and write surface — ADR-0003.
//
// Three questions this answers, and they are genuinely different:
//
//   - "what is attached to this asset" — one hop, both directions, paged. The
//     Relationships tab.
//   - "what does the neighbourhood look like" — N hops, node- and edge-capped,
//     the shape the map (workstream 2.9) draws.
//   - "what breaks if this changes" — the depth-capped closure over the
//     impact-bearing types only (ADR-0003 D5), which is a different and much
//     narrower walk than the neighbourhood.
//
// Every path runs inside `database.WithTenantTx`, so `app.tenant_id` is set and
// the RLS policy on `asset_relationships` is the isolation boundary rather than
// a WHERE clause someone can forget. The explicit `tenant_id = $1` predicates
// below are belt-and-braces on top of that, matching the house pattern.
package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// Caps. Each is a REFUSAL TO GUESS, not a performance tuning knob: past the
// cap the answer is reported as truncated with the real totals, never silently
// shortened. A map that quietly drops the node a user was looking for is worse
// than one that says it could not draw everything.
const (
	// MaxNeighbourhoodDepth bounds the hop count (ADR-0006 D4 draws two by
	// default; three is as far as the endpoint will go). Beyond three, a
	// neighbourhood of an ordinary datacentre asset is the whole datacentre.
	MaxNeighbourhoodDepth = 3
	// DefaultNeighbourhoodDepth is what the tab asks for when it says nothing.
	DefaultNeighbourhoodDepth = 2
	// NeighbourhoodNodeCap / NeighbourhoodEdgeCap bound one response.
	NeighbourhoodNodeCap = 500
	NeighbourhoodEdgeCap = 2000

	// MaxImpactDepth bounds the impact closure. ADR-0003 D5 sets the DEFAULT at
	// six ("depth-capped (default 6)"); this is the hard ceiling a caller may
	// raise it to, and the recursion terminates on it whatever the graph does.
	MaxImpactDepth     = 10
	DefaultImpactDepth = 6
	// ImpactNodeCap bounds the returned closure the same way.
	ImpactNodeCap = 500

	// RelationshipPageSize / RelationshipMaxPageSize page the one-hop list.
	RelationshipPageSize    = 50
	RelationshipMaxPageSize = 200
)

// Directions for the one-hop list and the impact walk.
const (
	DirectionOut  = "out"
	DirectionIn   = "in"
	DirectionBoth = "both"

	ImpactDownstream = "downstream"
	ImpactUpstream   = "upstream"
)

// Edge statuses, mirroring the CHECK on the table.
const (
	EdgeStatusPending  = "pending"
	EdgeStatusActive   = "active"
	EdgeStatusRejected = "rejected"
	EdgeStatusStale    = "stale"
)

// Provenance kinds, mirroring the CHECK on the table (and ADR-0005's fact
// vocabulary, which is deliberately the same four words).
const (
	SourceKindMeasured = "measured"
	SourceKindDeclared = "declared"
	SourceKindImported = "imported"
	SourceKindInferred = "inferred"
)

// Errors the handler maps onto statuses.
var (
	// ErrRelationshipNotFound — no such edge in this tenant, or it does not
	// touch the asset the request was about.
	ErrRelationshipNotFound = errors.New("relationship not found")

	// ErrRelationshipNotDeclared is the 409 a DELETE of a measured edge gets.
	//
	// A measured edge is an OBSERVATION. Deleting one asserts that a collector
	// did not see what it says it saw, and the next run would re-create it
	// anyway — so the delete would appear to work and then silently undo
	// itself, which is the worst of both answers. Measured edges are retired by
	// their collector ceasing to observe them (they go `stale` and are archived
	// by the lifecycle policy), or rejected as a proposal.
	ErrRelationshipNotDeclared = errors.New("only a declared relationship can be deleted")

	// ErrRelationshipDecided — the proposal already has an answer.
	ErrRelationshipDecided = errors.New("this relationship has already been decided")

	// ErrRelationshipExists — the (from, to, type) triple is already an edge.
	ErrRelationshipExists = errors.New("that relationship already exists")

	// ErrRelationshipSelfEdge — from and to are the same asset.
	ErrRelationshipSelfEdge = errors.New("an asset cannot have a relationship with itself")

	// ErrRelationshipUnknownType — not one of the ten (ADR-0003 D2).
	ErrRelationshipUnknownType = errors.New("unknown relationship type")

	// ErrRelationshipPeerNotFound — the named peer is not an asset of this
	// tenant. Distinct from a 404 on the edge: the request named a thing that
	// does not exist, rather than asking about one that does not.
	ErrRelationshipPeerNotFound = errors.New("peer asset not found")

	// ErrRelationshipEndPending is the 409 an ACCEPT gets when an end of the
	// edge is not itself monitored.
	//
	// ADR-0003 D1: "An edge whose either endpoint is pending is itself
	// pending." Activating one anyway produces a confirmed relationship to an
	// asset nobody has admitted to the inventory — and because the impact
	// closure walks active edges, the unadmitted asset then appears in a
	// blast-radius answer someone plans a change around.
	//
	// The proposal queue's own predicate already excludes these, so nothing in
	// the Approvals flow can reach this. The asset page can: its Relationships
	// tab lists the edge from the PENDING asset's own side, where the only end
	// it can see decorated is the monitored peer. This is the check that makes
	// the invariant hold at the API rather than at one caller.
	ErrRelationshipEndPending = errors.New("an end of this relationship is still awaiting approval")
)

// RelationshipPeer is the other end of an edge, decorated enough to render a
// row and follow a link without a second read.
type RelationshipPeer struct {
	AssetID     uuid.UUID `json:"asset_id"`
	DisplayName string    `json:"display_name,omitempty"`
	ClassKey    string    `json:"class_key,omitempty"`
	AssetStatus string    `json:"asset_status,omitempty"`
	// PrimaryIdentifier is the strongest identifier the peer carries, as
	// `kind:value` — the thing a reviewer recognises when `display_name` is
	// empty, which it is for most freshly discovered assets.
	PrimaryIdentifier string `json:"primary_identifier,omitempty"`
	RiskScore         *int   `json:"risk_score,omitempty"`
	// Deleted marks a peer that has been soft-deleted or merged away. Shown
	// rather than dropped: an edge whose peer silently vanishes reads as a
	// corrupt row, and "that thing is gone" is the actual answer.
	Deleted bool `json:"deleted"`
}

// RelationshipEdge is one edge as the API returns it.
type RelationshipEdge struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	FromAssetID uuid.UUID `json:"from_asset_id"`
	ToAssetID   uuid.UUID `json:"to_asset_id"`
	Type        string    `json:"type"`
	// Direction is relative to the asset the READ was about: `out` when that
	// asset is the from end, `in` when it is the to end. It is not a property
	// of the row — the same row is `out` from one side and `in` from the other.
	Direction string `json:"direction,omitempty"`
	// Label is how the edge reads from the asset's own side: the type itself
	// outbound, the vocabulary's reverse label inbound (`runs_on` / `runs`).
	// Derived, never stored (ADR-0003 D1).
	Label            string            `json:"label,omitempty"`
	SourceKind       string            `json:"source_kind"`
	SourceRef        string            `json:"source_ref,omitempty"`
	Confidence       float64           `json:"confidence"`
	Status           string            `json:"status"`
	Attributes       map[string]any    `json:"attributes,omitempty"`
	FirstSeenAt      time.Time         `json:"first_seen_at"`
	LastSeenAt       time.Time         `json:"last_seen_at"`
	ObservationCount int               `json:"observation_count"`
	CreatedBy        *uuid.UUID        `json:"created_by,omitempty"`
	ApprovedBy       *uuid.UUID        `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time        `json:"approved_at,omitempty"`
	Peer             *RelationshipPeer `json:"peer,omitempty"`
	// From / To decorate BOTH ends. Populated only on the proposal queue, where
	// the reviewer has no asset page around them for context and has to be able
	// to read the whole sentence.
	From *RelationshipPeer `json:"from,omitempty"`
	To   *RelationshipPeer `json:"to,omitempty"`
}

// RelationshipListOptions are the one-hop list's filters.
type RelationshipListOptions struct {
	Direction string
	Type      string
	Status    string
	Limit     int
	Offset    int
}

// NeighbourhoodNode is one node of the neighbourhood graph.
type NeighbourhoodNode struct {
	AssetID     uuid.UUID `json:"asset_id"`
	DisplayName string    `json:"display_name,omitempty"`
	ClassKey    string    `json:"class_key,omitempty"`
	AssetStatus string    `json:"asset_status,omitempty"`
	RiskScore   *int      `json:"risk_score,omitempty"`
	// Depth is the SHORTEST hop count from the root, so a node reachable by
	// several routes is placed once, at the distance a person would say it is.
	Depth  int  `json:"depth"`
	IsRoot bool `json:"is_root"`
}

// Neighbourhood is the graph the Relationships tab and (from 2.9) the map draw.
type Neighbourhood struct {
	RootAssetID    uuid.UUID           `json:"root_asset_id"`
	Depth          int                 `json:"depth"`
	IncludePending bool                `json:"include_pending"`
	Nodes          []NeighbourhoodNode `json:"nodes"`
	Edges          []RelationshipEdge  `json:"edges"`
	// Truncated says the caps bit. When it is true the graph below is a
	// PREFIX of the real one and must be labelled as such wherever it is drawn.
	Truncated bool `json:"truncated"`
	// TotalNodes / TotalEdges are what the traversal actually found, which is
	// what `nodes`/`edges` would have been without the caps.
	TotalNodes int `json:"total_nodes"`
	TotalEdges int `json:"total_edges"`
	NodeCap    int `json:"node_cap"`
	EdgeCap    int `json:"edge_cap"`
}

// ImpactDepthCount is how many assets sit at one distance from the root.
type ImpactDepthCount struct {
	Depth int `json:"depth"`
	Count int `json:"count"`
}

// ImpactResult is the answer to "what breaks if this changes".
type ImpactResult struct {
	RootAssetID uuid.UUID `json:"root_asset_id"`
	Direction   string    `json:"direction"`
	Depth       int       `json:"depth"`
	// Types is the impact-bearing vocabulary the closure walked, echoed so a
	// consumer can see which question was answered (ADR-0003 D5).
	Types         []string            `json:"types"`
	Nodes         []NeighbourhoodNode `json:"nodes"`
	CountsByDepth []ImpactDepthCount  `json:"counts_by_depth"`
	Total         int                 `json:"total"`
	Truncated     bool                `json:"truncated"`
	NodeCap       int                 `json:"node_cap"`
}

// DeclaredEdgeInput is the body of a user-asserted edge.
type DeclaredEdgeInput struct {
	Type        string    `json:"type"`
	PeerAssetID uuid.UUID `json:"peer_asset_id"`
	// Direction says which end the asset in the path is. `out` (the default)
	// makes it the from end. A user declaring "this VM is hosted on that
	// hypervisor" from the hypervisor's page needs `in`, and without it they
	// would have to navigate to the other asset to say the same thing.
	Direction  string         `json:"direction"`
	Attributes map[string]any `json:"attributes"`
	Confidence *float64       `json:"confidence"`
}

// RelationshipService reads and writes `asset_relationships`.
type RelationshipService struct {
	db *database.DB
}

// NewRelationshipService constructs the service.
func NewRelationshipService(db *database.DB) *RelationshipService {
	return &RelationshipService{db: db}
}

// ClampRelationshipPage applies the page bounds. Out-of-range falls back to the
// default rather than erroring — the same rule the merge-proposal queue uses.
func ClampRelationshipPage(limit, offset int) (int, int) {
	if limit <= 0 || limit > RelationshipMaxPageSize {
		limit = RelationshipPageSize
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// ClampNeighbourhoodDepth bounds the hop count to [1, MaxNeighbourhoodDepth].
func ClampNeighbourhoodDepth(depth int) int {
	if depth <= 0 {
		return DefaultNeighbourhoodDepth
	}
	if depth > MaxNeighbourhoodDepth {
		return MaxNeighbourhoodDepth
	}
	return depth
}

// ClampImpactDepth bounds the impact closure to [1, MaxImpactDepth].
func ClampImpactDepth(depth int) int {
	if depth <= 0 {
		return DefaultImpactDepth
	}
	if depth > MaxImpactDepth {
		return MaxImpactDepth
	}
	return depth
}

// NormalizeDirection maps a query parameter onto one of the three directions,
// defaulting to `both`.
func NormalizeDirection(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", DirectionBoth:
		return DirectionBoth, true
	case DirectionOut:
		return DirectionOut, true
	case DirectionIn:
		return DirectionIn, true
	default:
		return "", false
	}
}

// NormalizeImpactDirection maps a query parameter onto an impact direction.
//
// `downstream` is the default because it is the question the endpoint exists
// for: "if I take this down, what goes with it".
func NormalizeImpactDirection(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", ImpactDownstream:
		return ImpactDownstream, true
	case ImpactUpstream:
		return ImpactUpstream, true
	default:
		return "", false
	}
}

// ------------------------------------------------------- the one-hop list --

// peerColumns is the decoration every peer read selects. Named once so the
// three call sites cannot come to disagree about what a peer is.
const peerColumns = `
	a.id, a.display_name, a.hostname, a.class_key, a.asset_status, a.risk_score,
	(a.deleted_at IS NOT NULL OR a.asset_status = 'archived') AS deleted`

// edgeColumns is every column of an edge row, in scan order, qualified for a
// query that aliases the table `r`. edgeColumnsBare is the same list for a
// RETURNING clause, which has no alias to qualify with.
//
// Two spellings rather than one plus a string rewrite: rewriting `r.` out of
// the qualified form would also rewrite any literal that happened to contain
// it, and a scan order that silently shifts is a whole column of wrong values
// with no error anywhere.
const edgeColumns = `
	r.id, r.tenant_id, r.from_asset_id, r.to_asset_id, r.type, r.source_kind,
	COALESCE(r.source_ref, ''), r.confidence, r.status, r.attributes::text,
	r.first_seen_at, r.last_seen_at, r.observation_count,
	r.created_by, r.approved_by, r.approved_at`

const edgeColumnsBare = `
	id, tenant_id, from_asset_id, to_asset_id, type, source_kind,
	COALESCE(source_ref, ''), confidence, status, attributes::text,
	first_seen_at, last_seen_at, observation_count,
	created_by, approved_by, approved_at`

// ListForAsset returns one page of the asset's edges with each peer decorated,
// plus the total the page was cut from.
//
// The total is counted over the SAME predicate in the SAME transaction as the
// page, so a count and a list can never describe two different worlds — the
// rule the merge-proposal queue already follows and the reason its header stopped
// lying about how much work was waiting.
func (s *RelationshipService) ListForAsset(
	ctx context.Context, tenantID, assetID uuid.UUID, opts RelationshipListOptions,
) ([]RelationshipEdge, int, error) {
	direction, ok := NormalizeDirection(opts.Direction)
	if !ok {
		return nil, 0, fmt.Errorf("direction must be out, in or both")
	}
	if opts.Type != "" && !relationships.Type(opts.Type).Valid() {
		return nil, 0, fmt.Errorf("%w: %q", ErrRelationshipUnknownType, opts.Type)
	}
	limit, offset := ClampRelationshipPage(opts.Limit, opts.Offset)

	where, args := edgePredicate(tenantID, assetID, direction, opts.Type, opts.Status)

	var (
		edges []RelationshipEdge
		total int
	)
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM asset_relationships r WHERE `+where, args...,
		).Scan(&total); err != nil {
			return fmt.Errorf("count relationships: %w", err)
		}
		pageArgs := append(append([]any{}, args...), limit, offset)
		rows, err := tx.QueryContext(ctx, `
			SELECT `+edgeColumns+`
			FROM asset_relationships r
			WHERE `+where+`
			ORDER BY r.last_seen_at DESC, r.id
			LIMIT $`+fmt.Sprint(len(args)+1)+` OFFSET $`+fmt.Sprint(len(args)+2),
			pageArgs...)
		if err != nil {
			return fmt.Errorf("query relationships: %w", err)
		}
		defer func() { _ = rows.Close() }()

		peerIDs := map[uuid.UUID]struct{}{}
		for rows.Next() {
			e, err := scanEdge(rows)
			if err != nil {
				return err
			}
			decorateDirection(&e, assetID)
			peerIDs[peerOf(e, assetID)] = struct{}{}
			edges = append(edges, e)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("scan relationships: %w", err)
		}
		// One read for every peer on the page, not one per row: a page of fifty
		// edges is fifty round trips in the naive form, for one tab.
		peers, err := loadPeers(ctx, tx, tenantID, keysOf(peerIDs))
		if err != nil {
			return err
		}
		for i := range edges {
			if p, ok := peers[peerOf(edges[i], assetID)]; ok {
				cp := p
				edges[i].Peer = &cp
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if edges == nil {
		edges = []RelationshipEdge{}
	}
	return edges, total, nil
}

// edgePredicate builds the WHERE clause and its arguments for the one-hop list.
func edgePredicate(tenantID, assetID uuid.UUID, direction, edgeType, status string) (string, []any) {
	args := []any{tenantID, assetID}
	var b strings.Builder
	b.WriteString("r.tenant_id = $1 AND ")
	switch direction {
	case DirectionOut:
		b.WriteString("r.from_asset_id = $2")
	case DirectionIn:
		b.WriteString("r.to_asset_id = $2")
	default:
		b.WriteString("(r.from_asset_id = $2 OR r.to_asset_id = $2)")
	}
	if edgeType != "" {
		args = append(args, edgeType)
		fmt.Fprintf(&b, " AND r.type = $%d", len(args))
	}
	if status != "" {
		args = append(args, status)
		fmt.Fprintf(&b, " AND r.status = $%d", len(args))
	} else {
		// No status filter does NOT mean "every row". A rejected edge is a
		// decision someone recorded — re-showing it on the tab would invite the
		// same reviewer to reject it again every time they visit.
		b.WriteString(" AND r.status <> 'rejected'")
	}
	return b.String(), args
}

// decorateDirection stamps the direction and the label an edge reads as from
// the asset the request was about.
func decorateDirection(e *RelationshipEdge, assetID uuid.UUID) {
	if e.FromAssetID == assetID {
		e.Direction = DirectionOut
		e.Label = e.Type
		return
	}
	e.Direction = DirectionIn
	e.Label = relationships.Type(e.Type).Reverse()
}

func peerOf(e RelationshipEdge, assetID uuid.UUID) uuid.UUID {
	if e.FromAssetID == assetID {
		return e.ToAssetID
	}
	return e.FromAssetID
}

// ------------------------------------------------------------ neighbourhood --

// Neighbourhood walks out to `depth` hops and returns the nodes and the edges
// between them.
//
// Cycle safety is the recursion's `UNION` over `(asset_id, depth)` plus the
// depth bound, NOT a visited-path array. Carrying the path defeats the
// deduplication entirely — every route through a node carries a different path,
// so every route produces a row and a dense graph goes exponential. That is the
// exact bug the query language's traversal hit (QUERY_LANGUAGE A7: 340 rows for
// a graph of 16 nodes, 16 rows after the fix), and it is fixed here the same
// way. Termination does not need the path: the depth bound is what stops the
// walk, and a route that revisits a node reaches nothing a shorter one does not.
func (s *RelationshipService) Neighbourhood(
	ctx context.Context, tenantID, assetID uuid.UUID, depth int, includePending bool,
) (*Neighbourhood, error) {
	depth = ClampNeighbourhoodDepth(depth)
	out := &Neighbourhood{
		RootAssetID:    assetID,
		Depth:          depth,
		IncludePending: includePending,
		Nodes:          []NeighbourhoodNode{},
		Edges:          []RelationshipEdge{},
		NodeCap:        NeighbourhoodNodeCap,
		EdgeCap:        NeighbourhoodEdgeCap,
	}
	// Active only by default (ADR-0006 D4 greys pending edges when they are
	// asked for). A pending edge is something nobody has agreed is true, and a
	// map that draws it like the rest states it as fact.
	statuses := []string{EdgeStatusActive}
	if includePending {
		statuses = append(statuses, EdgeStatusPending)
	}

	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		nodeIDs, depths, total, err := neighbourhoodNodes(ctx, tx, tenantID, assetID, depth, statuses)
		if err != nil {
			return err
		}
		out.TotalNodes = total
		if total > len(nodeIDs) {
			out.Truncated = true
		}

		peers, err := loadPeers(ctx, tx, tenantID, nodeIDs)
		if err != nil {
			return err
		}
		for _, id := range nodeIDs {
			n := NeighbourhoodNode{AssetID: id, Depth: depths[id], IsRoot: id == assetID}
			if p, ok := peers[id]; ok {
				n.DisplayName, n.ClassKey, n.AssetStatus, n.RiskScore = p.DisplayName, p.ClassKey, p.AssetStatus, p.RiskScore
			}
			out.Nodes = append(out.Nodes, n)
		}

		// Edges are those with BOTH ends in the node set that was actually
		// returned. Drawing an edge to a node the cap removed would render as a
		// line into empty space.
		edges, totalEdges, err := edgesAmong(ctx, tx, tenantID, nodeIDs, statuses)
		if err != nil {
			return err
		}
		out.Edges, out.TotalEdges = edges, totalEdges
		if totalEdges > len(edges) {
			out.Truncated = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// neighbourhoodNodes runs the recursive CTE and returns the capped node list in
// depth order, the shortest depth of each, and the untruncated total.
func neighbourhoodNodes(
	ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, depth int, statuses []string,
) ([]uuid.UUID, map[uuid.UUID]int, int, error) {
	rows, err := tx.QueryContext(ctx, `
		WITH RECURSIVE walk(asset_id, depth) AS (
			SELECT $2::uuid, 0
		  UNION
			SELECT CASE WHEN r.from_asset_id = w.asset_id THEN r.to_asset_id ELSE r.from_asset_id END,
			       w.depth + 1
			  FROM walk w
			  JOIN asset_relationships r
			    ON r.tenant_id = $1
			   AND (r.from_asset_id = w.asset_id OR r.to_asset_id = w.asset_id)
			   AND r.status = ANY($4)
			 WHERE w.depth < $3
		),
		reached AS (
			SELECT asset_id, MIN(depth) AS depth FROM walk GROUP BY asset_id
		),
		live AS (
			SELECT reached.asset_id, reached.depth
			  FROM reached
			  JOIN assets a ON a.tenant_id = $1 AND a.id = reached.asset_id
			 WHERE a.deleted_at IS NULL
		)
		SELECT (SELECT count(*) FROM live) AS total, live.asset_id, live.depth
		  FROM live
		 ORDER BY live.depth, live.asset_id
		 LIMIT $5`,
		tenantID, assetID, depth, pq.Array(statuses), NeighbourhoodNodeCap)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("walk neighbourhood: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var (
		ids    []uuid.UUID
		depths = map[uuid.UUID]int{}
		total  int
	)
	for rows.Next() {
		var (
			id uuid.UUID
			d  int
		)
		if err := rows.Scan(&total, &id, &d); err != nil {
			return nil, nil, 0, fmt.Errorf("scan neighbourhood node: %w", err)
		}
		ids = append(ids, id)
		depths[id] = d
	}
	if err := rows.Err(); err != nil {
		return nil, nil, 0, fmt.Errorf("scan neighbourhood: %w", err)
	}
	return ids, depths, total, nil
}

// edgesAmong returns the edges whose BOTH ends are in `ids`, capped.
func edgesAmong(
	ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, ids []uuid.UUID, statuses []string,
) ([]RelationshipEdge, int, error) {
	edges := []RelationshipEdge{}
	if len(ids) == 0 {
		return edges, 0, nil
	}
	rows, err := tx.QueryContext(ctx, `
		WITH scoped AS (
			SELECT * FROM asset_relationships r
			 WHERE r.tenant_id = $1
			   AND r.from_asset_id = ANY($2)
			   AND r.to_asset_id = ANY($2)
			   AND r.status = ANY($3)
		)
		SELECT (SELECT count(*) FROM scoped) AS total, `+edgeColumns+`
		  FROM scoped r
		 ORDER BY r.last_seen_at DESC, r.id
		 LIMIT $4`,
		tenantID, pq.Array(ids), pq.Array(statuses), NeighbourhoodEdgeCap)
	if err != nil {
		return nil, 0, fmt.Errorf("query neighbourhood edges: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var total int
	for rows.Next() {
		e, err := scanEdgeWithTotal(rows, &total)
		if err != nil {
			return nil, 0, err
		}
		// No `direction`/`label` here on purpose: a graph edge has no
		// privileged end, and stamping one would make the same row read
		// differently depending on which node the reader started from.
		edges = append(edges, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("scan neighbourhood edges: %w", err)
	}
	return edges, total, nil
}

// ------------------------------------------------------------------ impact --

// Impact is the depth-capped closure over the impact-bearing types (ADR-0003
// D5, as amended.
//
// Direction is PER TYPE, and that is the amendment. The naive reading — "walk
// every edge backwards" — is right for the six types that point from the
// dependent to the thing it rests on: an application `runs_on` a server, so
// "what breaks if the SERVER dies" follows that edge from its to-end back to
// its from-end. It is exactly wrong for the types that point the other way. A
// controller `manages` an access point and a virtual network `contains` a
// subnet; walking those backwards answered "what breaks if this controller
// dies" with NOTHING, and answered it of the access point with the controller.
// The registry declares the direction of each type
// ([relationships.ImpactDirectionOf]); this reads it rather than deciding.
//
// `impacts` is crossed ONCE and only as the LAST hop of a downstream answer: it
// names a business service, which is where a blast-radius sentence ends, and
// continuing through it would walk whatever else that service happens to touch
// and turn a specific answer into a vague one.
//
// Stating the rule on the DOWNSTREAM path shape is what keeps `upstream` an
// exact mirror, and getting this wrong is how the mirror first broke here. A
// naive "stop as soon as you cross an `impacts` edge, in both walks" is not
// symmetric: downstream reaches the service at the END of a long chain, while
// upstream meets that same edge FIRST and would stop dead on it — so
// `downstream(hypervisor)` contained the payroll service while
// `upstream(payroll)` did not contain the hypervisor. The mirror of "last hop
// downstream" is "first hop upstream", and that is what the two clauses below
// say. The property is asserted directly by
// TestIntegration_Impact_UpstreamIsTheExactMirror.
func (s *RelationshipService) Impact(
	ctx context.Context, tenantID, assetID uuid.UUID, direction string, depth int,
) (*ImpactResult, error) {
	dir, ok := NormalizeImpactDirection(direction)
	if !ok {
		return nil, fmt.Errorf("direction must be upstream or downstream")
	}
	depth = ClampImpactDepth(depth)
	out := &ImpactResult{
		RootAssetID:   assetID,
		Direction:     dir,
		Depth:         depth,
		Types:         relationships.ImpactBearingStrings(),
		Nodes:         []NeighbourhoodNode{},
		CountsByDepth: []ImpactDepthCount{},
		NodeCap:       ImpactNodeCap,
	}

	// The two halves of the vocabulary, and the swap that makes upstream the
	// mirror. One CTE with the direction carried in PARAMETERS rather than two
	// hand-written spellings: the direction is genuinely per type now, so two
	// spellings would be two copies of a nine-entry table to keep in step, and
	// the mirror would be a property somebody has to maintain instead of one
	// the swap gives for free.
	reverseWalked := relationships.ImpactReverseStrings()
	forwardWalked := relationships.ImpactForwardStrings()
	if dir == ImpactUpstream {
		reverseWalked, forwardWalked = forwardWalked, reverseWalked
	}

	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			WITH RECURSIVE walk(asset_id, depth, crossed) AS (
				SELECT $2::uuid, 0, false
			  UNION
				-- Which end this step lands on is decided by which arm matched,
				-- so the CASE and the join condition read off the SAME array.
				-- They cannot be allowed to disagree: the registry test asserts
				-- the two arrays are disjoint and together cover the
				-- vocabulary, which is what makes this CASE total.
				SELECT CASE WHEN r.type = ANY($4) THEN r.from_asset_id ELSE r.to_asset_id END,
				       w.depth + 1,
				       w.crossed OR r.type = ANY($6)
				  FROM walk w
				  JOIN asset_relationships r
				    ON r.tenant_id = $1
				   AND r.status = 'active'
				   AND (
				        (r.type = ANY($4) AND r.to_asset_id   = w.asset_id)
				     OR (r.type = ANY($5) AND r.from_asset_id = w.asset_id)
				   )
				 WHERE w.depth < $3
				   -- DOWNSTREAM: a terminal edge is the LAST hop, so nothing is
				   -- traversed once one has been crossed.
				   AND ($7 OR NOT w.crossed)
				   -- UPSTREAM: the mirror of "last hop downstream" is "first hop
				   -- upstream", so a terminal edge may only be step one — and
				   -- after it the walk CONTINUES, which is what makes the two
				   -- closures exact reflections of each other.
				   AND (NOT $7 OR w.depth = 0 OR r.type <> ALL($6))
			),
			reached AS (
				SELECT asset_id, MIN(depth) AS depth
				  FROM walk
				 -- The root is excluded from its own closure: "this asset is
				 -- affected by a change to this asset" is true and useless, and
				 -- a cycle would otherwise return it at some positive depth as
				 -- if it were a separate consequence.
				 WHERE asset_id <> $2::uuid
				 GROUP BY asset_id
			),
			live AS (
				SELECT reached.asset_id, reached.depth
				  FROM reached
				  JOIN assets a ON a.tenant_id = $1 AND a.id = reached.asset_id
				 WHERE a.deleted_at IS NULL
			)
			SELECT (SELECT count(*) FROM live) AS total, live.asset_id, live.depth
			  FROM live
			 ORDER BY live.depth, live.asset_id
			 LIMIT $8`,
			tenantID, assetID, depth,
			pq.Array(reverseWalked), pq.Array(forwardWalked),
			pq.Array(relationships.ImpactTerminalStrings()), dir == ImpactUpstream, ImpactNodeCap)
		if err != nil {
			return fmt.Errorf("walk impact: %w", err)
		}
		defer func() { _ = rows.Close() }()

		var ids []uuid.UUID
		depths := map[uuid.UUID]int{}
		for rows.Next() {
			var (
				id uuid.UUID
				d  int
			)
			if err := rows.Scan(&out.Total, &id, &d); err != nil {
				return fmt.Errorf("scan impact node: %w", err)
			}
			ids = append(ids, id)
			depths[id] = d
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("scan impact: %w", err)
		}
		out.Truncated = out.Total > len(ids)

		peers, err := loadPeers(ctx, tx, tenantID, ids)
		if err != nil {
			return err
		}
		byDepth := map[int]int{}
		for _, id := range ids {
			n := NeighbourhoodNode{AssetID: id, Depth: depths[id]}
			if p, ok := peers[id]; ok {
				n.DisplayName, n.ClassKey, n.AssetStatus, n.RiskScore = p.DisplayName, p.ClassKey, p.AssetStatus, p.RiskScore
			}
			out.Nodes = append(out.Nodes, n)
			byDepth[depths[id]]++
		}
		// Counts are over the RETURNED nodes. When `truncated` is true they are
		// a floor, which the flag is there to say — a count that silently
		// described a capped set as the whole set is the failure this endpoint
		// is written to avoid.
		for d := 1; d <= depth; d++ {
			if c := byDepth[d]; c > 0 {
				out.CountsByDepth = append(out.CountsByDepth, ImpactDepthCount{Depth: d, Count: c})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ------------------------------------------------------------------ writes --

// Declare records a user-asserted edge.
//
// ADR-0003 D3: "A user with `assets.update` asserting an edge is the same as
// editing an attribute" — so a declared edge between two monitored assets is
// `active` immediately. It is only `pending` when an END is still pending, and
// then it resolves with that asset exactly as a measured edge does.
func (s *RelationshipService) Declare(
	ctx context.Context, tenantID, assetID, actorUserID uuid.UUID, in DeclaredEdgeInput,
) (*RelationshipEdge, error) {
	edgeType := relationships.Type(strings.TrimSpace(in.Type))
	if !edgeType.Valid() {
		return nil, fmt.Errorf("%w: %q is not one of %s",
			ErrRelationshipUnknownType, in.Type, strings.Join(relationships.Strings(), ", "))
	}
	if in.PeerAssetID == uuid.Nil {
		return nil, fmt.Errorf("%w: peer_asset_id is required", ErrRelationshipPeerNotFound)
	}
	if in.PeerAssetID == assetID {
		return nil, ErrRelationshipSelfEdge
	}
	direction, ok := NormalizeDirection(in.Direction)
	if !ok || direction == DirectionBoth {
		// `both` is not a thing to store. An edge has one canonical direction
		// (ADR-0003 D1) and a declaration that will not say which way it points
		// is not a declaration.
		direction = DirectionOut
	}
	from, to := assetID, in.PeerAssetID
	if direction == DirectionIn {
		from, to = in.PeerAssetID, assetID
	}
	confidence := 1.0
	if in.Confidence != nil {
		if *in.Confidence < 0 || *in.Confidence > 1 {
			return nil, fmt.Errorf("confidence must be between 0 and 1")
		}
		confidence = *in.Confidence
	}
	attrs := in.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrJSON, err := json.Marshal(attrs)
	if err != nil {
		return nil, fmt.Errorf("marshal attributes: %w", err)
	}

	var edge *RelationshipEdge
	err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		statuses, err := assetStatuses(ctx, tx, tenantID, []uuid.UUID{from, to})
		if err != nil {
			return err
		}
		if len(statuses) != 2 {
			return ErrRelationshipPeerNotFound
		}
		// An edge is active only when BOTH ends are monitored — the same rule
		// `promoteEdgesForApprovedAssets` enforces from the other side.
		status := EdgeStatusPending
		if statuses[from] == identity.StatusMonitoring && statuses[to] == identity.StatusMonitoring {
			status = EdgeStatusActive
		}
		var approvedAt any
		if status == EdgeStatusActive {
			approvedAt = time.Now().UTC()
		}

		row := tx.QueryRowContext(ctx, `
			INSERT INTO asset_relationships
				(tenant_id, from_asset_id, to_asset_id, type, source_kind, source_ref,
				 confidence, status, attributes, created_by, approved_by, approved_at)
			VALUES ($1, $2, $3, $4, 'declared', $5, $6, $7, $8::jsonb, $9, $10, $11)
			ON CONFLICT (tenant_id, from_asset_id, to_asset_id, type) DO NOTHING
			RETURNING `+edgeColumnsBare,
			tenantID, from, to, string(edgeType), "user:"+actorUserID.String(),
			confidence, status, attrJSON, nullUUID(actorUserID),
			nullableApprover(status, actorUserID), approvedAt)

		e, err := scanEdgeRow(row)
		if errors.Is(err, sql.ErrNoRows) {
			// DO NOTHING swallowed it: the triple already exists. Answering
			// "created" here would be a lie the UI would render as a second row.
			return ErrRelationshipExists
		}
		if err != nil {
			return fmt.Errorf("insert relationship: %w", err)
		}
		decorateDirection(&e, assetID)
		if err := writeRelationshipHistory(ctx, tx, tenantID, e, actorUserID, string(identity.ActionEdgeAdded), map[string]any{
			"status": status,
		}); err != nil {
			return err
		}
		edge = &e
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.attachPeer(ctx, tenantID, assetID, edge); err != nil {
		return nil, err
	}
	return edge, nil
}

// Delete removes a DECLARED edge.
//
// Measured, imported and inferred edges are refused with
// [ErrRelationshipNotDeclared] — see its comment for why a delete that the next
// collector run undoes is worse than a refusal.
func (s *RelationshipService) Delete(
	ctx context.Context, tenantID, assetID, edgeID, actorUserID uuid.UUID,
) error {
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT `+edgeColumns+`
			  FROM asset_relationships r
			 WHERE r.tenant_id = $1 AND r.id = $2
			   AND (r.from_asset_id = $3 OR r.to_asset_id = $3)`,
			tenantID, edgeID, assetID)
		e, err := scanEdgeRow(row)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRelationshipNotFound
		}
		if err != nil {
			return fmt.Errorf("read relationship: %w", err)
		}
		if e.SourceKind != SourceKindDeclared {
			return fmt.Errorf("%w: this edge is %s", ErrRelationshipNotDeclared, e.SourceKind)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM asset_relationships WHERE tenant_id = $1 AND id = $2`, tenantID, edgeID); err != nil {
			return fmt.Errorf("delete relationship: %w", err)
		}
		return writeRelationshipHistory(ctx, tx, tenantID, e, actorUserID, string(identity.ActionEdgeRemoved), nil)
	})
}

// -------------------------------------------------------------- proposals --

// ListProposals returns the pending edges a PERSON has to decide, and the total.
//
// The predicate is "pending, and both ends are monitored". That is not the same
// as "pending", and the difference is the whole design:
//
//   - A pending edge with a pending END is not a relationship question. It is
//     waiting on the asset approval, and `promoteEdgesForApprovedAssets` will
//     activate it the moment the asset is accepted (ADR-0003 D3: "Approving the
//     asset approves what was observed about it"). Listing it here would ask the
//     reviewer the same question twice and let them answer it two ways.
//   - A pending edge whose ends are BOTH monitored is stuck: nothing in the
//     system will ever promote it. That is either an `inferred` edge, which D3
//     says enters as a proposal by design, or an edge that arrived pending for
//     review from an import. Both need a human, and without this queue both
//     would sit in the table forever.
func (s *RelationshipService) ListProposals(
	ctx context.Context, tenantID uuid.UUID, limit, offset int,
) ([]RelationshipEdge, int, error) {
	limit, offset = ClampRelationshipPage(limit, offset)

	const predicate = `
		r.tenant_id = $1
		AND r.status = 'pending'
		AND EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = $1 AND a.id = r.from_asset_id
		                                     AND a.deleted_at IS NULL AND a.asset_status = 'monitoring')
		AND EXISTS (SELECT 1 FROM assets b WHERE b.tenant_id = $1 AND b.id = r.to_asset_id
		                                     AND b.deleted_at IS NULL AND b.asset_status = 'monitoring')`

	var (
		edges []RelationshipEdge
		total int
	)
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM asset_relationships r WHERE `+predicate, tenantID).Scan(&total); err != nil {
			return fmt.Errorf("count relationship proposals: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT `+edgeColumns+`
			  FROM asset_relationships r
			 WHERE `+predicate+`
			 ORDER BY r.first_seen_at DESC, r.id
			 LIMIT $2 OFFSET $3`, tenantID, limit, offset)
		if err != nil {
			return fmt.Errorf("query relationship proposals: %w", err)
		}
		defer func() { _ = rows.Close() }()

		ends := map[uuid.UUID]struct{}{}
		for rows.Next() {
			e, err := scanEdge(rows)
			if err != nil {
				return err
			}
			ends[e.FromAssetID] = struct{}{}
			ends[e.ToAssetID] = struct{}{}
			edges = append(edges, e)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("scan relationship proposals: %w", err)
		}
		// BOTH ends are decorated here, unlike the asset-page list: the reviewer
		// is on Approvals with no asset around them for context, and
		// "<something> depends on <something>" is not a reviewable sentence.
		peers, err := loadPeers(ctx, tx, tenantID, keysOf(ends))
		if err != nil {
			return err
		}
		for i := range edges {
			if p, ok := peers[edges[i].FromAssetID]; ok {
				cp := p
				edges[i].From = &cp
			}
			if p, ok := peers[edges[i].ToAssetID]; ok {
				cp := p
				edges[i].To = &cp
			}
			edges[i].Label = edges[i].Type
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if edges == nil {
		edges = []RelationshipEdge{}
	}
	return edges, total, nil
}

// Decide accepts or rejects one proposal, stamping the actor and writing
// history.
//
// ACCEPTING re-checks that both ends are monitored. The proposal queue only
// lists edges that already satisfy that, so the check is redundant for the
// Approvals flow and is not redundant for the API: the asset page's
// Relationships tab offers Accept from the pending asset's OWN side, where the
// only end it has decorated is the monitored peer. Without the check, one click
// there produced an `active` edge to an asset nobody had admitted — which
// ADR-0003 D1 forbids ("an edge whose either endpoint is pending is itself
// pending") and which the impact closure would then walk.
//
// REJECTING is unconditional. "This claim is wrong" is answerable whatever the
// endpoints are doing, and refusing it would leave the edge with no way out.
func (s *RelationshipService) Decide(
	ctx context.Context, tenantID, edgeID, actorUserID uuid.UUID, accept bool,
) (*RelationshipEdge, error) {
	status, action := EdgeStatusRejected, string(identity.ActionEdgeRejected)
	if accept {
		status, action = EdgeStatusActive, string(identity.ActionEdgeAccepted)
	}

	var edge *RelationshipEdge
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// SELECT ... FOR UPDATE, then check: two reviewers on the same stale
		// page must not both get a 200 for opposite answers.
		row := tx.QueryRowContext(ctx, `
			SELECT `+edgeColumns+`
			  FROM asset_relationships r
			 WHERE r.tenant_id = $1 AND r.id = $2
			 FOR UPDATE`, tenantID, edgeID)
		current, err := scanEdgeRow(row)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRelationshipNotFound
		}
		if err != nil {
			return fmt.Errorf("read relationship: %w", err)
		}
		if current.Status != EdgeStatusPending {
			return fmt.Errorf("%w: it is %s", ErrRelationshipDecided, current.Status)
		}
		if accept {
			statuses, err := assetStatuses(ctx, tx, tenantID, []uuid.UUID{current.FromAssetID, current.ToAssetID})
			if err != nil {
				return err
			}
			for _, end := range []uuid.UUID{current.FromAssetID, current.ToAssetID} {
				if statuses[end] != identity.StatusMonitoring {
					// Named, not just refused: the reviewer has to know which
					// asset to go and approve, and that approving it is what
					// resolves this.
					return fmt.Errorf("%w: asset %s is %q", ErrRelationshipEndPending, end,
						firstNonEmpty(statuses[end], "missing"))
				}
			}
		}

		row = tx.QueryRowContext(ctx, `
			UPDATE asset_relationships
			   SET status = $3, approved_by = $4, approved_at = NOW(), updated_at = NOW()
			 WHERE tenant_id = $1 AND id = $2
			RETURNING `+edgeColumnsBare,
			tenantID, edgeID, status, nullUUID(actorUserID))
		updated, err := scanEdgeRow(row)
		if err != nil {
			return fmt.Errorf("decide relationship: %w", err)
		}
		updated.Label = updated.Type
		if err := writeRelationshipHistory(ctx, tx, tenantID, updated, actorUserID, action, map[string]any{
			"from_status": current.Status,
			"to_status":   status,
		}); err != nil {
			return err
		}
		edge = &updated
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.attachPeer(ctx, tenantID, uuid.Nil, edge); err != nil {
		return nil, err
	}
	return edge, nil
}

// ---------------------------------------------------------------- plumbing --

// attachPeer decorates both ends of a single edge after its own transaction has
// committed. `assetID` may be uuid.Nil, in which case only From/To are filled.
func (s *RelationshipService) attachPeer(ctx context.Context, tenantID, assetID uuid.UUID, e *RelationshipEdge) error {
	if e == nil {
		return nil
	}
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		peers, err := loadPeers(ctx, tx, tenantID, []uuid.UUID{e.FromAssetID, e.ToAssetID})
		if err != nil {
			return err
		}
		if p, ok := peers[e.FromAssetID]; ok {
			cp := p
			e.From = &cp
		}
		if p, ok := peers[e.ToAssetID]; ok {
			cp := p
			e.To = &cp
		}
		if assetID != uuid.Nil {
			if p, ok := peers[peerOf(*e, assetID)]; ok {
				cp := p
				e.Peer = &cp
			}
		}
		return nil
	})
}

// loadPeers decorates a set of asset ids in one read, with each asset's
// strongest identifier.
//
// The identifier comes from a LATERAL, not a join: a join would multiply the
// asset row by its identifier count, and a per-asset query would be N+1 for a
// page of fifty.
func loadPeers(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]RelationshipPeer, error) {
	out := map[uuid.UUID]RelationshipPeer{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT `+peerColumns+`, COALESCE(ident.label, '')
		  FROM assets a
		  LEFT JOIN LATERAL (
		        SELECT i.kind || ':' || i.value AS label
		          FROM asset_identifiers i
		         WHERE i.tenant_id = a.tenant_id AND i.asset_id = a.id
		         ORDER BY i.confidence DESC, i.last_seen_at DESC, i.id
		         LIMIT 1
		  ) ident ON true
		 WHERE a.tenant_id = $1 AND a.id = ANY($2)`,
		tenantID, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("decorate relationship peers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			p         RelationshipPeer
			name      sql.NullString
			hostname  sql.NullString
			classKey  sql.NullString
			status    sql.NullString
			riskScore sql.NullInt64
			label     string
		)
		if err := rows.Scan(&p.AssetID, &name, &hostname, &classKey, &status, &riskScore, &p.Deleted, &label); err != nil {
			return nil, fmt.Errorf("scan relationship peer: %w", err)
		}
		// Hostname is the fallback display name, the same order the asset page
		// and every list row use. A peer rendered as a bare UUID is a peer
		// nobody can decide anything about.
		p.DisplayName = firstNonEmpty(name.String, hostname.String)
		p.ClassKey = classKey.String
		p.AssetStatus = status.String
		p.PrimaryIdentifier = label
		if riskScore.Valid {
			v := int(riskScore.Int64)
			p.RiskScore = &v
		}
		out[p.AssetID] = p
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan relationship peers: %w", err)
	}
	return out, nil
}

// assetStatuses reads the lifecycle status of each named, live asset.
func assetStatuses(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	rows, err := tx.QueryContext(ctx,
		`SELECT id, asset_status FROM assets
		  WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL`,
		tenantID, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read asset statuses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			id uuid.UUID
			st string
		)
		if err := rows.Scan(&id, &st); err != nil {
			return nil, fmt.Errorf("scan asset status: %w", err)
		}
		out[id] = st
	}
	return out, rows.Err()
}

// writeRelationshipHistory records the edge on the FROM asset's timeline.
//
// One row, not two. ADR-0003's consequences say edges "write `asset_history` on
// the from asset", and the edge is stored once in the canonical direction, so
// the from asset is the one place the change is unambiguously attributed.
func writeRelationshipHistory(
	ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, e RelationshipEdge, actor uuid.UUID,
	action string, extra map[string]any,
) error {
	changes := map[string]any{
		"kind":            "relationship",
		"relationship_id": e.ID.String(),
		"type":            e.Type,
		"from_asset_id":   e.FromAssetID.String(),
		"to_asset_id":     e.ToAssetID.String(),
		"source_kind":     e.SourceKind,
	}
	for k, v := range extra {
		changes[k] = v
	}
	payload, err := json.Marshal(changes)
	if err != nil {
		return fmt.Errorf("marshal %s history: %w", action, err)
	}
	source := "manual"
	if e.SourceKind == SourceKindMeasured || e.SourceKind == SourceKindInferred {
		source = "discovery"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_history (asset_id, tenant_id, actor_user_id, source, action, changes_json)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		e.FromAssetID, tenantID, nullUUID(actor), source, action, payload); err != nil {
		return fmt.Errorf("record %s: %w", action, err)
	}
	return nil
}

// The edge scanners take the package's existing [rowScanner] (declared beside
// the merge-proposal scanner), which both *sql.Rows and *sql.Row satisfy.

func scanEdge(rs rowScanner) (RelationshipEdge, error) {
	return scanEdgeInto(rs, nil)
}

func scanEdgeWithTotal(rs rowScanner, total *int) (RelationshipEdge, error) {
	return scanEdgeInto(rs, total)
}

func scanEdgeRow(rs rowScanner) (RelationshipEdge, error) {
	return scanEdgeInto(rs, nil)
}

func scanEdgeInto(rs rowScanner, total *int) (RelationshipEdge, error) {
	var (
		e          RelationshipEdge
		sourceRef  string
		attrsJSON  string
		createdBy  uuid.NullUUID
		approvedBy uuid.NullUUID
		approvedAt sql.NullTime
	)
	dest := []any{
		&e.ID, &e.TenantID, &e.FromAssetID, &e.ToAssetID, &e.Type, &e.SourceKind,
		&sourceRef, &e.Confidence, &e.Status, &attrsJSON,
		&e.FirstSeenAt, &e.LastSeenAt, &e.ObservationCount,
		&createdBy, &approvedBy, &approvedAt,
	}
	if total != nil {
		dest = append([]any{total}, dest...)
	}
	if err := rs.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return e, err
		}
		return e, fmt.Errorf("scan relationship: %w", err)
	}
	e.SourceRef = sourceRef
	if attrsJSON != "" && attrsJSON != "{}" {
		var attrs map[string]any
		if err := json.Unmarshal([]byte(attrsJSON), &attrs); err == nil {
			e.Attributes = attrs
		}
	}
	if createdBy.Valid {
		v := createdBy.UUID
		e.CreatedBy = &v
	}
	if approvedBy.Valid {
		v := approvedBy.UUID
		e.ApprovedBy = &v
	}
	if approvedAt.Valid {
		v := approvedAt.Time
		e.ApprovedAt = &v
	}
	return e, nil
}

func keysOf(m map[uuid.UUID]struct{}) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func nullableApprover(status string, actor uuid.UUID) any {
	if status != EdgeStatusActive {
		return nil
	}
	return nullUUID(actor)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
