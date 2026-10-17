package services

// Physical cabling on the map (DCIM BUILD_PLAN row 3.6; asset-inventory
// ADR-0006 D4, ADR-0010 D6).
//
// Two additive reads ride on the map's existing endpoints:
//
//   - Each LOGICAL edge of the neighbourhood names the interface it was seen
//     on at each end, when the observation carried one. LLDP is the producer
//     today: the SNMP and PAN-OS collectors record `local_port` (the subject's
//     port, the edge's FROM end — both write SubjectToPeer) and `remote_port`
//     (the neighbour's port, the TO end) in the edge's attributes. Those are
//     NAMES; this resolves each to the asset's interface by exact name, then
//     by exact label, and leaves the id off when the name matches nothing or
//     matches two interfaces. A guessed port would send "Show physical path"
//     to the wrong cable.
//
//   - The neighbourhood and the topology carry the CABLE PATHS between the
//     assets they show, read from row 3.2's cached `cable_paths` (never
//     recomputed here). One entry per pair of interfaces: a complete path is
//     stored once from each end, and the two are the same cable run.
//
// Only interface-to-interface paths are drawn. A console cable or a path that
// ends on a circuit's provider network connects an asset to something the map
// has no node for.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/cablepath"
)

// Relationship attribute keys an observation uses for the interface it was
// seen on (shared/deviceinterrogation's LLDP collectors).
const (
	edgeAttrLocalPort  = "local_port"
	edgeAttrRemotePort = "remote_port"
)

// NeighbourhoodCablePath is one cable path between two assets on the map.
type NeighbourhoodCablePath struct {
	// ID is stable for the pair of interfaces: the origin interface the
	// stored path was read from (the lower of the two ids).
	ID                string    `json:"id"`
	FromAssetID       uuid.UUID `json:"from_asset_id"`
	ToAssetID         uuid.UUID `json:"to_asset_id"`
	FromInterfaceID   uuid.UUID `json:"from_interface_id"`
	FromInterfaceName string    `json:"from_interface_name"`
	ToInterfaceID     uuid.UUID `json:"to_interface_id"`
	ToInterfaceName   string    `json:"to_interface_name"`
	// CableID is the cable on the FROM interface — the first cable of the run.
	CableID    uuid.UUID `json:"cable_id"`
	CableLabel string    `json:"cable_label,omitempty"`
	// Status is the cable lifecycle across the run: `pending` when any cable
	// on it is a proposal nobody has approved (row 3.3), else `active`.
	Status string `json:"status"`
	// OperationalStatus is the worst link status on the run: `connected`
	// only when every cable is.
	OperationalStatus string `json:"operational_status"`
	CableCount        int    `json:"cable_count"`
	// PatchPanelCount / CircuitCount are the devices and circuits the run
	// passes through between the two interfaces.
	PatchPanelCount int `json:"patch_panel_count"`
	CircuitCount    int `json:"circuit_count"`
}

// TopologyCablePaths aggregates the cable paths crossing between two prefixes.
// Undirected: a cable has no dependant end, so each pair is listed once with
// the names in order.
type TopologyCablePaths struct {
	FromPrefixID   *uuid.UUID `json:"from_prefix_id"`
	FromPrefixName string     `json:"from_prefix_name"`
	ToPrefixID     *uuid.UUID `json:"to_prefix_id"`
	ToPrefixName   string     `json:"to_prefix_name"`
	Count          int        `json:"count"`
	// PendingCount is how many of them run over a cable awaiting approval.
	PendingCount int `json:"pending_count"`
}

// pathSummary is what a stored path's hops say about the run.
type pathSummary struct {
	CableIDs        []uuid.UUID
	CableCount      int
	PatchPanelCount int
	CircuitCount    int
}

// summarisePath reads a stored path (groups of hops: near ends, cables, far
// ends, …). Between two cable groups the run passes through something: a
// patch panel (its far end is a front or rear port) or a circuit (a circuit
// termination). The far end of the LAST cable is the destination, not an
// intermediate.
func summarisePath(groups [][]cablepath.Node) pathSummary {
	var s pathSummary
	seen := map[uuid.UUID]bool{}
	var cableGroups []int
	for i, g := range groups {
		if len(g) == 0 || g[0].Kind != dcim.ObjectKindCable {
			continue
		}
		cableGroups = append(cableGroups, i)
		for _, n := range g {
			if !seen[n.ID] {
				seen[n.ID] = true
				s.CableIDs = append(s.CableIDs, n.ID)
			}
		}
	}
	s.CableCount = len(cableGroups)
	for k, i := range cableGroups {
		if k == len(cableGroups)-1 || i+1 >= len(groups) || len(groups[i+1]) == 0 {
			continue
		}
		switch groups[i+1][0].Kind {
		case dcim.ObjectKindCircuitTermination:
			s.CircuitCount++
		case dcim.ObjectKindFrontPort, dcim.ObjectKindRearPort:
			s.PatchPanelCount++
		}
	}
	return s
}

// worseOperationalStatus orders link statuses: decommissioning < planned <
// connected. An unknown value counts as not connected.
func worseOperationalStatus(a, b string) string {
	rank := func(s string) int {
		switch s {
		case string(dcim.CableStatusConnected):
			return 2
		case "planned":
			return 1
		default:
			return 0
		}
	}
	if a == "" {
		return b
	}
	if rank(b) < rank(a) {
		return b
	}
	return a
}

// resolveEdgeInterfaces stamps each edge with the interfaces its observation
// names, where they resolve to exactly one interface of that end's asset.
func resolveEdgeInterfaces(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, edges []RelationshipEdge) error {
	assets := map[uuid.UUID]struct{}{}
	names := map[string]struct{}{}
	portOf := func(e RelationshipEdge, key string) string {
		v, _ := e.Attributes[key].(string)
		return strings.TrimSpace(v)
	}
	for _, e := range edges {
		if p := portOf(e, edgeAttrLocalPort); p != "" {
			assets[e.FromAssetID], names[p] = struct{}{}, struct{}{}
		}
		if p := portOf(e, edgeAttrRemotePort); p != "" {
			assets[e.ToAssetID], names[p] = struct{}{}, struct{}{}
		}
	}
	if len(names) == 0 {
		return nil
	}
	nameList := make([]string, 0, len(names))
	for n := range names {
		nameList = append(nameList, n)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT i.id, i.asset_id, i.name, COALESCE(i.label, '')
		  FROM interfaces i
		 WHERE i.tenant_id = $1
		   AND i.asset_id = ANY($2)
		   AND i.status <> 'rejected'
		   AND (i.name = ANY($3) OR i.label = ANY($3))`,
		tenantID, pq.Array(keysOf(assets)), pq.Array(nameList))
	if err != nil {
		return fmt.Errorf("resolve edge interfaces: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type hit struct {
		id   uuid.UUID
		name string
	}
	byName := map[string][]hit{}  // asset|name
	byLabel := map[string][]hit{} // asset|label
	for rows.Next() {
		var (
			id, asset   uuid.UUID
			name, label string
		)
		if err := rows.Scan(&id, &asset, &name, &label); err != nil {
			return fmt.Errorf("scan edge interface: %w", err)
		}
		byName[asset.String()+"|"+name] = append(byName[asset.String()+"|"+name], hit{id, name})
		if label != "" {
			byLabel[asset.String()+"|"+label] = append(byLabel[asset.String()+"|"+label], hit{id, name})
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("scan edge interfaces: %w", err)
	}
	resolve := func(asset uuid.UUID, port string) (*uuid.UUID, string) {
		if port == "" {
			return nil, ""
		}
		key := asset.String() + "|" + port
		for _, hits := range [][]hit{byName[key], byLabel[key]} {
			if len(hits) == 1 {
				id := hits[0].id
				return &id, hits[0].name
			}
			if len(hits) > 1 {
				// Two interfaces answer to the name: refuse to pick one.
				return nil, ""
			}
		}
		return nil, ""
	}
	for i := range edges {
		edges[i].FromInterfaceID, edges[i].FromInterfaceName = resolve(edges[i].FromAssetID, portOf(edges[i], edgeAttrLocalPort))
		edges[i].ToInterfaceID, edges[i].ToInterfaceName = resolve(edges[i].ToAssetID, portOf(edges[i], edgeAttrRemotePort))
	}
	return nil
}

// storedCablePath is one interface-to-interface path as cable_paths holds it.
type storedCablePath struct {
	originID, destID       uuid.UUID
	fromAsset, toAsset     uuid.UUID
	fromName, toName       string
	summary                pathSummary
	status, operational    string
	firstCable             uuid.UUID
	firstCableLabel        string
	fromPrefix, toPrefix   *uuid.UUID
	fromPrefixN, toPrefixN string
}

// loadCablePaths reads the complete interface-to-interface paths whose two
// ends are on different assets, once per pair of interfaces, optionally
// restricted to paths with both ends on `assets`. Runs over a rejected or
// archived cable are dropped (row 3.2 recomputes on delete; this is the
// belt-and-braces for a lifecycle change that left a path behind).
func loadCablePaths(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, assets []uuid.UUID) ([]storedCablePath, error) {
	scope := ""
	args := []any{tenantID, TopologyNoPrefix}
	if assets != nil {
		if len(assets) == 0 {
			return nil, nil
		}
		scope = `AND oi.asset_id = ANY($3) AND di.asset_id = ANY($3)`
		args = append(args, pq.Array(assets))
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT ON (LEAST(cp.origin_id, cp.destination_id), GREATEST(cp.origin_id, cp.destination_id))
		       cp.origin_id, cp.destination_id, cp.path::text,
		       oi.asset_id, oi.name, di.asset_id, di.name,
		       oa.prefix_id, COALESCE(op.prefix::text, $2), da.prefix_id, COALESCE(dp.prefix::text, $2)
		  FROM cable_paths cp
		  JOIN interfaces oi ON oi.tenant_id = cp.tenant_id AND oi.id = cp.origin_id
		  JOIN interfaces di ON di.tenant_id = cp.tenant_id AND di.id = cp.destination_id
		  JOIN assets oa ON oa.tenant_id = cp.tenant_id AND oa.id = oi.asset_id AND oa.deleted_at IS NULL
		  JOIN assets da ON da.tenant_id = cp.tenant_id AND da.id = di.asset_id AND da.deleted_at IS NULL
		  LEFT JOIN prefixes op ON op.tenant_id = cp.tenant_id AND op.id = oa.prefix_id
		  LEFT JOIN prefixes dp ON dp.tenant_id = cp.tenant_id AND dp.id = da.prefix_id
		 WHERE cp.tenant_id = $1
		   AND cp.origin_kind = 'interface'
		   AND cp.destination_kind = 'interface'
		   AND cp.is_complete
		   AND oi.asset_id <> di.asset_id
		   `+scope+`
		 ORDER BY LEAST(cp.origin_id, cp.destination_id), GREATEST(cp.origin_id, cp.destination_id), cp.origin_id`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("query cable paths: %w", err)
	}
	var out []storedCablePath
	cableSet := map[uuid.UUID]struct{}{}
	for rows.Next() {
		var (
			p   storedCablePath
			raw string
		)
		if err := rows.Scan(&p.originID, &p.destID, &raw, &p.fromAsset, &p.fromName, &p.toAsset, &p.toName,
			&p.fromPrefix, &p.fromPrefixN, &p.toPrefix, &p.toPrefixN); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan cable path: %w", err)
		}
		var groups [][]cablepath.Node
		if err := json.Unmarshal([]byte(raw), &groups); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("decode cable path %s: %w", p.originID, err)
		}
		p.summary = summarisePath(groups)
		if len(p.summary.CableIDs) == 0 {
			continue
		}
		p.firstCable = p.summary.CableIDs[0]
		for _, id := range p.summary.CableIDs {
			cableSet[id] = struct{}{}
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("scan cable paths: %w", err)
	}
	_ = rows.Close()
	if len(out) == 0 {
		return nil, nil
	}

	type cableRow struct{ label, status, operational string }
	cables := map[uuid.UUID]cableRow{}
	crows, err := tx.QueryContext(ctx, `
		SELECT id, COALESCE(label, ''), status, operational_status
		  FROM cables WHERE tenant_id = $1 AND id = ANY($2)`,
		tenantID, pq.Array(keysOf(cableSet)))
	if err != nil {
		return nil, fmt.Errorf("query path cables: %w", err)
	}
	defer func() { _ = crows.Close() }()
	for crows.Next() {
		var (
			id uuid.UUID
			c  cableRow
		)
		if err := crows.Scan(&id, &c.label, &c.status, &c.operational); err != nil {
			return nil, fmt.Errorf("scan path cable: %w", err)
		}
		cables[id] = c
	}
	if err := crows.Err(); err != nil {
		return nil, fmt.Errorf("scan path cables: %w", err)
	}

	kept := out[:0]
	for _, p := range out {
		p.status = EdgeStatusActive
		drop := false
		for _, id := range p.summary.CableIDs {
			c, ok := cables[id]
			if !ok || c.status == "rejected" || c.status == "archived" {
				drop = true
				break
			}
			if c.status == EdgeStatusPending {
				p.status = EdgeStatusPending
			}
			p.operational = worseOperationalStatus(p.operational, c.operational)
		}
		if drop {
			continue
		}
		p.firstCableLabel = cables[p.firstCable].label
		kept = append(kept, p)
	}
	return kept, nil
}

// neighbourhoodCablePaths is the cable paths among the neighbourhood's nodes,
// capped at the edge cap, with the untruncated total.
func neighbourhoodCablePaths(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, ids []uuid.UUID) ([]NeighbourhoodCablePath, int, error) {
	out := []NeighbourhoodCablePath{}
	if ids == nil {
		ids = []uuid.UUID{}
	}
	paths, err := loadCablePaths(ctx, tx, tenantID, ids)
	if err != nil {
		return nil, 0, err
	}
	for _, p := range paths {
		if len(out) >= NeighbourhoodEdgeCap {
			break
		}
		out = append(out, NeighbourhoodCablePath{
			ID:          p.originID.String(),
			FromAssetID: p.fromAsset, ToAssetID: p.toAsset,
			FromInterfaceID: p.originID, FromInterfaceName: p.fromName,
			ToInterfaceID: p.destID, ToInterfaceName: p.toName,
			CableID: p.firstCable, CableLabel: p.firstCableLabel,
			Status: p.status, OperationalStatus: p.operational,
			CableCount: p.summary.CableCount, PatchPanelCount: p.summary.PatchPanelCount, CircuitCount: p.summary.CircuitCount,
		})
	}
	return out, len(paths), nil
}

// topologyCablePaths aggregates the tenant's cable paths by the (unordered)
// pair of prefixes their two assets are in. Same-prefix runs are not here,
// for the reason same-prefix relationships are not: D4 asks for cross-prefix
// summaries.
func topologyCablePaths(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID) ([]TopologyCablePaths, int, error) {
	paths, err := loadCablePaths(ctx, tx, tenantID, nil)
	if err != nil {
		return nil, 0, err
	}
	key := func(id *uuid.UUID) string {
		if id == nil {
			return ""
		}
		return id.String()
	}
	idx := map[string]int{}
	agg := []TopologyCablePaths{}
	for _, p := range paths {
		fk, tk := key(p.fromPrefix), key(p.toPrefix)
		if fk == tk {
			continue
		}
		fromID, fromN, toID, toN := p.fromPrefix, p.fromPrefixN, p.toPrefix, p.toPrefixN
		if fromN > toN || (fromN == toN && fk > tk) {
			fromID, fromN, toID, toN, fk, tk = toID, toN, fromID, fromN, tk, fk
		}
		k := fk + "<->" + tk
		i, ok := idx[k]
		if !ok {
			i = len(agg)
			idx[k] = i
			agg = append(agg, TopologyCablePaths{FromPrefixID: fromID, FromPrefixName: fromN, ToPrefixID: toID, ToPrefixName: toN})
		}
		agg[i].Count++
		if p.status == EdgeStatusPending {
			agg[i].PendingCount++
		}
	}
	sort.SliceStable(agg, func(a, b int) bool {
		if agg[a].Count != agg[b].Count {
			return agg[a].Count > agg[b].Count
		}
		if agg[a].FromPrefixName != agg[b].FromPrefixName {
			return agg[a].FromPrefixName < agg[b].FromPrefixName
		}
		return agg[a].ToPrefixName < agg[b].ToPrefixName
	})
	total := len(agg)
	if len(agg) > TopologyEdgeCap {
		agg = agg[:TopologyEdgeCap]
	}
	return agg, total, nil
}
