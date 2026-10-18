package services

// CableService owns cables, their terminations and the cached cable paths
// (DCIM BUILD_PLAN row 3.2; asset-inventory ADR-0010 D6; DATA_MODEL §4).
//
// A cable is written through the IPAM object engine (its columns, change
// recording, RLS-scoped transaction) and its A and B ends are written here, in
// the same transaction:
//
//   - each end is a non-empty set of terminations of ONE kind on ONE parent
//     (an asset, or a circuit for circuit terminations);
//   - the two ends' kinds must be compatible (NetBox's
//     COMPATIBLE_TERMINATION_TYPES, standards/cable-types.yaml →
//     dcim.CableCompatible);
//   - a termination is on at most one cable (cable_terminations'
//     unique (termination_kind, termination_id) is the backstop: a race
//     answers 409, not a second cable);
//   - a termination marked connected (mark_connected: "there is a cable here
//     we do not model") cannot take a cable, and a virtual or wireless
//     interface never can;
//   - both ends may be on the same asset (a loopback or a patch between two
//     ports of one panel).
//
// Every write recomputes the cached path of every origin it can move
// (shared/dcim/cablepath: the cable's own terminations plus every stored path
// running through the cable or its terminations), in the same transaction.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/cablepath"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// CableRoute is the engine route of cables.
const CableRoute = "cables"

// CableStatuses is cables.operational_status (NetBox LinkStatusChoices).
func CableStatuses() []string {
	var out []string
	for _, s := range dcim.AllCableStatuses() {
		out = append(out, string(s))
	}
	return out
}

// terminationTables maps a termination kind onto the table holding it.
// power_feed and power_panel are not object kinds until power ships
// (ADR-0010 D9); a cable onto one is refused as an unknown kind.
var terminationTables = map[dcim.ObjectKind]string{
	dcim.ObjectKindInterface:          "interfaces",
	dcim.ObjectKindFrontPort:          "front_ports",
	dcim.ObjectKindRearPort:           "rear_ports",
	dcim.ObjectKindConsolePort:        "console_ports",
	dcim.ObjectKindConsoleServerPort:  "console_server_ports",
	dcim.ObjectKindPowerPort:          "power_ports",
	dcim.ObjectKindPowerOutlet:        "power_outlets",
	dcim.ObjectKindCircuitTermination: "circuit_terminations",
}

// TraceRoutes maps each trace route segment onto its termination kind.
var TraceRoutes = map[string]dcim.ObjectKind{
	"interfaces":           dcim.ObjectKindInterface,
	"front-ports":          dcim.ObjectKindFrontPort,
	"rear-ports":           dcim.ObjectKindRearPort,
	"console-ports":        dcim.ObjectKindConsolePort,
	"console-server-ports": dcim.ObjectKindConsoleServerPort,
	"circuit-terminations": dcim.ObjectKindCircuitTermination,
}

// cableTermName is the SQL naming one termination (alias ct) after the
// per-kind LEFT JOINs in cableTermJoins.
const cableTermName = `COALESCE(ti.name, tcp.name, tcs.name, tfp.name, trp.name, tpp.name, tpo.name, tci.cid || ' ' || tct.term_side::text)`

const cableTermJoins = `
	LEFT JOIN public.assets ta ON ta.id = ct.asset_id
	LEFT JOIN public.interfaces ti ON ct.termination_kind = 'interface' AND ti.id = ct.termination_id
	LEFT JOIN public.console_ports tcp ON ct.termination_kind = 'console_port' AND tcp.id = ct.termination_id
	LEFT JOIN public.console_server_ports tcs ON ct.termination_kind = 'console_server_port' AND tcs.id = ct.termination_id
	LEFT JOIN public.front_ports tfp ON ct.termination_kind = 'front_port' AND tfp.id = ct.termination_id
	LEFT JOIN public.rear_ports trp ON ct.termination_kind = 'rear_port' AND trp.id = ct.termination_id
	LEFT JOIN public.power_ports tpp ON ct.termination_kind = 'power_port' AND tpp.id = ct.termination_id
	LEFT JOIN public.power_outlets tpo ON ct.termination_kind = 'power_outlet' AND tpo.id = ct.termination_id
	LEFT JOIN public.circuit_terminations tct ON ct.termination_kind = 'circuit_termination' AND tct.id = ct.termination_id
	LEFT JOIN public.circuits tci ON tci.id = tct.circuit_id
	LEFT JOIN public.sites tsi ON tsi.id = ct.site_id
	LEFT JOIN public.racks trk ON trk.id = ct.rack_id`

func cableEndSQL(end string) string {
	return `COALESCE((SELECT jsonb_agg(jsonb_build_object(
		'termination_kind', ct.termination_kind, 'termination_id', ct.termination_id,
		'asset_id', ct.asset_id, 'asset_name', COALESCE(ta.display_name, ta.hostname, host(ta.primary_address)),
		'circuit_id', tct.circuit_id, 'name', ` + cableTermName + `,
		'site_id', ct.site_id, 'site_name', tsi.name, 'rack_id', ct.rack_id, 'rack_name', trk.name)
		ORDER BY ` + cableTermName + `, ct.termination_id)
		FROM public.cable_terminations ct` + cableTermJoins + `
		WHERE ct.cable_id = t.id AND ct.cable_end = '` + end + `'), '[]'::jsonb)`
}

// cableSelect is a cable in its API shape: the row plus both ends.
var cableSelect = `to_jsonb(t) || jsonb_build_object('a_terminations', ` + cableEndSQL("A") + `, 'b_terminations', ` + cableEndSQL("B") + `)`

func cableTermFilter(col string) func(string, int) (string, any, error) {
	return func(v string, n int) (string, any, error) {
		id, err := uuid.Parse(v)
		if err != nil {
			return "", nil, ipamInvalid("%s must be a UUID", col)
		}
		return fmt.Sprintf(`EXISTS (SELECT 1 FROM public.cable_terminations f WHERE f.cable_id = t.id AND f.%s = $%d)`, col, n), id, nil
	}
}

func cableSpec() *ipamSpec {
	return &ipamSpec{
		Kind: dcim.ObjectKindCable, Table: "cables", Route: CableRoute, Lifecycle: true,
		Cols: append(withSubstrate(
			ipamCol{Name: "type", Type: colText},
			ipamCol{Name: "operational_status", Type: colText},
			ipamCol{Name: "label", Type: colText},
			ipamCol{Name: "color", Type: colText},
			ipamCol{Name: "length", Type: colNumeric},
			ipamCol{Name: "length_unit", Type: colText},
			ipamCol{Name: "business_unit_id", Type: colUUID},
			externalIDsCol,
		), lifecycleCols...),
		Filters: []ipamFilter{
			{Param: "type", Column: "type", Type: colText},
			{Param: "operational_status", Column: "operational_status", Type: colText},
			{Param: "status", Column: "status", Type: colText},
			{Param: "label", Column: "label", Type: colText},
			{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
			{Param: "asset_id", Custom: cableTermFilter("asset_id")},
			{Param: "site_id", Custom: cableTermFilter("site_id")},
			{Param: "location_id", Custom: cableTermFilter("location_id")},
			{Param: "rack_id", Custom: cableTermFilter("rack_id")},
			{Param: "termination_id", Custom: cableTermFilter("termination_id")},
			{Param: "termination_kind", Custom: func(v string, n int) (string, any, error) {
				if !cablepath.IsTermination(dcim.ObjectKind(v)) {
					return "", nil, ipamInvalid("termination_kind %q is not a cable termination kind", v)
				}
				return fmt.Sprintf(`EXISTS (SELECT 1 FROM public.cable_terminations f WHERE f.cable_id = t.id AND f.termination_kind = $%d)`, n), v, nil
			}},
		},
		Search:     []string{"label", "description"},
		Order:      "t.label NULLS LAST, t.created_at, t.id",
		ListSelect: cableSelect,
		Prepare:    prepareCable,
	}
}

func prepareCable(_ context.Context, _ *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if err := validType(row, "type", false, func(s string) bool { _, ok := dcim.ParseCableType(s); return ok }); err != nil {
		return err
	}
	if isEmpty(row["operational_status"]) {
		row["operational_status"] = string(dcim.CableStatusConnected)
	}
	if err := oneOf(row, "operational_status", CableStatuses()); err != nil {
		return err
	}
	var units []string
	for _, u := range dcim.AllCableLengthUnits() {
		units = append(units, string(u))
	}
	if err := oneOf(row, "length_unit", units); err != nil {
		return err
	}
	if !isEmpty(row["length"]) {
		if isEmpty(row["length_unit"]) {
			return ipamInvalid("length_unit is required when length is set")
		}
		if s := fmt.Sprint(row["length"]); strings.HasPrefix(s, "-") {
			return ipamInvalid("length cannot be negative")
		}
	} else {
		row["length"] = nil
	}
	if l, ok := row["label"].(string); ok && len(l) > 100 {
		return ipamInvalid("label must be at most 100 characters")
	}
	return normaliseColor(row, "color")
}

// CableService is the cable store.
type CableService struct {
	db  *sql.DB
	eng *IPAMService
}

// NewCableService returns the store over db (the raw pool; RLS per tx).
func NewCableService(db *sql.DB) *CableService {
	return &CableService{db: db, eng: newObjectEngine(db, []*ipamSpec{cableSpec()})}
}

// TerminationRef names one termination in a request body.
type TerminationRef struct {
	Kind dcim.ObjectKind `json:"termination_kind"`
	ID   uuid.UUID       `json:"termination_id"`
}

// List returns one page of cables with both ends.
func (s *CableService) List(ctx context.Context, tenant uuid.UUID, p IPAMListParams) ([]json.RawMessage, int, error) {
	return s.eng.List(ctx, tenant, CableRoute, p)
}

// Get returns one cable with both ends.
func (s *CableService) Get(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error) {
	var out json.RawMessage
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var err error
		out, err = getCableTx(ctx, tx, id)
		return err
	})
	return out, mapIPAMError(err, false)
}

func getCableTx(ctx context.Context, tx *sql.Tx, id uuid.UUID) (json.RawMessage, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT `+cableSelect+` FROM public.cables t WHERE t.id = $1`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIPAMNotFound
	}
	return raw, err
}

// splitCableBody separates a body's a_terminations / b_terminations from the
// cable's own columns. present reports which ends the body names.
func splitCableBody(body []byte) (rest []byte, a, b []TerminationRef, hasA, hasB bool, err error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, nil, nil, false, false, ipamInvalid("body must be a JSON object")
	}
	read := func(key string) ([]TerminationRef, bool, error) {
		raw, ok := m[key]
		if !ok {
			return nil, false, nil
		}
		delete(m, key)
		var refs []TerminationRef
		if err := json.Unmarshal(raw, &refs); err != nil {
			return nil, true, ipamInvalid("%s must be a list of {termination_kind, termination_id}", key)
		}
		return refs, true, nil
	}
	if a, hasA, err = read("a_terminations"); err != nil {
		return
	}
	if b, hasB, err = read("b_terminations"); err != nil {
		return
	}
	rest, err = json.Marshal(m)
	return
}

// termTarget is a termination's target row as the rules need it.
type termTarget struct {
	ref           TerminationRef
	parent        uuid.UUID // asset, or circuit for a circuit termination
	assetID       uuid.NullUUID
	siteID        uuid.NullUUID
	locationID    uuid.NullUUID
	rackID        uuid.NullUUID
	cableID       uuid.NullUUID
	markConnected bool
	ifType        string
}

func loadTermTarget(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, r TerminationRef) (termTarget, error) {
	t := termTarget{ref: r}
	if !cablepath.IsTermination(r.Kind) {
		return t, ipamInvalid("termination_kind %q is not a cable termination kind", r.Kind)
	}
	table, ok := terminationTables[r.Kind]
	if !ok {
		return t, ipamInvalid("%s terminations are not available yet", r.Kind)
	}
	if r.ID == uuid.Nil {
		return t, ipamInvalid("termination_id is required")
	}
	var q string
	switch r.Kind {
	case dcim.ObjectKindCircuitTermination:
		q = `SELECT x.circuit_id, NULL::uuid, CASE WHEN x.termination_kind = 'site' THEN x.termination_id END,
		            CASE WHEN x.termination_kind = 'location' THEN x.termination_id END, NULL::uuid,
		            x.cable_id, x.mark_connected, ''
		       FROM public.circuit_terminations x WHERE x.tenant_id = $1 AND x.id = $2`
	case dcim.ObjectKindInterface:
		q = `SELECT x.asset_id, x.asset_id, a.site_id, a.location_id, a.rack_id, x.cable_id, x.mark_connected, x.type
		       FROM public.interfaces x JOIN public.assets a ON a.id = x.asset_id
		      WHERE x.tenant_id = $1 AND x.id = $2 AND x.status <> 'rejected' AND a.deleted_at IS NULL`
	default:
		q = fmt.Sprintf(`SELECT x.asset_id, x.asset_id, a.site_id, a.location_id, a.rack_id, x.cable_id, x.mark_connected, ''
		       FROM public.%s x JOIN public.assets a ON a.id = x.asset_id
		      WHERE x.tenant_id = $1 AND x.id = $2 AND x.status <> 'rejected' AND a.deleted_at IS NULL`, pq.QuoteIdentifier(table))
	}
	err := tx.QueryRowContext(ctx, q, tenant, r.ID).Scan(&t.parent, &t.assetID, &t.siteID, &t.locationID, &t.rackID, &t.cableID, &t.markConnected, &t.ifType)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ipamInvalid("no such %s %s", strings.ReplaceAll(string(r.Kind), "_", " "), r.ID)
	}
	return t, err
}

// checkEnds applies the termination rules to both ends of a cable (cable is
// uuid.Nil on create). It returns the targets, A then B.
func checkEnds(ctx context.Context, tx *sql.Tx, tenant, cable uuid.UUID, a, b []TerminationRef) ([]termTarget, []termTarget, error) {
	if len(a) == 0 || len(b) == 0 {
		return nil, nil, ipamInvalid("a cable needs at least one termination on each end (a_terminations and b_terminations)")
	}
	seen := map[TerminationRef]bool{}
	side := func(name string, refs []TerminationRef) ([]termTarget, error) {
		var out []termTarget
		for _, r := range refs {
			if seen[r] {
				return nil, ipamInvalid("%s %s is named more than once", r.Kind, r.ID)
			}
			seen[r] = true
			t, err := loadTermTarget(ctx, tx, tenant, r)
			if err != nil {
				return nil, err
			}
			if r.Kind != refs[0].Kind {
				return nil, ipamInvalid("every termination on the %s end must be of one kind (%s and %s)", name, refs[0].Kind, r.Kind)
			}
			if len(out) > 0 && t.parent != out[0].parent {
				return nil, ipamInvalid("every termination on the %s end must belong to the same %s", name, parentNoun(r.Kind))
			}
			if t.markConnected {
				return nil, ipamInvalid("%s %s is marked as connected; clear mark_connected before attaching a cable", r.Kind, r.ID)
			}
			if r.Kind == dcim.ObjectKindInterface {
				g := dcim.InterfaceTypeGroup(dcim.InterfaceType(t.ifType))
				if g == "virtual" || g == "wireless" {
					return nil, ipamInvalid("a %s interface (%s) cannot take a cable", g, t.ifType)
				}
			}
			if t.cableID.Valid && t.cableID.UUID != cable {
				return nil, fmt.Errorf("%w: %s %s is already on cable %s", ErrIPAMConflict, r.Kind, r.ID, t.cableID.UUID)
			}
			out = append(out, t)
		}
		return out, nil
	}
	at, err := side("A", a)
	if err != nil {
		return nil, nil, err
	}
	bt, err := side("B", b)
	if err != nil {
		return nil, nil, err
	}
	if !dcim.CableCompatible(a[0].Kind, b[0].Kind) {
		return nil, nil, ipamInvalid("a %s cannot be cabled to a %s", a[0].Kind, b[0].Kind)
	}
	return at, bt, nil
}

func parentNoun(k dcim.ObjectKind) string {
	if k == dcim.ObjectKindCircuitTermination {
		return "circuit"
	}
	return "asset"
}

// attach writes one termination row and the component's cable_id/cable_end,
// recording the termination's creation.
func attach(ctx context.Context, tx *sql.Tx, tenant, cable uuid.UUID, end string, t termTarget) error {
	var raw []byte
	err := tx.QueryRowContext(ctx, `
		INSERT INTO public.cable_terminations AS ct (tenant_id, cable_id, cable_end, termination_kind, termination_id, asset_id,
		    site_id, location_id, rack_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING to_jsonb(ct)`,
		tenant, cable, end, string(t.ref.Kind), t.ref.ID, t.assetID, t.siteID, t.locationID, t.rackID).Scan(&raw)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`UPDATE public.%s SET cable_id = $3, cable_end = $4, updated_at = now() WHERE tenant_id = $1 AND id = $2`,
		pq.QuoteIdentifier(terminationTables[t.ref.Kind])), tenant, t.ref.ID, cable, end); err != nil {
		return err
	}
	var post map[string]any
	if err := json.Unmarshal(raw, &post); err != nil {
		return err
	}
	return recordTermination(ctx, tx, tenant, changes.ActionCreate, nil, post)
}

func recordTermination(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, action changes.Action, pre, post map[string]any) error {
	row := post
	if row == nil {
		row = pre
	}
	id, err := uuid.Parse(fmt.Sprint(row["id"]))
	if err != nil {
		return fmt.Errorf("cable termination has no id: %w", err)
	}
	c := changes.Change{TenantID: tenant, Kind: dcim.ObjectKindCableTermination, ID: id, Action: action}
	if pre != nil {
		c.Pre = pre
	}
	if post != nil {
		c.Post = post
	}
	return changes.InTx(tx).Record(ctx, c)
}

// detachWhere deletes the termination rows matching where (over alias ct),
// clears each component's cable_id/cable_end and records the deletions. It
// returns the deleted terminations.
func detachWhere(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, where string, args ...any) ([]cablepath.Node, error) {
	rows, err := tx.QueryContext(ctx, `DELETE FROM public.cable_terminations ct WHERE ct.tenant_id = $1 AND (`+where+`) RETURNING to_jsonb(ct)`,
		append([]any{tenant}, args...)...)
	if err != nil {
		return nil, err
	}
	var pres []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			_ = rows.Close()
			return nil, err
		}
		pres = append(pres, m)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var out []cablepath.Node
	for _, pre := range pres {
		k := dcim.ObjectKind(fmt.Sprint(pre["termination_kind"]))
		id, err := uuid.Parse(fmt.Sprint(pre["termination_id"]))
		if err != nil {
			return nil, err
		}
		out = append(out, cablepath.N(k, id))
		if table, ok := terminationTables[k]; ok {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(`UPDATE public.%s SET cable_id = NULL, cable_end = NULL, updated_at = now() WHERE tenant_id = $1 AND id = $2`,
				pq.QuoteIdentifier(table)), tenant, id); err != nil {
				return nil, err
			}
		}
		if err := recordTermination(ctx, tx, tenant, changes.ActionDelete, pre, nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// recomputeAround recomputes every path that runs through nodes or starts at
// one of them. Call it with the nodes a write touched, before or after the
// write: cable_paths still holds the old paths until Recompute rewrites them.
func recomputeAround(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, nodes []cablepath.Node) error {
	origins, err := cablepath.Through(ctx, tx, tenant, nodes)
	if err != nil {
		return err
	}
	return cablepath.Recompute(ctx, tx, tenant, origins)
}

// Create declares a cable with its A and B ends.
func (s *CableService) Create(ctx context.Context, tenant uuid.UUID, body []byte) (json.RawMessage, error) {
	sp, _ := s.eng.spec(CableRoute)
	rest, a, b, _, _, err := splitCableBody(body)
	if err != nil {
		return nil, err
	}
	patch, err := decodeBody(sp, rest)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		at, bt, err := checkEnds(ctx, tx, tenant, uuid.Nil, a, b)
		if err != nil {
			return err
		}
		row, err := s.eng.createTx(ctx, tx, sp, tenant, patch, "")
		if err != nil {
			return err
		}
		id, err := uuid.Parse(fmt.Sprint(row["id"]))
		if err != nil {
			return err
		}
		if err := s.attachAll(ctx, tx, tenant, id, at, bt); err != nil {
			return err
		}
		nodes, err := cablepath.CableNodes(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		if err := recomputeAround(ctx, tx, tenant, nodes); err != nil {
			return err
		}
		out, err = getCableTx(ctx, tx, id)
		return err
	})
	return out, mapIPAMError(err, false)
}

func (s *CableService) attachAll(ctx context.Context, tx *sql.Tx, tenant, cable uuid.UUID, at, bt []termTarget) error {
	for end, ts := range map[string][]termTarget{"A": at, "B": bt} {
		for _, t := range ts {
			if err := attach(ctx, tx, tenant, cable, end, t); err != nil {
				return err
			}
		}
	}
	return nil
}

func currentEnd(ctx context.Context, tx *sql.Tx, tenant, cable uuid.UUID, end string) ([]TerminationRef, error) {
	rows, err := tx.QueryContext(ctx, `SELECT termination_kind, termination_id FROM public.cable_terminations
		WHERE tenant_id = $1 AND cable_id = $2 AND cable_end = $3 ORDER BY termination_kind, termination_id`, tenant, cable, end)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []TerminationRef
	for rows.Next() {
		var r TerminationRef
		var k string
		if err := rows.Scan(&k, &r.ID); err != nil {
			return nil, err
		}
		r.Kind = dcim.ObjectKind(k)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Update patches a cable. a_terminations / b_terminations, when present,
// replace that end; the result is held to the same rules as a new cable.
func (s *CableService) Update(ctx context.Context, tenant, id uuid.UUID, body []byte) (json.RawMessage, error) {
	sp, _ := s.eng.spec(CableRoute)
	rest, a, b, hasA, hasB, err := splitCableBody(body)
	if err != nil {
		return nil, err
	}
	patch, err := decodeBody(sp, rest)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if _, err := s.eng.updateTx(ctx, tx, sp, tenant, id, patch, ""); err != nil {
			return err
		}
		before, err := cablepath.CableNodes(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		beforeAssets, err := cableEndAssets(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		if hasA || hasB {
			curA, err := currentEnd(ctx, tx, tenant, id, "A")
			if err != nil {
				return err
			}
			curB, err := currentEnd(ctx, tx, tenant, id, "B")
			if err != nil {
				return err
			}
			if !hasA {
				a = curA
			}
			if !hasB {
				b = curB
			}
			at, bt, err := checkEnds(ctx, tx, tenant, id, a, b)
			if err != nil {
				return err
			}
			// Replace both ends: detach what is there, attach the new set. A
			// termination kept on its end is detached and re-attached, which
			// the change log shows as a delete and a create of the row.
			if _, err := detachWhere(ctx, tx, tenant, `ct.cable_id = $2`, id); err != nil {
				return err
			}
			if err := s.attachAll(ctx, tx, tenant, id, at, bt); err != nil {
				return err
			}
		}
		after, err := cablepath.CableNodes(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		if err := recomputeAround(ctx, tx, tenant, append(before, after...)); err != nil {
			return err
		}
		// A changed cable answers any drift finding on its ends; the next
		// observation re-raises it if the network still disagrees (row 3.3).
		assets, err := cableEndAssets(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		if err := resolveCableDriftTx(ctx, tx, tenant, append(assets, beforeAssets...)); err != nil {
			return err
		}
		out, err = getCableTx(ctx, tx, id)
		return err
	})
	return out, mapIPAMError(err, false)
}

// Delete removes a cable, frees its terminations and recomputes the paths
// that ran over it.
func (s *CableService) Delete(ctx context.Context, tenant, id uuid.UUID) error {
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		return s.deleteTx(ctx, tx, tenant, id)
	})
	return mapIPAMError(err, true)
}

// deleteTx is Delete on the caller's transaction.
func (s *CableService) deleteTx(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID) error {
	sp, _ := s.eng.spec(CableRoute)
	pre, err := getRow(ctx, tx, sp, id, true)
	if err != nil {
		return err
	}
	nodes, err := cablepath.CableNodes(ctx, tx, tenant, id)
	if err != nil {
		return err
	}
	origins, err := cablepath.Through(ctx, tx, tenant, nodes)
	if err != nil {
		return err
	}
	assets, err := cableEndAssets(ctx, tx, tenant, id)
	if err != nil {
		return err
	}
	if _, err := detachWhere(ctx, tx, tenant, `ct.cable_id = $2`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM public.cables WHERE tenant_id = $1 AND id = $2`, tenant, id); err != nil {
		return err
	}
	if err := recordIPAMChange(ctx, tx, sp, tenant, changes.ActionDelete, pre, nil, ""); err != nil {
		return err
	}
	if err := resolveCableDriftTx(ctx, tx, tenant, assets); err != nil {
		return err
	}
	return cablepath.Recompute(ctx, tx, tenant, origins)
}

// sweepOrphanTerminations detaches the terminations of kinds whose object no
// longer exists (deleted directly, or by a cascade: a rear port's front
// ports, a circuit's terminations) and recomputes the paths that ran through
// them. Called after a component delete, in its transaction.
func sweepOrphanTerminations(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, kinds ...dcim.ObjectKind) error {
	var gone []cablepath.Node
	for _, k := range kinds {
		table, ok := terminationTables[k]
		if !ok {
			continue
		}
		// The far ends first: their paths must be recomputed once the
		// orphan is gone.
		rows, err := tx.QueryContext(ctx, fmt.Sprintf(`
			SELECT ct.termination_kind, ct.termination_id, ct.cable_id FROM public.cable_terminations ct
			 WHERE ct.tenant_id = $1 AND ct.termination_kind = $2
			   AND NOT EXISTS (SELECT 1 FROM public.%s x WHERE x.id = ct.termination_id)`, pq.QuoteIdentifier(table)), tenant, string(k))
		if err != nil {
			return err
		}
		var cables []uuid.UUID
		for rows.Next() {
			var kind string
			var id, cable uuid.UUID
			if err := rows.Scan(&kind, &id, &cable); err != nil {
				_ = rows.Close()
				return err
			}
			gone = append(gone, cablepath.N(dcim.ObjectKind(kind), id))
			cables = append(cables, cable)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, c := range cables {
			ns, err := cablepath.CableNodes(ctx, tx, tenant, c)
			if err != nil {
				return err
			}
			gone = append(gone, ns...)
		}
	}
	if len(gone) == 0 {
		return nil
	}
	origins, err := cablepath.Through(ctx, tx, tenant, gone)
	if err != nil {
		return err
	}
	for _, k := range kinds {
		table, ok := terminationTables[k]
		if !ok {
			continue
		}
		if _, err := detachWhere(ctx, tx, tenant, fmt.Sprintf(`ct.termination_kind = $2 AND NOT EXISTS (SELECT 1 FROM public.%s x WHERE x.id = ct.termination_id)`,
			pq.QuoteIdentifier(table)), string(k)); err != nil {
			return err
		}
	}
	return cablepath.Recompute(ctx, tx, tenant, origins)
}

// ---------------------------------------------------------------- trace ----

// TraceNode is one hop of a trace, named for display.
type TraceNode struct {
	Kind dcim.ObjectKind `json:"kind"`
	ID   uuid.UUID       `json:"id"`
	Name string          `json:"name"`
	// AssetID / AssetName for a component; CircuitID for a circuit
	// termination.
	AssetID   *uuid.UUID `json:"asset_id"`
	AssetName *string    `json:"asset_name"`
	CircuitID *uuid.UUID `json:"circuit_id"`
	// Cable hops: the cable's type, operational status, label and colour.
	Type   *string `json:"type,omitempty"`
	Status *string `json:"operational_status,omitempty"`
	Color  *string `json:"color,omitempty"`
}

// TraceSegment is one cable crossing.
type TraceSegment struct {
	NearEnd []TraceNode `json:"near_end"`
	Cables  []TraceNode `json:"cables"`
	FarEnd  []TraceNode `json:"far_end"`
}

// TracePath is one path: from its origin, segment by segment.
type TracePath struct {
	Origin      TraceNode      `json:"origin"`
	Segments    []TraceSegment `json:"steps"`
	Destination *TraceNode     `json:"destination"`
	IsComplete  bool           `json:"is_complete"`
	IsActive    bool           `json:"is_active"`
	IsSplit     bool           `json:"is_split"`
}

// TraceResult answers GET /dcim/{kind}/{id}/trace: the paths starting at the
// object (an endpoint or a circuit termination; at most one) or running
// through it (a front or rear port; any number).
type TraceResult struct {
	Object TraceNode   `json:"object"`
	Paths  []TracePath `json:"paths"`
}

// Trace returns the cached paths for an object. It reads cable_paths only:
// one indexed read, plus naming the hops.
func (s *CableService) Trace(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) (TraceResult, error) {
	var out TraceResult
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		self := cablepath.N(kind, id)
		names, err := describeNodes(ctx, tx, []cablepath.Node{self})
		if err != nil {
			return err
		}
		if _, ok := names[self]; !ok {
			return ErrIPAMNotFound
		}
		out.Object = names[self]
		var rows *sql.Rows
		if cablepath.IsOrigin(kind) {
			rows, err = tx.QueryContext(ctx, `SELECT origin_kind, origin_id, path, is_complete, is_active, is_split FROM public.cable_paths
				WHERE tenant_id = $1 AND origin_kind = $2 AND origin_id = $3`, tenant, string(kind), id)
		} else {
			probe, _ := json.Marshal([][]cablepath.Node{{self}})
			rows, err = tx.QueryContext(ctx, `SELECT origin_kind, origin_id, path, is_complete, is_active, is_split FROM public.cable_paths
				WHERE tenant_id = $1 AND path @> $2::jsonb ORDER BY origin_kind, origin_id LIMIT 100`, tenant, string(probe))
		}
		if err != nil {
			return err
		}
		type stored struct {
			origin                    cablepath.Node
			nodes                     [][]cablepath.Node
			complete, active, isSplit bool
		}
		var paths []stored
		for rows.Next() {
			var p stored
			var k string
			var raw []byte
			if err := rows.Scan(&k, &p.origin.ID, &raw, &p.complete, &p.active, &p.isSplit); err != nil {
				_ = rows.Close()
				return err
			}
			p.origin.Kind = dcim.ObjectKind(k)
			if err := json.Unmarshal(raw, &p.nodes); err != nil {
				_ = rows.Close()
				return err
			}
			paths = append(paths, p)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		var all []cablepath.Node
		for _, p := range paths {
			all = append(all, p.origin)
			for _, g := range p.nodes {
				all = append(all, g...)
			}
		}
		names, err = describeNodes(ctx, tx, all)
		if err != nil {
			return err
		}
		name := func(ns []cablepath.Node) []TraceNode {
			out := make([]TraceNode, 0, len(ns))
			for _, n := range ns {
				tn, ok := names[n]
				if !ok {
					// Deleted under a stale path (recompute normally
					// prevents it): say so rather than drop the hop.
					tn = TraceNode{Kind: n.Kind, ID: n.ID, Name: "(deleted)"}
				}
				out = append(out, tn)
			}
			return out
		}
		out.Paths = []TracePath{}
		for _, p := range paths {
			tp := TracePath{Origin: name([]cablepath.Node{p.origin})[0], IsComplete: p.complete, IsActive: p.active, IsSplit: p.isSplit, Segments: []TraceSegment{}}
			for _, sg := range cablepath.Segments(p.nodes) {
				tp.Segments = append(tp.Segments, TraceSegment{NearEnd: name(sg.Near), Cables: name(sg.Cable), FarEnd: name(sg.Far)})
			}
			if p.complete && len(p.nodes) > 0 {
				last := p.nodes[len(p.nodes)-1]
				if len(last) > 0 {
					d := name(last[:1])[0]
					tp.Destination = &d
				}
			}
			out.Paths = append(out.Paths, tp)
		}
		return nil
	})
	return out, mapIPAMError(err, false)
}

// describeNodes names nodes: one query per kind present.
func describeNodes(ctx context.Context, tx *sql.Tx, nodes []cablepath.Node) (map[cablepath.Node]TraceNode, error) {
	byKind := map[dcim.ObjectKind][]uuid.UUID{}
	out := map[cablepath.Node]TraceNode{}
	for _, n := range nodes {
		if _, done := out[n]; done {
			continue
		}
		out[n] = TraceNode{}
		byKind[n.Kind] = append(byKind[n.Kind], n.ID)
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)
	found := map[cablepath.Node]bool{}
	for _, ks := range kinds {
		k := dcim.ObjectKind(ks)
		var q string
		switch k {
		case cablepath.KindCable:
			q = `SELECT x.id, COALESCE(NULLIF(x.label, ''), 'Cable'), NULL::uuid, NULL::text, NULL::uuid, x.type, x.operational_status, x.color
			       FROM public.cables x WHERE x.id = ANY($1)`
		case dcim.ObjectKindCircuitTermination:
			q = `SELECT x.id, c.cid || ' ' || x.term_side::text, NULL::uuid, NULL::text, x.circuit_id, NULL::text, NULL::text, NULL::text
			       FROM public.circuit_terminations x JOIN public.circuits c ON c.id = x.circuit_id WHERE x.id = ANY($1)`
		case dcim.ObjectKindProviderNetwork:
			q = `SELECT x.id, x.name, NULL::uuid, NULL::text, NULL::uuid, NULL::text, NULL::text, NULL::text
			       FROM public.provider_networks x WHERE x.id = ANY($1)`
		default:
			table, ok := terminationTables[k]
			if !ok {
				continue
			}
			q = fmt.Sprintf(`SELECT x.id, x.name, x.asset_id, COALESCE(a.display_name, a.hostname, host(a.primary_address)), NULL::uuid, NULL::text, NULL::text, NULL::text
			       FROM public.%s x JOIN public.assets a ON a.id = x.asset_id WHERE x.id = ANY($1)`, pq.QuoteIdentifier(table))
		}
		rows, err := tx.QueryContext(ctx, q, pq.Array(byKind[k]))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var tn TraceNode
			var asset, circuit uuid.NullUUID
			var assetName, typ, status, color sql.NullString
			if err := rows.Scan(&tn.ID, &tn.Name, &asset, &assetName, &circuit, &typ, &status, &color); err != nil {
				_ = rows.Close()
				return nil, err
			}
			tn.Kind = k
			if asset.Valid {
				a := asset.UUID
				tn.AssetID = &a
			}
			if circuit.Valid {
				c := circuit.UUID
				tn.CircuitID = &c
			}
			tn.AssetName, tn.Type, tn.Status, tn.Color = nullStrPtr(assetName), nullStrPtr(typ), nullStrPtr(status), nullStrPtr(color)
			out[cablepath.N(k, tn.ID)] = tn
			found[cablepath.N(k, tn.ID)] = true
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	for n := range out {
		if !found[n] {
			delete(out, n)
		}
	}
	return out, nil
}

func nullStrPtr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}

// CableObject describes the cable route for the contract test: table, kind,
// writable and create-required columns (the ends are not columns).
func CableObject() IPAMObjectInfo {
	sp := cableSpec()
	info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
	for _, c := range sp.Cols {
		if !c.Computed {
			info.Writable = append(info.Writable, c.Name)
		}
	}
	return info
}
