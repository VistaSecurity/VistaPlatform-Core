package services

// The IPAM object store (asset-inventory ADR-0010 D3; DCIM BUILD_PLAN row 1.3).
//
// Thirteen NetBox-shaped objects share one CRUD path: each is described by an
// ipamSpec (its table, its writable columns and their types, its filters and
// its validation hook), and the engine below builds the SQL. Reads return the
// row as Postgres serialises it (`to_jsonb(t)`), so the API shape IS the
// table's column list — ipam_spec_parity_test.go holds each OpenAPI schema to
// that list, which is how a column added here without a spec property (or the
// reverse) goes red.
//
// Every call is one transaction scoped to the tenant (set_tenant_context, so
// RLS applies to the app role), and every create/update/delete records its
// change in object_changes through shared/dcim/changes inside that
// transaction.
//
// Enumerations and identity are enforced by the schema's CHECKs and unique
// indexes; the engine maps their violations onto 400/409. What the schema
// cannot say (cross-table rules: a VLAN's vid inside its group's ranges, an
// address unique in a VRF that enforces it, a role from the tenant's own
// catalogue) is each spec's Prepare hook.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// Errors the handlers map onto statuses.
var (
	ErrIPAMNotFound = errors.New("not found")
	ErrIPAMInvalid  = errors.New("invalid")
	ErrIPAMConflict = errors.New("conflict")
	ErrIPAMReadOnly = errors.New("platform-provided rows cannot be changed")
	ErrIPAMInUse    = errors.New("in use")
)

func ipamInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrIPAMInvalid, fmt.Sprintf(format, args...))
}

// zeroUUID is how identity indexes fold the global table (vrf_id IS NULL).
const zeroUUID = "00000000-0000-0000-0000-000000000000"

type ipamColType int

const (
	colText ipamColType = iota
	colBool
	colInt
	colBigint
	colUUID
	colInet
	colCidr
	colDate
	colJSON
	colTextArray
	colVidRanges
	colMAC
	colNumeric
	colBigintArray
	colUUIDArray
	// colJSONValue is a jsonb column holding any JSON value (an array, a
	// scalar), not only an object: a choice set's choices, a custom field's
	// default (row 5.1).
	colJSONValue
)

func (t ipamColType) cast() string {
	switch t {
	case colBool:
		return "boolean"
	case colInt:
		return "integer"
	case colBigint:
		return "bigint"
	case colUUID:
		return "uuid"
	case colInet:
		return "inet"
	case colCidr:
		return "cidr"
	case colDate:
		return "date"
	case colJSON, colJSONValue:
		return "jsonb"
	case colTextArray:
		return "text[]"
	case colVidRanges:
		return "int4range[]"
	case colMAC:
		return "macaddr8"
	case colNumeric:
		return "numeric"
	case colBigintArray:
		return "bigint[]"
	case colUUIDArray:
		return "uuid[]"
	default:
		return "text"
	}
}

type ipamCol struct {
	Name     string
	Type     ipamColType
	Required bool // on create
	Computed bool // set by Prepare, never by the caller
}

// ipamFilter is one list filter: a query parameter and the SQL it adds.
type ipamFilter struct {
	Param  string
	Column string
	Type   ipamColType
	// Custom builds the clause itself (argument $n); used for containment.
	Custom func(value string, n int) (clause string, arg any, err error)
}

type ipamSpec struct {
	Kind      dcim.ObjectKind
	Table     string
	Route     string // path segment under /ipam
	Catalogue bool   // tenant_id NULL rows are platform-seeded
	Lifecycle bool   // carries status/approved_by/approved_at
	// NoCreatedBy: the table has no created_by column (the device catalogue's
	// component templates carry no substrate, DATA_MODEL §2).
	NoCreatedBy bool
	Cols        []ipamCol
	Filters     []ipamFilter
	Search      []string // columns matched by ?q= (as text, ILIKE)
	Order       string
	// ListSelect replaces the list projection (default `to_jsonb(t)`); Join is
	// appended to FROM. The prefixes list joins the utilisation cache.
	ListSelect string
	Join       string
	// Prepare validates and normalises the merged row (existing row + patch)
	// before it is written; it may set Computed columns. id is uuid.Nil on
	// create.
	Prepare func(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error
	// AfterWrite runs after the row is written (pre nil on create, post nil
	// on delete), in the same transaction: the utilisation refresh.
	AfterWrite func(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error
	// BeforeDelete runs after the row is locked and before it is deleted, in
	// the same transaction: a rack unplaces its devices (rack_service.go).
	BeforeDelete func(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre map[string]any) error
	// Present rewrites a stored row into its API shape.
	Present func(row map[string]any)
}

func (s *ipamSpec) col(name string) (ipamCol, bool) {
	for _, c := range s.Cols {
		if c.Name == name {
			return c, true
		}
	}
	return ipamCol{}, false
}

// IPAMService implements the IPAM store over Postgres (the app-role pool).
type IPAMService struct {
	db    *sql.DB
	specs map[string]*ipamSpec // by Route
}

// NewIPAMService returns the store over db.
func NewIPAMService(db *sql.DB) *IPAMService {
	s := &IPAMService{db: db, specs: map[string]*ipamSpec{}}
	for _, sp := range ipamSpecs() {
		s.specs[sp.Route] = sp
	}
	return s
}

// newObjectEngine returns the same engine over another set of NetBox-shaped
// specs: the device catalogue (DCIM row 2.2, catalogue_service.go) is served by
// it, so a catalogue object gets exactly IPAM's CRUD, change recording, RLS
// scoping and platform-row refusal.
func newObjectEngine(db *sql.DB, specs []*ipamSpec) *IPAMService {
	s := &IPAMService{db: db, specs: map[string]*ipamSpec{}}
	for _, sp := range specs {
		s.specs[sp.Route] = sp
	}
	return s
}

// IPAMRoutes lists the object route segments the engine serves, in order.
func IPAMRoutes() []string {
	var out []string
	for _, sp := range ipamSpecs() {
		out = append(out, sp.Route)
	}
	return out
}

func (s *IPAMService) spec(route string) (*ipamSpec, error) {
	sp, ok := s.specs[route]
	if !ok {
		return nil, fmt.Errorf("%w: unknown object type %q", ErrIPAMNotFound, route)
	}
	return sp, nil
}

func (s *IPAMService) tx(ctx context.Context, tenant uuid.UUID, fn func(*sql.Tx) error) error {
	return database.WithTenantTx(ctx, s.db, tenant, fn)
}

// IPAMListParams is a list request.
type IPAMListParams struct {
	Filters map[string]string
	Q       string
	Limit   int
	Offset  int
}

// List returns one page of route's objects and the total.
func (s *IPAMService) List(ctx context.Context, tenant uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	sp, err := s.spec(route)
	if err != nil {
		return nil, 0, err
	}
	var where []string
	var args []any
	for _, f := range sp.Filters {
		v, ok := p.Filters[f.Param]
		if !ok || v == "" {
			continue
		}
		n := len(args) + 1
		if f.Custom != nil {
			clause, arg, err := f.Custom(v, n)
			if err != nil {
				return nil, 0, err
			}
			where = append(where, clause)
			if arg != nil {
				args = append(args, arg)
			}
			continue
		}
		if f.Type == colUUID && (v == "null" || v == "global") {
			where = append(where, fmt.Sprintf("t.%s IS NULL", pq.QuoteIdentifier(f.Column)))
			continue
		}
		val, err := filterValue(f.Type, v)
		if err != nil {
			return nil, 0, ipamInvalid("%s: %v", f.Param, err)
		}
		where = append(where, fmt.Sprintf("t.%s = $%d::%s", pq.QuoteIdentifier(f.Column), n, f.Type.cast()))
		args = append(args, val)
	}
	if q := strings.TrimSpace(p.Q); q != "" && len(sp.Search) > 0 {
		var ors []string
		for _, c := range sp.Search {
			ors = append(ors, fmt.Sprintf("t.%s::text ILIKE $%d", pq.QuoteIdentifier(c), len(args)+1))
		}
		where = append(where, "("+strings.Join(ors, " OR ")+")")
		args = append(args, "%"+escapeLike(q)+"%")
	}
	sel := sp.ListSelect
	if sel == "" {
		sel = "to_jsonb(t)"
	}
	from := fmt.Sprintf(` FROM public.%s t %s`, pq.QuoteIdentifier(sp.Table), sp.Join)
	if len(where) > 0 {
		from += " WHERE " + strings.Join(where, " AND ")
	}
	// The total is its own count: a count(*) OVER () window would make Postgres
	// serialise every matching row to JSON before the LIMIT.
	query := `SELECT ` + sel + from + " ORDER BY " + sp.Order + fmt.Sprintf(" LIMIT %d OFFSET %d", p.Limit, p.Offset)

	out := []json.RawMessage{}
	total := 0
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(*)`+from, args...).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			b, err := present(sp, raw)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, mapIPAMError(err, false)
	}
	return out, total, nil
}

// Get returns one object.
func (s *IPAMService) Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error) {
	sp, err := s.spec(route)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		row, err := getRow(ctx, tx, sp, id, false)
		if err != nil {
			return err
		}
		out, err = json.Marshal(row)
		return err
	})
	return out, mapIPAMError(err, false)
}

// getRow reads one row in its API shape. RLS limits it to the tenant's rows
// (and, for a catalogue, the platform's).
func getRow(ctx context.Context, tx *sql.Tx, sp *ipamSpec, id uuid.UUID, lock bool) (map[string]any, error) {
	q := fmt.Sprintf(`SELECT to_jsonb(t) FROM public.%s t WHERE t.id = $1`, pq.QuoteIdentifier(sp.Table))
	if lock {
		q += " FOR UPDATE"
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, q, id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIPAMNotFound
		}
		return nil, err
	}
	return decodeRow(sp, raw)
}

// Create inserts one object from a JSON body and returns it.
func (s *IPAMService) Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	sp, err := s.spec(route)
	if err != nil {
		return nil, err
	}
	patch, err := decodeBody(sp, body)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		row, err := s.createTx(ctx, tx, sp, tenant, patch, "")
		if err != nil {
			return err
		}
		out, err = json.Marshal(row)
		return err
	})
	return out, mapIPAMError(err, false)
}

// createTx inserts row (API shape) and records the change. source overrides
// the context's change source ("" = the request's).
func (s *IPAMService) createTx(ctx context.Context, tx *sql.Tx, sp *ipamSpec, tenant uuid.UUID, row map[string]any, source changes.Source) (map[string]any, error) {
	for _, c := range sp.Cols {
		if c.Required && isEmpty(row[c.Name]) {
			return nil, ipamInvalid("%s is required", c.Name)
		}
	}
	if err := applyEngineCustomFields(ctx, tx, sp, true, nil, row, row, source); err != nil {
		return nil, err
	}
	if err := prepareCommon(ctx, tx, sp, tenant, uuid.Nil, row); err != nil {
		return nil, err
	}
	cols := []string{"tenant_id", "created_by"}
	var createdBy any
	if a, ok := changes.ActorFrom(ctx); ok {
		createdBy = a.UserID
	}
	args := []any{tenant, createdBy}
	vals := []string{"$1", "$2::uuid"}
	if sp.NoCreatedBy {
		cols, args, vals = cols[:1], args[:1], vals[:1]
	}
	for _, c := range sp.Cols {
		v, present := row[c.Name]
		if !present {
			continue
		}
		p, err := sqlParam(c, v)
		if err != nil {
			return nil, err
		}
		args = append(args, p)
		cols = append(cols, pq.QuoteIdentifier(c.Name))
		vals = append(vals, fmt.Sprintf("$%d::%s", len(args), c.Type.cast()))
	}
	q := fmt.Sprintf(`INSERT INTO public.%s AS t (%s) VALUES (%s) RETURNING to_jsonb(t)`,
		pq.QuoteIdentifier(sp.Table), strings.Join(cols, ", "), strings.Join(vals, ", "))
	var raw []byte
	if err := tx.QueryRowContext(ctx, q, args...).Scan(&raw); err != nil {
		return nil, err
	}
	post, err := decodeRow(sp, raw)
	if err != nil {
		return nil, err
	}
	if err := recordIPAMChange(ctx, tx, sp, tenant, changes.ActionCreate, nil, post, source); err != nil {
		return nil, err
	}
	if sp.AfterWrite != nil {
		if err := sp.AfterWrite(ctx, tx, tenant, nil, post); err != nil {
			return nil, err
		}
	}
	return post, nil
}

// Update applies a partial update (PATCH semantics) and returns the object.
func (s *IPAMService) Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	sp, err := s.spec(route)
	if err != nil {
		return nil, err
	}
	patch, err := decodeBody(sp, body)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		row, err := s.updateTx(ctx, tx, sp, tenant, id, patch, "")
		if err != nil {
			return err
		}
		out, err = json.Marshal(row)
		return err
	})
	return out, mapIPAMError(err, false)
}

func (s *IPAMService) updateTx(ctx context.Context, tx *sql.Tx, sp *ipamSpec, tenant, id uuid.UUID, patch map[string]any, source changes.Source) (map[string]any, error) {
	if err := refuseCatalogueRow(ctx, tx, sp, id); err != nil {
		return nil, err
	}
	pre, err := getRow(ctx, tx, sp, id, true)
	if err != nil {
		return nil, err
	}
	merged := map[string]any{}
	for k, v := range pre {
		merged[k] = v
	}
	for k, v := range patch {
		merged[k] = v
	}
	for _, c := range sp.Cols {
		if c.Required && isEmpty(merged[c.Name]) {
			return nil, ipamInvalid("%s is required", c.Name)
		}
	}
	if err := applyEngineCustomFields(ctx, tx, sp, false, pre, patch, merged, source); err != nil {
		return nil, err
	}
	if err := prepareCommon(ctx, tx, sp, tenant, id, merged); err != nil {
		return nil, err
	}
	var sets []string
	args := []any{tenant, id}
	for _, c := range sp.Cols {
		_, inPatch := patch[c.Name]
		if !inPatch && !c.Computed && !normalisedChange(c, pre, merged) {
			continue
		}
		p, err := sqlParam(c, merged[c.Name])
		if err != nil {
			return nil, err
		}
		args = append(args, p)
		sets = append(sets, fmt.Sprintf("%s = $%d::%s", pq.QuoteIdentifier(c.Name), len(args), c.Type.cast()))
	}
	if sp.Lifecycle {
		if st, ok := patch["status"].(string); ok && st == "active" && pre["status"] != "active" {
			var approver any
			if a, ok := changes.ActorFrom(ctx); ok {
				approver = a.UserID
			}
			args = append(args, approver)
			sets = append(sets, fmt.Sprintf("approved_by = $%d::uuid, approved_at = now()", len(args)))
		}
	}
	if len(sets) == 0 {
		return pre, nil
	}
	q := fmt.Sprintf(`UPDATE public.%s AS t SET %s, updated_at = now() WHERE t.tenant_id = $1 AND t.id = $2 RETURNING to_jsonb(t)`,
		pq.QuoteIdentifier(sp.Table), strings.Join(sets, ", "))
	var raw []byte
	if err := tx.QueryRowContext(ctx, q, args...).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIPAMNotFound
		}
		return nil, err
	}
	post, err := decodeRow(sp, raw)
	if err != nil {
		return nil, err
	}
	if err := recordIPAMChange(ctx, tx, sp, tenant, changes.ActionUpdate, pre, post, source); err != nil {
		return nil, err
	}
	if sp.AfterWrite != nil {
		if err := sp.AfterWrite(ctx, tx, tenant, pre, post); err != nil {
			return nil, err
		}
	}
	return post, nil
}

// prepareCommon runs the checks every object shares, then its own Prepare. A
// business unit is referenced by a plain foreign key, which checks that the
// row exists but not whose it is (an FK does not see RLS), so the reference is
// checked here under the tenant's own scope.
func prepareCommon(ctx context.Context, tx *sql.Tx, sp *ipamSpec, tenant, id uuid.UUID, row map[string]any) error {
	if _, ok := sp.col("business_unit_id"); ok {
		if err := visible(ctx, tx, "business_units", row["business_unit_id"]); err != nil {
			return err
		}
	}
	if sp.Prepare != nil {
		return sp.Prepare(ctx, tx, tenant, id, row)
	}
	return nil
}

// normalisedChange: Prepare rewrote a column the patch did not name (e.g. a
// slug derived from a new name).
func normalisedChange(c ipamCol, pre, merged map[string]any) bool {
	a, _ := json.Marshal(pre[c.Name])
	b, _ := json.Marshal(merged[c.Name])
	return string(a) != string(b)
}

// Delete removes one object.
func (s *IPAMService) Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error {
	sp, err := s.spec(route)
	if err != nil {
		return err
	}
	err = s.tx(ctx, tenant, func(tx *sql.Tx) error {
		if err := refuseCatalogueRow(ctx, tx, sp, id); err != nil {
			return err
		}
		pre, err := getRow(ctx, tx, sp, id, true)
		if err != nil {
			return err
		}
		if sp.BeforeDelete != nil {
			if err := sp.BeforeDelete(ctx, tx, tenant, pre); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM public.%s WHERE tenant_id = $1 AND id = $2`, pq.QuoteIdentifier(sp.Table)), tenant, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrIPAMNotFound
		}
		if err := recordIPAMChange(ctx, tx, sp, tenant, changes.ActionDelete, pre, nil, ""); err != nil {
			return err
		}
		if sp.AfterWrite != nil {
			return sp.AfterWrite(ctx, tx, tenant, pre, nil)
		}
		return nil
	})
	return mapIPAMError(err, true)
}

// refuseCatalogueRow answers ErrIPAMReadOnly for a platform-seeded catalogue
// row. It reads without a lock: FOR UPDATE applies the UPDATE policy, which
// hides platform rows, so a locking read would call them "not found".
func refuseCatalogueRow(ctx context.Context, tx *sql.Tx, sp *ipamSpec, id uuid.UUID) error {
	if !sp.Catalogue {
		return nil
	}
	row, err := getRow(ctx, tx, sp, id, false)
	if err != nil {
		return err
	}
	if row["tenant_id"] == nil {
		return ErrIPAMReadOnly
	}
	return nil
}

func recordIPAMChange(ctx context.Context, tx *sql.Tx, sp *ipamSpec, tenant uuid.UUID, action changes.Action, pre, post map[string]any, source changes.Source) error {
	row := post
	if row == nil {
		row = pre
	}
	id, err := uuid.Parse(fmt.Sprint(row["id"]))
	if err != nil {
		return fmt.Errorf("ipam: row has no id: %w", err)
	}
	c := changes.Change{TenantID: tenant, Kind: sp.Kind, ID: id, Action: action, Source: source}
	if pre != nil {
		c.Pre = pre
	}
	if post != nil {
		c.Post = post
	}
	return changes.InTx(tx).Record(ctx, c)
}

// IPAMObjectInfo describes one object route for the contract tests: its
// table, its vocabulary kind, the columns a caller may write and the ones a
// create requires.
type IPAMObjectInfo struct {
	Route, Table, Kind string
	Writable, Required []string
}

// IPAMObjects lists every object the engine serves.
func IPAMObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range ipamSpecs() {
		info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
		for _, c := range sp.Cols {
			if c.Computed {
				continue
			}
			info.Writable = append(info.Writable, c.Name)
			if c.Required {
				info.Required = append(info.Required, c.Name)
			}
		}
		out = append(out, info)
	}
	return out
}
