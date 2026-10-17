package services

// Racks, rack roles, rack types and rack reservations (DCIM BUILD_PLAN row 2.3;
// ADR-0010 D4; DATA_MODEL §3). CRUD runs on the IPAM object engine
// (ipam_engine.go) over rackSpecs(): one tenant-scoped transaction per call,
// RLS in force, every write recorded in object_changes, platform rack roles and
// rack types (tenant_id NULL) readable and refused with ErrIPAMReadOnly on any
// write. Column names are binding: they are the API property names, the
// OpenAPI schema properties (rack_contract_test.go) and the query-language
// fields.
//
// What each spec's hooks add over the schema:
//
//   - racks: the site and location are the tenant's and the location is in the
//     site; a rack type, when named or changed, stamps its dimensions onto the
//     rack (NetBox 4.1's copy-on-assign); a resize must still hold every placed
//     device and reserved unit; a move to another site or location carries the
//     placed devices with it; the rack_utilization row is kept in step; and a
//     delete unplaces the devices first.
//   - rack reservations: the units exist in the rack, and overlap neither
//     another reservation nor an installed device (under the rack's lock).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// RackObjectRoutes are the rack object routes under /dcim, in order.
func RackObjectRoutes() []string {
	return []string{"rack-roles", "rack-types", "racks", "rack-reservations"}
}

// RackService is the rack object store.
type RackService struct {
	eng *IPAMService
}

// NewRackService returns the store over db (the raw pool; RLS is set per
// transaction).
func NewRackService(db *sql.DB) *RackService {
	return &RackService{eng: newObjectEngine(db, rackSpecs())}
}

func isRackObject(route string) bool {
	for _, r := range RackObjectRoutes() {
		if r == route {
			return true
		}
	}
	return false
}

func unknownRackObject(route string) error {
	return fmt.Errorf("%w: unknown rack object %q", ErrIPAMNotFound, route)
}

// List returns one page of a rack object route.
func (s *RackService) List(ctx context.Context, tenant uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	if !isRackObject(route) {
		return nil, 0, unknownRackObject(route)
	}
	return s.eng.List(ctx, tenant, route, p)
}

// Get returns one rack object.
func (s *RackService) Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error) {
	if !isRackObject(route) {
		return nil, unknownRackObject(route)
	}
	return s.eng.Get(ctx, tenant, route, id)
}

// Create creates a rack object.
func (s *RackService) Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	if !isRackObject(route) {
		return nil, unknownRackObject(route)
	}
	return s.eng.Create(ctx, tenant, route, body)
}

// Update patches a rack object.
func (s *RackService) Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	if !isRackObject(route) {
		return nil, unknownRackObject(route)
	}
	return s.eng.Update(ctx, tenant, route, id, body)
}

// Delete removes a rack object. A rack type a rack uses answers ErrIPAMInUse.
func (s *RackService) Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error {
	if !isRackObject(route) {
		return unknownRackObject(route)
	}
	return s.eng.Delete(ctx, tenant, route, id)
}

// RackObjects lists every rack object the engine serves (contract tests).
func RackObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range rackSpecs() {
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

var rackFormFactors = []string{"2-post-frame", "4-post-frame", "4-post-cabinet", "wall-frame", "wall-frame-vertical",
	"wall-cabinet", "wall-cabinet-vertical"}

// rackDimensionCols are the physical columns a rack type stamps onto a rack.
var rackDimensionCols = []string{"form_factor", "width", "u_height", "starting_unit", "desc_units", "outer_width",
	"outer_depth", "outer_unit", "mounting_depth", "weight", "max_weight", "weight_unit"}

func rackDimensionSpec() []ipamCol {
	return []ipamCol{
		{Name: "width", Type: colInt},
		{Name: "u_height", Type: colInt},
		{Name: "starting_unit", Type: colInt},
		{Name: "desc_units", Type: colBool},
		{Name: "outer_width", Type: colInt},
		{Name: "outer_depth", Type: colInt},
		{Name: "outer_unit", Type: colText},
		{Name: "mounting_depth", Type: colInt},
		{Name: "weight", Type: colNumeric},
		{Name: "max_weight", Type: colInt},
		{Name: "weight_unit", Type: colText},
	}
}

func prepareRackDimensions(row map[string]any) error {
	if err := oneOf(row, "form_factor", rackFormFactors); err != nil {
		return err
	}
	if err := oneOf(row, "outer_unit", []string{"mm", "in"}); err != nil {
		return err
	}
	return oneOf(row, "weight_unit", []string{"kg", "g", "lb", "oz"})
}

func rackSpecs() []*ipamSpec {
	reservationCols := []ipamCol{
		{Name: "rack_id", Type: colUUID, Required: true},
		{Name: "units", Type: colBigintArray, Required: true},
		{Name: "user_id", Type: colUUID},
		{Name: "business_unit_id", Type: colUUID},
		externalIDsCol,
		{Name: "description", Type: colText, Required: true},
	}
	for _, c := range substrateCols {
		if c.Name != "description" {
			reservationCols = append(reservationCols, c)
		}
	}
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindRackRole, Table: "rack_roles", Route: "rack-roles", Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "color", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}, {Param: "scope", Custom: scopeFilter}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
				if err := prepareSlug(ctx, tx, tenant, id, row); err != nil {
					return err
				}
				return normaliseColor(row, "color")
			},
		},
		{
			Kind: dcim.ObjectKindRackType, Table: "rack_types", Route: "rack-types", Catalogue: true,
			Cols: withSubstrate(append([]ipamCol{
				{Name: "manufacturer_id", Type: colUUID, Required: true},
				{Name: "model", Type: colText, Required: true},
				{Name: "slug", Type: colText},
				{Name: "form_factor", Type: colText, Required: true},
			}, append(rackDimensionSpec(), externalIDsCol)...)...),
			Filters: []ipamFilter{
				{Param: "manufacturer_id", Column: "manufacturer_id", Type: colUUID},
				{Param: "slug", Column: "slug", Type: colText},
				{Param: "form_factor", Column: "form_factor", Type: colText},
				{Param: "scope", Custom: scopeFilter},
			},
			Search: []string{"model", "slug", "description"},
			Order:  "lower(m.name), lower(t.model), t.id",
			ListSelect: `to_jsonb(t) || jsonb_build_object(
				'manufacturer', jsonb_build_object('id', m.id, 'name', m.name, 'slug', m.slug))`,
			Join: "JOIN public.manufacturers m ON m.id = t.manufacturer_id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := prepareModelSlug(row); err != nil {
					return err
				}
				if err := prepareRackDimensions(row); err != nil {
					return err
				}
				return visible(ctx, tx, "manufacturers", row["manufacturer_id"])
			},
		},
		{
			Kind: dcim.ObjectKindRack, Table: "racks", Route: "racks",
			Cols: withSubstrate(append([]ipamCol{
				{Name: "name", Type: colText, Required: true},
				{Name: "facility_id", Type: colText},
				{Name: "site_id", Type: colUUID, Required: true},
				{Name: "location_id", Type: colUUID},
				{Name: "business_unit_id", Type: colUUID},
				{Name: "role_id", Type: colUUID},
				{Name: "rack_type_id", Type: colUUID},
				{Name: "operational_status", Type: colText},
				{Name: "serial", Type: colText},
				{Name: "asset_tag", Type: colText},
				{Name: "form_factor", Type: colText},
				{Name: "airflow", Type: colText},
			}, append(rackDimensionSpec(), externalIDsCol)...)...),
			Filters: []ipamFilter{
				{Param: "site_id", Column: "site_id", Type: colUUID},
				{Param: "location_id", Column: "location_id", Type: colUUID},
				{Param: "role_id", Column: "role_id", Type: colUUID},
				{Param: "rack_type_id", Column: "rack_type_id", Type: colUUID},
				{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
				{Param: "operational_status", Column: "operational_status", Type: colText},
				{Param: "name", Column: "name", Type: colText},
			},
			Search: []string{"name", "facility_id", "serial", "asset_tag", "description"},
			Order:  "lower(st.name), lower(t.name), t.id",
			// The list carries what the Racks table shows — site, location,
			// role, type, utilisation and device count — so it is one request.
			ListSelect: `to_jsonb(t) || jsonb_build_object(
				'site', jsonb_build_object('id', st.id, 'name', st.name, 'slug', st.slug),
				'location', CASE WHEN lc.id IS NULL THEN NULL ELSE jsonb_build_object('id', lc.id, 'name', lc.name) END,
				'role', CASE WHEN rr.id IS NULL THEN NULL ELSE jsonb_build_object('id', rr.id, 'name', rr.name, 'slug', rr.slug, 'color', rr.color) END,
				'rack_type', CASE WHEN rt.id IS NULL THEN NULL ELSE jsonb_build_object('id', rt.id, 'model', rt.model, 'slug', rt.slug) END,
				'utilization', CASE WHEN ru.rack_id IS NULL THEN NULL ELSE jsonb_build_object('used_units', ru.used_units, 'total_units', ru.total_units, 'utilization', ru.utilization) END,
				'device_count', (SELECT count(*) FROM public.assets a WHERE a.tenant_id = t.tenant_id AND a.rack_id = t.id AND a.deleted_at IS NULL))`,
			Join: `JOIN public.sites st ON st.id = t.site_id
				LEFT JOIN public.locations lc ON lc.id = t.location_id
				LEFT JOIN public.rack_roles rr ON rr.id = t.role_id
				LEFT JOIN public.rack_types rt ON rt.id = t.rack_type_id
				LEFT JOIN public.rack_utilization ru ON ru.rack_id = t.id`,
			Prepare:    prepareRack,
			AfterWrite: afterRackWrite,
			BeforeDelete: func(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre map[string]any) error {
				return unplaceRackTx(ctx, tx, tenant, rowID(pre))
			},
		},
		{
			Kind: dcim.ObjectKindRackReservation, Table: "rack_reservations", Route: "rack-reservations",
			Cols: reservationCols,
			Filters: []ipamFilter{
				{Param: "rack_id", Column: "rack_id", Type: colUUID},
				{Param: "user_id", Column: "user_id", Type: colUUID},
				{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
			},
			Search: []string{"description"},
			Order:  "lower(rk.name), t.created_at, t.id",
			ListSelect: `to_jsonb(t) || jsonb_build_object(
				'rack', jsonb_build_object('id', rk.id, 'name', rk.name, 'site_id', rk.site_id))`,
			Join:    "JOIN public.racks rk ON rk.id = t.rack_id",
			Prepare: prepareReservation,
		},
	}
}

func rowID(row map[string]any) uuid.UUID {
	id, _ := uuid.Parse(fmt.Sprint(row["id"]))
	return id
}

func rowUUID(row map[string]any, col string) uuid.NullUUID {
	v, ok := row[col]
	if !ok || v == nil || v == "" {
		return uuid.NullUUID{}
	}
	id, err := uuid.Parse(fmt.Sprint(v))
	if err != nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: id, Valid: true}
}

func rackRowInt(row map[string]any, col string, def int) int {
	v, ok := row[col]
	if !ok || v == nil {
		return def
	}
	n, err := strconv.Atoi(fmt.Sprint(v))
	if err != nil {
		return def
	}
	return n
}

// prepareRack validates a rack's references and geometry; on update the row is
// already locked (the engine reads it FOR UPDATE), which is the rack lock the
// placement checks share.
func prepareRack(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	if err := prepareRackDimensions(row); err != nil {
		return err
	}
	if err := oneOf(row, "airflow", []string{"front-to-rear", "rear-to-front"}); err != nil {
		return err
	}
	if err := oneOf(row, "operational_status", []string{"reserved", "available", "planned", "active", "deprecated"}); err != nil {
		return err
	}
	if err := visible(ctx, tx, "sites", row["site_id"]); err != nil {
		return err
	}
	site := rowUUID(row, "site_id")
	if loc := rowUUID(row, "location_id"); loc.Valid {
		var locSite uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT site_id FROM locations WHERE id = $1`, loc.UUID).Scan(&locSite)
		if errors.Is(err, sql.ErrNoRows) {
			return ipamInvalid("no such location %s", loc.UUID)
		}
		if err != nil {
			return err
		}
		if !site.Valid || locSite != site.UUID {
			return ipamInvalid("the location is not in the rack's site")
		}
	}
	if err := visible(ctx, tx, "rack_roles", row["role_id"]); err != nil {
		return err
	}
	if err := visible(ctx, tx, "rack_types", row["rack_type_id"]); err != nil {
		return err
	}
	// A rack type, when first named or changed, stamps its dimensions onto
	// the rack (NetBox 4.1 Rack.copy_racktype_attrs).
	if rt := rowUUID(row, "rack_type_id"); rt.Valid {
		var prior uuid.NullUUID
		if id != uuid.Nil {
			if err := tx.QueryRowContext(ctx, `SELECT rack_type_id FROM racks WHERE id = $1`, id).Scan(&prior); err != nil {
				return err
			}
		}
		if !prior.Valid || prior.UUID != rt.UUID {
			if err := stampRackType(ctx, tx, rt.UUID, row); err != nil {
				return err
			}
		}
	}
	if id == uuid.Nil {
		return nil
	}
	return checkRackStillHolds(ctx, tx, tenant, id, rackRowInt(row, "starting_unit", 1), rackRowInt(row, "u_height", 42))
}

func stampRackType(ctx context.Context, tx *sql.Tx, rackType uuid.UUID, row map[string]any) error {
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT to_jsonb(t) FROM rack_types t WHERE t.id = $1`, rackType).Scan(&raw); err != nil {
		return err
	}
	var t map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&t); err != nil {
		return err
	}
	for _, c := range rackDimensionCols {
		row[c] = t[c]
	}
	return nil
}

// checkRackStillHolds refuses a resize (or renumbering) that would leave a
// placed device or a reserved unit outside the rack.
func checkRackStillHolds(ctx context.Context, tx *sql.Tx, tenant, rack uuid.UUID, start, uHeight int) error {
	g := rackGeometry{StartingUnit: start, UHeight: uHeight}
	devs, err := loadRackDevices(ctx, tx, tenant, rack)
	if err != nil {
		return err
	}
	for _, d := range devs {
		if !g.fits(d.Pos2, d.Pos2+d.H2) {
			return ipamInvalid("%s at U%s would no longer fit %s; move or unplace it first", d.Name, fmtU(float64(d.Pos2)/2), g.unitRange())
		}
	}
	res, err := loadRackReservations(ctx, tx, tenant, rack, uuid.Nil)
	if err != nil {
		return err
	}
	for _, r := range res {
		for _, u := range r.Units {
			if u < start || u >= start+uHeight {
				return ipamInvalid("reservation %q holds U%d, outside %s", r.Description, u, g.unitRange())
			}
		}
	}
	return nil
}

// afterRackWrite keeps the utilisation row in step and carries placed devices
// to the rack's new site/location (NetBox moves a rack's devices with it).
func afterRackWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	if post == nil {
		return nil // deleted: the utilisation row cascades
	}
	rack := rowID(post)
	if pre != nil && (fmt.Sprint(pre["site_id"]) != fmt.Sprint(post["site_id"]) || fmt.Sprint(pre["location_id"]) != fmt.Sprint(post["location_id"])) {
		if err := carryRackDevices(ctx, tx, tenant, rack, rowUUID(post, "site_id"), rowUUID(post, "location_id")); err != nil {
			return err
		}
	}
	return refreshRackUtilizationTx(ctx, tx, tenant, rack)
}

func carryRackDevices(ctx context.Context, tx *sql.Tx, tenant, rack uuid.UUID, site, loc uuid.NullUUID) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, site_id, location_id FROM assets
		WHERE tenant_id = $1 AND rack_id = $2 AND deleted_at IS NULL ORDER BY id FOR UPDATE`, tenant, rack)
	if err != nil {
		return err
	}
	type moved struct {
		id        uuid.UUID
		site, loc uuid.NullUUID
	}
	var all []moved
	for rows.Next() {
		var m moved
		if err := rows.Scan(&m.id, &m.site, &m.loc); err != nil {
			_ = rows.Close()
			return err
		}
		all = append(all, m)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET site_id = $3, location_id = $4, updated_at = now()
		WHERE tenant_id = $1 AND rack_id = $2`, tenant, rack, site, loc); err != nil {
		return err
	}
	rec := changes.InTx(tx)
	for _, m := range all {
		if err := rec.Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindAsset, ID: m.id, Action: changes.ActionUpdate,
			Pre:  map[string]any{"site_id": nullUUIDString(m.site), "location_id": nullUUIDString(m.loc)},
			Post: map[string]any{"site_id": nullUUIDString(site), "location_id": nullUUIDString(loc)}}); err != nil {
			return err
		}
	}
	return nil
}

// prepareReservation locks the rack and checks the units: inside the rack,
// sorted and unique, overlapping neither another reservation nor a device.
func prepareReservation(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	if err := visible(ctx, tx, "business_units", row["business_unit_id"]); err != nil {
		return err
	}
	if id == uuid.Nil && isEmpty(row["user_id"]) {
		if a, ok := changes.ActorFrom(ctx); ok {
			row["user_id"] = a.UserID.String()
		}
	}
	rack := rowUUID(row, "rack_id")
	if !rack.Valid {
		return ipamInvalid("rack_id is required")
	}
	racks, err := lockRacks(ctx, tx, tenant, rack.UUID)
	if err != nil {
		return err
	}
	g, ok := racks[rack.UUID]
	if !ok {
		return ipamInvalid("no such rack %s", rack.UUID)
	}
	units, err := reservationUnits(row["units"])
	if err != nil {
		return err
	}
	for _, u := range units {
		if u < g.StartingUnit || u >= g.StartingUnit+g.UHeight {
			return ipamInvalid("U%d is not in rack %s (%s)", u, g.Name, g.unitRange())
		}
	}
	vals := make([]any, len(units))
	for i, u := range units {
		vals[i] = json.Number(strconv.Itoa(u))
	}
	row["units"] = vals

	others, err := loadRackReservations(ctx, tx, tenant, g.ID, id)
	if err != nil {
		return err
	}
	devs, err := loadRackDevices(ctx, tx, tenant, g.ID)
	if err != nil {
		return err
	}
	for _, u := range units {
		for _, o := range others {
			if o.covers(2*u, 2*u+2) {
				return &PlacementConflictError{
					Message:             fmt.Sprintf("U%d is already reserved (%s)", u, o.Description),
					BlockingReservation: o.blocker(),
				}
			}
		}
		for _, d := range devs {
			if d.H2 > 0 && d.Pos2 < 2*u+2 && 2*u < d.Pos2+d.H2 {
				return &PlacementConflictError{
					Message:       fmt.Sprintf("U%d is occupied by %s", u, d.Name),
					BlockingAsset: d.blocker(),
				}
			}
		}
	}
	return nil
}

func reservationUnits(v any) ([]int, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, ipamInvalid("units must be a list of unit numbers")
	}
	seen := map[int]bool{}
	var out []int
	for _, e := range arr {
		n, err := strconv.Atoi(fmt.Sprint(e))
		if err != nil {
			return nil, ipamInvalid("units must be whole unit numbers")
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, ipamInvalid("units must name at least one unit")
	}
	sort.Ints(out)
	return out, nil
}

// RackCountForSite is the number of racks in a site (the site page's count).
func RackCountForSite(ctx context.Context, tx changes.DBTX, tenant, site uuid.UUID) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM racks WHERE tenant_id = $1 AND site_id = $2`, tenant, site).Scan(&n)
	return n, err
}
