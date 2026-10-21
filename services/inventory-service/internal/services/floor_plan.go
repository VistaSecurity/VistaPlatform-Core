package services

// Floor plans (DCIM gap 9; DATA_MODEL sections 1 and 3): a location carries a
// rectangular grid (locations.floor_plan_width x floor_plan_depth, in metres
// or feet) and each of its racks a place on it (racks.floor_x / floor_y, the
// centre of the rack's footprint measured from the plan's top-left corner, and
// floor_rotation, the way the rack's front faces: 0 = towards the bottom edge
// of the plan, then clockwise in quarter turns). The shape follows the NetBox
// floorplan plugin's FloorPlan (a size in a unit) and its tiles (an object at
// x, y, rotation); NetBox core has no floor plan, so nothing here is synced.
//
// What the database says: the plan's three columns are set together, a
// rack's three columns are set together, the rotation is a quarter turn. What
// the service says (this file):
//
//   - a rack is placed only on its own location's plan, and only when that
//     location has one;
//   - the rack's footprint, turned by its rotation, lies inside the plan;
//   - a rack that moves to another location leaves the old plan (its place
//     is cleared unless the same write places it on the new one);
//   - a plan cannot shrink past, change the unit under, or be removed from
//     racks that are placed on it; deleting the location takes its racks off.
//
// A rack's footprint is its outer width x outer depth (NetBox's outer_width /
// outer_depth in outer_unit). When either is not recorded the default
// footprint stands in for it: 600 mm x 1000 mm, the common 19-inch cabinet,
// and the floor plan read says so per rack (footprint_default), so a guessed
// size is never shown as a measured one.
//
// Overlap between racks is not checked: aisles, cages and half-depth frames
// share floor legitimately, and the drawing shows it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// Floor plan limits and defaults.
const (
	// FloorPlanMaxSide is the largest plan side, in the plan's unit.
	FloorPlanMaxSide = 10000.0
	// DefaultRackFootprintWidthMM / DepthMM stand in for a rack whose outer
	// dimensions are not recorded.
	DefaultRackFootprintWidthMM = 600.0
	DefaultRackFootprintDepthMM = 1000.0
	floorEpsilon                = 1e-6
)

// floorPlanUnits are the plan units (metres, feet).
var floorPlanUnits = []string{"m", "ft"}

// floorRotations are the quarter turns a rack takes on a plan.
var floorRotations = []int{0, 90, 180, 270}

// FloorPlanSize is a location's plan: Width (x) by Depth (y) in Unit.
type FloorPlanSize struct {
	Width float64
	Depth float64
	Unit  string
}

// round2 is the numeric(8,2) a coordinate or a side is stored as.
func round2(v float64) float64 { return math.Round(v*100) / 100 }

// FloorLength converts a rack's outer dimension in mm or in to the plan's unit
// (m or ft).
func FloorLength(v float64, from, to string) float64 {
	mm := v
	if from == "in" {
		mm = v * 25.4
	}
	if to == "ft" {
		return mm / 304.8
	}
	return mm / 1000
}

// RackFootprint is a rack's width x depth in the plan's unit, and whether the
// default footprint stood in for either side.
func RackFootprint(outerWidth, outerDepth *float64, outerUnit *string, planUnit string) (w, d float64, defaulted bool) {
	unit := "mm"
	if outerUnit != nil && *outerUnit != "" {
		unit = *outerUnit
	}
	if outerWidth != nil && *outerWidth > 0 {
		w = FloorLength(*outerWidth, unit, planUnit)
	} else {
		w, defaulted = FloorLength(DefaultRackFootprintWidthMM, "mm", planUnit), true
	}
	if outerDepth != nil && *outerDepth > 0 {
		d = FloorLength(*outerDepth, unit, planUnit)
	} else {
		d, defaulted = FloorLength(DefaultRackFootprintDepthMM, "mm", planUnit), true
	}
	return w, d, defaulted
}

// FloorExtent is the footprint's axis-aligned size on the plan once turned: a
// quarter turn swaps width and depth.
func FloorExtent(w, d float64, rotation int) (ex, ey float64) {
	if rotation == 90 || rotation == 270 {
		return d, w
	}
	return w, d
}

// FloorFitProblem is why a footprint of w x d centred at (x, y) and turned by
// rotation does not lie inside plan; "" when it does.
func FloorFitProblem(plan FloorPlanSize, x, y, w, d float64, rotation int) string {
	ex, ey := FloorExtent(w, d, rotation)
	if ex > plan.Width+floorEpsilon || ey > plan.Depth+floorEpsilon {
		return fmt.Sprintf("its footprint (%s x %s %s) is larger than the floor plan (%s x %s %s)",
			fmtFloor(ex), fmtFloor(ey), plan.Unit, fmtFloor(plan.Width), fmtFloor(plan.Depth), plan.Unit)
	}
	if x-ex/2 < -floorEpsilon || x+ex/2 > plan.Width+floorEpsilon || y-ey/2 < -floorEpsilon || y+ey/2 > plan.Depth+floorEpsilon {
		return fmt.Sprintf("centred at (%s, %s) its footprint runs past the edge of the %s x %s %s floor plan; x must be between %s and %s and y between %s and %s",
			fmtFloor(x), fmtFloor(y), fmtFloor(plan.Width), fmtFloor(plan.Depth), plan.Unit,
			fmtFloor(ex/2), fmtFloor(plan.Width-ex/2), fmtFloor(ey/2), fmtFloor(plan.Depth-ey/2))
	}
	return ""
}

func fmtFloor(v float64) string { return strconv.FormatFloat(round2(v), 'f', -1, 64) }

// ValidateFloorPlanSize checks a location's plan input: all three or none, each
// side above 0 and at most FloorPlanMaxSide, a known unit. Nil for none.
func ValidateFloorPlanSize(width, depth *float64, unit *string) (*FloorPlanSize, error) {
	u := ""
	if unit != nil {
		u = strings.TrimSpace(*unit)
	}
	if width == nil && depth == nil && u == "" {
		return nil, nil
	}
	if width == nil || depth == nil || u == "" {
		return nil, siteInvalid("floor_plan_width, floor_plan_depth and floor_plan_unit are set together")
	}
	if !containsString(floorPlanUnits, u) {
		return nil, siteInvalid("floor_plan_unit must be m or ft")
	}
	p := FloorPlanSize{Width: round2(*width), Depth: round2(*depth), Unit: u}
	for _, side := range []float64{p.Width, p.Depth} {
		if side <= 0 || side > FloorPlanMaxSide || math.IsNaN(side) {
			return nil, siteInvalid("a floor plan's width and depth must be above 0 and at most %s %s", fmtFloor(FloorPlanMaxSide), u)
		}
	}
	return &p, nil
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func planOf(l *models.Location) *FloorPlanSize {
	if l == nil || l.FloorPlanWidth == nil || l.FloorPlanDepth == nil || l.FloorPlanUnit == nil {
		return nil
	}
	return &FloorPlanSize{Width: *l.FloorPlanWidth, Depth: *l.FloorPlanDepth, Unit: *l.FloorPlanUnit}
}

// placedRack is a rack placed on a location's plan.
type placedRack struct {
	ID                     uuid.UUID
	Name                   string
	X, Y                   float64
	Rotation               int
	OuterWidth, OuterDepth *float64
	OuterUnit              *string
}

func loadPlacedRacks(ctx context.Context, q changes.DBTX, tenant, location uuid.UUID) ([]placedRack, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name, floor_x, floor_y, floor_rotation, outer_width, outer_depth, outer_unit
		FROM racks WHERE tenant_id = $1 AND location_id = $2 AND floor_x IS NOT NULL ORDER BY lower(name), id`, tenant, location)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []placedRack
	for rows.Next() {
		var r placedRack
		var rot int64
		if err := rows.Scan(&r.ID, &r.Name, &r.X, &r.Y, &rot, &r.OuterWidth, &r.OuterDepth, &r.OuterUnit); err != nil {
			return nil, err
		}
		r.Rotation = int(rot)
		out = append(out, r)
	}
	return out, rows.Err()
}

// checkLocationPlanHolds refuses a plan change that would strand a placed
// rack: removing the plan, changing its unit, or shrinking it past a rack.
func checkLocationPlanHolds(ctx context.Context, q changes.DBTX, tenant, location uuid.UUID, before, after *FloorPlanSize) error {
	racks, err := loadPlacedRacks(ctx, q, tenant, location)
	if err != nil || len(racks) == 0 {
		return err
	}
	if after == nil {
		return siteInvalid("%s placed on this floor plan; take them off the plan before removing it", racksPhrase(len(racks)))
	}
	if before != nil && before.Unit != after.Unit {
		return siteInvalid("the floor plan's unit cannot change while %s placed on it", racksPhrase(len(racks)))
	}
	for _, r := range racks {
		w, d, _ := RackFootprint(r.OuterWidth, r.OuterDepth, r.OuterUnit, after.Unit)
		if p := FloorFitProblem(*after, r.X, r.Y, w, d, r.Rotation); p != "" {
			return siteInvalid("rack %s would no longer fit the floor plan (%s); move it first", r.Name, p)
		}
	}
	return nil
}

func racksPhrase(n int) string {
	if n == 1 {
		return "1 rack is"
	}
	return fmt.Sprintf("%d racks are", n)
}

// clearFloorPlacementsTx takes every rack of the locations off their plans
// (the locations are being deleted) and records each change.
func (s *SiteService) clearFloorPlacementsTx(ctx context.Context, tx *sqlx.Tx, tenant, actor uuid.UUID, locations []uuid.UUID) error {
	for _, loc := range locations {
		racks, err := loadPlacedRacks(ctx, tx, tenant, loc)
		if err != nil {
			return err
		}
		for _, r := range racks {
			if _, err := tx.ExecContext(ctx, `UPDATE racks SET floor_x = NULL, floor_y = NULL, floor_rotation = NULL, updated_at = now()
				WHERE tenant_id = $1 AND id = $2`, tenant, r.ID); err != nil {
				return err
			}
			if err := s.record(ctx, tx, tenant, actor, dcim.ObjectKindRack, "update", r.ID,
				map[string]any{"floor_x": r.X, "floor_y": r.Y, "floor_rotation": r.Rotation},
				map[string]any{"floor_x": nil, "floor_y": nil, "floor_rotation": nil}); err != nil {
				return err
			}
		}
	}
	return nil
}

// rowFloat reads a numeric column of an engine row (json.Number, a number or
// a numeric string); nil when empty.
func rowFloat(row map[string]any, col string) (*float64, error) {
	v, ok := row[col]
	if !ok || isEmpty(v) {
		return nil, nil
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(v)), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, ipamInvalid("%s must be a number", col)
	}
	return &f, nil
}

func rowStringPtr(row map[string]any, col string) *string {
	v, ok := row[col].(string)
	if !ok || v == "" {
		return nil
	}
	return &v
}

func clearRackFloor(row map[string]any) {
	row["floor_x"], row["floor_y"], row["floor_rotation"] = nil, nil, nil
}

// prepareRackFloor validates a rack's place on its location's floor plan (the
// rack spec's Prepare, so a rack PATCH, a bulk import and a sync write all
// pass through it). On update the rack row is already locked.
func prepareRackFloor(ctx context.Context, tx *sql.Tx, id uuid.UUID, row map[string]any) error {
	loc := rowUUID(row, "location_id")
	if id != uuid.Nil {
		// A rack that moves to another location leaves the old plan,
		// unless the same write gives it a new place.
		var prior uuid.NullUUID
		var px, py sql.NullFloat64
		var prot sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT location_id, floor_x, floor_y, floor_rotation FROM racks WHERE id = $1`, id).
			Scan(&prior, &px, &py, &prot); err != nil {
			return err
		}
		if prior != loc && px.Valid {
			x, _ := rowFloat(row, "floor_x")
			y, _ := rowFloat(row, "floor_y")
			r, _ := rowFloat(row, "floor_rotation")
			unchanged := x != nil && y != nil && *x == px.Float64 && *y == py.Float64 &&
				(r == nil || (prot.Valid && int64(*r) == prot.Int64))
			if unchanged {
				clearRackFloor(row)
				return nil
			}
		}
	}
	x, err := rowFloat(row, "floor_x")
	if err != nil {
		return err
	}
	y, err := rowFloat(row, "floor_y")
	if err != nil {
		return err
	}
	rot, err := rowFloat(row, "floor_rotation")
	if err != nil {
		return err
	}
	if x == nil && y == nil {
		if rot != nil {
			return ipamInvalid("floor_rotation needs floor_x and floor_y")
		}
		clearRackFloor(row)
		return nil
	}
	if x == nil || y == nil {
		return ipamInvalid("floor_x and floor_y are set together")
	}
	rotation := 0
	if rot != nil {
		rotation = int(*rot)
		if float64(rotation) != *rot || !containsInt(floorRotations, rotation) {
			return ipamInvalid("floor_rotation must be 0, 90, 180 or 270")
		}
	}
	if !loc.Valid {
		return ipamInvalid("a rack is placed on its location's floor plan; give the rack a location first")
	}
	var name string
	var w, d sql.NullFloat64
	var unit sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT name, floor_plan_width, floor_plan_depth, floor_plan_unit FROM locations WHERE id = $1`, loc.UUID).
		Scan(&name, &w, &d, &unit)
	if errors.Is(err, sql.ErrNoRows) {
		return ipamInvalid("no such location %s", loc.UUID)
	}
	if err != nil {
		return err
	}
	if !w.Valid || !d.Valid || !unit.Valid {
		return ipamInvalid("location %s has no floor plan; set its size first", name)
	}
	plan := FloorPlanSize{Width: w.Float64, Depth: d.Float64, Unit: unit.String}
	ow, err := rowFloat(row, "outer_width")
	if err != nil {
		return err
	}
	od, err := rowFloat(row, "outer_depth")
	if err != nil {
		return err
	}
	fx, fy := round2(*x), round2(*y)
	fw, fd, _ := RackFootprint(ow, od, rowStringPtr(row, "outer_unit"), plan.Unit)
	if p := FloorFitProblem(plan, fx, fy, fw, fd, rotation); p != "" {
		return ipamInvalid("the rack does not fit the floor plan of %s: %s", name, p)
	}
	row["floor_x"] = json.Number(strconv.FormatFloat(fx, 'f', -1, 64))
	row["floor_y"] = json.Number(strconv.FormatFloat(fy, 'f', -1, 64))
	row["floor_rotation"] = json.Number(strconv.Itoa(rotation))
	return nil
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GET /dcim/locations/{id}/floor-plan
// ---------------------------------------------------------------------------

// FloorPlanLocation is the location a floor plan read is for.
type FloorPlanLocation struct {
	ID             uuid.UUID `json:"id"`
	SiteID         uuid.UUID `json:"site_id"`
	Name           string    `json:"name"`
	Path           string    `json:"path"`
	FloorPlanWidth *float64  `json:"floor_plan_width"`
	FloorPlanDepth *float64  `json:"floor_plan_depth"`
	FloorPlanUnit  *string   `json:"floor_plan_unit"`
}

// FloorPlanFootprint is the default rack footprint.
type FloorPlanFootprint struct {
	Width float64 `json:"width"`
	Depth float64 `json:"depth"`
	Unit  string  `json:"unit"`
}

// FloorPlanRack is one rack of the location, placed or not.
type FloorPlanRack struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	OperationalStatus string    `json:"operational_status"`
	FloorX            *float64  `json:"floor_x"`
	FloorY            *float64  `json:"floor_y"`
	FloorRotation     *int      `json:"floor_rotation"`
	OuterWidth        *float64  `json:"outer_width"`
	OuterDepth        *float64  `json:"outer_depth"`
	OuterUnit         *string   `json:"outer_unit"`
	// FootprintWidth / FootprintDepth are the footprint in the plan's unit
	// (unturned); nil when the location has no plan.
	FootprintWidth   *float64 `json:"footprint_width"`
	FootprintDepth   *float64 `json:"footprint_depth"`
	FootprintDefault bool     `json:"footprint_default"`
	// Utilization is the rack_utilization cache's percentage of units in use;
	// nil before its first refresh.
	Utilization *float64 `json:"utilization"`
	UsedUnits   *float64 `json:"used_units"`
	TotalUnits  *float64 `json:"total_units"`
	// PowerUtilization is the rack power budget's allocated / available
	// percentage; nil when no feed serves the rack or none declares power.
	PowerUtilization *float64 `json:"power_utilization"`
	DeviceCount      int      `json:"device_count"`
}

// LocationFloorPlan is the floor plan read: the location's plan and every rack
// in the location (placed ones carry floor_x / floor_y).
type LocationFloorPlan struct {
	Location         FloorPlanLocation  `json:"location"`
	DefaultFootprint FloorPlanFootprint `json:"default_footprint"`
	Racks            []FloorPlanRack    `json:"racks"`
}

// LocationFloorPlan reads one location's floor plan.
func (s *SiteService) LocationFloorPlan(ctx context.Context, tenantID, id uuid.UUID) (*LocationFloorPlan, error) {
	var out *LocationFloorPlan
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		l, err := s.getLocationTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		plan := planOf(l)
		fp := &LocationFloorPlan{
			Location: FloorPlanLocation{ID: l.ID, SiteID: l.SiteID, Name: l.Name, Path: l.Path,
				FloorPlanWidth: l.FloorPlanWidth, FloorPlanDepth: l.FloorPlanDepth, FloorPlanUnit: l.FloorPlanUnit},
			DefaultFootprint: FloorPlanFootprint{Width: DefaultRackFootprintWidthMM, Depth: DefaultRackFootprintDepthMM, Unit: "mm"},
			Racks:            []FloorPlanRack{},
		}
		rows, err := tx.QueryContext(ctx, `SELECT t.id, t.name, t.operational_status, t.floor_x, t.floor_y, t.floor_rotation,
				t.outer_width, t.outer_depth, t.outer_unit, ru.utilization, ru.used_units, ru.total_units,
				(SELECT count(*) FROM public.assets a WHERE a.tenant_id = t.tenant_id AND a.rack_id = t.id AND a.deleted_at IS NULL),
				(`+rackPowerUtilizationSQL+`)->>'utilization'
			  FROM public.racks t LEFT JOIN public.rack_utilization ru ON ru.rack_id = t.id
			 WHERE t.tenant_id = $1 AND t.location_id = $2
			 ORDER BY lower(t.name), t.id`, tenantID, id)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r FloorPlanRack
			var rot sql.NullInt64
			if err := rows.Scan(&r.ID, &r.Name, &r.OperationalStatus, &r.FloorX, &r.FloorY, &rot,
				&r.OuterWidth, &r.OuterDepth, &r.OuterUnit, &r.Utilization, &r.UsedUnits, &r.TotalUnits,
				&r.DeviceCount, &r.PowerUtilization); err != nil {
				return err
			}
			if rot.Valid {
				v := int(rot.Int64)
				r.FloorRotation = &v
			}
			if plan != nil {
				w, d, def := RackFootprint(r.OuterWidth, r.OuterDepth, r.OuterUnit, plan.Unit)
				w, d = round2(w), round2(d)
				r.FootprintWidth, r.FootprintDepth, r.FootprintDefault = &w, &d, def
			} else {
				_, _, r.FootprintDefault = RackFootprint(r.OuterWidth, r.OuterDepth, r.OuterUnit, "m")
			}
			fp.Racks = append(fp.Racks, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		out = fp
		return nil
	})
	return out, err
}
