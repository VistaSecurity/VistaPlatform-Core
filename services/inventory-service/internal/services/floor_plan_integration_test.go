package services

// DB-integration tests for floor plans (DCIM gap 9): a location's plan size
// through the location service, a rack's place on it through the rack PATCH,
// and the floor plan read. Both services run on the NON-OWNER app role, so RLS
// is in force. Skipped unless TEST_DATABASE_URL is set.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type floorFix struct {
	*rackFix
	sites *SiteService
}

func newFloorFix(t *testing.T) *floorFix {
	t.Helper()
	f := newRackFix(t)
	return &floorFix{rackFix: f, sites: NewSiteService(&database.DB{DB: sqlx.NewDb(f.app, "postgres")})}
}

func (f *floorFix) setPlan(t *testing.T, loc uuid.UUID, body string) (*models.Location, error) {
	t.Helper()
	var in models.LocationInput
	if err := json.Unmarshal([]byte(body), &in); err != nil {
		t.Fatal(err)
	}
	return f.sites.UpdateLocation(f.ctx, f.tenant, uuid.Nil, loc, in)
}

func (f *floorFix) patchRack(id uuid.UUID, body string) (map[string]any, error) {
	raw, err := f.racks.Update(f.ctx, f.tenant, "racks", id, []byte(body))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (f *floorFix) floor(t *testing.T, id uuid.UUID) (x, y, rot any) {
	t.Helper()
	var fx, fy, fr *float64
	if err := f.owner.QueryRow(`SELECT floor_x, floor_y, floor_rotation FROM racks WHERE id = $1`, id).Scan(&fx, &fy, &fr); err != nil {
		t.Fatal(err)
	}
	deref := func(p *float64) any {
		if p == nil {
			return nil
		}
		return *p
	}
	return deref(fx), deref(fy), deref(fr)
}

func wantInvalid(t *testing.T, err error, sentinel error, fragment string) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), fragment) {
		t.Fatalf("err = %q, want it to mention %q", err, fragment)
	}
}

// Placement end to end: refused without a location or a plan, bounds-checked
// against the turned footprint, cleared by a move to another location and by
// a null patch.
//
// Mutation: drop the prepareRackFloor call from prepareRack → the "no floor
// plan" and bounds refusals go red; drop the location-change branch → the
// move keeps a stale place and goes red.
func TestIntegration_FloorPlan_RackPlacement(t *testing.T) {
	f := newFloorFix(t)
	hall := f.newLocation(t, f.site, "Hall "+uuid.NewString()[:6])
	cage := f.newLocation(t, f.site, "Cage "+uuid.NewString()[:6])
	rack := f.rack(t, fmt.Sprintf(`{"name":"R1","site_id":%q,"location_id":%q,"outer_width":600,"outer_depth":1200,"outer_unit":"mm"}`, f.site, hall))
	loose := f.rack(t, fmt.Sprintf(`{"name":"R2","site_id":%q}`, f.site))

	_, err := f.patchRack(loose, `{"floor_x":1,"floor_y":1}`)
	wantInvalid(t, err, ErrIPAMInvalid, "give the rack a location first")
	_, err = f.patchRack(rack, `{"floor_x":1,"floor_y":1}`)
	wantInvalid(t, err, ErrIPAMInvalid, "has no floor plan")

	if _, err := f.setPlan(t, hall, `{"floor_plan_width":10,"floor_plan_depth":8,"floor_plan_unit":"m"}`); err != nil {
		t.Fatal(err)
	}
	_, err = f.patchRack(rack, `{"floor_x":1}`)
	wantInvalid(t, err, ErrIPAMInvalid, "set together")
	_, err = f.patchRack(rack, `{"floor_x":1,"floor_y":1,"floor_rotation":45}`)
	wantInvalid(t, err, ErrIPAMInvalid, "0, 90, 180 or 270")
	_, err = f.patchRack(rack, `{"floor_x":0.2,"floor_y":1}`)
	wantInvalid(t, err, ErrIPAMInvalid, "edge")
	// Unturned (0.6 wide) it fits at x=0.5; a quarter turn makes it 1.2 wide.
	_, err = f.patchRack(rack, `{"floor_x":0.5,"floor_y":1,"floor_rotation":90}`)
	wantInvalid(t, err, ErrIPAMInvalid, "edge")

	got, err := f.patchRack(rack, `{"floor_x":0.5,"floor_y":1.004}`)
	if err != nil {
		t.Fatal(err)
	}
	if got["floor_x"] != 0.5 || got["floor_y"] != 1.0 || got["floor_rotation"] != float64(0) {
		t.Fatalf("placed row %v %v %v, want 0.5 1 0 (rounded, rotation defaulted)", got["floor_x"], got["floor_y"], got["floor_rotation"])
	}
	if _, err := f.patchRack(rack, `{"floor_x":0.7,"floor_y":1,"floor_rotation":270}`); err != nil {
		t.Fatal(err)
	}
	// A resize that would push the placed rack past the edge is refused.
	_, err = f.patchRack(rack, `{"outer_depth":2000}`) // turned, the depth runs along x
	wantInvalid(t, err, ErrIPAMInvalid, "edge")

	// Moving to another location takes it off the old plan.
	if _, err := f.patchRack(rack, fmt.Sprintf(`{"location_id":%q}`, cage)); err != nil {
		t.Fatal(err)
	}
	if x, y, r := f.floor(t, rack); x != nil || y != nil || r != nil {
		t.Fatalf("after the move the rack is still at %v %v %v", x, y, r)
	}

	// Back in the hall, placed, then taken off with a null patch.
	if _, err := f.patchRack(rack, fmt.Sprintf(`{"location_id":%q,"floor_x":5,"floor_y":4,"floor_rotation":180}`, hall)); err != nil {
		t.Fatal(err)
	}
	if x, _, r := f.floor(t, rack); x != 5.0 || r != 180.0 {
		t.Fatalf("placed on the hall again: %v rot %v", x, r)
	}
	if _, err := f.patchRack(rack, `{"floor_x":null,"floor_y":null,"floor_rotation":null}`); err != nil {
		t.Fatal(err)
	}
	if x, _, _ := f.floor(t, rack); x != nil {
		t.Fatalf("unplaced rack still at %v", x)
	}

	// Every placement write is in the rack's change log.
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_id = $2
		AND 'floor_x' = ANY(changed_fields)`, f.tenant, rack).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no change recorded for the rack's floor placement")
	}
}

// A plan cannot be removed from, have its unit changed under, or shrink past
// a placed rack; growing it is fine. Deleting the location takes its racks off.
//
// Mutation: make checkLocationPlanHolds return nil → the three refusals go
// red; drop clearFloorPlacementsTx from DeleteLocation → the rack keeps a
// place with no location and the last assertion goes red.
func TestIntegration_FloorPlan_PlanHoldsPlacedRacks(t *testing.T) {
	f := newFloorFix(t)
	hall := f.newLocation(t, f.site, "Hall "+uuid.NewString()[:6])
	if _, err := f.setPlan(t, hall, `{"floor_plan_width":10,"floor_plan_depth":8,"floor_plan_unit":"m"}`); err != nil {
		t.Fatal(err)
	}
	rack := f.rack(t, fmt.Sprintf(`{"name":"R1","site_id":%q,"location_id":%q}`, f.site, hall))
	if _, err := f.patchRack(rack, `{"floor_x":9,"floor_y":7}`); err != nil {
		t.Fatal(err)
	}

	_, err := f.setPlan(t, hall, `{"floor_plan_width":null,"floor_plan_depth":null,"floor_plan_unit":null}`)
	wantInvalid(t, err, ErrSiteInvalid, "1 rack is placed")
	_, err = f.setPlan(t, hall, `{"floor_plan_unit":"ft"}`)
	wantInvalid(t, err, ErrSiteInvalid, "unit cannot change")
	_, err = f.setPlan(t, hall, `{"floor_plan_width":5}`)
	wantInvalid(t, err, ErrSiteInvalid, "would no longer fit")
	_, err = f.setPlan(t, hall, `{"floor_plan_depth":null}`)
	wantInvalid(t, err, ErrSiteInvalid, "set together")

	l, err := f.setPlan(t, hall, `{"floor_plan_width":20.5}`)
	if err != nil {
		t.Fatal(err)
	}
	if l.FloorPlanWidth == nil || *l.FloorPlanWidth != 20.5 || *l.FloorPlanDepth != 8 || *l.FloorPlanUnit != "m" {
		t.Fatalf("grown plan %v x %v %v", l.FloorPlanWidth, l.FloorPlanDepth, l.FloorPlanUnit)
	}

	if err := f.sites.DeleteLocation(f.ctx, f.tenant, uuid.Nil, hall); err != nil {
		t.Fatal(err)
	}
	var loc *uuid.UUID
	if err := f.owner.QueryRow(`SELECT location_id FROM racks WHERE id = $1`, rack).Scan(&loc); err != nil {
		t.Fatal(err)
	}
	if x, _, _ := f.floor(t, rack); loc != nil || x != nil {
		t.Fatalf("after the location's delete the rack has location %v and place %v", loc, x)
	}
}

// The floor plan read: the plan, every rack of the location (placed or not)
// with its footprint in the plan's unit, the default footprint flagged, the
// utilisation and the power budget; no racks of another location; another
// tenant reads nothing.
func TestIntegration_FloorPlan_Read(t *testing.T) {
	f := newFloorFix(t)
	hall := f.newLocation(t, f.site, "Hall "+uuid.NewString()[:6])
	other := f.newLocation(t, f.site, "Other "+uuid.NewString()[:6])

	fp, err := f.sites.LocationFloorPlan(f.ctx, f.tenant, hall)
	if err != nil {
		t.Fatal(err)
	}
	if fp.Location.FloorPlanWidth != nil || len(fp.Racks) != 0 || fp.DefaultFootprint.Width != 600 || fp.DefaultFootprint.Unit != "mm" {
		t.Fatalf("empty location: %+v", fp)
	}

	if _, err := f.setPlan(t, hall, `{"floor_plan_width":30,"floor_plan_depth":20,"floor_plan_unit":"ft"}`); err != nil {
		t.Fatal(err)
	}
	sized := f.rack(t, fmt.Sprintf(`{"name":"A1","site_id":%q,"location_id":%q,"outer_width":24,"outer_depth":48,"outer_unit":"in"}`, f.site, hall))
	bare := f.rack(t, fmt.Sprintf(`{"name":"A2","site_id":%q,"location_id":%q}`, f.site, hall))
	f.rack(t, fmt.Sprintf(`{"name":"B1","site_id":%q,"location_id":%q}`, f.site, other))
	if _, err := f.patchRack(sized, `{"floor_x":3,"floor_y":4,"floor_rotation":90}`); err != nil {
		t.Fatal(err)
	}

	fp, err = f.sites.LocationFloorPlan(f.ctx, f.tenant, hall)
	if err != nil {
		t.Fatal(err)
	}
	if fp.Location.FloorPlanWidth == nil || *fp.Location.FloorPlanWidth != 30 || *fp.Location.FloorPlanUnit != "ft" {
		t.Fatalf("plan %+v", fp.Location)
	}
	if len(fp.Racks) != 2 || fp.Racks[0].ID != sized || fp.Racks[1].ID != bare {
		t.Fatalf("racks %+v, want A1 and A2 only", fp.Racks)
	}
	a1, a2 := fp.Racks[0], fp.Racks[1]
	if a1.FloorX == nil || *a1.FloorX != 3 || a1.FloorRotation == nil || *a1.FloorRotation != 90 {
		t.Fatalf("A1 place %v rot %v", a1.FloorX, a1.FloorRotation)
	}
	if a1.FootprintWidth == nil || *a1.FootprintWidth != 2 || *a1.FootprintDepth != 4 || a1.FootprintDefault {
		t.Fatalf("A1 footprint %v x %v default %v, want 2 x 4 ft", a1.FootprintWidth, a1.FootprintDepth, a1.FootprintDefault)
	}
	if a2.FloorX != nil || !a2.FootprintDefault || a2.FootprintWidth == nil || *a2.FootprintWidth != 1.97 {
		t.Fatalf("A2 (unplaced, default footprint) %+v", a2)
	}
	if a1.Utilization == nil || *a1.Utilization != 0 || a1.TotalUnits == nil || *a1.TotalUnits != 42 {
		t.Fatalf("A1 utilisation %v of %v, want 0 of 42", a1.Utilization, a1.TotalUnits)
	}
	if a1.PowerUtilization != nil {
		t.Fatalf("A1 power %v, want nil (no feed serves it)", *a1.PowerUtilization)
	}

	b := testdb.NewTenant(t, f.owner)
	if _, err := f.sites.LocationFloorPlan(f.ctx, b, hall); !errors.Is(err, ErrSiteNotFound) {
		t.Fatalf("another tenant's read = %v, want not found", err)
	}
}

// The database's own guards: a rack's three floor columns are set together
// and the rotation is a quarter turn; a plan's three columns likewise.
//
// Mutation: drop racks_floor_position_check / locations_floor_plan_check from
// schema.sql → the matching write succeeds and this goes red.
func TestIntegration_FloorPlan_TableChecks(t *testing.T) {
	f := newFloorFix(t)
	hall := f.newLocation(t, f.site, "Hall "+uuid.NewString()[:6])
	rack := f.rack(t, fmt.Sprintf(`{"name":"R1","site_id":%q,"location_id":%q}`, f.site, hall))
	for name, q := range map[string]string{
		"x without y":        `UPDATE racks SET floor_x = 1 WHERE id = $1`,
		"no rotation":        `UPDATE racks SET floor_x = 1, floor_y = 1 WHERE id = $1`,
		"rotation 45":        `UPDATE racks SET floor_x = 1, floor_y = 1, floor_rotation = 45 WHERE id = $1`,
		"negative x":         `UPDATE racks SET floor_x = -1, floor_y = 1, floor_rotation = 0 WHERE id = $1`,
		"rotation, no place": `UPDATE racks SET floor_rotation = 90 WHERE id = $1`,
	} {
		if _, err := f.owner.Exec(q, rack); err == nil || !strings.Contains(err.Error(), "check") {
			t.Errorf("%s: err %v, want a check violation", name, err)
		}
	}
	for name, q := range map[string]string{
		"width alone": `UPDATE locations SET floor_plan_width = 5 WHERE id = $1`,
		"zero depth":  `UPDATE locations SET floor_plan_width = 5, floor_plan_depth = 0, floor_plan_unit = 'm' WHERE id = $1`,
		"yards":       `UPDATE locations SET floor_plan_width = 5, floor_plan_depth = 5, floor_plan_unit = 'yd' WHERE id = $1`,
	} {
		if _, err := f.owner.Exec(q, hall); err == nil || !strings.Contains(err.Error(), "check") {
			t.Errorf("%s: err %v, want a check violation", name, err)
		}
	}
	if _, err := f.owner.Exec(`UPDATE locations SET floor_plan_width = 5, floor_plan_depth = 4, floor_plan_unit = 'm' WHERE id = $1`, hall); err != nil {
		t.Fatalf("a whole plan: %v", err)
	}
	if _, err := f.owner.Exec(`UPDATE racks SET floor_x = 1, floor_y = 1, floor_rotation = 270 WHERE id = $1`, rack); err != nil {
		t.Fatalf("a whole place: %v", err)
	}
}
