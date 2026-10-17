package services

// DB-integration tests for racks, reservations and placement (DCIM BUILD_PLAN
// row 2.3). Skipped unless TEST_DATABASE_URL is set; run with make
// test-integration-db. The services run on the NON-OWNER app role, so RLS is
// in force exactly as in production.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/testdb/dcimfixture"
)

type rackFix struct {
	owner, app *sql.DB
	tenant     uuid.UUID
	racks      *RackService
	place      *PlacementService
	ctx        context.Context
	site       uuid.UUID
	mfr        uuid.UUID
}

func newRackFix(t *testing.T) *rackFix {
	t.Helper()
	owner, app, tenant := ifaceFixture(t)
	f := &rackFix{owner: owner, app: app, tenant: tenant, racks: NewRackService(app), place: NewPlacementService(app), ctx: ifaceActorCtx()}
	f.site = f.newSite(t, "Site A "+uuid.NewString()[:6])
	if err := owner.QueryRow(`INSERT INTO manufacturers (tenant_id, name, slug) VALUES ($1, 'Acme', 'acme') RETURNING id`, tenant).Scan(&f.mfr); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *rackFix) newSite(t *testing.T, name string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(fmt.Sprint(testdb.EnsureSite(t, f.owner, f.tenant, name)))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *rackFix) newLocation(t *testing.T, site uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.owner.QueryRow(`INSERT INTO locations (tenant_id, site_id, name, slug) VALUES ($1, $2, $3, $4) RETURNING id`,
		f.tenant, site, name, Slugify(name)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// deviceType makes a tenant device type of height h and depth.
func (f *rackFix) deviceType(t *testing.T, h string, fullDepth bool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	model := "DT-" + uuid.NewString()[:8]
	if err := f.owner.QueryRow(`INSERT INTO device_types (tenant_id, manufacturer_id, model, slug, u_height, is_full_depth)
		VALUES ($1, $2, $3, lower($3), $4::numeric, $5) RETURNING id`, f.tenant, f.mfr, model, h, fullDepth).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// asset makes a switch with an optional device type.
func (f *rackFix) asset(t *testing.T, name string, deviceType uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var dt any
	if deviceType != uuid.Nil {
		dt = deviceType
	}
	if _, err := f.owner.Exec(`INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status, device_type_id)
		VALUES ($1, $2, $3, $3, 'switch', 'hardware.network_device.switch', 'monitoring', $4)`, id, f.tenant, name, dt); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *rackFix) rack(t *testing.T, body string) uuid.UUID {
	t.Helper()
	raw, err := f.racks.Create(f.ctx, f.tenant, "racks", []byte(body))
	if err != nil {
		t.Fatalf("create rack %s: %v", body, err)
	}
	return catID(t, raw)
}

func (f *rackFix) simpleRack(t *testing.T, name string) uuid.UUID {
	return f.rack(t, fmt.Sprintf(`{"name":%q,"site_id":%q}`, name, f.site))
}

func wantConflictWith(t *testing.T, err error, blocker uuid.UUID, what string) {
	t.Helper()
	var pc *PlacementConflictError
	if !errors.As(err, &pc) {
		t.Fatalf("%s: %v, want a placement conflict", what, err)
	}
	if !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("%s: the conflict does not unwrap to ErrIPAMConflict (the 409)", what)
	}
	switch {
	case pc.BlockingAsset != nil && pc.BlockingAsset.ID == blocker:
	case pc.BlockingReservation != nil && pc.BlockingReservation.ID == blocker:
	default:
		t.Fatalf("%s: conflict %+v does not name %s", what, pc, blocker)
	}
}

// RLS on racks and reservations: tenant B sees none of A's, cannot reserve
// units of A's rack, and the app role cannot write a row into another tenant
// (USING doubles as WITH CHECK).
//
// Mutation: drop racks_tenant_isolation (or the reservations' policy) → B
// reads A's rack and the cross-tenant INSERT succeeds.
func TestIntegration_Racks_RLS(t *testing.T) {
	f := newRackFix(t)
	tenantB := testdb.NewTenant(t, f.owner)
	r := f.simpleRack(t, "R1")
	res, err := f.racks.Create(f.ctx, f.tenant, "rack-reservations", []byte(fmt.Sprintf(`{"rack_id":%q,"units":[1,2],"description":"held"}`, r)))
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := f.racks.Get(f.ctx, tenantB, "racks", r); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B read A's rack: %v", err)
	}
	if _, err := f.racks.Get(f.ctx, tenantB, "rack-reservations", catID(t, res)); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B read A's reservation: %v", err)
	}
	if rows, total, err := f.racks.List(f.ctx, tenantB, "racks", IPAMListParams{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("tenant B lists %d racks (%v)", total, err)
	}
	if _, err := f.racks.Create(f.ctx, tenantB, "rack-reservations", []byte(fmt.Sprintf(`{"rack_id":%q,"units":[5],"description":"x"}`, r))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("tenant B reserved units of A's rack: %v", err)
	}
	if _, err := f.place.Elevation(f.ctx, tenantB, r); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B read A's elevation: %v", err)
	}
	for _, q := range []string{
		`INSERT INTO racks (tenant_id, site_id, name) VALUES ($1, $2, 'sneaky')`,
		`INSERT INTO rack_reservations (tenant_id, rack_id, units, description) VALUES ($1, $3, '{9}', 'sneaky')`,
	} {
		var insErr error
		testdb.AsTenant(t, f.app, tenantB, func(tx *sql.Tx) {
			_, insErr = tx.Exec(q, f.tenant, f.site, r)
		})
		if insErr == nil {
			t.Fatalf("app role under tenant B wrote a row for tenant A: %s", q)
		}
	}
}

// A rack name is unique within (site, location), a NULL location included.
//
// Mutation: drop racks_identity_key → the second "R12" directly in the site
// is accepted.
func TestIntegration_Racks_NameUniquePerSiteAndLocation(t *testing.T) {
	f := newRackFix(t)
	row3 := f.newLocation(t, f.site, "Row 3")
	f.simpleRack(t, "R12")
	if _, err := f.racks.Create(f.ctx, f.tenant, "racks", []byte(fmt.Sprintf(`{"name":"R12","site_id":%q}`, f.site))); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("second R12 with no location: %v, want conflict", err)
	}
	f.rack(t, fmt.Sprintf(`{"name":"R12","site_id":%q,"location_id":%q}`, f.site, row3))
	if _, err := f.racks.Create(f.ctx, f.tenant, "racks", []byte(fmt.Sprintf(`{"name":"R12","site_id":%q,"location_id":%q}`, f.site, row3))); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("second R12 in Row 3: %v, want conflict", err)
	}
	other := f.newSite(t, "Site B "+uuid.NewString()[:6])
	f.rack(t, fmt.Sprintf(`{"name":"R12","site_id":%q}`, other))
	// The location must be in the rack's site.
	if _, err := f.racks.Create(f.ctx, f.tenant, "racks", []byte(fmt.Sprintf(`{"name":"R13","site_id":%q,"location_id":%q}`, other, row3))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("a location of another site: %v, want invalid", err)
	}
}

// Overlap: 2U at U10 then 1U at U11 on the same face is refused naming the
// first; the rear face is free when both are half depth; a full-depth device
// blocks both faces.
//
// Mutation: make rackDevice.blocks ignore depth (`return d.Face == face`) →
// the full-depth rear placement is accepted; make it ignore the span (drop
// the range test) → the U20 placement is refused.
func TestIntegration_Placement_Overlap(t *testing.T) {
	f := newRackFix(t)
	r := f.simpleRack(t, "R1")
	half2U := f.deviceType(t, "2", false)
	half1U := f.deviceType(t, "1", false)
	full1U := f.deviceType(t, "1", true)
	a := f.asset(t, "a-2u", half2U)
	b := f.asset(t, "b-1u", half1U)
	c := f.asset(t, "c-full", full1U)
	d := f.asset(t, "d-full", full1U)

	if _, err := f.place.Place(f.ctx, f.tenant, a, PlaceInput{RackID: r, Position: 10, Face: "front"}); err != nil {
		t.Fatalf("place a: %v", err)
	}
	_, err := f.place.Place(f.ctx, f.tenant, b, PlaceInput{RackID: r, Position: 11, Face: "front"})
	wantConflictWith(t, err, a, "1U at U11 front over a 2U at U10")
	if _, err := f.place.Place(f.ctx, f.tenant, b, PlaceInput{RackID: r, Position: 11, Face: "rear"}); err != nil {
		t.Fatalf("half-depth 1U at U11 rear behind a half-depth 2U: %v", err)
	}
	_, err = f.place.Place(f.ctx, f.tenant, c, PlaceInput{RackID: r, Position: 10, Face: "rear"})
	wantConflictWith(t, err, a, "full-depth at U10 rear behind a front device")
	if _, err := f.place.Place(f.ctx, f.tenant, c, PlaceInput{RackID: r, Position: 20, Face: "rear"}); err != nil {
		t.Fatalf("full depth at U20: %v", err)
	}
	_, err = f.place.Place(f.ctx, f.tenant, d, PlaceInput{RackID: r, Position: 20, Face: "front"})
	wantConflictWith(t, err, c, "front at U20 in front of a full-depth device")
	// Half-U steps: a spans [10, 12), so U11.5 front overlaps it and U12.5
	// front (b behind it ends at U12) is clear.
	_, err = f.place.Place(f.ctx, f.tenant, d, PlaceInput{RackID: r, Position: 11.5, Face: "front"})
	wantConflictWith(t, err, a, "U11.5 front over a 2U at U10")
	if _, err := f.place.Place(f.ctx, f.tenant, d, PlaceInput{RackID: r, Position: 12.5, Face: "front"}); err != nil {
		t.Fatalf("full depth at U12.5: %v", err)
	}
	// Bounds: a 2U at U42 of a 42U rack does not fit; position 0 and 3.3 refused.
	e := f.asset(t, "e-2u", half2U)
	for _, pos := range []float64{42, 0, 3.3} {
		if _, err := f.place.Place(f.ctx, f.tenant, e, PlaceInput{RackID: r, Position: pos, Face: "front"}); !errors.Is(err, ErrIPAMInvalid) {
			t.Fatalf("position %v: %v, want invalid", pos, err)
		}
	}
	// An asset with no device type is 1U, full depth: it cannot go in front
	// of a half-depth device on the rear.
	h := f.asset(t, "h-rear", half1U)
	if _, err := f.place.Place(f.ctx, f.tenant, h, PlaceInput{RackID: r, Position: 30, Face: "rear"}); err != nil {
		t.Fatal(err)
	}
	g := f.asset(t, "g-untyped", uuid.Nil)
	_, err = f.place.Place(f.ctx, f.tenant, g, PlaceInput{RackID: r, Position: 30, Face: "front"})
	wantConflictWith(t, err, h, "untyped (full depth) at U30 front with h at U30 rear")
}

// The brief's "done means": rack R12 under Site A › Row 3, a discovered switch
// at U40 front from its Placement card, a second 2U at U39 refused, U1–U2
// reserved, and the elevation shows it.
func TestIntegration_Placement_DoneMeansScenario(t *testing.T) {
	f := newRackFix(t)
	row3 := f.newLocation(t, f.site, "Row 3")
	r := f.rack(t, fmt.Sprintf(`{"name":"R12","site_id":%q,"location_id":%q}`, f.site, row3))
	sw := f.asset(t, "core-sw-1", f.deviceType(t, "1", true))
	got, err := f.place.Place(f.ctx, f.tenant, sw, PlaceInput{RackID: r, Position: 40, Face: "front"})
	if err != nil {
		t.Fatalf("place switch: %v", err)
	}
	if got.Rack == nil || got.Rack.ID != r || got.Site == nil || got.Site.ID != f.site || got.Location == nil || got.Location.ID != row3 || *got.Position != 40 || *got.Face != "front" {
		t.Fatalf("placement %+v: want R12 / Site A / Row 3 / U40 front", got)
	}
	second := f.asset(t, "dist-2u", f.deviceType(t, "2", true))
	_, err = f.place.Place(f.ctx, f.tenant, second, PlaceInput{RackID: r, Position: 39, Face: "front"})
	wantConflictWith(t, err, sw, "2U at U39 under the switch at U40")
	if _, err := f.racks.Create(f.ctx, f.tenant, "rack-reservations", []byte(fmt.Sprintf(`{"rack_id":%q,"units":[2,1],"description":"Future PDU"}`, r))); err != nil {
		t.Fatalf("reserve U1-U2: %v", err)
	}
	el, err := f.place.Elevation(f.ctx, f.tenant, r)
	if err != nil {
		t.Fatalf("elevation: %v", err)
	}
	if len(el.Units) != 42 || el.Units[0].Unit != 42 || el.Units[41].Unit != 1 {
		t.Fatalf("units run %d..%d (%d), want 42 down to 1", el.Units[0].Unit, el.Units[len(el.Units)-1].Unit, len(el.Units))
	}
	u40 := el.Units[2]
	if u40.Unit != 40 || !slices.Contains(u40.Front, sw.String()) || !slices.Contains(u40.Rear, sw.String()) {
		t.Fatalf("U40 %+v: want the full-depth switch on both faces", u40)
	}
	if el.Units[41].ReservationID == nil || el.Units[40].ReservationID == nil || len(el.Reservations) != 1 || !slices.Equal(el.Reservations[0].Units, []int{1, 2}) {
		t.Fatalf("reservation not on U1-U2: %+v / %+v", el.Units[40:], el.Reservations)
	}
	if len(el.Devices) != 1 || el.Devices[0].AssetID != sw || el.Utilization == nil || el.Utilization.UsedUnits != 1 {
		t.Fatalf("devices %+v utilisation %+v", el.Devices, el.Utilization)
	}
	// The asset list carries the placement (and so the CSV export).
	var rack json.RawMessage
	if err := f.owner.QueryRow(`SELECT `+assetRackSQL+` FROM assets a WHERE a.id = $1`, sw).Scan(&rack); err != nil {
		t.Fatal(err)
	}
	var ref struct {
		Name     string  `json:"name"`
		Position float64 `json:"position"`
		Face     string  `json:"face"`
	}
	if err := json.Unmarshal(rack, &ref); err != nil || ref.Name != "R12" || ref.Position != 40 || ref.Face != "front" {
		t.Fatalf("asset rack ref %s", rack)
	}
	// Both sides recorded the change.
	var assetChanges, rackChanges int
	if err := f.owner.QueryRow(`SELECT count(*) FILTER (WHERE object_kind = 'asset' AND object_id = $2),
		count(*) FILTER (WHERE object_kind = 'rack' AND object_id = $3 AND action = 'update')
		FROM object_changes WHERE tenant_id = $1`, f.tenant, sw, r).Scan(&assetChanges, &rackChanges); err != nil {
		t.Fatal(err)
	}
	if assetChanges != 1 || rackChanges != 1 {
		t.Fatalf("change records: asset %d, rack %d, want 1 and 1", assetChanges, rackChanges)
	}
}

// Concurrency: eight goroutines place eight different devices over the same
// units of one rack at once; exactly one succeeds and seven are refused as
// conflicts. Repeated over several racks so a race has room to show.
//
// Mutation: remove `FOR UPDATE` from lockRacks → several placements commit and
// the rack holds overlapping devices.
func TestIntegration_Placement_ConcurrentOverlapExactlyOneWins(t *testing.T) {
	f := newRackFix(t)
	dt := f.deviceType(t, "2", true)
	for round := 0; round < 5; round++ {
		r := f.simpleRack(t, fmt.Sprintf("C%d", round))
		var assets []uuid.UUID
		for i := 0; i < 8; i++ {
			assets = append(assets, f.asset(t, fmt.Sprintf("c%d-%d", round, i), dt))
		}
		var (
			wg      sync.WaitGroup
			start   = make(chan struct{})
			mu      sync.Mutex
			ok      int
			refused int
			other   []error
		)
		for i, a := range assets {
			wg.Add(1)
			go func(i int, a uuid.UUID) {
				defer wg.Done()
				<-start
				// Overlapping spans: U10, U10.5, U11 … all 2U on the front.
				_, err := f.place.Place(f.ctx, f.tenant, a, PlaceInput{RackID: r, Position: 10 + float64(i%3)*0.5, Face: "front"})
				mu.Lock()
				defer mu.Unlock()
				var pc *PlacementConflictError
				switch {
				case err == nil:
					ok++
				case errors.As(err, &pc):
					refused++
				default:
					other = append(other, err)
				}
			}(i, a)
		}
		close(start)
		wg.Wait()
		if len(other) > 0 {
			t.Fatalf("round %d: unexpected errors %v", round, other)
		}
		var racked int
		if err := f.owner.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND rack_id = $2`, f.tenant, r).Scan(&racked); err != nil {
			t.Fatal(err)
		}
		if ok != 1 || refused != 7 || racked != 1 {
			t.Fatalf("round %d: %d placed, %d refused, %d in the rack — want exactly one", round, ok, refused, racked)
		}
	}
}

// Reservations refuse units an installed device takes and units another
// reservation holds; a placement into reserved units is refused naming the
// reservation; units outside the rack are invalid.
//
// Mutation: drop the device loop in prepareReservation → the U10 reservation
// is accepted; drop the reservation loop in conflictFor → the U30 placement
// is accepted.
func TestIntegration_Reservations_Overlap(t *testing.T) {
	f := newRackFix(t)
	r := f.simpleRack(t, "R1")
	sw := f.asset(t, "sw", f.deviceType(t, "2", false))
	if _, err := f.place.Place(f.ctx, f.tenant, sw, PlaceInput{RackID: r, Position: 10, Face: "rear"}); err != nil {
		t.Fatal(err)
	}
	reserve := func(units string) (uuid.UUID, error) {
		raw, err := f.racks.Create(f.ctx, f.tenant, "rack-reservations", []byte(fmt.Sprintf(`{"rack_id":%q,"units":%s,"description":"held"}`, r, units)))
		if err != nil {
			return uuid.Nil, err
		}
		return catID(t, raw), nil
	}
	_, err := reserve(`[9, 10]`)
	wantConflictWith(t, err, sw, "reserving U10 under a device at U10-U11 (rear)")
	held, err := reserve(`[30, 31]`)
	if err != nil {
		t.Fatalf("reserve U30-31: %v", err)
	}
	_, err = reserve(`[31, 32]`)
	wantConflictWith(t, err, held, "reserving U31 twice")
	if _, err := reserve(`[43]`); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("U43 of a 42U rack: %v, want invalid", err)
	}
	other := f.asset(t, "other", uuid.Nil)
	_, err = f.place.Place(f.ctx, f.tenant, other, PlaceInput{RackID: r, Position: 30, Face: "front"})
	wantConflictWith(t, err, held, "placing into reserved U30")
	// Editing the reservation onto the device is refused too.
	if _, err := f.racks.Update(f.ctx, f.tenant, "rack-reservations", held, []byte(`{"units":[11]}`)); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("moving the reservation onto the device: %v, want conflict", err)
	}
	// The user defaults to the actor.
	raw, _ := f.racks.Get(f.ctx, f.tenant, "rack-reservations", held)
	var row struct {
		UserID *uuid.UUID `json:"user_id"`
	}
	_ = json.Unmarshal(raw, &row)
	if row.UserID == nil {
		t.Fatalf("reservation has no user: %s", raw)
	}
}

// The utilisation cache follows place, move and unplace; excluded device
// types count neither as used nor as available.
//
// Mutation: drop refreshRackUtilizationTx from placeTx (or Unplace) → the
// cached numbers lag the rack.
func TestIntegration_Placement_UtilizationRefreshed(t *testing.T) {
	f := newRackFix(t)
	r := f.rack(t, fmt.Sprintf(`{"name":"R1","site_id":%q,"u_height":10}`, f.site))
	util := func() (used, total, pct float64) {
		t.Helper()
		if err := f.owner.QueryRow(`SELECT used_units, total_units, utilization FROM rack_utilization WHERE rack_id = $1`, r).Scan(&used, &total, &pct); err != nil {
			t.Fatalf("utilisation row: %v", err)
		}
		return
	}
	if u, tot, p := util(); u != 0 || tot != 10 || p != 0 {
		t.Fatalf("new rack: %v/%v (%v%%), want 0/10", u, tot, p)
	}
	a := f.asset(t, "a", f.deviceType(t, "2", true))
	if _, err := f.place.Place(f.ctx, f.tenant, a, PlaceInput{RackID: r, Position: 1, Face: "front"}); err != nil {
		t.Fatal(err)
	}
	if u, tot, p := util(); u != 2 || tot != 10 || p != 20 {
		t.Fatalf("after place: %v/%v (%v%%), want 2/10 = 20%%", u, tot, p)
	}
	var excluded uuid.UUID
	if err := f.owner.QueryRow(`INSERT INTO device_types (tenant_id, manufacturer_id, model, slug, u_height, exclude_from_utilization)
		VALUES ($1, $2, 'Blank', 'blank', 1, true) RETURNING id`, f.tenant, f.mfr).Scan(&excluded); err != nil {
		t.Fatal(err)
	}
	blank := f.asset(t, "blank", excluded)
	if _, err := f.place.Place(f.ctx, f.tenant, blank, PlaceInput{RackID: r, Position: 5, Face: "front"}); err != nil {
		t.Fatal(err)
	}
	if u, tot, p := util(); u != 2 || tot != 9 || p != 22.22 {
		t.Fatalf("with an excluded 1U: %v/%v (%v%%), want 2/9", u, tot, p)
	}
	if _, err := f.place.Unplace(f.ctx, f.tenant, a); err != nil {
		t.Fatal(err)
	}
	if u, tot, _ := util(); u != 0 || tot != 9 {
		t.Fatalf("after unplace: %v/%v, want 0/9", u, tot)
	}
	p, err := f.place.Get(f.ctx, f.tenant, a)
	if err != nil || p.Rack != nil || p.Position != nil || p.Site == nil || p.Site.ID != f.site {
		t.Fatalf("unplaced asset keeps its site and loses the rack: %+v (%v)", p, err)
	}
}

// Rack edits: a resize that would strand a device is refused; moving the rack
// to another site carries its devices; deleting it unplaces them (and the
// position never outlives the rack); a rack type stamps its dimensions; a
// device type change that no longer fits is refused; an asset's site cannot
// be moved away from its rack's.
func TestIntegration_Racks_EditsKeepPlacementsConsistent(t *testing.T) {
	f := newRackFix(t)
	r := f.simpleRack(t, "R1")
	dt1 := f.deviceType(t, "1", true)
	a := f.asset(t, "a", dt1)
	if _, err := f.place.Place(f.ctx, f.tenant, a, PlaceInput{RackID: r, Position: 30, Face: "front"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.racks.Update(f.ctx, f.tenant, "racks", r, []byte(`{"u_height":20}`)); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("shrinking below a device: %v, want invalid", err)
	}
	// Device type change: a 20U type at U30 of a 42U rack does not fit.
	tall := f.deviceType(t, "20", true)
	if _, err := NewCatalogueService(f.app).UpdateHardware(f.ctx, f.tenant, a, HardwarePatch{"device_type_id": json.RawMessage(fmt.Sprintf("%q", tall))}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("a device type that no longer fits: %v, want invalid", err)
	}
	// The asset's site cannot leave the rack's.
	other := f.newSite(t, "Site C "+uuid.NewString()[:6])
	var checkErr error
	testdb.AsTenant(t, f.app, f.tenant, func(tx *sql.Tx) {
		o := other
		checkErr = CheckRackConsistencyTx(f.ctx, tx, f.tenant, a, &o, nil)
	})
	if !errors.Is(checkErr, ErrSiteInvalid) {
		t.Fatalf("moving a racked asset to another site: %v, want invalid", checkErr)
	}
	// Moving the rack moves the device.
	if _, err := f.racks.Update(f.ctx, f.tenant, "racks", r, []byte(fmt.Sprintf(`{"site_id":%q}`, other))); err != nil {
		t.Fatalf("move rack: %v", err)
	}
	var site uuid.UUID
	if err := f.owner.QueryRow(`SELECT site_id FROM assets WHERE id = $1`, a).Scan(&site); err != nil || site != other {
		t.Fatalf("the device stayed in %s (%v), want %s", site, err, other)
	}
	// A rack type stamps its dimensions.
	rt, err := f.racks.Create(f.ctx, f.tenant, "rack-types", []byte(fmt.Sprintf(`{"manufacturer_id":%q,"model":"AR3100","form_factor":"4-post-frame","u_height":48,"width":19}`, f.mfr)))
	if err != nil {
		t.Fatalf("create rack type: %v", err)
	}
	upd, err := f.racks.Update(f.ctx, f.tenant, "racks", r, []byte(fmt.Sprintf(`{"rack_type_id":%q}`, catID(t, rt))))
	if err != nil {
		t.Fatalf("assign rack type: %v", err)
	}
	var got struct {
		UHeight    int    `json:"u_height"`
		FormFactor string `json:"form_factor"`
	}
	_ = json.Unmarshal(upd, &got)
	if got.UHeight != 48 || got.FormFactor != "4-post-frame" {
		t.Fatalf("rack after type: %s", upd)
	}
	if err := f.racks.Delete(f.ctx, f.tenant, "rack-types", catID(t, rt)); !errors.Is(err, ErrIPAMInUse) {
		t.Fatalf("deleting a rack type in use: %v, want in use", err)
	}
	// Delete: the device leaves the rack, keeps its site.
	if err := f.racks.Delete(f.ctx, f.tenant, "racks", r); err != nil {
		t.Fatalf("delete rack: %v", err)
	}
	var rack uuid.NullUUID
	var pos sql.NullFloat64
	if err := f.owner.QueryRow(`SELECT rack_id, position FROM assets WHERE id = $1`, a).Scan(&rack, &pos); err != nil || rack.Valid || pos.Valid {
		t.Fatalf("after rack delete: rack %v position %v (%v)", rack, pos, err)
	}
}

// Platform rack roles are seeded, readable and read-only.
func TestIntegration_RackRoles_PlatformSeedReadOnly(t *testing.T) {
	f := newRackFix(t)
	if _, err := f.owner.Exec(`INSERT INTO rack_roles (tenant_id, name, slug, color) VALUES (NULL, 'Compute', 'compute', '2196f3') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	rows, _, err := f.racks.List(f.ctx, f.tenant, "rack-roles", IPAMListParams{Filters: map[string]string{"slug": "compute"}, Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("platform role compute: %d rows (%v)", len(rows), err)
	}
	if _, err := f.racks.Update(f.ctx, f.tenant, "rack-roles", catID(t, rows[0]), []byte(`{"color":"000000"}`)); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("PATCH a platform rack role: %v, want read-only", err)
	}
}

// DATA_MODEL §12: rack elevation < 100 ms on the scale fixture (Small, or
// Scale1 with DCIM_SCALE=1), the median of five reads of a full rack.
func TestIntegration_RackElevation_Budget(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	testdb.HoldSchemaShareLock(t, owner)
	scale := dcimfixture.Small()
	if os.Getenv("DCIM_SCALE") == "1" {
		scale = dcimfixture.Scale1()
	}
	sum := dcimfixture.Populate(context.Background(), t, owner, tenant, scale)
	if sum.Counts["racks"] != scale.Racks() {
		t.Fatalf("fixture wrote %d racks, want %d (skipped %v)", sum.Counts["racks"], scale.Racks(), sum.Skipped)
	}
	for _, q := range []string{`ANALYZE racks`, `ANALYZE assets`, `ANALYZE rack_reservations`, `ANALYZE rack_utilization`, `ANALYZE device_types`} {
		if _, err := owner.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var rack uuid.UUID
	if err := owner.QueryRow(`SELECT id FROM racks WHERE tenant_id = $1 AND name = $2`, tenant, dcimfixture.RackName(scale.Sites-1, scale.RacksPerSite-1)).Scan(&rack); err != nil {
		t.Fatal(err)
	}
	svc := NewPlacementService(app)
	ctx := ifaceActorCtx()
	ipamMedian(t, "rack elevation", 100*time.Millisecond, func() error {
		el, err := svc.Elevation(ctx, tenant, rack)
		if err == nil && len(el.Devices) != scale.AssetsPerRack {
			err = fmt.Errorf("elevation shows %d devices, want %d", len(el.Devices), scale.AssetsPerRack)
		}
		return err
	})
}

// The rack query fields run against Postgres through the asset list (the
// Inventory page's predicate path), on the app role; and the site page counts
// the site's racks.
func TestIntegration_Racks_QueryFieldsAndSiteCount(t *testing.T) {
	f := newRackFix(t)
	var network uuid.UUID
	if err := f.owner.QueryRow(`INSERT INTO rack_roles (tenant_id, name, slug) VALUES ($1, 'Network gear', 'network-gear') RETURNING id`, f.tenant).Scan(&network); err != nil {
		t.Fatal(err)
	}
	r12 := f.rack(t, fmt.Sprintf(`{"name":"R12","site_id":%q,"role_id":%q,"facility_id":"CAGE-7"}`, f.site, network))
	r13 := f.simpleRack(t, "R13")
	a := f.asset(t, "a", uuid.Nil)
	b := f.asset(t, "b", uuid.Nil)
	f.asset(t, "c", uuid.Nil)
	if _, err := f.place.Place(f.ctx, f.tenant, a, PlaceInput{RackID: r12, Position: 40, Face: "front"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.place.Place(f.ctx, f.tenant, b, PlaceInput{RackID: r13, Position: 3.5, Face: "rear"}); err != nil {
		t.Fatal(err)
	}
	var siteSlug string
	if err := f.owner.QueryRow(`SELECT slug FROM sites WHERE id = $1`, f.site).Scan(&siteSlug); err != nil {
		t.Fatal(err)
	}
	svc := NewAssetService(&database.DB{DB: sqlx.NewDb(f.app, "postgres")})
	for q, want := range map[string]int{
		`rack = R12`:                       1,
		`rack = "CAGE-7"`:                  1,
		`rack != R12`:                      2, // b, and c which is in no rack
		`rack.id = "` + r13.String() + `"`: 1,
		`rack.site:` + siteSlug:            2,
		`rack.role = network-gear`:         1,
		`position >= 40`:                   1,
		`position = 3.5`:                   1,
		`face = rear`:                      1,
		`exists(rack)`:                     2,
	} {
		_, total, err := svc.GetAssets(f.tenant, models.AssetFilters{Query: q, Page: 1, PageSize: 50, AssetStatus: []string{"monitoring"}})
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if total != want {
			t.Errorf("%s matched %d, want %d", q, total, want)
		}
	}
	sites := NewSiteService(&database.DB{DB: sqlx.NewDb(f.app, "postgres")})
	st, err := sites.GetSite(context.Background(), f.tenant, f.site)
	if err != nil {
		t.Fatal(err)
	}
	if st.Counts == nil || st.Counts.Racks != 2 {
		t.Fatalf("site counts %+v, want 2 racks", st.Counts)
	}
}
