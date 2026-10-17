package services

// Asset placement in racks (DCIM BUILD_PLAN row 2.3; ADR-0010 D4: placement is
// a typed set of fields with a rack coordinate, not an edge; DATA_MODEL §2
// "Asset columns added for DCIM" and §3).
//
// An asset is racked by rack_id + position (the LOWEST unit it occupies, in
// half-U steps) + face. Its span is [position, position + u_height) where
// u_height is its device type's (an asset with no device type is 1U and full
// depth, NetBox's defaults). Two devices conflict when their spans overlap and
// they are on the same face — or either is full depth, which takes both faces.
// A child device (in a parent's device bay) takes no units, and neither does a
// 0U device. Reservations are whole units; a device may not take a reserved
// unit and a reservation may not cover an occupied one.
//
// No index can express "no two ranges overlap" over multi-U devices on two
// faces, so every write that changes what a rack holds (Place, Unplace, a
// reservation, a rack resize, a device type change of a racked asset) runs in
// one transaction that first takes the rack row FOR UPDATE: placements into
// one rack are serialised, and the check that follows reads a stable rack.
// Lock order is asset row first, then racks by id, everywhere, so a move
// between two racks cannot deadlock with a placement into either.
//
// Each change is recorded through shared/dcim/changes on the asset AND on the
// rack, and the rack's rack_utilization row is recomputed in the same
// transaction.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// PlacementConflictError is a placement or reservation refused because
// something already holds the units. Exactly one of the blocking fields is set.
// It wraps ErrIPAMConflict, so generic handlers answer 409.
type PlacementConflictError struct {
	Message string `json:"message"`
	// BlockingAsset is the device occupying the units.
	BlockingAsset *PlacementBlocker `json:"blocking_asset,omitempty"`
	// BlockingReservation is the reservation holding the units.
	BlockingReservation *ReservationBlocker `json:"blocking_reservation,omitempty"`
}

// PlacementBlocker names the asset in the way.
type PlacementBlocker struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	Position float64   `json:"position"`
	Face     string    `json:"face"`
	UHeight  float64   `json:"u_height"`
}

// ReservationBlocker names the reservation in the way.
type ReservationBlocker struct {
	ID          uuid.UUID `json:"id"`
	Description string    `json:"description"`
	Units       []int     `json:"units"`
}

func (e *PlacementConflictError) Error() string { return e.Message }

// Unwrap makes errors.Is(err, ErrIPAMConflict) true.
func (e *PlacementConflictError) Unwrap() error { return ErrIPAMConflict }

// rackDevice is one racked device as the overlap check sees it, in half-units.
type rackDevice struct {
	AssetID   uuid.UUID
	Name      string
	Pos2      int // position * 2
	Face      string
	H2        int // u_height * 2
	FullDepth bool
	Excluded  bool // device_types.exclude_from_utilization
}

// blocks reports whether d is in the way of a device of height spanning
// half-units [lo, hi) on face, fullDepth or not.
func (d rackDevice) blocks(face string, fullDepth bool, lo, hi int) bool {
	if d.H2 <= 0 || hi <= lo {
		return false
	}
	if d.Pos2 >= hi || lo >= d.Pos2+d.H2 {
		return false
	}
	return d.Face == face || d.FullDepth || fullDepth
}

func (d rackDevice) blocker() *PlacementBlocker {
	return &PlacementBlocker{ID: d.AssetID, Name: d.Name, Position: float64(d.Pos2) / 2, Face: d.Face, UHeight: float64(d.H2) / 2}
}

// rackReservation is one reservation as the checks see it.
type rackReservation struct {
	ID          uuid.UUID
	Description string
	Units       []int
}

// covers reports whether any reserved unit intersects half-units [lo, hi).
func (r rackReservation) covers(lo, hi int) bool {
	for _, u := range r.Units {
		if 2*u < hi && lo < 2*u+2 {
			return true
		}
	}
	return false
}

func (r rackReservation) blocker() *ReservationBlocker {
	return &ReservationBlocker{ID: r.ID, Description: r.Description, Units: r.Units}
}

// rackGeometry is the part of a rack the checks need.
type rackGeometry struct {
	ID           uuid.UUID
	Name         string
	SiteID       uuid.UUID
	LocationID   uuid.NullUUID
	UHeight      int
	StartingUnit int
}

// lowest and highest half-unit bounds: a device spanning [lo, hi) fits when
// lo >= 2*starting_unit and hi <= 2*(starting_unit + u_height).
func (g rackGeometry) fits(lo, hi int) bool {
	return lo >= 2*g.StartingUnit && hi <= 2*(g.StartingUnit+g.UHeight)
}

func (g rackGeometry) unitRange() string {
	return fmt.Sprintf("U%d–U%d", g.StartingUnit, g.StartingUnit+g.UHeight-1)
}

// conflictFor returns the first device or reservation in the way of a device
// of h2 half-units at pos2 on face, or nil.
func conflictFor(devs []rackDevice, res []rackReservation, self uuid.UUID, pos2, h2 int, face string, fullDepth bool) *PlacementConflictError {
	lo, hi := pos2, pos2+h2
	for _, d := range devs {
		if d.AssetID == self {
			continue
		}
		if d.blocks(face, fullDepth, lo, hi) {
			return &PlacementConflictError{
				Message:       fmt.Sprintf("U%s on the %s face is occupied by %s (U%s, %s, %sU)", fmtU(float64(pos2)/2), face, d.Name, fmtU(float64(d.Pos2)/2), d.Face, fmtU(float64(d.H2)/2)),
				BlockingAsset: d.blocker(),
			}
		}
	}
	for _, r := range res {
		if r.covers(lo, hi) {
			return &PlacementConflictError{
				Message:             fmt.Sprintf("U%s is reserved (%s)", fmtU(float64(pos2)/2), r.Description),
				BlockingReservation: r.blocker(),
			}
		}
	}
	return nil
}

func fmtU(v float64) string {
	if v == math.Trunc(v) {
		return fmt.Sprintf("%d", int(v))
	}
	return fmt.Sprintf("%.1f", v)
}

// halfUnits converts a position or height to half-units, refusing anything
// that is not a multiple of 0.5.
func halfUnits(v float64, what string) (int, error) {
	h := v * 2
	if math.IsNaN(h) || math.IsInf(h, 0) || h != math.Trunc(h) {
		return 0, ipamInvalid("%s must be a whole or half unit", what)
	}
	return int(h), nil
}

// lockRacks takes FOR UPDATE on the racks in id order and returns them.
func lockRacks(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, ids ...uuid.UUID) (map[uuid.UUID]rackGeometry, error) {
	uniq := map[uuid.UUID]bool{}
	var ordered []string
	for _, id := range ids {
		if id == uuid.Nil || uniq[id] {
			continue
		}
		uniq[id] = true
		ordered = append(ordered, id.String())
	}
	sort.Strings(ordered)
	out := map[uuid.UUID]rackGeometry{}
	for _, s := range ordered {
		var g rackGeometry
		err := tx.QueryRowContext(ctx, `SELECT id, name, site_id, location_id, u_height, starting_unit
			FROM racks WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenant, s).Scan(
			&g.ID, &g.Name, &g.SiteID, &g.LocationID, &g.UHeight, &g.StartingUnit)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[g.ID] = g
	}
	return out, nil
}

// assetNameSQL is how an asset is named in a conflict and on the elevation.
const assetNameSQL = `COALESCE(NULLIF(a.display_name, ''), NULLIF(a.hostname, ''), host(a.primary_address), a.id::text)`

// loadRackDevices reads the devices racked (with a position) in rack.
func loadRackDevices(ctx context.Context, tx *sql.Tx, tenant, rack uuid.UUID) ([]rackDevice, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, `+assetNameSQL+`, a.position::float8, a.face,
		       COALESCE(dt.u_height, 1)::float8, COALESCE(dt.is_full_depth, true), COALESCE(dt.exclude_from_utilization, false)
		  FROM assets a
		  LEFT JOIN device_types dt ON dt.id = a.device_type_id
		 WHERE a.tenant_id = $1 AND a.rack_id = $2 AND a.position IS NOT NULL AND a.deleted_at IS NULL
		   AND a.device_bay_id IS NULL AND a.parent_asset_id IS NULL
		 ORDER BY a.position, a.id`, tenant, rack)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []rackDevice
	for rows.Next() {
		var (
			d    rackDevice
			p, h float64
		)
		if err := rows.Scan(&d.AssetID, &d.Name, &p, &d.Face, &h, &d.FullDepth, &d.Excluded); err != nil {
			return nil, err
		}
		d.Pos2, d.H2 = int(math.Round(p*2)), int(math.Round(h*2))
		out = append(out, d)
	}
	return out, rows.Err()
}

// loadRackReservations reads rack's reservations, except skip.
func loadRackReservations(ctx context.Context, tx *sql.Tx, tenant, rack, skip uuid.UUID) ([]rackReservation, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, description, units FROM rack_reservations
		WHERE tenant_id = $1 AND rack_id = $2 AND id <> $3 ORDER BY created_at, id`, tenant, rack, skip)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []rackReservation
	for rows.Next() {
		var (
			r     rackReservation
			units pq.Int64Array
		)
		if err := rows.Scan(&r.ID, &r.Description, &units); err != nil {
			return nil, err
		}
		for _, u := range units {
			r.Units = append(r.Units, int(u))
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// refreshRackUtilizationTx recomputes rack's rack_utilization row
// (DATA_MODEL §3: occupied U / (u_height minus the units only excluded devices
// take)). A unit counts once whichever face, or both, holds it; half-units
// count as half.
func refreshRackUtilizationTx(ctx context.Context, tx *sql.Tx, tenant, rack uuid.UUID) error {
	var uHeight, start int
	err := tx.QueryRowContext(ctx, `SELECT u_height, starting_unit FROM racks WHERE tenant_id = $1 AND id = $2`, tenant, rack).Scan(&uHeight, &start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	devs, err := loadRackDevices(ctx, tx, tenant, rack)
	if err != nil {
		return err
	}
	used, total := utilization(devs, uHeight, start)
	pct := 0.0
	if total > 0 {
		pct = math.Round(used/total*10000) / 100
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO rack_utilization (rack_id, tenant_id, used_units, total_units, utilization, refreshed_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (rack_id) DO UPDATE SET used_units = EXCLUDED.used_units, total_units = EXCLUDED.total_units,
		       utilization = EXCLUDED.utilization, refreshed_at = now()`, rack, tenant, used, total, pct)
	return err
}

// utilization returns the occupied and the countable units of a rack.
func utilization(devs []rackDevice, uHeight, start int) (used, total float64) {
	lo, hi := 2*start, 2*(start+uHeight)
	occupied := map[int]bool{}
	excluded := map[int]bool{}
	for _, d := range devs {
		for h := d.Pos2; h < d.Pos2+d.H2; h++ {
			if h < lo || h >= hi {
				continue
			}
			if d.Excluded {
				excluded[h] = true
			} else {
				occupied[h] = true
			}
		}
	}
	onlyExcluded := 0
	for h := range excluded {
		if !occupied[h] {
			onlyExcluded++
		}
	}
	return float64(len(occupied)) / 2, float64(2*uHeight-onlyExcluded) / 2
}

// ------------------------------------------------------------- the service --

// PlacementService places assets in racks and reads rack elevations.
type PlacementService struct {
	db *sql.DB
}

// NewPlacementService returns the service over db (the raw pool; RLS is set
// per transaction).
func NewPlacementService(db *sql.DB) *PlacementService {
	return &PlacementService{db: db}
}

// AssetPlacement is an asset's Placement card: Site › Location › Rack › U · Face.
type AssetPlacement struct {
	AssetID  uuid.UUID     `json:"asset_id"`
	Site     *PlacementRef `json:"site"`
	Location *PlacementRef `json:"location"`
	Rack     *PlacementRef `json:"rack"`
	// Position is the lowest unit, nil when the asset is not racked.
	Position *float64 `json:"position"`
	Face     *string  `json:"face"`
	// UHeight and IsFullDepth are what the placement checks use: the device
	// type's, or 1U full depth when the asset has no device type.
	UHeight     float64 `json:"u_height"`
	IsFullDepth bool    `json:"is_full_depth"`
	// HasDeviceType is false when UHeight/IsFullDepth are the defaults.
	HasDeviceType bool `json:"has_device_type"`
	// IsChild is true for a device in a parent's device bay: it takes no units.
	IsChild bool `json:"is_child"`
}

// PlacementRef is a referenced site, location or rack.
type PlacementRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Path string    `json:"path,omitempty"`
}

// PlaceInput is PUT /dcim/assets/{id}/placement.
type PlaceInput struct {
	RackID   uuid.UUID `json:"rack_id"`
	Position float64   `json:"position"`
	Face     string    `json:"face"`
}

// assetPlacementRow is the locked asset as Place sees it.
type assetPlacementRow struct {
	rack          uuid.NullUUID
	position      sql.NullFloat64
	face          sql.NullString
	site, loc     uuid.NullUUID
	child         bool
	h             float64
	fullDepth     bool
	hasType       bool
	subdeviceRole sql.NullString
}

func lockAssetPlacement(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID) (*assetPlacementRow, error) {
	r := &assetPlacementRow{}
	var dt uuid.NullUUID
	err := tx.QueryRowContext(ctx, `
		SELECT a.rack_id, a.position::float8, a.face, a.site_id, a.location_id,
		       (a.device_bay_id IS NOT NULL OR a.parent_asset_id IS NOT NULL), a.device_type_id
		  FROM assets a WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL FOR UPDATE`, tenant, asset).Scan(
		&r.rack, &r.position, &r.face, &r.site, &r.loc, &r.child, &dt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCatalogueAssetNotFound
	}
	if err != nil {
		return nil, err
	}
	r.h, r.fullDepth = 1, true
	if dt.Valid {
		r.hasType = true
		if err := tx.QueryRowContext(ctx, `SELECT u_height::float8, is_full_depth, subdevice_role FROM device_types WHERE id = $1`, dt.UUID).Scan(
			&r.h, &r.fullDepth, &r.subdeviceRole); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Get returns the asset's placement.
func (s *PlacementService) Get(ctx context.Context, tenant, asset uuid.UUID) (*AssetPlacement, error) {
	var out *AssetPlacement
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var err error
		out, err = placementTx(ctx, tx, tenant, asset)
		return err
	})
	return out, mapIPAMError(err, false)
}

func placementTx(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID) (*AssetPlacement, error) {
	p := &AssetPlacement{AssetID: asset}
	var (
		siteID, locID, rackID      uuid.NullUUID
		siteName, locName, locPath sql.NullString
		rackName                   sql.NullString
		pos                        sql.NullFloat64
		face                       sql.NullString
		dtID                       uuid.NullUUID
		h                          sql.NullFloat64
		full                       sql.NullBool
	)
	err := tx.QueryRowContext(ctx, `
		SELECT st.id, st.name, lc.id, lc.name, public.location_path(lc.id), rk.id, rk.name,
		       a.position::float8, a.face, (a.device_bay_id IS NOT NULL OR a.parent_asset_id IS NOT NULL),
		       dt.id, dt.u_height::float8, dt.is_full_depth
		  FROM assets a
		  LEFT JOIN sites st ON st.id = a.site_id
		  LEFT JOIN locations lc ON lc.id = a.location_id
		  LEFT JOIN racks rk ON rk.id = a.rack_id
		  LEFT JOIN device_types dt ON dt.id = a.device_type_id
		 WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL`, tenant, asset).Scan(
		&siteID, &siteName, &locID, &locName, &locPath, &rackID, &rackName, &pos, &face, &p.IsChild, &dtID, &h, &full)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCatalogueAssetNotFound
	}
	if err != nil {
		return nil, err
	}
	if siteID.Valid {
		p.Site = &PlacementRef{ID: siteID.UUID, Name: siteName.String}
	}
	if locID.Valid {
		p.Location = &PlacementRef{ID: locID.UUID, Name: locName.String, Path: locPath.String}
	}
	if rackID.Valid {
		p.Rack = &PlacementRef{ID: rackID.UUID, Name: rackName.String}
	}
	if pos.Valid {
		v := pos.Float64
		p.Position = &v
	}
	if face.Valid {
		v := face.String
		p.Face = &v
	}
	p.UHeight, p.IsFullDepth = 1, true
	if dtID.Valid {
		p.HasDeviceType, p.UHeight, p.IsFullDepth = true, h.Float64, full.Bool
	}
	return p, nil
}

// Place racks the asset at position on face of rack: a first placement, a move
// within its rack, or a move to another rack. The asset takes the rack's site
// and location. Refused with a *PlacementConflictError (409) when a device or
// a reservation holds any unit of the span on that face.
func (s *PlacementService) Place(ctx context.Context, tenant, asset uuid.UUID, in PlaceInput) (*AssetPlacement, error) {
	var out *AssetPlacement
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if err := placeTx(ctx, tx, tenant, asset, in); err != nil {
			return err
		}
		var err error
		out, err = placementTx(ctx, tx, tenant, asset)
		return err
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}

// MoveWithinRack changes the position and face of an asset already in a rack.
func (s *PlacementService) MoveWithinRack(ctx context.Context, tenant, asset uuid.UUID, position float64, face string) (*AssetPlacement, error) {
	var out *AssetPlacement
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var rack uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT rack_id FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenant, asset).Scan(&rack); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrCatalogueAssetNotFound
			}
			return err
		}
		if !rack.Valid {
			return ipamInvalid("the asset is not in a rack")
		}
		if err := placeTx(ctx, tx, tenant, asset, PlaceInput{RackID: rack.UUID, Position: position, Face: face}); err != nil {
			return err
		}
		var err error
		out, err = placementTx(ctx, tx, tenant, asset)
		return err
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}

func placeTx(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, in PlaceInput) error {
	if in.RackID == uuid.Nil {
		return ipamInvalid("rack_id is required")
	}
	if in.Face != "front" && in.Face != "rear" {
		return ipamInvalid("face must be front or rear")
	}
	pos2, err := halfUnits(in.Position, "position")
	if err != nil {
		return err
	}
	a, err := lockAssetPlacement(ctx, tx, tenant, asset)
	if err != nil {
		return err
	}
	racks, err := lockRacks(ctx, tx, tenant, in.RackID, a.rack.UUID)
	if err != nil {
		return err
	}
	g, ok := racks[in.RackID]
	if !ok {
		return ipamInvalid("no such rack %s", in.RackID)
	}
	if a.child || a.subdeviceRole.String == "child" {
		return ipamInvalid("a child device sits in its parent's device bay and takes no rack units")
	}
	h2, err := halfUnits(a.h, "u_height")
	if err != nil {
		return err
	}
	if h2 == 0 {
		return ipamInvalid("a 0U device cannot take a rack position")
	}
	if !g.fits(pos2, pos2+h2) {
		return ipamInvalid("a %sU device at U%s does not fit rack %s (%s)", fmtU(a.h), fmtU(in.Position), g.Name, g.unitRange())
	}
	devs, err := loadRackDevices(ctx, tx, tenant, g.ID)
	if err != nil {
		return err
	}
	res, err := loadRackReservations(ctx, tx, tenant, g.ID, uuid.Nil)
	if err != nil {
		return err
	}
	if c := conflictFor(devs, res, asset, pos2, h2, in.Face, a.fullDepth); c != nil {
		return c
	}

	pre := placementImage(a.rack, a.position, a.face, a.site, a.loc)
	post := map[string]any{
		"rack_id": g.ID.String(), "position": float64(pos2) / 2, "face": in.Face,
		"site_id": g.SiteID.String(), "location_id": nullUUIDString(g.LocationID),
	}
	if sameImage(pre, post) {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET rack_id = $3, position = $4, face = $5, site_id = $6, location_id = $7, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenant, asset, g.ID, float64(pos2)/2, in.Face, g.SiteID, g.LocationID); err != nil {
		return err
	}
	if err := recordPlacementChanges(ctx, tx, tenant, asset, pre, post); err != nil {
		return err
	}
	if err := refreshRackUtilizationTx(ctx, tx, tenant, g.ID); err != nil {
		return err
	}
	if a.rack.Valid && a.rack.UUID != g.ID {
		return refreshRackUtilizationTx(ctx, tx, tenant, a.rack.UUID)
	}
	return nil
}

// Unplace takes the asset out of its rack. It keeps its site and location.
func (s *PlacementService) Unplace(ctx context.Context, tenant, asset uuid.UUID) (*AssetPlacement, error) {
	var out *AssetPlacement
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		a, err := lockAssetPlacement(ctx, tx, tenant, asset)
		if err != nil {
			return err
		}
		if a.rack.Valid {
			if _, err := lockRacks(ctx, tx, tenant, a.rack.UUID); err != nil {
				return err
			}
			if err := unplaceTx(ctx, tx, tenant, asset, a); err != nil {
				return err
			}
			if err := refreshRackUtilizationTx(ctx, tx, tenant, a.rack.UUID); err != nil {
				return err
			}
		}
		out, err = placementTx(ctx, tx, tenant, asset)
		return err
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}

func unplaceTx(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, a *assetPlacementRow) error {
	pre := placementImage(a.rack, a.position, a.face, a.site, a.loc)
	post := placementImage(uuid.NullUUID{}, sql.NullFloat64{}, sql.NullString{}, a.site, a.loc)
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET rack_id = NULL, position = NULL, face = NULL, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenant, asset); err != nil {
		return err
	}
	return recordPlacementChanges(ctx, tx, tenant, asset, pre, post)
}

func nullUUIDString(u uuid.NullUUID) any {
	if !u.Valid {
		return nil
	}
	return u.UUID.String()
}

func placementImage(rack uuid.NullUUID, pos sql.NullFloat64, face sql.NullString, site, loc uuid.NullUUID) map[string]any {
	m := map[string]any{"rack_id": nullUUIDString(rack), "position": nil, "face": nil,
		"site_id": nullUUIDString(site), "location_id": nullUUIDString(loc)}
	if pos.Valid {
		m["position"] = pos.Float64
	}
	if face.Valid {
		m["face"] = face.String
	}
	return m
}

func sameImage(a, b map[string]any) bool {
	for k, v := range a {
		if fmt.Sprint(v) != fmt.Sprint(b[k]) {
			return false
		}
	}
	return len(a) == len(b)
}

// recordPlacementChanges records the asset's change (the placement columns
// that moved) and an update on every rack it left or entered, whose images
// name the asset and its units there.
func recordPlacementChanges(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, pre, post map[string]any) error {
	before, after := map[string]any{}, map[string]any{}
	for k := range post {
		if fmt.Sprint(pre[k]) != fmt.Sprint(post[k]) {
			before[k], after[k] = pre[k], post[k]
		}
	}
	if len(after) == 0 {
		return nil
	}
	rec := changes.InTx(tx)
	if err := rec.Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindAsset, ID: asset,
		Action: changes.ActionUpdate, Pre: before, Post: after}); err != nil {
		return err
	}
	slot := func(img map[string]any) map[string]any {
		if img["rack_id"] == nil {
			return nil
		}
		return map[string]any{"asset_id": asset.String(), "position": img["position"], "face": img["face"]}
	}
	type rackChange struct {
		id       any
		pre, pos map[string]any
	}
	var rcs []rackChange
	if fmt.Sprint(pre["rack_id"]) == fmt.Sprint(post["rack_id"]) {
		rcs = append(rcs, rackChange{post["rack_id"], slot(pre), slot(post)})
	} else {
		rcs = append(rcs, rackChange{pre["rack_id"], slot(pre), nil}, rackChange{post["rack_id"], nil, slot(post)})
	}
	for _, r := range rcs {
		if r.id == nil {
			continue
		}
		rid, err := uuid.Parse(fmt.Sprint(r.id))
		if err != nil {
			return err
		}
		if err := rec.Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindRack, ID: rid, Action: changes.ActionUpdate,
			Pre: map[string]any{"placement": r.pre}, Post: map[string]any{"placement": r.pos}}); err != nil {
			return err
		}
	}
	return nil
}

// unplaceRackTx unplaces every device in rack (a rack being deleted), recording
// each live asset's change. Soft-deleted assets are cleared too, so the FK's
// SET NULL never leaves a position without a rack.
func unplaceRackTx(ctx context.Context, tx *sql.Tx, tenant, rack uuid.UUID) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, position::float8, face, site_id, location_id, deleted_at IS NOT NULL
		FROM assets WHERE tenant_id = $1 AND rack_id = $2 ORDER BY id FOR UPDATE`, tenant, rack)
	if err != nil {
		return err
	}
	type row struct {
		id        uuid.UUID
		pos       sql.NullFloat64
		face      sql.NullString
		site, loc uuid.NullUUID
		deleted   bool
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.pos, &r.face, &r.site, &r.loc, &r.deleted); err != nil {
			_ = rows.Close()
			return err
		}
		all = append(all, r)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(all) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET rack_id = NULL, position = NULL, face = NULL, updated_at = now()
		WHERE tenant_id = $1 AND rack_id = $2`, tenant, rack); err != nil {
		return err
	}
	rec := changes.InTx(tx)
	for _, r := range all {
		if r.deleted {
			continue
		}
		pre := placementImage(uuid.NullUUID{UUID: rack, Valid: true}, r.pos, r.face, r.site, r.loc)
		if err := rec.Record(ctx, changes.Change{TenantID: tenant, Kind: dcim.ObjectKindAsset, ID: r.id, Action: changes.ActionUpdate,
			Pre:  map[string]any{"rack_id": pre["rack_id"], "position": pre["position"], "face": pre["face"]},
			Post: map[string]any{"rack_id": nil, "position": nil, "face": nil}}); err != nil {
			return err
		}
	}
	return nil
}

// RevalidatePlacementTx re-checks a racked asset's placement after its device
// type changed (height or depth), under the rack's lock, and refreshes the
// rack's utilisation. The asset row is already locked by the caller. A type
// that no longer fits, or now overlaps a neighbour, is refused (409/400), so
// the type change rolls back.
func RevalidatePlacementTx(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID) error {
	a, err := lockAssetPlacement(ctx, tx, tenant, asset)
	if err != nil || !a.rack.Valid {
		return err
	}
	racks, err := lockRacks(ctx, tx, tenant, a.rack.UUID)
	if err != nil {
		return err
	}
	g, ok := racks[a.rack.UUID]
	if !ok || !a.position.Valid {
		return refreshRackUtilizationTx(ctx, tx, tenant, a.rack.UUID)
	}
	if a.subdeviceRole.String == "child" {
		return ipamInvalid("a child device type cannot be racked; unplace the asset first")
	}
	pos2, _ := halfUnits(a.position.Float64, "position")
	h2, err := halfUnits(a.h, "u_height")
	if err != nil {
		return err
	}
	if h2 == 0 {
		return ipamInvalid("a 0U device type cannot keep a rack position; unplace the asset first")
	}
	if !g.fits(pos2, pos2+h2) {
		return ipamInvalid("a %sU device at U%s does not fit rack %s (%s); unplace or move the asset first", fmtU(a.h), fmtU(a.position.Float64), g.Name, g.unitRange())
	}
	devs, err := loadRackDevices(ctx, tx, tenant, g.ID)
	if err != nil {
		return err
	}
	res, err := loadRackReservations(ctx, tx, tenant, g.ID, uuid.Nil)
	if err != nil {
		return err
	}
	if c := conflictFor(devs, res, asset, pos2, h2, a.face.String, a.fullDepth); c != nil {
		return c
	}
	return refreshRackUtilizationTx(ctx, tx, tenant, g.ID)
}

// CheckRackConsistencyTx is the rule an asset's site/location edit must keep
// (DATA_MODEL §2: rack_id requires a site match): a racked asset's site is its
// rack's, and its location the rack's when the rack has one. dbtx is the
// caller's transaction (sql.Tx or sqlx.Tx).
func CheckRackConsistencyTx(ctx context.Context, dbtx changes.DBTX, tenant, asset uuid.UUID, site, loc *uuid.UUID) error {
	var (
		rackName       string
		rackSite       uuid.UUID
		rackLoc        uuid.NullUUID
		rackLocPathRaw sql.NullString
	)
	err := dbtx.QueryRowContext(ctx, `SELECT rk.name, rk.site_id, rk.location_id, public.location_path(rk.location_id)
		FROM assets a JOIN racks rk ON rk.id = a.rack_id WHERE a.tenant_id = $1 AND a.id = $2`, tenant, asset).Scan(
		&rackName, &rackSite, &rackLoc, &rackLocPathRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if site == nil || *site != rackSite {
		return siteInvalid("the asset is in rack %s, which is in another site; unplace it from the rack first", rackName)
	}
	if rackLoc.Valid && (loc == nil || *loc != rackLoc.UUID) {
		return siteInvalid("the asset is in rack %s, which is in %s; unplace it from the rack first", rackName, strings.TrimSpace(rackLocPathRaw.String))
	}
	return nil
}

// --------------------------------------------------------------- elevation --

// RackElevation is GET /dcim/racks/{id}/elevation: the rack, every racked
// device, the per-unit occupancy of both faces, the reservations and the
// cached utilisation, from ONE query.
type RackElevation struct {
	Rack         json.RawMessage        `json:"rack"`
	Devices      []ElevationDevice      `json:"devices"`
	Units        []ElevationUnit        `json:"units"`
	Reservations []ElevationReservation `json:"reservations"`
	// NonRacked counts assets in the rack without a position (NetBox's
	// "non-racked devices").
	NonRacked   int                   `json:"non_racked"`
	Utilization *ElevationUtilization `json:"utilization"`
}

// ElevationDevice is one racked device.
type ElevationDevice struct {
	AssetID     uuid.UUID        `json:"asset_id"`
	Name        string           `json:"name"`
	ClassKey    string           `json:"class_key"`
	Position    float64          `json:"position"`
	Face        string           `json:"face"`
	UHeight     float64          `json:"u_height"`
	IsFullDepth bool             `json:"is_full_depth"`
	DeviceType  *ElevationDevTyp `json:"device_type"`
	ChildCount  int              `json:"child_count"`
	// Serial is the asset's declared serial (the rack page's Devices table).
	Serial *string `json:"serial"`
	// Posture is the crypto overlay's read (rack_posture.go), present only
	// when the elevation is asked for with include=posture.
	Posture *DevicePosture `json:"posture,omitempty"`
}

// ElevationDevTyp is a racked device's type, with its image refs (object
// storage keys, DATA_MODEL §2) when it has them.
type ElevationDevTyp struct {
	ID            uuid.UUID `json:"id"`
	Model         string    `json:"model"`
	Slug          string    `json:"slug"`
	FrontImageRef *string   `json:"front_image_ref"`
	RearImageRef  *string   `json:"rear_image_ref"`
}

// ElevationUnit is one whole unit: who holds each face (a half-U device shows
// on the units it touches) and the reservation covering it.
type ElevationUnit struct {
	Unit          int        `json:"unit"`
	Front         []string   `json:"front"`
	Rear          []string   `json:"rear"`
	ReservationID *uuid.UUID `json:"reservation_id"`
}

// ElevationReservation is one reservation.
type ElevationReservation struct {
	ID          uuid.UUID  `json:"id"`
	Units       []int      `json:"units"`
	Description string     `json:"description"`
	UserID      *uuid.UUID `json:"user_id"`
}

// ElevationUtilization is the rack's cached utilisation row.
type ElevationUtilization struct {
	UsedUnits   float64 `json:"used_units"`
	TotalUnits  float64 `json:"total_units"`
	Utilization float64 `json:"utilization"`
	RefreshedAt string  `json:"refreshed_at"`
}

const elevationSQL = `
SELECT to_jsonb(r) || jsonb_build_object(
         'site', jsonb_build_object('id', st.id, 'name', st.name, 'slug', st.slug),
         'location', CASE WHEN lc.id IS NULL THEN NULL ELSE jsonb_build_object('id', lc.id, 'name', lc.name, 'path', public.location_path(lc.id)) END,
         'role', CASE WHEN rr.id IS NULL THEN NULL ELSE jsonb_build_object('id', rr.id, 'name', rr.name, 'slug', rr.slug, 'color', rr.color) END),
       COALESCE((
         SELECT jsonb_agg(jsonb_build_object(
                  'asset_id', a.id, 'name', ` + assetNameSQL + `, 'class_key', a.class_key,
                  'position', a.position, 'face', a.face,
                  'u_height', COALESCE(dt.u_height, 1), 'is_full_depth', COALESCE(dt.is_full_depth, true),
                  'device_type', CASE WHEN dt.id IS NULL THEN NULL ELSE jsonb_build_object(
                      'id', dt.id, 'model', dt.model, 'slug', dt.slug,
                      'front_image_ref', dt.front_image_ref, 'rear_image_ref', dt.rear_image_ref) END,
                  'child_count', (SELECT count(*) FROM assets c WHERE c.tenant_id = a.tenant_id AND c.parent_asset_id = a.id AND c.deleted_at IS NULL),
                  'serial', a.serial)
                ORDER BY a.position DESC, a.face, a.id)
           FROM assets a LEFT JOIN device_types dt ON dt.id = a.device_type_id
          WHERE a.tenant_id = r.tenant_id AND a.rack_id = r.id AND a.position IS NOT NULL AND a.deleted_at IS NULL
            AND a.device_bay_id IS NULL AND a.parent_asset_id IS NULL), '[]'::jsonb),
       (SELECT count(*) FROM assets a WHERE a.tenant_id = r.tenant_id AND a.rack_id = r.id AND a.position IS NULL AND a.deleted_at IS NULL),
       COALESCE((
         SELECT jsonb_agg(jsonb_build_object('id', v.id, 'units', v.units, 'description', v.description, 'user_id', v.user_id)
                ORDER BY v.created_at, v.id)
           FROM rack_reservations v WHERE v.tenant_id = r.tenant_id AND v.rack_id = r.id), '[]'::jsonb),
       (SELECT jsonb_build_object('used_units', u.used_units, 'total_units', u.total_units,
                                  'utilization', u.utilization, 'refreshed_at', u.refreshed_at)
          FROM rack_utilization u WHERE u.rack_id = r.id)
  FROM racks r
  JOIN sites st ON st.id = r.site_id
  LEFT JOIN locations lc ON lc.id = r.location_id
  LEFT JOIN rack_roles rr ON rr.id = r.role_id
 WHERE r.tenant_id = $1 AND r.id = $2`

// Elevation returns the rack's elevation.
func (s *PlacementService) Elevation(ctx context.Context, tenant, rack uuid.UUID) (*RackElevation, error) {
	var (
		rackRaw, devRaw, resRaw []byte
		utilRaw                 []byte
		nonRacked               int
	)
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, elevationSQL, tenant, rack).Scan(&rackRaw, &devRaw, &nonRacked, &resRaw, &utilRaw)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIPAMNotFound
	}
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return buildElevation(rackRaw, devRaw, resRaw, utilRaw, nonRacked)
}

func buildElevation(rackRaw, devRaw, resRaw, utilRaw []byte, nonRacked int) (*RackElevation, error) {
	e := &RackElevation{Rack: rackRaw, Devices: []ElevationDevice{}, Reservations: []ElevationReservation{}, NonRacked: nonRacked}
	if err := json.Unmarshal(devRaw, &e.Devices); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(resRaw, &e.Reservations); err != nil {
		return nil, err
	}
	if len(utilRaw) > 0 {
		e.Utilization = &ElevationUtilization{}
		if err := json.Unmarshal(utilRaw, e.Utilization); err != nil {
			return nil, err
		}
	}
	var geo struct {
		UHeight      int  `json:"u_height"`
		StartingUnit int  `json:"starting_unit"`
		DescUnits    bool `json:"desc_units"`
	}
	if err := json.Unmarshal(rackRaw, &geo); err != nil {
		return nil, err
	}
	byUnit := map[int]*ElevationUnit{}
	for u := geo.StartingUnit; u < geo.StartingUnit+geo.UHeight; u++ {
		e.Units = append(e.Units, ElevationUnit{Unit: u, Front: []string{}, Rear: []string{}})
	}
	for i := range e.Units {
		byUnit[e.Units[i].Unit] = &e.Units[i]
	}
	add := func(list []string, id string) []string {
		for _, x := range list {
			if x == id {
				return list
			}
		}
		return append(list, id)
	}
	for _, d := range e.Devices {
		lo, hi := d.Position, d.Position+d.UHeight
		for u := int(math.Floor(lo)); float64(u) < hi; u++ {
			cell, ok := byUnit[u]
			if !ok {
				continue
			}
			id := d.AssetID.String()
			if d.Face == "front" || d.IsFullDepth {
				cell.Front = add(cell.Front, id)
			}
			if d.Face == "rear" || d.IsFullDepth {
				cell.Rear = add(cell.Rear, id)
			}
		}
	}
	for _, r := range e.Reservations {
		for _, u := range r.Units {
			if cell, ok := byUnit[u]; ok && cell.ReservationID == nil {
				id := r.ID
				cell.ReservationID = &id
			}
		}
	}
	// Top of the rack first, as an elevation is drawn; desc_units racks number
	// top-down, so their lowest number is at the top.
	if !geo.DescUnits {
		for i, j := 0, len(e.Units)-1; i < j; i, j = i+1, j-1 {
			e.Units[i], e.Units[j] = e.Units[j], e.Units[i]
		}
	}
	return e, nil
}
