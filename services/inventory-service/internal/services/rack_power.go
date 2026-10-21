package services

// The rack power budget (DCIM BUILD_PLAN row 6.2; ADR-0010 D9): what the
// devices a rack's feeds power declare they draw, against what those feeds can
// supply. NetBox's Rack.get_power_utilization, computed the same way:
//
//   - the feeds are the ones declared as serving the rack (power_feeds.rack_id),
//     whatever their status;
//   - each feed's draw is that of the power port at the far end of its cable
//     (the PDU inlet) — NetBox PowerPort.get_power_draw: the port's own
//     allocated_draw when it declares a draw, else the sum of the allocated
//     draws of the power ports cabled to the outlets it feeds;
//   - utilisation = sum of allocated draw / sum of available power × 100, to
//     one decimal.
//
// Where NetBox answers 0 for a rack with no feeds, this answers no budget at
// all (a rack whose power nobody declared is not a rack drawing nothing). A
// feed's per-leg figures (a three-phase feed) split its available power in
// three, as NetBox's power port view does.
//
// Measured readings (a PDU collector's, power_intake.go) are shown BESIDE the
// declared figures and never enter the budget: allocated_draw is NetBox's
// field (standards/sync-authority.yaml), and a measured draw is what the
// devices took when the PDU was read, not what they are allowed.
//
// Computed on read, in SQL, from the tables — there is no cache to keep in
// step. The rack list (one subquery per listed rack), the rack page and the
// facilities roll-up all use powerFeedDrawSQL, so the three numbers agree.

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
)

// powerFeedDrawSQL is one row per power feed with its draw (alias fd when
// selected from). Callers append a WHERE on f.* (f.rack_id, f.tenant_id).
const powerFeedDrawSQL = `
SELECT f.tenant_id, f.id AS feed_id, f.rack_id, f.name AS feed_name, f.power_panel_id, pp.name AS panel_name,
       f.operational_status, f.phase, f.available_power,
       dp.id AS port_id, dp.name AS port_name, dp.asset_id AS port_asset_id,
       COALESCE(da.display_name, da.hostname, host(da.primary_address)) AS port_asset_name,
       (dp.id IS NOT NULL AND dp.allocated_draw IS NULL AND dp.maximum_draw IS NULL) AS aggregated,
       CASE WHEN dp.id IS NULL THEN 0
            WHEN dp.allocated_draw IS NULL AND dp.maximum_draw IS NULL THEN COALESCE(ds.allocated, 0)
            ELSE COALESCE(dp.allocated_draw, 0) END AS allocated_draw,
       CASE WHEN dp.id IS NULL THEN 0
            WHEN dp.allocated_draw IS NULL AND dp.maximum_draw IS NULL THEN COALESCE(ds.maximum, 0)
            ELSE COALESCE(dp.maximum_draw, 0) END AS maximum_draw,
       CASE WHEN dp.id IS NULL THEN 0
            WHEN dp.allocated_draw IS NULL AND dp.maximum_draw IS NULL THEN COALESCE(ds.recorded, 0)
            ELSE 1 END AS recorded_count,
       COALESCE(ds.outlets, 0) AS outlet_count,
       COALESCE(dp.measured_draw, ds.measured) AS measured_draw,
       dp.measured_at
  FROM public.power_feeds f
  JOIN public.power_panels pp ON pp.id = f.power_panel_id
  LEFT JOIN public.cable_paths cp ON cp.tenant_id = f.tenant_id AND cp.origin_kind = 'power_feed' AND cp.origin_id = f.id
       AND cp.is_complete AND cp.destination_kind = 'power_port'
  LEFT JOIN public.power_ports dp ON dp.id = cp.destination_id
  LEFT JOIN public.assets da ON da.id = dp.asset_id
  LEFT JOIN LATERAL (
       SELECT count(*) AS outlets,
              sum(xp.allocated_draw) AS allocated, sum(xp.maximum_draw) AS maximum,
              count(xp.id) FILTER (WHERE xp.allocated_draw IS NOT NULL OR xp.maximum_draw IS NOT NULL) AS recorded,
              sum(o.measured_draw) AS measured
         FROM public.power_outlets o
         LEFT JOIN public.cable_paths op ON op.tenant_id = o.tenant_id AND op.origin_kind = 'power_outlet' AND op.origin_id = o.id
              AND op.is_complete AND op.destination_kind = 'power_port'
         LEFT JOIN public.power_ports xp ON xp.id = op.destination_id
        WHERE o.tenant_id = dp.tenant_id AND o.power_port_id = dp.id AND o.status <> 'rejected') ds ON dp.id IS NOT NULL`

// rackPowerUtilizationSQL is the rack list's `power_utilization` (alias t is
// the rack): NULL for a rack no feed serves.
const rackPowerUtilizationSQL = `(SELECT CASE WHEN count(*) = 0 THEN NULL ELSE jsonb_build_object(
	'feed_count', count(*),
	'available_power', sum(fd.available_power),
	'allocated_draw', sum(fd.allocated_draw),
	'utilization', CASE WHEN sum(fd.available_power) > 0 THEN round(sum(fd.allocated_draw)::numeric * 100 / sum(fd.available_power), 1) END,
	'measured_draw', sum(fd.measured_draw)) END
	FROM (` + powerFeedDrawSQL + `
	 WHERE f.tenant_id = t.tenant_id AND f.rack_id = t.id) fd)`

// PowerBudgetPercent is a draw's share of available power, to one decimal (as
// NetBox rounds); nil when nothing is available.
func PowerBudgetPercent(allocated, available int) *float64 {
	if available <= 0 {
		return nil
	}
	v := math.Round(float64(allocated)*1000/float64(available)) / 10
	return &v
}

// RackPowerLeg is one leg of a three-phase feed.
type RackPowerLeg struct {
	Leg            string   `json:"leg"`
	OutletCount    int      `json:"outlet_count"`
	AllocatedDraw  int      `json:"allocated_draw"`
	MaximumDraw    int      `json:"maximum_draw"`
	AvailablePower int      `json:"available_power"`
	Utilization    *float64 `json:"utilization"`
	MeasuredDraw   *int     `json:"measured_draw"`
}

// RackPowerFeed is one feed serving the rack with what it powers.
type RackPowerFeed struct {
	ID                uuid.UUID      `json:"id"`
	Name              string         `json:"name"`
	PowerPanelID      uuid.UUID      `json:"power_panel_id"`
	PowerPanelName    string         `json:"power_panel_name"`
	OperationalStatus string         `json:"operational_status"`
	Phase             string         `json:"phase"`
	AvailablePower    int            `json:"available_power"`
	PowerPort         *PowerEndpoint `json:"power_port"`
	// Aggregated: the port declares no draw of its own, so the draw is its
	// outlets' devices' (NetBox get_power_draw).
	Aggregated    bool     `json:"aggregated"`
	AllocatedDraw int      `json:"allocated_draw"`
	MaximumDraw   int      `json:"maximum_draw"`
	RecordedCount int      `json:"recorded_count"`
	OutletCount   int      `json:"outlet_count"`
	Utilization   *float64 `json:"utilization"`
	// MeasuredDraw is the PDU inlet's measured load (else its outlets'
	// measured loads, summed); nil when nothing measured it.
	MeasuredDraw *int           `json:"measured_draw"`
	MeasuredAt   *string        `json:"measured_at"`
	Legs         []RackPowerLeg `json:"legs"`
}

// RackPowerDevice is one device in the rack with its own declared draws.
type RackPowerDevice struct {
	AssetID uuid.UUID `json:"asset_id"`
	// PowerPorts counts the device's power ports; the draws are nil when none
	// of them declares (or measured) one — never 0.
	PowerPorts    int  `json:"power_port_count"`
	AllocatedDraw *int `json:"allocated_draw"`
	MaximumDraw   *int `json:"maximum_draw"`
	MeasuredDraw  *int `json:"measured_draw"`
	// Share is the allocated draw's percentage of the rack's available power;
	// nil without both.
	Share *float64 `json:"share"`
}

// RackPowerBudget answers GET /dcim/racks/{id}/power.
type RackPowerBudget struct {
	RackID         uuid.UUID         `json:"rack_id"`
	FeedCount      int               `json:"feed_count"`
	AvailablePower int               `json:"available_power"`
	AllocatedDraw  int               `json:"allocated_draw"`
	MaximumDraw    int               `json:"maximum_draw"`
	Utilization    *float64          `json:"utilization"`
	MeasuredDraw   *int              `json:"measured_draw"`
	Feeds          []RackPowerFeed   `json:"feeds"`
	Devices        []RackPowerDevice `json:"devices"`
}

// RackPower returns the rack's power budget.
func (s *PowerService) RackPower(ctx context.Context, tenant, rack uuid.UUID) (*RackPowerBudget, error) {
	out := &RackPowerBudget{RackID: rack, Feeds: []RackPowerFeed{}, Devices: []RackPowerDevice{}}
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.racks WHERE id = $1)`, rack).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrIPAMNotFound
		}
		rows, err := tx.QueryContext(ctx, `SELECT fd.feed_id, fd.feed_name, fd.power_panel_id, fd.panel_name, fd.operational_status, fd.phase,
			       fd.available_power, fd.port_id, fd.port_name, fd.port_asset_id, fd.port_asset_name, fd.aggregated,
			       fd.allocated_draw, fd.maximum_draw, fd.recorded_count, fd.outlet_count, fd.measured_draw,
			       to_char(fd.measured_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			  FROM (`+powerFeedDrawSQL+` WHERE f.tenant_id = $1 AND f.rack_id = $2) fd
			 ORDER BY fd.panel_name, fd.feed_name, fd.feed_id`, tenant, rack)
		if err != nil {
			return err
		}
		for rows.Next() {
			var f RackPowerFeed
			var portID, portAsset uuid.NullUUID
			var portName, portAssetName, measuredAt sql.NullString
			var measured sql.NullInt64
			if err := rows.Scan(&f.ID, &f.Name, &f.PowerPanelID, &f.PowerPanelName, &f.OperationalStatus, &f.Phase, &f.AvailablePower,
				&portID, &portName, &portAsset, &portAssetName, &f.Aggregated, &f.AllocatedDraw, &f.MaximumDraw, &f.RecordedCount,
				&f.OutletCount, &measured, &measuredAt); err != nil {
				_ = rows.Close()
				return err
			}
			if portID.Valid {
				e := &PowerEndpoint{Kind: "power_port", ID: portID.UUID, Name: portName.String, AssetName: nullStrPtr(portAssetName)}
				if portAsset.Valid {
					a := portAsset.UUID
					e.AssetID = &a
				}
				f.PowerPort = e
			}
			f.MeasuredDraw, f.MeasuredAt = nullIntPtr(measured), nullStrPtr(measuredAt)
			f.Utilization = PowerBudgetPercent(f.AllocatedDraw, f.AvailablePower)
			f.Legs = []RackPowerLeg{}
			out.Feeds = append(out.Feeds, f)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for i := range out.Feeds {
			f := &out.Feeds[i]
			out.FeedCount++
			out.AvailablePower += f.AvailablePower
			out.AllocatedDraw += f.AllocatedDraw
			out.MaximumDraw += f.MaximumDraw
			if f.MeasuredDraw != nil {
				m := *f.MeasuredDraw
				if out.MeasuredDraw != nil {
					m += *out.MeasuredDraw
				}
				out.MeasuredDraw = &m
			}
			if f.Phase == "three-phase" && f.PowerPort != nil {
				legs, err := rackPowerLegs(ctx, tx, tenant, f.PowerPort.ID, f.AvailablePower, f.Aggregated)
				if err != nil {
					return err
				}
				f.Legs = legs
			}
		}
		out.Utilization = PowerBudgetPercent(out.AllocatedDraw, out.AvailablePower)

		devs, err := tx.QueryContext(ctx, `
			SELECT a.id, count(p.id),
			       sum(p.allocated_draw), count(p.allocated_draw),
			       sum(p.maximum_draw), count(p.maximum_draw),
			       sum(p.measured_draw), count(p.measured_draw)
			  FROM public.assets a
			  LEFT JOIN public.power_ports p ON p.tenant_id = a.tenant_id AND p.asset_id = a.id AND p.status <> 'rejected'
			 WHERE a.tenant_id = $1 AND a.rack_id = $2 AND a.deleted_at IS NULL
			 GROUP BY a.id
			 ORDER BY a.id`, tenant, rack)
		if err != nil {
			return err
		}
		defer func() { _ = devs.Close() }()
		for devs.Next() {
			var d RackPowerDevice
			var alloc, maxd, meas sql.NullInt64
			var nAlloc, nMax, nMeas int
			if err := devs.Scan(&d.AssetID, &d.PowerPorts, &alloc, &nAlloc, &maxd, &nMax, &meas, &nMeas); err != nil {
				return err
			}
			if nAlloc > 0 {
				d.AllocatedDraw = nullIntPtr(alloc)
			}
			if nMax > 0 {
				d.MaximumDraw = nullIntPtr(maxd)
			}
			if nMeas > 0 {
				d.MeasuredDraw = nullIntPtr(meas)
			}
			if d.AllocatedDraw != nil {
				d.Share = PowerBudgetPercent(*d.AllocatedDraw, out.AvailablePower)
			}
			out.Devices = append(out.Devices, d)
		}
		return devs.Err()
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}

// rackPowerLegs is a three-phase feed's per-leg draw: the outlets of its PDU
// inlet grouped by feed leg (NetBox computes legs only when the inlet declares
// no draw of its own), each leg against a third of the feed's available power,
// with the inlet's measured per-leg load beside it.
func rackPowerLegs(ctx context.Context, tx *sql.Tx, tenant, port uuid.UUID, available int, aggregated bool) ([]RackPowerLeg, error) {
	legs := []RackPowerLeg{}
	byLeg := map[string]*RackPowerLeg{}
	per := available / 3
	for _, l := range []string{"A", "B", "C"} {
		legs = append(legs, RackPowerLeg{Leg: l, AvailablePower: per})
	}
	for i := range legs {
		byLeg[legs[i].Leg] = &legs[i]
	}
	if aggregated {
		rows, err := tx.QueryContext(ctx, `
			SELECT o.feed_leg, count(*), COALESCE(sum(xp.allocated_draw), 0), COALESCE(sum(xp.maximum_draw), 0)
			  FROM public.power_outlets o
			  LEFT JOIN public.cable_paths op ON op.tenant_id = o.tenant_id AND op.origin_kind = 'power_outlet' AND op.origin_id = o.id
			       AND op.is_complete AND op.destination_kind = 'power_port'
			  LEFT JOIN public.power_ports xp ON xp.id = op.destination_id
			 WHERE o.tenant_id = $1 AND o.power_port_id = $2 AND o.status <> 'rejected' AND o.feed_leg IS NOT NULL
			 GROUP BY o.feed_leg`, tenant, port)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var leg string
			var n, alloc, maxd int
			if err := rows.Scan(&leg, &n, &alloc, &maxd); err != nil {
				_ = rows.Close()
				return nil, err
			}
			if l, ok := byLeg[leg]; ok {
				l.OutletCount, l.AllocatedDraw, l.MaximumDraw = n, alloc, maxd
			}
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT measured_legs FROM public.power_ports WHERE tenant_id = $1 AND id = $2`, tenant, port).Scan(&raw); err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		var measured []struct {
			Leg          string `json:"leg"`
			MeasuredDraw *int   `json:"measured_draw"`
		}
		if err := json.Unmarshal(raw, &measured); err == nil {
			for _, m := range measured {
				if l, ok := byLeg[m.Leg]; ok {
					l.MeasuredDraw = m.MeasuredDraw
				}
			}
		}
	}
	for i := range legs {
		legs[i].Utilization = PowerBudgetPercent(legs[i].AllocatedDraw, legs[i].AvailablePower)
	}
	return legs, nil
}
