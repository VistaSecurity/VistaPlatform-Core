package services

// The facilities capacity roll-up (DCIM gap 6, dashboard half): one read that
// answers the questions a facilities operator asks of the estate as a whole —
// how much rack space is left and where, which switches are running out of
// ports, which prefixes are nearly full, and how old the cabling backlog is.
//
// Nothing here is a new source of truth. Rack figures come from the
// rack_utilization cache that placement keeps in step, prefix figures from the
// prefix_utilization cache IPAM keeps in step, and port and cable figures from
// interfaces and cables. Every list is computed with set-based SQL and capped
// in SQL; there is no per-row loop in Go.
//
// The thresholds below are plain capacity percentages. They are NOT risk bands
// (shared/riskbands is the CVSS-anchored ladder for risk scores and has nothing
// to say about how full a rack is), and they are deliberately the same two
// numbers for racks and prefixes so the dashboard has one vocabulary for
// "getting full" and "full".
//
// Honesty rules the SQL follows:
//   - a rack with no rack_utilization row has never had a placement, so it is
//     empty: used 0 of its u_height. A deprecated rack is not capacity and is
//     left out.
//   - a prefix with no addresses and no child prefixes recorded is reported as
//     0 % AND counted in prefixes.no_addresses_recorded, so "0 % full" is never
//     mistaken for "known to be empty".
//   - a switch port is free only when it is enabled, uncabled and not marked
//     connected ("there is a cable here we do not model"). Virtual and wireless
//     interfaces cannot take a cable and are not ports.

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// Capacity thresholds, in percent. "Over" is strictly greater.
const (
	CapacityWarnPercent     = 80
	CapacityCriticalPercent = 95
	// capacityListLimit caps every "fullest / fewest / oldest" list.
	capacityListLimit = 10
	// capacitySiteLimit caps the per-site table; SitesTotal says how many
	// sites have racks so the UI can say the table is truncated.
	capacitySiteLimit = 200
)

// Cable backlog ages, in days.
const (
	CapacityPlannedAgedDays   = 30
	CapacityPlannedStaleDays  = 90
	capacityBacklogListWindow = CapacityPlannedAgedDays
)

// CapacityService computes the roll-up.
type CapacityService struct {
	db  *sql.DB
	now func() time.Time
}

// NewCapacityService returns the service over the app-role pool.
func NewCapacityService(db *sql.DB) *CapacityService {
	return &CapacityService{db: db, now: time.Now}
}

// RackTotals is the tenant-wide rack figure the dashboard tiles read; the
// per-site table is capped, these are not.
type RackTotals struct {
	Racks         int     `json:"racks"`
	TotalUnits    float64 `json:"total_units"`
	UsedUnits     float64 `json:"used_units"`
	ReservedUnits float64 `json:"reserved_units"`
	FreeUnits     float64 `json:"free_units"`
	RacksOver80   int     `json:"racks_over_80"`
	RacksOver95   int     `json:"racks_over_95"`
	// RacksWithPower counts the racks a power feed is declared to serve;
	// RacksOverPowerBudget those whose devices' allocated draw exceeds the
	// feeds' available power (rack_power.go, row 6.2).
	RacksWithPower       int `json:"racks_with_power"`
	RacksOverPowerBudget int `json:"racks_over_power_budget"`
}

// SiteCapacity is one site's rack space.
type SiteCapacity struct {
	SiteID        uuid.UUID `json:"site_id"`
	SiteName      string    `json:"site_name"`
	Racks         int       `json:"racks"`
	TotalUnits    float64   `json:"total_units"`
	UsedUnits     float64   `json:"used_units"`
	ReservedUnits float64   `json:"reserved_units"`
	FreeUnits     float64   `json:"free_units"`
	Utilization   float64   `json:"utilization"`
	RacksOver80   int       `json:"racks_over_80"`
	RacksOver95   int       `json:"racks_over_95"`
	// The power budget, as RackTotals.
	RacksWithPower       int `json:"racks_with_power"`
	RacksOverPowerBudget int `json:"racks_over_power_budget"`
}

// RackCapacity is one of the fullest racks.
type RackCapacity struct {
	RackID      uuid.UUID `json:"rack_id"`
	RackName    string    `json:"rack_name"`
	SiteID      uuid.UUID `json:"site_id"`
	SiteName    string    `json:"site_name"`
	UsedUnits   float64   `json:"used_units"`
	TotalUnits  float64   `json:"total_units"`
	Utilization float64   `json:"utilization"`
}

// SwitchPorts is one switch's port headroom.
type SwitchPorts struct {
	AssetID         uuid.UUID `json:"asset_id"`
	Name            string    `json:"name"`
	Total           int       `json:"total"`
	Cabled          int       `json:"cabled"`
	MarkedConnected int       `json:"marked_connected"`
	Free            int       `json:"free"`
}

// PortCapacity is the switch-port roll-up.
type PortCapacity struct {
	Switches        int           `json:"switches"`
	Total           int           `json:"total"`
	Cabled          int           `json:"cabled"`
	MarkedConnected int           `json:"marked_connected"`
	Free            int           `json:"free"`
	FewestFree      []SwitchPorts `json:"fewest_free"`
}

// PrefixFill is one of the fullest prefixes. Size is the decimal address count
// (an IPv6 prefix overflows every integer type).
type PrefixFill struct {
	PrefixID    uuid.UUID  `json:"prefix_id"`
	Prefix      string     `json:"prefix"`
	VRFID       *uuid.UUID `json:"vrf_id"`
	VRFName     *string    `json:"vrf_name"`
	Size        string     `json:"size"`
	IPCount     int        `json:"ip_count"`
	ChildCount  int        `json:"child_count"`
	Utilization float64    `json:"utilization"`
}

// PrefixCapacity is the prefix roll-up.
type PrefixCapacity struct {
	Total               int          `json:"total"`
	NoAddressesRecorded int          `json:"no_addresses_recorded"`
	Over80              int          `json:"over_80"`
	Over95              int          `json:"over_95"`
	Fullest             []PrefixFill `json:"fullest"`
}

// CableByStatus is the live-cable count per operational status.
type CableByStatus struct {
	Connected       int `json:"connected"`
	Planned         int `json:"planned"`
	Decommissioning int `json:"decommissioning"`
}

// PlannedCable is one aged planned cable.
type PlannedCable struct {
	CableID   uuid.UUID `json:"cable_id"`
	Label     *string   `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	AgeDays   int       `json:"age_days"`
}

// CableBacklog is the cabling roll-up.
type CableBacklog struct {
	ByStatus               CableByStatus  `json:"by_status"`
	ProposedPending        int            `json:"proposed_pending"`
	PlannedOver30Days      int            `json:"planned_over_30_days"`
	PlannedOver90Days      int            `json:"planned_over_90_days"`
	OldestPlanned          []PlannedCable `json:"oldest_planned"`
	DeclaredNeverConfirmed int            `json:"declared_never_confirmed"`
}

// CapacityReport is the whole document.
type CapacityReport struct {
	SitesTotal  int            `json:"sites_total"`
	RackTotals  RackTotals     `json:"rack_totals"`
	Sites       []SiteCapacity `json:"sites"`
	RacksTop    []RackCapacity `json:"racks_top"`
	Ports       PortCapacity   `json:"ports"`
	Prefixes    PrefixCapacity `json:"prefixes"`
	Cables      CableBacklog   `json:"cables"`
	GeneratedAt time.Time      `json:"generated_at"`
}

// rackCapacityCTE is one row per capacity-bearing rack with its used, total and
// reserved units. reserved counts distinct reserved units that fall inside the
// rack's own range; free = max(total - used - reserved, 0) is derived by the
// callers so a clash between a reservation and a device (placement refuses
// them, an import may not) can never produce negative space.
const rackCapacityCTE = `
WITH rk AS (
  SELECT r.id, r.name, r.site_id,
         COALESCE(u.used_units, 0)::float8 AS used,
         COALESCE(u.total_units, r.u_height)::float8 AS total,
         COALESCE((
           SELECT count(DISTINCT x) FROM rack_reservations v, unnest(v.units) x
            WHERE v.tenant_id = r.tenant_id AND v.rack_id = r.id
              AND x >= r.starting_unit AND x < r.starting_unit + r.u_height), 0)::float8 AS reserved
    FROM racks r
    LEFT JOIN rack_utilization u ON u.tenant_id = r.tenant_id AND u.rack_id = r.id
   WHERE r.tenant_id = $1 AND r.operational_status <> 'deprecated'
), rkp AS (
  SELECT rk.*, GREATEST(total - used - reserved, 0) AS free,
         CASE WHEN total > 0 THEN round((used / total * 100)::numeric, 2)::float8 ELSE 0 END AS pct
    FROM rk
)`

// rackPowerCTE extends rackCapacityCTE with each rack's power budget (rpw):
// the sum of its feeds' available power and of the draw allocated on them.
const rackPowerCTE = `, rpw AS (
  SELECT fd.rack_id, sum(fd.available_power) AS avail, sum(fd.allocated_draw) AS alloc
    FROM (` + powerFeedDrawSQL + `
   WHERE f.tenant_id = $1 AND f.rack_id IS NOT NULL) fd
   GROUP BY fd.rack_id
)`

// Report computes the roll-up for the tenant.
func (s *CapacityService) Report(ctx context.Context, tenant uuid.UUID) (CapacityReport, error) {
	now := s.now().UTC()
	rep := CapacityReport{
		Sites: []SiteCapacity{}, RacksTop: []RackCapacity{},
		Ports:       PortCapacity{FewestFree: []SwitchPorts{}},
		Prefixes:    PrefixCapacity{Fullest: []PrefixFill{}},
		Cables:      CableBacklog{OldestPlanned: []PlannedCable{}},
		GeneratedAt: now,
	}
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if err := s.racks(ctx, tx, tenant, &rep); err != nil {
			return err
		}
		if err := s.ports(ctx, tx, tenant, &rep); err != nil {
			return err
		}
		if err := s.prefixes(ctx, tx, tenant, &rep); err != nil {
			return err
		}
		return s.cables(ctx, tx, tenant, now, &rep)
	})
	return rep, err
}

func (s *CapacityService) racks(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, rep *CapacityReport) error {
	if err := tx.QueryRowContext(ctx, rackCapacityCTE+rackPowerCTE+`
SELECT count(*), COALESCE(sum(total),0), COALESCE(sum(used),0), COALESCE(sum(reserved),0), COALESCE(sum(free),0),
       count(*) FILTER (WHERE pct > $2), count(*) FILTER (WHERE pct > $3), count(DISTINCT site_id),
       count(rpw.rack_id), count(*) FILTER (WHERE rpw.alloc > rpw.avail)
  FROM rkp LEFT JOIN rpw ON rpw.rack_id = rkp.id`, tenant, CapacityWarnPercent, CapacityCriticalPercent).Scan(
		&rep.RackTotals.Racks, &rep.RackTotals.TotalUnits, &rep.RackTotals.UsedUnits, &rep.RackTotals.ReservedUnits,
		&rep.RackTotals.FreeUnits, &rep.RackTotals.RacksOver80, &rep.RackTotals.RacksOver95, &rep.SitesTotal,
		&rep.RackTotals.RacksWithPower, &rep.RackTotals.RacksOverPowerBudget); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, rackCapacityCTE+rackPowerCTE+`
SELECT st.id, st.name, count(*), sum(rkp.total), sum(rkp.used), sum(rkp.reserved), sum(rkp.free),
       CASE WHEN sum(rkp.total) > 0 THEN round((sum(rkp.used) / sum(rkp.total) * 100)::numeric, 2)::float8 ELSE 0 END AS pct,
       count(*) FILTER (WHERE rkp.pct > $2), count(*) FILTER (WHERE rkp.pct > $3),
       count(rpw.rack_id), count(*) FILTER (WHERE rpw.alloc > rpw.avail)
  FROM rkp JOIN sites st ON st.id = rkp.site_id AND st.tenant_id = $1
  LEFT JOIN rpw ON rpw.rack_id = rkp.id
 GROUP BY st.id, st.name
 ORDER BY pct DESC, st.name, st.id
 LIMIT $4`, tenant, CapacityWarnPercent, CapacityCriticalPercent, capacitySiteLimit)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var c SiteCapacity
		if err := rows.Scan(&c.SiteID, &c.SiteName, &c.Racks, &c.TotalUnits, &c.UsedUnits, &c.ReservedUnits,
			&c.FreeUnits, &c.Utilization, &c.RacksOver80, &c.RacksOver95, &c.RacksWithPower, &c.RacksOverPowerBudget); err != nil {
			return err
		}
		rep.Sites = append(rep.Sites, c)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	top, err := tx.QueryContext(ctx, rackCapacityCTE+`
SELECT rkp.id, rkp.name, st.id, st.name, rkp.used, rkp.total, rkp.pct
  FROM rkp JOIN sites st ON st.id = rkp.site_id AND st.tenant_id = $1
 WHERE rkp.total > 0
 ORDER BY rkp.pct DESC, rkp.name, rkp.id
 LIMIT $2`, tenant, capacityListLimit)
	if err != nil {
		return err
	}
	defer func() { _ = top.Close() }()
	for top.Next() {
		var r RackCapacity
		if err := top.Scan(&r.RackID, &r.RackName, &r.SiteID, &r.SiteName, &r.UsedUnits, &r.TotalUnits, &r.Utilization); err != nil {
			return err
		}
		rep.RacksTop = append(rep.RacksTop, r)
	}
	return top.Err()
}

// cableableInterfaceTypes is every interface type that can take a cable: the
// registry's types outside the virtual and wireless groups (the same rule
// CableService enforces on write).
func cableableInterfaceTypes() []string {
	var out []string
	for _, t := range dcim.AllInterfaceTypes() {
		if g := dcim.InterfaceTypeGroup(t); g != "virtual" && g != "wireless" {
			out = append(out, string(t))
		}
	}
	return out
}

func (s *CapacityService) ports(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, rep *CapacityReport) error {
	// Per switch: the class is the registry's `switch` (assetclass.KeySwitch);
	// routers and firewalls are different classes and are not counted here.
	const perSwitch = `
WITH sw AS (
  SELECT a.id, COALESCE(NULLIF(a.display_name, ''), NULLIF(a.hostname, ''), a.id::text) AS name,
         count(i.id)::int AS total,
         count(i.id) FILTER (WHERE i.cable_id IS NOT NULL)::int AS cabled,
         count(i.id) FILTER (WHERE i.cable_id IS NULL AND i.mark_connected)::int AS marked,
         count(i.id) FILTER (WHERE i.cable_id IS NULL AND NOT i.mark_connected AND i.enabled)::int AS free
    FROM assets a
    JOIN interfaces i ON i.tenant_id = a.tenant_id AND i.asset_id = a.id AND i.type = ANY($3)
   WHERE a.tenant_id = $1 AND a.class_key = $2 AND a.deleted_at IS NULL
   GROUP BY a.id, a.display_name, a.hostname
)`
	// One pass: the window aggregates see every switch before LIMIT cuts the
	// list, so the totals are not capped and the interfaces are scanned once.
	// No rows means no switches, and the totals stay zero.
	rows, err := tx.QueryContext(ctx, perSwitch+`
SELECT id, name, total, cabled, marked, free,
       (count(*) OVER ())::int, (sum(total) OVER ())::int, (sum(cabled) OVER ())::int,
       (sum(marked) OVER ())::int, (sum(free) OVER ())::int
  FROM sw ORDER BY free, total DESC, name, id LIMIT $4`,
		tenant, string(assetclass.KeySwitch), pq.Array(cableableInterfaceTypes()), capacityListLimit)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var w SwitchPorts
		if err := rows.Scan(&w.AssetID, &w.Name, &w.Total, &w.Cabled, &w.MarkedConnected, &w.Free,
			&rep.Ports.Switches, &rep.Ports.Total, &rep.Ports.Cabled, &rep.Ports.MarkedConnected, &rep.Ports.Free); err != nil {
			return err
		}
		rep.Ports.FewestFree = append(rep.Ports.FewestFree, w)
	}
	return rows.Err()
}

func (s *CapacityService) prefixes(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, rep *CapacityReport) error {
	if err := tx.QueryRowContext(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE COALESCE(u.ip_count, 0) = 0 AND COALESCE(u.child_count, 0) = 0),
       count(*) FILTER (WHERE COALESCE(u.utilization, 0) > $2),
       count(*) FILTER (WHERE COALESCE(u.utilization, 0) > $3)
  FROM prefixes p
  LEFT JOIN prefix_utilization u ON u.tenant_id = p.tenant_id AND u.prefix_id = p.id
 WHERE p.tenant_id = $1 AND p.status = 'active'`, tenant, CapacityWarnPercent, CapacityCriticalPercent).Scan(
		&rep.Prefixes.Total, &rep.Prefixes.NoAddressesRecorded, &rep.Prefixes.Over80, &rep.Prefixes.Over95); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT p.id, p.prefix::text, v.id, v.name,
       power(2::numeric, (CASE family(p.prefix) WHEN 4 THEN 32 ELSE 128 END) - masklen(p.prefix))::numeric(40,0)::text,
       u.ip_count, u.child_count, u.utilization::float8
  FROM prefixes p
  JOIN prefix_utilization u ON u.tenant_id = p.tenant_id AND u.prefix_id = p.id
  LEFT JOIN vrfs v ON v.tenant_id = p.tenant_id AND v.id = p.vrf_id
 WHERE p.tenant_id = $1 AND p.status = 'active' AND u.utilization > 0
 ORDER BY u.utilization DESC, u.ip_count DESC, p.prefix, p.id
 LIMIT $2`, tenant, capacityListLimit)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var f PrefixFill
		var vrfID uuid.NullUUID
		var vrfName sql.NullString
		if err := rows.Scan(&f.PrefixID, &f.Prefix, &vrfID, &vrfName, &f.Size, &f.IPCount, &f.ChildCount, &f.Utilization); err != nil {
			return err
		}
		if vrfID.Valid {
			f.VRFID = &vrfID.UUID
			f.VRFName = &vrfName.String
		}
		rep.Prefixes.Fullest = append(rep.Prefixes.Fullest, f)
	}
	return rows.Err()
}

// cables counts live cables only (status 'active'); a proposal awaiting
// approval is reported on its own, a rejected or archived cable not at all.
// "Declared, never confirmed" is a connected cable a person declared that no
// LLDP / CDP observation has ever agreed with — planned cables are not on the
// wire yet, so the network cannot confirm them.
func (s *CapacityService) cables(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, now time.Time, rep *CapacityReport) error {
	c := &rep.Cables
	if err := tx.QueryRowContext(ctx, `
SELECT count(*) FILTER (WHERE status = 'active' AND operational_status = 'connected'),
       count(*) FILTER (WHERE status = 'active' AND operational_status = 'planned'),
       count(*) FILTER (WHERE status = 'active' AND operational_status = 'decommissioning'),
       count(*) FILTER (WHERE status = 'pending'),
       count(*) FILTER (WHERE status = 'active' AND operational_status = 'planned' AND created_at < $2::timestamptz - make_interval(days => $3)),
       count(*) FILTER (WHERE status = 'active' AND operational_status = 'planned' AND created_at < $2::timestamptz - make_interval(days => $4)),
       count(*) FILTER (WHERE status = 'active' AND operational_status = 'connected' AND source_kind = 'declared' AND lldp_confirmed_at IS NULL)
  FROM cables WHERE tenant_id = $1`, tenant, now, CapacityPlannedAgedDays, CapacityPlannedStaleDays).Scan(
		&c.ByStatus.Connected, &c.ByStatus.Planned, &c.ByStatus.Decommissioning, &c.ProposedPending,
		&c.PlannedOver30Days, &c.PlannedOver90Days, &c.DeclaredNeverConfirmed); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT id, label, created_at, floor(extract(epoch FROM ($2::timestamptz - created_at)) / 86400)::int
  FROM cables
 WHERE tenant_id = $1 AND status = 'active' AND operational_status = 'planned'
   AND created_at < $2::timestamptz - make_interval(days => $3)
 ORDER BY created_at, id
 LIMIT $4`, tenant, now, capacityBacklogListWindow, capacityListLimit)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p PlannedCable
		var label sql.NullString
		if err := rows.Scan(&p.CableID, &label, &p.CreatedAt, &p.AgeDays); err != nil {
			return err
		}
		if label.Valid {
			p.Label = &label.String
		}
		c.OldestPlanned = append(c.OldestPlanned, p)
	}
	return rows.Err()
}
