package services

// Power panels and power feeds (DCIM BUILD_PLAN row 6.1; ADR-0010 D9;
// DATA_MODEL §3a). CRUD runs on the IPAM object engine (ipam_engine.go) over
// powerSpecs(): one tenant-scoped transaction per call, RLS in force, every
// write recorded in object_changes. Column names are binding: they are the API
// property names, the OpenAPI schema properties (power_contract_test.go) and
// the query-language fields.
//
// What each spec's hooks add over the schema:
//
//   - power panels: the site is the tenant's and the location, if any, is in
//     it; a panel cannot move to another site while one of its feeds serves a
//     rack of the old one; a delete takes its feeds (FK CASCADE) and sweeps
//     their cable ends.
//   - power feeds: the panel and the rack are the tenant's and in one site
//     (NetBox PowerFeed.clean); a DC supply cannot be three-phase (the same);
//     mark_connected cannot be set while a cable is attached; a feed is a cable
//     end, so a delete sweeps its termination and a rack change moves the
//     termination's denormalised rack, location and site with it.
//
// AssetPower answers the per-asset power summary the Ports tab shows.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// The power object routes under /dcim.
const (
	PowerRoutePanels = "power-panels"
	PowerRouteFeeds  = "power-feeds"
)

// PowerObjectRoutes are the power object routes, in order.
func PowerObjectRoutes() []string { return []string{PowerRoutePanels, PowerRouteFeeds} }

// NetBox 4.3 PowerFeed*Choices (not in standards/netbox-choices.v4.3.5.json,
// whose snapshot carries only the port and outlet types). The schema CHECKs
// hold the same lists.
var (
	PowerFeedStatuses = []string{"offline", "active", "planned", "failed"}
	PowerFeedTypes    = []string{"primary", "redundant"}
	PowerFeedSupplies = []string{"ac", "dc"}
	PowerFeedPhases   = []string{"single-phase", "three-phase"}
)

// PowerService is the power object store.
type PowerService struct {
	db  *sql.DB
	eng *IPAMService
}

// NewPowerService returns the store over db (the raw pool; RLS per tx).
func NewPowerService(db *sql.DB) *PowerService {
	return &PowerService{db: db, eng: newObjectEngine(db, powerSpecs())}
}

func isPowerObject(route string) bool {
	return route == PowerRoutePanels || route == PowerRouteFeeds
}

func unknownPowerObject(route string) error {
	return fmt.Errorf("%w: unknown power object %q", ErrIPAMNotFound, route)
}

// List returns one page of a power object route.
func (s *PowerService) List(ctx context.Context, tenant uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	if !isPowerObject(route) {
		return nil, 0, unknownPowerObject(route)
	}
	return s.eng.List(ctx, tenant, route, p)
}

// Get returns one power object.
func (s *PowerService) Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error) {
	if !isPowerObject(route) {
		return nil, unknownPowerObject(route)
	}
	return s.eng.Get(ctx, tenant, route, id)
}

// Create creates a power object.
func (s *PowerService) Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	if !isPowerObject(route) {
		return nil, unknownPowerObject(route)
	}
	return s.eng.Create(ctx, tenant, route, body)
}

// Update patches a power object.
func (s *PowerService) Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	if !isPowerObject(route) {
		return nil, unknownPowerObject(route)
	}
	return s.eng.Update(ctx, tenant, route, id, body)
}

// Delete removes a power object.
func (s *PowerService) Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error {
	if !isPowerObject(route) {
		return unknownPowerObject(route)
	}
	return s.eng.Delete(ctx, tenant, route, id)
}

// PowerObjects lists every power object the engine serves (contract tests).
func PowerObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range powerSpecs() {
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

// powerFeedSelect is a feed in its list shape: the row plus its panel, rack
// and what its cable path reaches (the PDU inlet it powers).
const powerFeedSelect = `to_jsonb(t) || jsonb_build_object(
	'power_panel', jsonb_build_object('id', pp.id, 'name', pp.name, 'site_id', pp.site_id),
	'rack', CASE WHEN rk.id IS NULL THEN NULL ELSE jsonb_build_object('id', rk.id, 'name', rk.name) END,
	'connected_endpoint', (SELECT jsonb_build_object('kind', cp.destination_kind, 'id', cp.destination_id,
	        'name', dp.name, 'asset_id', dp.asset_id, 'asset_name', COALESCE(da.display_name, da.hostname, host(da.primary_address)))
	    FROM public.cable_paths cp
	    JOIN public.power_ports dp ON cp.destination_kind = 'power_port' AND dp.id = cp.destination_id
	    JOIN public.assets da ON da.id = dp.asset_id
	   WHERE cp.tenant_id = t.tenant_id AND cp.origin_kind = 'power_feed' AND cp.origin_id = t.id AND cp.is_complete))`

const powerFeedJoin = `JOIN public.power_panels pp ON pp.id = t.power_panel_id LEFT JOIN public.racks rk ON rk.id = t.rack_id`

func powerFeedSiteFilter(col string) func(string, int) (string, any, error) {
	return func(v string, n int) (string, any, error) {
		id, err := uuid.Parse(v)
		if err != nil {
			return "", nil, ipamInvalid("%s must be a UUID", col)
		}
		return fmt.Sprintf(`pp.%s = $%d::uuid`, col, n), id, nil
	}
}

func powerSpecs() []*ipamSpec {
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindPowerPanel, Table: "power_panels", Route: PowerRoutePanels,
			Cols: withSubstrate(
				ipamCol{Name: "site_id", Type: colUUID, Required: true},
				ipamCol{Name: "location_id", Type: colUUID},
				ipamCol{Name: "name", Type: colText, Required: true},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "site_id", Column: "site_id", Type: colUUID},
				{Param: "location_id", Column: "location_id", Type: colUUID},
				{Param: "name", Column: "name", Type: colText},
			},
			Search: []string{"name", "description"},
			Order:  "lower(st.name), lower(t.name), t.id",
			ListSelect: `to_jsonb(t) || jsonb_build_object(
				'site', jsonb_build_object('id', st.id, 'name', st.name),
				'location', CASE WHEN lc.id IS NULL THEN NULL ELSE jsonb_build_object('id', lc.id, 'name', lc.name) END,
				'feed_count', (SELECT count(*) FROM public.power_feeds f WHERE f.tenant_id = t.tenant_id AND f.power_panel_id = t.id))`,
			Join:       `JOIN public.sites st ON st.id = t.site_id LEFT JOIN public.locations lc ON lc.id = t.location_id`,
			Prepare:    preparePowerPanel,
			AfterWrite: afterPowerPanelWrite,
		},
		{
			Kind: dcim.ObjectKindPowerFeed, Table: "power_feeds", Route: PowerRouteFeeds,
			Cols: withSubstrate(
				ipamCol{Name: "power_panel_id", Type: colUUID, Required: true},
				ipamCol{Name: "rack_id", Type: colUUID},
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "operational_status", Type: colText},
				ipamCol{Name: "type", Type: colText},
				ipamCol{Name: "supply", Type: colText},
				ipamCol{Name: "phase", Type: colText},
				ipamCol{Name: "voltage", Type: colInt},
				ipamCol{Name: "amperage", Type: colInt},
				ipamCol{Name: "max_utilization", Type: colInt},
				ipamCol{Name: "mark_connected", Type: colBool},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "power_panel_id", Column: "power_panel_id", Type: colUUID},
				{Param: "rack_id", Column: "rack_id", Type: colUUID},
				{Param: "operational_status", Column: "operational_status", Type: colText},
				{Param: "type", Column: "type", Type: colText},
				{Param: "supply", Column: "supply", Type: colText},
				{Param: "phase", Column: "phase", Type: colText},
				{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
				{Param: "site_id", Custom: powerFeedSiteFilter("site_id")},
				{Param: "location_id", Custom: powerFeedSiteFilter("location_id")},
			},
			Search:     []string{"name", "description"},
			Order:      "lower(pp.name), lower(t.name), t.id",
			ListSelect: powerFeedSelect,
			Join:       powerFeedJoin,
			Prepare:    preparePowerFeed,
			AfterWrite: afterPowerFeedWrite,
		},
	}
}

// locationInSite refuses a location that is not in the site.
func locationInSite(ctx context.Context, tx *sql.Tx, row map[string]any, what string) error {
	site := rowUUID(row, "site_id")
	loc := rowUUID(row, "location_id")
	if !loc.Valid {
		return nil
	}
	var locSite uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT site_id FROM locations WHERE id = $1`, loc.UUID).Scan(&locSite)
	if errors.Is(err, sql.ErrNoRows) {
		return ipamInvalid("no such location %s", loc.UUID)
	}
	if err != nil {
		return err
	}
	if !site.Valid || locSite != site.UUID {
		return ipamInvalid("the location is not in the %s's site", what)
	}
	return nil
}

func preparePowerPanel(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	if err := visible(ctx, tx, "sites", row["site_id"]); err != nil {
		return err
	}
	if err := locationInSite(ctx, tx, row, "power panel"); err != nil {
		return err
	}
	if id == uuid.Nil {
		return nil
	}
	// A feed's rack is in its panel's site: a panel cannot leave that site
	// under a feed that serves one of its racks.
	var stranded int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM power_feeds f JOIN racks r ON r.id = f.rack_id
		 WHERE f.tenant_id = $1 AND f.power_panel_id = $2 AND r.site_id <> $3::uuid`,
		tenant, id, fmt.Sprint(row["site_id"])).Scan(&stranded); err != nil {
		return err
	}
	if stranded > 0 {
		return ipamInvalid("%d of this panel's feeds serve racks in its current site; clear their racks before moving the panel", stranded)
	}
	return nil
}

func preparePowerFeed(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	for col, allowed := range map[string][]string{
		"operational_status": PowerFeedStatuses, "type": PowerFeedTypes, "supply": PowerFeedSupplies, "phase": PowerFeedPhases,
	} {
		if err := oneOf(row, col, allowed); err != nil {
			return err
		}
	}
	if row["supply"] == "dc" && row["phase"] == "three-phase" {
		return ipamInvalid("a DC supply cannot be three-phase")
	}
	if err := refuseMarkConnectedWithCable(row); err != nil {
		return err
	}
	if err := visible(ctx, tx, "power_panels", row["power_panel_id"]); err != nil {
		return err
	}
	rack := rowUUID(row, "rack_id")
	if !rack.Valid {
		return nil
	}
	if err := visible(ctx, tx, "racks", row["rack_id"]); err != nil {
		return err
	}
	var same bool
	if err := tx.QueryRowContext(ctx, `
		SELECT r.site_id = p.site_id FROM racks r, power_panels p WHERE r.id = $1 AND p.id = $2::uuid`,
		rack.UUID, fmt.Sprint(row["power_panel_id"])).Scan(&same); err != nil {
		return err
	}
	if !same {
		return ipamInvalid("the rack and the power panel are in different sites")
	}
	return nil
}

// afterPowerPanelWrite: a delete cascades the panel's feeds, whose cable ends
// are swept; a move (site or location) re-stamps the denormalised site and
// location on its feeds' cable terminations.
func afterPowerPanelWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	if post == nil {
		return sweepOrphanTerminations(ctx, tx, tenant, dcim.ObjectKindPowerFeed)
	}
	if pre == nil || (fmt.Sprint(pre["site_id"]) == fmt.Sprint(post["site_id"]) && fmt.Sprint(pre["location_id"]) == fmt.Sprint(post["location_id"])) {
		return nil
	}
	return restampFeedTerminations(ctx, tx, tenant, `f.power_panel_id = $2`, rowID(post))
}

// afterPowerFeedWrite: a delete sweeps the feed's cable end; a rack change
// re-stamps its termination's rack, location and site.
func afterPowerFeedWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	if post == nil {
		return sweepOrphanTerminations(ctx, tx, tenant, dcim.ObjectKindPowerFeed)
	}
	if pre == nil || fmt.Sprint(pre["rack_id"]) == fmt.Sprint(post["rack_id"]) {
		return nil
	}
	return restampFeedTerminations(ctx, tx, tenant, `f.id = $2`, rowID(post))
}

// feedPlacementSQL is a feed's denormalised placement as a cable termination
// carries it: the rack it serves, the rack's location (else the panel's) and
// the panel's site.
const feedPlacementSQL = `SELECT f.id, p.site_id, COALESCE(r.location_id, p.location_id), f.rack_id
	  FROM power_feeds f JOIN power_panels p ON p.id = f.power_panel_id LEFT JOIN racks r ON r.id = f.rack_id
	 WHERE f.tenant_id = $1 AND `

func restampFeedTerminations(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, where string, arg any) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE cable_terminations ct SET site_id = x.site_id, location_id = x.location_id, rack_id = x.rack_id, updated_at = now()
		  FROM (`+feedPlacementSQL+where+`) AS x(id, site_id, location_id, rack_id)
		 WHERE ct.tenant_id = $1 AND ct.termination_kind = 'power_feed' AND ct.termination_id = x.id`, tenant, arg)
	return err
}

// ---------------------------------------------------------------- summary ----

// PowerEndpoint is the far end of a power port's or outlet's cable path.
type PowerEndpoint struct {
	Kind      dcim.ObjectKind `json:"kind"`
	ID        uuid.UUID       `json:"id"`
	Name      string          `json:"name"`
	AssetID   *uuid.UUID      `json:"asset_id"`
	AssetName *string         `json:"asset_name"`
	// PowerPanelID / PowerPanelName name a power feed's panel.
	PowerPanelID   *uuid.UUID `json:"power_panel_id"`
	PowerPanelName *string    `json:"power_panel_name"`
}

// PowerSummaryPort is one power port of the asset.
type PowerSummaryPort struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	Type          *string    `json:"type"`
	MaximumDraw   *int       `json:"maximum_draw"`
	AllocatedDraw *int       `json:"allocated_draw"`
	CableID       *uuid.UUID `json:"cable_id"`
	MarkConnected bool       `json:"mark_connected"`
	// Endpoint is where the port's cable path ends (an outlet, a feed); nil
	// for an uncabled port or an incomplete path.
	Endpoint *PowerEndpoint `json:"endpoint"`
	// PathComplete is whether the cached path reached an endpoint (false for
	// an uncabled port too).
	PathComplete bool `json:"path_complete"`
	// Downstream is what the asset's own outlets fed by this port draw (a
	// PDU's inlet; NetBox PowerPort.get_power_draw): the connected power
	// ports' declared draws, summed, and how many outlets are on it.
	Downstream PowerDraw `json:"downstream"`
}

// PowerDraw sums declared draws. Recorded counts the ports that declared one:
// a port with no declared draw adds nothing and is not counted as zero.
type PowerDraw struct {
	Outlets       int `json:"outlet_count"`
	Connected     int `json:"connected_count"`
	Recorded      int `json:"recorded_count"`
	MaximumDraw   int `json:"maximum_draw"`
	AllocatedDraw int `json:"allocated_draw"`
}

// PowerSummaryOutlet is one power outlet of the asset.
type PowerSummaryOutlet struct {
	ID            uuid.UUID      `json:"id"`
	Name          string         `json:"name"`
	Type          *string        `json:"type"`
	FeedLeg       *string        `json:"feed_leg"`
	PowerPortID   *uuid.UUID     `json:"power_port_id"`
	PowerPortName *string        `json:"power_port_name"`
	CableID       *uuid.UUID     `json:"cable_id"`
	MarkConnected bool           `json:"mark_connected"`
	Endpoint      *PowerEndpoint `json:"endpoint"`
}

// PowerSummaryFeed is a power feed the asset's power ports reach.
type PowerSummaryFeed struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	PowerPanelID      uuid.UUID `json:"power_panel_id"`
	PowerPanelName    string    `json:"power_panel_name"`
	OperationalStatus string    `json:"operational_status"`
	Supply            string    `json:"supply"`
	Phase             string    `json:"phase"`
	Voltage           int       `json:"voltage"`
	Amperage          int       `json:"amperage"`
	AvailablePower    int       `json:"available_power"`
}

// AssetPowerSummary answers GET /dcim/assets/{id}/power.
type AssetPowerSummary struct {
	AssetID      uuid.UUID            `json:"asset_id"`
	PowerPorts   []PowerSummaryPort   `json:"power_ports"`
	PowerOutlets []PowerSummaryOutlet `json:"power_outlets"`
	Feeds        []PowerSummaryFeed   `json:"feeds"`
	// Totals sum the asset's own power ports' declared draws.
	Totals PowerDraw `json:"totals"`
}

// endpointSQL names a cable path's destination (alias cp) as a PowerEndpoint
// JSON object, or NULL.
const endpointSQL = `CASE WHEN cp.is_complete AND cp.destination_id IS NOT NULL THEN jsonb_build_object(
	'kind', cp.destination_kind, 'id', cp.destination_id,
	'name', COALESCE(ep.name, eo.name, ef.name),
	'asset_id', COALESCE(ep.asset_id, eo.asset_id),
	'asset_name', COALESCE(ea.display_name, ea.hostname, host(ea.primary_address)),
	'power_panel_id', ef.power_panel_id, 'power_panel_name', efp.name) END`

const endpointJoins = `
	LEFT JOIN public.power_ports ep ON cp.destination_kind = 'power_port' AND ep.id = cp.destination_id
	LEFT JOIN public.power_outlets eo ON cp.destination_kind = 'power_outlet' AND eo.id = cp.destination_id
	LEFT JOIN public.power_feeds ef ON cp.destination_kind = 'power_feed' AND ef.id = cp.destination_id
	LEFT JOIN public.power_panels efp ON efp.id = ef.power_panel_id
	LEFT JOIN public.assets ea ON ea.id = COALESCE(ep.asset_id, eo.asset_id)`

// AssetPower returns the asset's power ports (with their draws and where
// their paths end), its outlets, and the feeds its ports reach.
func (s *PowerService) AssetPower(ctx context.Context, tenant, asset uuid.UUID) (*AssetPowerSummary, error) {
	out := &AssetPowerSummary{AssetID: asset, PowerPorts: []PowerSummaryPort{}, PowerOutlets: []PowerSummaryOutlet{}, Feeds: []PowerSummaryFeed{}}
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.assets WHERE id = $1 AND deleted_at IS NULL)`, asset).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrIPAMNotFound
		}
		ports, err := tx.QueryContext(ctx, `
			SELECT p.id, p.name, p.type, p.maximum_draw, p.allocated_draw, p.cable_id, p.mark_connected,
			       COALESCE(cp.is_complete, false), `+endpointSQL+`,
			       (SELECT jsonb_build_object(
			           'outlet_count', count(*),
			           'connected_count', count(dp.id),
			           'recorded_count', count(dp.id) FILTER (WHERE dp.maximum_draw IS NOT NULL OR dp.allocated_draw IS NOT NULL),
			           'maximum_draw', COALESCE(sum(dp.maximum_draw), 0),
			           'allocated_draw', COALESCE(sum(dp.allocated_draw), 0))
			          FROM public.power_outlets o
			          LEFT JOIN public.cable_paths op ON op.tenant_id = o.tenant_id AND op.origin_kind = 'power_outlet' AND op.origin_id = o.id
			               AND op.is_complete AND op.destination_kind = 'power_port'
			          LEFT JOIN public.power_ports dp ON dp.id = op.destination_id
			         WHERE o.tenant_id = p.tenant_id AND o.power_port_id = p.id AND o.status <> 'rejected')
			  FROM public.power_ports p
			  LEFT JOIN public.cable_paths cp ON cp.tenant_id = p.tenant_id AND cp.origin_kind = 'power_port' AND cp.origin_id = p.id`+endpointJoins+`
			 WHERE p.tenant_id = $1 AND p.asset_id = $2 AND p.status <> 'rejected'
			 ORDER BY p.name, p.id`, tenant, asset)
		if err != nil {
			return err
		}
		feedIDs := map[uuid.UUID]bool{}
		for ports.Next() {
			var p PowerSummaryPort
			var typ sql.NullString
			var maxDraw, alloc sql.NullInt64
			var cable uuid.NullUUID
			var endpoint, down []byte
			if err := ports.Scan(&p.ID, &p.Name, &typ, &maxDraw, &alloc, &cable, &p.MarkConnected, &p.PathComplete, &endpoint, &down); err != nil {
				_ = ports.Close()
				return err
			}
			p.Type = nullStrPtr(typ)
			p.MaximumDraw, p.AllocatedDraw = nullIntPtr(maxDraw), nullIntPtr(alloc)
			if cable.Valid {
				c := cable.UUID
				p.CableID = &c
			}
			if len(endpoint) > 0 {
				var e PowerEndpoint
				if err := json.Unmarshal(endpoint, &e); err != nil {
					_ = ports.Close()
					return err
				}
				p.Endpoint = &e
				if e.Kind == dcim.ObjectKindPowerFeed {
					feedIDs[e.ID] = true
				}
			}
			if err := json.Unmarshal(down, &p.Downstream); err != nil {
				_ = ports.Close()
				return err
			}
			if p.MaximumDraw != nil || p.AllocatedDraw != nil {
				out.Totals.Recorded++
			}
			if p.MaximumDraw != nil {
				out.Totals.MaximumDraw += *p.MaximumDraw
			}
			if p.AllocatedDraw != nil {
				out.Totals.AllocatedDraw += *p.AllocatedDraw
			}
			if p.CableID != nil {
				out.Totals.Connected++
			}
			out.PowerPorts = append(out.PowerPorts, p)
		}
		if err := ports.Close(); err != nil {
			return err
		}

		outlets, err := tx.QueryContext(ctx, `
			SELECT o.id, o.name, o.type, o.feed_leg, o.power_port_id, pp.name, o.cable_id, o.mark_connected, `+endpointSQL+`
			  FROM public.power_outlets o
			  LEFT JOIN public.power_ports pp ON pp.id = o.power_port_id
			  LEFT JOIN public.cable_paths cp ON cp.tenant_id = o.tenant_id AND cp.origin_kind = 'power_outlet' AND cp.origin_id = o.id`+endpointJoins+`
			 WHERE o.tenant_id = $1 AND o.asset_id = $2 AND o.status <> 'rejected'
			 ORDER BY o.name, o.id`, tenant, asset)
		if err != nil {
			return err
		}
		for outlets.Next() {
			var o PowerSummaryOutlet
			var typ, leg, portName sql.NullString
			var port, cable uuid.NullUUID
			var endpoint []byte
			if err := outlets.Scan(&o.ID, &o.Name, &typ, &leg, &port, &portName, &cable, &o.MarkConnected, &endpoint); err != nil {
				_ = outlets.Close()
				return err
			}
			o.Type, o.FeedLeg, o.PowerPortName = nullStrPtr(typ), nullStrPtr(leg), nullStrPtr(portName)
			if port.Valid {
				v := port.UUID
				o.PowerPortID = &v
			}
			if cable.Valid {
				v := cable.UUID
				o.CableID = &v
			}
			if len(endpoint) > 0 {
				var e PowerEndpoint
				if err := json.Unmarshal(endpoint, &e); err != nil {
					_ = outlets.Close()
					return err
				}
				o.Endpoint = &e
			}
			out.PowerOutlets = append(out.PowerOutlets, o)
		}
		if err := outlets.Close(); err != nil {
			return err
		}
		out.Totals.Outlets = len(out.PowerOutlets)

		if len(feedIDs) == 0 {
			return nil
		}
		ids := make([]string, 0, len(feedIDs))
		for id := range feedIDs {
			ids = append(ids, id.String())
		}
		feeds, err := tx.QueryContext(ctx, `
			SELECT f.id, f.name, f.power_panel_id, p.name, f.operational_status, f.supply, f.phase, f.voltage, f.amperage, f.available_power
			  FROM public.power_feeds f JOIN public.power_panels p ON p.id = f.power_panel_id
			 WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[])
			 ORDER BY p.name, f.name, f.id`, tenant, uuidArrayLiteral(ids))
		if err != nil {
			return err
		}
		defer func() { _ = feeds.Close() }()
		for feeds.Next() {
			var f PowerSummaryFeed
			if err := feeds.Scan(&f.ID, &f.Name, &f.PowerPanelID, &f.PowerPanelName, &f.OperationalStatus, &f.Supply, &f.Phase,
				&f.Voltage, &f.Amperage, &f.AvailablePower); err != nil {
				return err
			}
			out.Feeds = append(out.Feeds, f)
		}
		return feeds.Err()
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}

func uuidArrayLiteral(ids []string) string {
	out := "{"
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += id
	}
	return out + "}"
}
