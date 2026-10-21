package services

// Power sockets from discovery (DCIM BUILD_PLAN row 6.2; ADR-0010 D9). A PDU
// collector's inlets and outlets (shared/identity/observed_power.go) reach
// here as the power half of a sighting, written on the identity engine's
// transaction once the sighting resolved to an asset — the hardware's pattern
// (inventory_item_service.go).
//
// The rules:
//
//   - A socket's identity is (asset, name). An observed socket is matched to
//     the asset's power port / outlet of that name; failing that, by its
//     number to the one socket whose name ends in that number ("Power Outlet
//     3" is the PDU's outlet 3 — what a device type from the devicetype
//     library names it). Two candidates is no match.
//   - A matched socket keeps everything a person or the NetBox sync declared.
//     Only its measured_* columns are written (the reading and measured_at),
//     with last_seen_at and the observation count; allocated_draw and
//     maximum_draw are never touched (standards/sync-authority.yaml: power_port
//     fields are NetBox's). An outlet's power port and feed leg are filled
//     only where nothing is recorded.
//   - An unmatched socket is created measured (source_kind = measured) with
//     the status its asset implies: pending while the asset waits for approval
//     (it is approved with the asset), active on an approved asset — as
//     interfaces are. A pending socket seen again after its asset was approved
//     becomes active.
//   - A reading is not a change worth recording: a measured_* update writes
//     no object_changes row (a PDU polled every few minutes would bury the
//     Changes lens). Creating a socket, or filling an outlet's power port or
//     feed leg, is recorded (source intake:power).
//   - A socket the observation does not list is left alone.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// powerChangeSource is the object_changes source of an observed power write.
var powerChangeSource = changes.IntakeSource("power")

// ObservedPowerResult is what one recording did, for logs and tests.
type ObservedPowerResult struct {
	PortsCreated, PortsUpdated     int
	OutletsCreated, OutletsUpdated int
	Skipped                        []string
}

// powerSocket is one existing power port or outlet of the asset.
type powerSocket struct {
	id          uuid.UUID
	name        string
	status      string
	powerPortID uuid.NullUUID
	feedLeg     sql.NullString
}

// trailingNumber is the number a socket's name ends in ("Power Outlet 12" → 12).
var trailingNumber = regexp.MustCompile(`(\d+)\s*$`)

func socketNumber(name string) int {
	m := trailingNumber.FindStringSubmatch(name)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}

// matchSocket finds the existing socket for an observed one: by name, else by
// number when exactly one socket's name ends in it. taken holds sockets this
// recording already matched, which cannot be matched twice.
func matchSocket(existing []powerSocket, name string, number int, taken map[uuid.UUID]bool) (powerSocket, bool) {
	for _, s := range existing {
		if s.name == name && !taken[s.id] {
			return s, true
		}
	}
	if number < 1 {
		return powerSocket{}, false
	}
	var hit []powerSocket
	for _, s := range existing {
		if !taken[s.id] && socketNumber(s.name) == number {
			hit = append(hit, s)
		}
	}
	if len(hit) == 1 {
		return hit[0], true
	}
	return powerSocket{}, false
}

// UpsertObservedPower records a sighting's power sockets for asset on the
// engine's transaction.
func UpsertObservedPower(ctx context.Context, tx *sqlx.Tx, tenant, asset uuid.UUID, ports []identity.ObservedPowerPort,
	outlets []identity.ObservedPowerOutlet, src identity.Source, at time.Time) (ObservedPowerResult, error) {
	return upsertObservedPowerTx(ctx, tx.Tx, tenant, asset, ports, outlets, src, at)
}

func upsertObservedPowerTx(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, ports []identity.ObservedPowerPort,
	outlets []identity.ObservedPowerOutlet, src identity.Source, at time.Time) (ObservedPowerResult, error) {
	var res ObservedPowerResult
	ports, outlets, dropped := identity.NormalizeObservedPower(ports, outlets)
	res.Skipped = append(res.Skipped, dropped...)
	if len(ports) == 0 && len(outlets) == 0 {
		return res, nil
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	at = at.UTC()
	ref := strings.TrimSpace(src.Ref)
	if ref == "" {
		ref = "intake:power"
	}
	ctx = changes.WithSource(ctx, powerChangeSource)
	eng := newObjectEngine(nil, componentSpecs())
	portSpec, _ := eng.spec(ComponentPowerPort)
	outletSpec, _ := eng.spec(ComponentPowerOutlet)

	var assetStatus sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, asset).Scan(&assetStatus); err != nil {
		return res, err
	}
	derived := "pending"
	if assetStatus.String == "monitoring" {
		derived = "active"
	}
	load := func(table string) ([]powerSocket, error) {
		q := `SELECT id, name, status, NULL::uuid, NULL::text FROM public.power_ports WHERE tenant_id = $1 AND asset_id = $2 AND status <> 'rejected' ORDER BY name, id`
		if table == "power_outlets" {
			q = `SELECT id, name, status, power_port_id, feed_leg FROM public.power_outlets WHERE tenant_id = $1 AND asset_id = $2 AND status <> 'rejected' ORDER BY name, id`
		}
		rows, err := tx.QueryContext(ctx, q, tenant, asset)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		var out []powerSocket
		for rows.Next() {
			var s powerSocket
			if err := rows.Scan(&s.id, &s.name, &s.status, &s.powerPortID, &s.feedLeg); err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, rows.Err()
	}
	// observedStatus is what a socket's status becomes on this sighting.
	observedStatus := func(cur string) string {
		if cur == "stale" || (cur == "pending" && derived == "active") {
			return derived
		}
		return cur
	}

	existingPorts, err := load("power_ports")
	if err != nil {
		return res, err
	}
	portIDs := map[string]uuid.UUID{} // observed port name → row
	taken := map[uuid.UUID]bool{}
	for _, p := range ports {
		cur, found := matchSocket(existingPorts, p.Name, p.Number, taken)
		id, status, created := cur.id, observedStatus(cur.status), false
		if !found {
			row, err := eng.createTx(ctx, tx, portSpec, tenant, map[string]any{
				"asset_id": asset.String(), "name": p.Name, "source_kind": "measured", "source_ref": ref, "status": derived,
			}, powerChangeSource)
			if err != nil {
				return res, fmt.Errorf("power port %q: %w", p.Name, err)
			}
			id, status, created = uuid.MustParse(fmt.Sprint(row["id"])), derived, true
			res.PortsCreated++
		} else {
			res.PortsUpdated++
		}
		taken[id] = true
		portIDs[p.Name] = id
		var legs any
		if len(p.Legs) > 0 {
			b, err := json.Marshal(p.Legs)
			if err != nil {
				return res, err
			}
			legs = string(b)
		}
		if err := writePowerReading(ctx, tx, "power_ports", tenant, id, status, created, at,
			`measured_legs = $5::jsonb`, powerReadingInt(p.MeasuredDraw), powerReadingFloat(p.MeasuredCurrent), legs); err != nil {
			return res, fmt.Errorf("power port %q: %w", p.Name, err)
		}
	}

	existingOutlets, err := load("power_outlets")
	if err != nil {
		return res, err
	}
	for _, o := range outlets {
		var portID any
		if id, ok := portIDs[o.PowerPort]; ok && o.PowerPort != "" {
			portID = id.String()
		}
		cur, found := matchSocket(existingOutlets, o.Name, o.Number, taken)
		id, status := cur.id, observedStatus(cur.status)
		if !found {
			row := map[string]any{"asset_id": asset.String(), "name": o.Name, "source_kind": "measured", "source_ref": ref, "status": derived}
			if portID != nil {
				row["power_port_id"] = portID
			}
			if o.FeedLeg != "" {
				row["feed_leg"] = o.FeedLeg
			}
			made, err := eng.createTx(ctx, tx, outletSpec, tenant, row, powerChangeSource)
			if err != nil {
				return res, fmt.Errorf("power outlet %q: %w", o.Name, err)
			}
			id, status = uuid.MustParse(fmt.Sprint(made["id"])), derived
			res.OutletsCreated++
		} else {
			// The device's wiring fills only what nobody recorded.
			patch := map[string]any{}
			if portID != nil && !cur.powerPortID.Valid {
				patch["power_port_id"] = portID
			}
			if o.FeedLeg != "" && !cur.feedLeg.Valid {
				patch["feed_leg"] = o.FeedLeg
			}
			if len(patch) > 0 {
				if _, err := eng.updateTx(ctx, tx, outletSpec, tenant, id, patch, powerChangeSource); err != nil {
					return res, fmt.Errorf("power outlet %q: %w", o.Name, err)
				}
			}
			res.OutletsUpdated++
		}
		taken[id] = true
		var state any
		if o.State != "" {
			state = o.State
		}
		if err := writePowerReading(ctx, tx, "power_outlets", tenant, id, status, !found, at,
			`measured_state = $5`, powerReadingInt(o.MeasuredDraw), powerReadingFloat(o.MeasuredCurrent), state); err != nil {
			return res, fmt.Errorf("power outlet %q: %w", o.Name, err)
		}
	}
	return res, nil
}

// writePowerReading stores a socket's reading and counts the observation. The
// column list IS the guard: nothing declared is in it.
func writePowerReading(ctx context.Context, tx *sql.Tx, table string, tenant, id uuid.UUID, status string, created bool, at time.Time,
	extraSet string, draw, current, extra any) error {
	seen := `last_seen_at = GREATEST(last_seen_at, $6), observation_count = observation_count + 1`
	if created {
		seen = `first_seen_at = $6, last_seen_at = $6, observation_count = 1`
	}
	q := `UPDATE public.` + table + ` SET measured_draw = $3, measured_current = $4, ` + extraSet + `, measured_at = $6, status = $7, ` + seen + `
	       WHERE tenant_id = $1 AND id = $2`
	_, err := tx.ExecContext(ctx, q, tenant, id, draw, current, extra, at, status)
	return err
}

func powerReadingInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func powerReadingFloat(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}
