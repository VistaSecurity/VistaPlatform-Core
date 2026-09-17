package sensorrouting

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// Store reads the router's inputs: the tenant's sensor fleet and which sensor
// last observed each address.
type Store struct {
	db *database.DB
}

func NewStore(db *database.DB) *Store { return &Store{db: db} }

// TenantSensors returns every non-deleted sensor the tenant has, the
// platform's own included (marked System so the router never routes to them).
// Coverage comes from agent_addresses, which the sensor's heartbeat maintains;
// a sensor that has reported no prefixed address falls back to its primary
// address widened to a LAN-sized guess.
func (s *Store) TenantSensors(ctx context.Context, tenantID uuid.UUID) ([]Sensor, error) {
	var out []Sensor
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// sensors and agent_addresses are both RLS-scoped through the tenant
		// transaction; the explicit tenant_id predicate on sensors stays as the
		// primary control.
		rows, err := tx.QueryContext(ctx, `
			SELECT s.id, s.name, s.status, s.last_heartbeat, COALESCE(s.reporting_interval, 0),
			       s.air_gapped, COALESCE(s.platform, ''), COALESCE(s.tags, '{}'::text[]),
			       COALESCE(s.ip_address, ''),
			       COALESCE((
			           SELECT array_agg(host(a.address) || '/' || a.prefix_length)
			           FROM agent_addresses a
			           WHERE a.sensor_id = s.id AND a.prefix_length IS NOT NULL
			       ), '{}'::text[]),
			       -- The addresses of the HOST THIS SENSOR RUNS ON, for the
			       -- never-scan-self guard (asset-inventory decision 9): every
			       -- ip_address identifier of the asset its own self-report
			       -- resolved to, falling back to its own primary address when
			       -- no asset link exists yet (older sensor, or the link
			       -- hasn't landed on its first self-observation).
			       COALESCE((
			           SELECT array_agg(DISTINCT ai.value)
			           FROM asset_identifiers ai
			           WHERE ai.tenant_id = s.tenant_id AND ai.asset_id = s.asset_id AND ai.kind = 'ip_address'
			       ), '{}'::text[])
			FROM sensors s
			WHERE s.tenant_id = $1 AND s.deleted_at IS NULL
			ORDER BY s.name, s.id`, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				sensor    Sensor
				platform  string
				tags      pq.StringArray
				primary   string
				bound     pq.StringArray
				selfAddrs pq.StringArray
			)
			if err := rows.Scan(&sensor.ID, &sensor.Name, &sensor.Status, &sensor.LastHeartbeat, &sensor.ReportingInterval,
				&sensor.AirGapped, &platform, &tags, &primary, &bound, &selfAddrs); err != nil {
				return err
			}
			sensor.System = isSystemSensor(platform, tags)
			sensor.Prefixes = PrefixesFor(bound, primary)
			sensor.SelfAddresses = selfAddressSet(selfAddrs, primary)
			out = append(out, sensor)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read the tenant's sensors: %w", err)
	}
	return out, nil
}

// selfAddressSet builds the never-scan-self address set for one sensor:
// every ip_address identifier of the asset its self-report resolved to when
// there is one, else its own reported primary address (asset-inventory
// decision 9 — see the SelfAddresses field doc on Sensor).
func selfAddressSet(fromAsset []string, primary string) map[string]bool {
	out := make(map[string]bool, len(fromAsset)+1)
	for _, addr := range fromAsset {
		if v := strings.TrimSpace(addr); v != "" {
			out[v] = true
		}
	}
	if len(out) == 0 {
		if v := strings.TrimSpace(primary); v != "" {
			out[v] = true
		}
	}
	return out
}

// isSystemSensor mirrors cluster-sensor's rule: the platform's own sensors
// carry the `system` tag and platform='platform'.
func isSystemSensor(platform string, tags []string) bool {
	if strings.EqualFold(strings.TrimSpace(platform), "platform") {
		return true
	}
	for _, tag := range tags {
		if strings.EqualFold(strings.TrimSpace(tag), "system") {
			return true
		}
	}
	return false
}

// LastObservingSensor maps each address to the TENANT sensor that most
// recently recorded a discovery against it. Addresses only the platform's own
// sensors have seen are absent from the map — that is what makes them
// platform targets downstream. Addresses that are not IP literals (hostnames)
// are not looked up; sensor_discoveries is keyed by dest_ip.
func (s *Store) LastObservingSensor(ctx context.Context, tenantID uuid.UUID, addresses []string) (map[string]uuid.UUID, error) {
	var ips []string
	for _, raw := range addresses {
		if addr, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
			ips = append(ips, addr.Unmap().String())
		}
	}
	out := map[string]uuid.UUID{}
	if len(ips) == 0 {
		return out, nil
	}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// sensor_discoveries is the RLS view over the partitioned queue, and
		// dest_ip is indexed on every partition. DISTINCT ON + ORDER BY
		// timestamp DESC picks the newest observation per address.
		rows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT ON (host(d.dest_ip)) host(d.dest_ip), d.sensor_id
			FROM sensor_discoveries d
			JOIN sensors s ON s.id = d.sensor_id AND s.tenant_id = d.tenant_id
			WHERE d.tenant_id = $1
			  AND d.dest_ip = ANY($2::inet[])
			  AND s.deleted_at IS NULL
			  AND COALESCE(s.platform, '') <> 'platform'
			  AND NOT ('system' = ANY(COALESCE(s.tags, '{}'::text[])))
			ORDER BY host(d.dest_ip), d."timestamp" DESC NULLS LAST`, tenantID, pq.Array(ips))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var addr string
			var sensorID uuid.UUID
			if err := rows.Scan(&addr, &sensorID); err != nil {
				return err
			}
			out[addr] = sensorID
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read which sensor last observed each address: %w", err)
	}
	return out, nil
}

// Resolve is the whole routing step for a set of targets: read the fleet and
// the observations, then plan.
func (s *Store) Resolve(ctx context.Context, tenantID uuid.UUID, targets []string, now time.Time) (Plan, error) {
	sensors, err := s.TenantSensors(ctx, tenantID)
	if err != nil {
		return Plan{}, err
	}
	observed, err := s.LastObservingSensor(ctx, tenantID, targets)
	if err != nil {
		return Plan{}, err
	}
	return Route(targets, observed, sensors, now), nil
}

// Errors a manual "Run from: <sensor>" choice can meet. They map onto the HTTP
// statuses cluster-sensor gives the same conditions, so a caller sees one
// vocabulary wherever the check happens.
var (
	ErrSensorNotFound        = errors.New("sensor not found")
	ErrSensorNotDispatchable = errors.New("sensor cannot run scans")
	ErrSensorOffline         = errors.New("sensor offline")
)

// FindDispatchable resolves a sensor the user chose by id and confirms it can
// take a job now. The three refusals are distinct on purpose: "pick another"
// (offline, 409), "that one never can" (the platform's own or air-gapped,
// 400), and "not yours" (404).
func (s *Store) FindDispatchable(ctx context.Context, tenantID, sensorID uuid.UUID, now time.Time) (Sensor, error) {
	sensors, err := s.TenantSensors(ctx, tenantID)
	if err != nil {
		return Sensor{}, err
	}
	return PickDispatchable(sensors, sensorID, now)
}

// PickDispatchable is FindDispatchable's pure half.
func PickDispatchable(sensors []Sensor, sensorID uuid.UUID, now time.Time) (Sensor, error) {
	for _, sensor := range sensors {
		if sensor.ID != sensorID {
			continue
		}
		switch {
		case sensor.System:
			return Sensor{}, fmt.Errorf("%w: %s is the platform sensor; choose \"Platform sensor\" to run from the platform", ErrSensorNotDispatchable, sensor.Name)
		case sensor.AirGapped:
			return Sensor{}, fmt.Errorf("%w: %s is air-gapped and cannot receive commands", ErrSensorNotDispatchable, sensor.Name)
		case !sensor.Dispatchable(now):
			return Sensor{}, fmt.Errorf("%w: %s has not checked in recently; nothing was scanned", ErrSensorOffline, sensor.Name)
		}
		return sensor, nil
	}
	return Sensor{}, fmt.Errorf("%w: %s", ErrSensorNotFound, sensorID)
}
