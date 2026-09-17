package services

// Tenant-sensor dispatch: the rules for WHICH sensor a `sensors` job
// may be handed to, shared by job creation (refuse a job that cannot run) and
// the dispatcher (re-check at the moment the command is written).
//
// Before this existed, "sensors" was refused at every entry point because
// nothing dispatched it and such jobs used to fall through to the in-cluster
// nmap path — a scan that ran from the platform cluster, reached nothing on a
// target only the tenant's sensor can see, and finished `completed` with zero
// findings. The dispatcher now exists; what survives from that era is the
// principle: a job must never run somewhere other than where the caller asked,
// and a job that cannot run where it was asked to must FAIL, visibly.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// ErrSensorDispatchInvalid is a request-shape refusal (400): preferred sensor
// ids on a mode that does not dispatch, more or fewer than one sensor for a
// `sensors` job, a sensor id that is not a UUID, or a sensor that can never run
// a job (the platform's own `system` sensor, an air-gapped one).
var ErrSensorDispatchInvalid = errors.New("invalid sensor dispatch request")

// ErrSensorNotFound is returned when the requested sensor is not one of the
// tenant's (404). A cross-tenant id and a genuinely unknown one look the same.
var ErrSensorNotFound = errors.New("sensor not found")

// ErrSensorOffline is returned when the requested sensor exists but is not
// live (409): its last heartbeat is outside its liveness window, or its status
// is not active. The job is not created — nothing is scanned — because a job
// waiting on a sensor that will not collect it is exactly the silent failure
// this whole feature exists to replace.
var ErrSensorOffline = errors.New("sensor offline")

// dispatchSensor is what the dispatch rules need to know about a sensor row.
type dispatchSensor struct {
	ID                uuid.UUID
	Name              string
	Status            string
	LastHeartbeat     *time.Time
	ReportingInterval int
	Tags              []string
	AirGapped         bool
	Platform          string
}

// system reports whether this is the platform's own in-cluster sensor rather
// than one the tenant deployed. Platform sensors carry the `system` tag (and
// platform='platform'); they run jobs through the in-cluster path, never
// through a command.
func (s dispatchSensor) system() bool {
	if strings.EqualFold(s.Platform, "platform") {
		return true
	}
	for _, tag := range s.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), "system") {
			return true
		}
	}
	return false
}

func (s dispatchSensor) live(now time.Time) bool {
	return sensordispatch.IsLive(s.Status, s.LastHeartbeat, s.ReportingInterval, now)
}

// isSensorExecutionMode is the one spelling check for "run this from a tenant
// sensor".
func isSensorExecutionMode(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), "sensors")
}

// decideSensorDispatch is the pure rule. `lookup` resolves a sensor id within
// the caller's tenant; it returns ok=false for an unknown or cross-tenant id.
//
// Returns the sensor to dispatch to, or nil when the mode does not dispatch.
func decideSensorDispatch(mode string, preferred []string, lookup func(uuid.UUID) (dispatchSensor, bool), now time.Time) (*dispatchSensor, error) {
	if !isSensorExecutionMode(mode) {
		if len(preferred) > 0 {
			return nil, fmt.Errorf("%w: preferred_sensor_ids only applies to execution_mode \"sensors\"", ErrSensorDispatchInvalid)
		}
		return nil, nil
	}
	if len(preferred) != 1 {
		return nil, fmt.Errorf("%w: execution_mode \"sensors\" needs exactly one preferred_sensor_id, got %d", ErrSensorDispatchInvalid, len(preferred))
	}
	id, err := uuid.Parse(strings.TrimSpace(preferred[0]))
	if err != nil {
		return nil, fmt.Errorf("%w: preferred_sensor_id %q is not a UUID", ErrSensorDispatchInvalid, preferred[0])
	}
	sensor, ok := lookup(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSensorNotFound, id)
	}
	if sensor.system() {
		return nil, fmt.Errorf("%w: %s is the platform sensor; use execution_mode \"auto\" or \"cloud\" to run from the platform", ErrSensorDispatchInvalid, sensor.Name)
	}
	if sensor.AirGapped {
		return nil, fmt.Errorf("%w: %s is air-gapped and cannot receive commands", ErrSensorDispatchInvalid, sensor.Name)
	}
	if !sensor.live(now) {
		return nil, fmt.Errorf("%w: %s", ErrSensorOffline, sensordispatch.SensorOfflineMessage(sensor.Name, sensor.LastHeartbeat))
	}
	return &sensor, nil
}

// lookupTenantSensor reads one of the tenant's sensors inside a tenant-scoped
// transaction. `sensors` is RLS-scoped AND the explicit tenant_id predicate is
// kept as the primary control (the repo's belt-and-braces rule): a
// cross-tenant id returns no row either way, and a test harness connected as
// the table owner — where RLS does not apply — still cannot make it return one.
func lookupTenantSensor(tx *sqlx.Tx, tenantID, id uuid.UUID) (dispatchSensor, bool) {
	var (
		s        dispatchSensor
		interval *int
		tags     pq.StringArray
	)
	err := tx.QueryRow(`
		SELECT id, name, status, last_heartbeat, reporting_interval, COALESCE(tags, '{}'), air_gapped, platform
		FROM sensors
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`, id, tenantID,
	).Scan(&s.ID, &s.Name, &s.Status, &s.LastHeartbeat, &interval, &tags, &s.AirGapped, &s.Platform)
	if err != nil {
		return dispatchSensor{}, false
	}
	if interval != nil {
		s.ReportingInterval = *interval
	}
	s.Tags = []string(tags)
	return s, true
}

// resolveDispatchSensor applies decideSensorDispatch against the database for
// one tenant. It is the check job creation runs (so a job that cannot run is
// refused with a reason) AND the check the dispatcher repeats at dispatch
// time (a sensor can go offline between the two).
func (s *DiscoveryService) resolveDispatchSensor(ctx context.Context, tenantID, mode string, preferred []string, now time.Time) (*dispatchSensor, error) {
	if !isSensorExecutionMode(mode) && len(preferred) == 0 {
		return nil, nil
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}
	var chosen *dispatchSensor
	err = s.withTenantTxx(ctx, tenantUUID, func(tx *sqlx.Tx) error {
		var derr error
		chosen, derr = decideSensorDispatch(mode, preferred, func(id uuid.UUID) (dispatchSensor, bool) {
			return lookupTenantSensor(tx, tenantUUID, id)
		}, now)
		return derr
	})
	if err != nil {
		return nil, err
	}
	return chosen, nil
}

// executorFor labels who runs (or ran) a job, for readers that should not have
// to infer it from which columns are set.
func executorFor(executionMode string, assignedSensorID *string) string {
	if assignedSensorID != nil && *assignedSensorID != "" {
		return "sensor"
	}
	if isSensorExecutionMode(executionMode) {
		// Asked for a sensor, not yet assigned (queued) — or failed before
		// assignment. Still a sensor job: it never ran on the platform.
		return "sensor"
	}
	return "platform"
}
