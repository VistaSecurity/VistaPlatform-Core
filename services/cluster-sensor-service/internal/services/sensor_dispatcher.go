package services

// The dispatcher: turns a `sensors` discovery job into a
// sensor_commands row the tenant's sensor collects on its next heartbeat, and
// fails — loudly, with the sensor named — any job whose command the sensor
// never collected or never finished.
//
// The job's results do NOT come back through here. The sensor submits them
// through the same authenticated discovery route every passive observation
// uses, so they flow StoreDiscoveries → sensor_discoveries → discovery-processor
// exactly like passive data, and then reports completion through a small
// sensor-authenticated callback on sensor-manager. This file only writes the
// command and watches for the ones nobody answered.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// dispatchTargetRow is one discovery_targets row, as the payload builder sees it.
type dispatchTargetRow struct {
	Input     string
	Protocols []string
	Ports     []int
}

// buildDispatchPayload folds a job's target rows into ONE command payload.
//
// cluster-sensor writes one target row per input carrying the job's whole
// protocol × port set (plus one row per OT probe with its single port), so the
// union across rows is the job's scan shape and the distinct inputs are its
// targets. Deduplicated and sorted so the payload is deterministic — the same
// job dispatched twice must read the same.
func buildDispatchPayload(job *models.DiscoveryJob, rows []dispatchTargetRow, options map[string]interface{}) sensordispatch.Payload {
	var (
		targets   []string
		seenT     = map[string]bool{}
		protocols []string
		seenP     = map[string]bool{}
		ports     []int
		seenPort  = map[int]bool{}
	)
	for _, row := range rows {
		if row.Input != "" && !seenT[row.Input] {
			seenT[row.Input] = true
			targets = append(targets, row.Input)
		}
		for _, p := range row.Protocols {
			if p != "" && !seenP[p] {
				seenP[p] = true
				protocols = append(protocols, p)
			}
		}
		for _, port := range row.Ports {
			if port > 0 && !seenPort[port] {
				seenPort[port] = true
				ports = append(ports, port)
			}
		}
	}
	sort.Strings(protocols)
	sort.Ints(ports)
	return sensordispatch.Payload{
		JobID:     job.ID,
		TenantID:  job.TenantID,
		Targets:   targets,
		Protocols: protocols,
		Ports:     ports,
		Options:   options,
	}
}

// dispatchToSensor hands a `sensors` job to the sensor it named.
//
// The sensor is re-validated at this instant — creation checked it too, but a
// sensor can drop offline in between, and writing a command a dead sensor will
// never collect is a job that says "awaiting sensor" until the sweep gives up
// on it. A job that cannot be dispatched is FAILED here with the reason; it is
// never run in-cluster instead (processDiscoveryJob guards that separately).
//
// Returns nil in every case: the job's outcome is recorded on the row, and a
// NATS redelivery would only repeat the same decision.
func (jp *JobProcessor) dispatchToSensor(job *models.DiscoveryJob) error {
	ctx := context.Background()
	now := time.Now()

	sensor, err := jp.discoveryService.resolveDispatchSensor(ctx, job.TenantID, job.ExecutionMode, job.RequestedSensorIDs, now)
	if err == nil && sensor == nil {
		err = fmt.Errorf("%w: job names no sensor", ErrSensorDispatchInvalid)
	}
	if err != nil {
		jp.failDispatch(job, err.Error())
		return nil
	}

	// The job's scan shape, read back from the rows CreateJob wrote.
	var rows []dispatchTargetRow
	err = jp.withTenantTxx(ctx, job.TenantID, func(tx *sqlx.Tx) error {
		q, e := tx.Query(`SELECT input, protocols, ports FROM discovery_targets WHERE job_id = $1 ORDER BY created_at, id`, job.ID)
		if e != nil {
			return e
		}
		defer func() { _ = q.Close() }()
		for q.Next() {
			var (
				row       dispatchTargetRow
				protocols pq.StringArray
				ports     pq.Int32Array
			)
			if e := q.Scan(&row.Input, &protocols, &ports); e != nil {
				return e
			}
			row.Protocols = []string(protocols)
			for _, p := range ports {
				row.Ports = append(row.Ports, int(p))
			}
			rows = append(rows, row)
		}
		return q.Err()
	})
	if err != nil {
		jp.failDispatch(job, fmt.Sprintf("could not read the job's targets: %v", err))
		return nil
	}
	options, err := jp.getJobOptions(job.TenantID, job.ID)
	if err != nil {
		return fmt.Errorf("read discovery job policy markers: %w", err)
	}
	payload := buildDispatchPayload(job, rows, options)
	if len(payload.Targets) == 0 {
		jp.failDispatch(job, "job has no targets; nothing was dispatched")
		return nil
	}
	payloadJSON, err := json.Marshal(payload.ToMap())
	if err != nil {
		jp.failDispatch(job, fmt.Sprintf("could not encode the command: %v", err))
		return nil
	}

	commandID := uuid.New()
	expiresAt := now.Add(sensordispatch.DispatchTimeout(sensor.ReportingInterval))

	// Command and job state change together or not at all. sensor_commands has
	// no tenant_id; its RLS policy isolates through sensors, so the tenant
	// transaction satisfies its WITH CHECK the same way it does the job's.
	err = jp.withTenantTxx(ctx, job.TenantID, func(tx *sqlx.Tx) error {
		if err := authorizeEnrichmentDispatch(tx, payload, sensor.ID); err != nil {
			return err
		}
		if _, e := tx.Exec(`
			INSERT INTO sensor_commands (id, sensor_id, command_type, payload, status, created_at, expires_at)
			VALUES ($1, $2, $3, $4::jsonb, 'pending', $5, $6)`,
			commandID, sensor.ID, sensordispatch.CommandType, string(payloadJSON), now, expiresAt); e != nil {
			return fmt.Errorf("write sensor command: %w", e)
		}
		res, e := tx.Exec(`
			UPDATE discovery_jobs
			SET status = $1, assigned_sensor_id = $2, dispatched_at = $3, updated_at = $3
			WHERE id = $4 AND tenant_id = $5 AND status = 'queued'`,
			sensordispatch.StatusAwaitingSensor, sensor.ID, now, job.ID, job.TenantID)
		if e != nil {
			return fmt.Errorf("mark job dispatched: %w", e)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("job %s is no longer queued; not dispatching twice", job.ID)
		}
		return nil
	})
	if errors.Is(err, errIdentityEnrichmentPaused) {
		return nil
	} // Retain queued work for the existing recovery sweep.
	if err != nil {
		// The transaction rolled back, so no command exists. If the job was
		// simply not queued any more (a concurrent processor got there first)
		// its row already says what happened; only fail a job that is still
		// ours.
		log.Printf("Dispatch of job %s to sensor %s failed: %v", job.ID, sensor.Name, err)
		if current, gerr := jp.discoveryService.GetJob(job.ID); gerr == nil && current.Status == "queued" {
			jp.failDispatch(job, fmt.Sprintf("could not dispatch to sensor %s: %v", sensor.Name, err))
		}
		return nil
	}

	log.Printf("Discovery job %s dispatched to sensor %s (%s): %d target(s), command %s expires %s",
		job.ID, sensor.Name, sensor.ID, len(payload.Targets), commandID, expiresAt.UTC().Format(time.RFC3339))
	return nil
}

// failDispatch records why a `sensors` job did not run, and tells the tenant.
func (jp *JobProcessor) failDispatch(job *models.DiscoveryJob, reason string) {
	log.Printf("Discovery job %s not dispatched: %s", job.ID, reason)
	if err := jp.discoveryService.UpdateJobStatus(job.ID, "failed", &reason); err != nil {
		log.Printf("Failed to mark job %s failed — job may be stuck in %q: %v", job.ID, job.Status, err)
	}
	if jp.alertService != nil {
		if err := jp.alertService.SendJobFailedAlert(job.TenantID, job.ID, reason); err != nil {
			log.Printf("Failed to send job-failed alert for job %s: %v", job.ID, err)
		}
	}
}

// staleDispatch is one awaiting_sensor job whose command has gone wrong.
type staleDispatch struct {
	JobID         string
	TenantID      string
	CommandID     string
	CommandStatus string
	CommandError  *string
	SensorName    string
	LastHeartbeat *time.Time
}

// dispatchFailureReason is the error_message a stale dispatch is failed with.
// Pure, so every wording is pinned by a test.
func dispatchFailureReason(d staleDispatch) string {
	switch d.CommandStatus {
	case "pending":
		// Never collected: the sensor did not heartbeat within its own window.
		return sensordispatch.SensorOfflineMessage(d.SensorName, d.LastHeartbeat)
	case "failed":
		msg := "sensor refused the job"
		if d.SensorName != "" {
			msg = fmt.Sprintf("sensor %s refused the job", d.SensorName)
		}
		if d.CommandError != nil && *d.CommandError != "" {
			msg += ": " + *d.CommandError
		}
		return msg + "; nothing was scanned"
	default:
		// delivered / acknowledged and then silence past the execution timeout.
		msg := "sensor collected the job but never reported completion"
		if d.SensorName != "" {
			msg = fmt.Sprintf("sensor %s collected the job but never reported completion", d.SensorName)
		}
		return fmt.Sprintf("%s within %s; results, if any, were submitted as ordinary discoveries", msg, sensordispatch.ExecutionTimeout)
	}
}

// findStaleDispatches lists every awaiting_sensor job whose command (a) expired
// before any sensor collected it, (b) was refused by the sensor, or (c) was
// collected and then not completed within the execution timeout.
//
// Platform-wide by design — it spans every tenant — so it runs on the bypass
// handle like the stuck-job sweep beside it.
func (jp *JobProcessor) findStaleDispatches(ctx context.Context) ([]staleDispatch, error) {
	rows, err := jp.bypassDB.QueryContext(ctx, `
		SELECT j.id, j.tenant_id, c.id, c.status, c.error_message,
		       COALESCE(s.name, ''), s.last_heartbeat
		FROM discovery_jobs j
		JOIN LATERAL (
			SELECT c.id, c.status, c.error_message, c.expires_at, c.delivered_at, c.created_at
			FROM sensor_commands c
			WHERE c.command_type = $1 AND c.payload ->> 'job_id' = j.id::text
			ORDER BY c.created_at DESC
			LIMIT 1
		) c ON true
		LEFT JOIN sensors s ON s.id = j.assigned_sensor_id
		WHERE j.status = $2
		  AND (
		        (c.status = 'pending' AND c.expires_at IS NOT NULL AND c.expires_at < NOW())
		     OR c.status = 'failed'
		     OR (c.status IN ('delivered', 'acknowledged')
		         AND COALESCE(c.delivered_at, c.created_at) < NOW() - make_interval(secs => $3))
		  )
		ORDER BY j.created_at ASC
		LIMIT 50`,
		sensordispatch.CommandType, sensordispatch.StatusAwaitingSensor, int(sensordispatch.ExecutionTimeout.Seconds()))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []staleDispatch
	for rows.Next() {
		var d staleDispatch
		if err := rows.Scan(&d.JobID, &d.TenantID, &d.CommandID, &d.CommandStatus, &d.CommandError, &d.SensorName, &d.LastHeartbeat); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// sweepStaleDispatches fails every stale dispatch with its reason. Runs on the
// stuck-job ticker. A job the sensor never collected also has its command
// marked failed, so the sensor cannot collect it later and run a job the
// platform already declared dead.
func (jp *JobProcessor) sweepStaleDispatches(ctx context.Context) {
	stale, err := jp.findStaleDispatches(ctx)
	if err != nil {
		log.Printf("Error checking for stale sensor dispatches: %v", err)
		return
	}
	for _, d := range stale {
		reason := dispatchFailureReason(d)
		if d.CommandStatus == "pending" {
			if _, err := jp.bypassDB.ExecContext(ctx, `
				UPDATE sensor_commands
				SET status = 'failed', error_message = $2, updated_at = NOW()
				WHERE id = $1 AND status = 'pending'`,
				d.CommandID, "expired before the sensor collected it"); err != nil {
				log.Printf("Failed to expire command %s for job %s: %v", d.CommandID, d.JobID, err)
			}
		}
		jp.failDispatch(&models.DiscoveryJob{ID: d.JobID, TenantID: d.TenantID, Status: sensordispatch.StatusAwaitingSensor}, reason)
	}
}
