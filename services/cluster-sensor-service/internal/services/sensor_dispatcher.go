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
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
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

	// A scan-plan job is handed only to a sensor that can run one (
	// WP2b): re-checked here, because the sensor may have been replaced by
	// older software since the job was created — and a job that cannot run
	// where it was asked to is FAILED with the reason, never run elsewhere.
	sensor, err := jp.discoveryService.resolveDispatchSensor(ctx, job.TenantID, job.ExecutionMode, job.RequestedSensorIDs, job.Plan != nil, now)
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
	// A job carrying confirmed external targets is never handed to a tenant
	// sensor (CreateJob refuses to create one; this catches any that exist
	// anyway). The sensor would re-resolve names and scan without the
	// platform's per-address re-check — including of the operator switch,
	// which the platform path reads again at scan time ( W5.13b).
	var hasExternal bool
	if err := jp.withTenantTxx(ctx, job.TenantID, func(tx *sqlx.Tx) error {
		var e error
		hasExternal, e = jobHasConfirmedExternalTargets(tx, job.ID)
		return e
	}); err != nil {
		jp.failDispatch(job, fmt.Sprintf("could not read the job's external-target record: %v", err))
		return nil
	}
	if hasExternal {
		jp.failDispatch(job, "targets outside the tenant's registered networks are only scanned from the platform sensor; nothing was dispatched")
		return nil
	}
	options, err := jp.getJobOptions(job.TenantID, job.ID)
	if err != nil {
		return fmt.Errorf("read discovery job policy markers: %w", err)
	}
	// A scan-plan job carries its plan ( WP2b, sensor_plan_dispatch.go):
	// units are created and authorized first, and the plan — stamped with
	// this dispatch's attempt — is built inside the transaction below. Only a
	// sensor that reported the capability got this far (resolveDispatchSensor).
	var (
		payload sensordispatch.Payload
		plan    *planDispatch
	)
	if job.Plan != nil {
		if job.Status != "queued" {
			// A duplicate delivery: the job is dispatched already (or ended).
			// The transaction's guard would refuse it; do not touch its units.
			log.Printf("Discovery job %s is %s, not queued — not dispatching it again", job.ID, job.Status)
			return nil
		}
		if plan, err = jp.preparePlanDispatch(job); err != nil {
			jp.failDispatch(job, fmt.Sprintf("could not prepare the scan plan: %v", err))
			return nil
		}
		payload = sensordispatch.Payload{JobID: job.ID, TenantID: job.TenantID, Options: options}
	} else {
		payload = buildDispatchPayload(job, rows, options)
		if len(payload.Targets) == 0 {
			jp.failDispatch(job, "job has no targets; nothing was dispatched")
			return nil
		}
	}

	commandID := uuid.New()
	expiresAt := now.Add(sensordispatch.DispatchTimeout(sensor.ReportingInterval))

	// Command and job state change together or not at all. sensor_commands has
	// no tenant_id; its RLS policy isolates through sensors, so the tenant
	// transaction satisfies its WITH CHECK the same way it does the job's.
	err = jp.withTenantTxx(ctx, job.TenantID, func(tx *sqlx.Tx) error {
		if plan != nil {
			p, e := plan.stamp(tx)
			if e != nil {
				return e
			}
			payload.Plan = p
		}
		// After the plan is stamped ( WP2): an automatic or identity
		// plan is judged on the addresses and ports the sensor is handed.
		// Before, it was judged on a payload with no targets at all.
		if err := authorizeEnrichmentDispatch(tx, payload, sensor.ID); err != nil {
			return err
		}
		payloadJSON, e := json.Marshal(payload.ToMap())
		if e != nil {
			return fmt.Errorf("encode the command: %w", e)
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
			return errJobNoLongerQueued
		}
		return nil
	})
	if errors.Is(err, errIdentityEnrichmentPaused) {
		return nil
	} // Retain queued work for the existing recovery sweep.
	if errors.Is(err, errJobNoLongerQueued) {
		// Another delivery of the same job — the stuck-job sweep's republish
		// or a broker redelivery, read on this or another replica — committed
		// its dispatch first. The guard above rolled this one back, so there
		// is exactly one command; nothing failed and there is nothing to do.
		log.Printf("Discovery job %s was dispatched by another delivery of it; this delivery does nothing", job.ID)
		return nil
	}
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

	targets := len(payload.Targets)
	if payload.Plan != nil {
		targets = len(payload.Plan.Targets)
	}
	log.Printf("Discovery job %s dispatched to sensor %s (%s): %d target(s), command %s expires %s",
		job.ID, sensor.Name, sensor.ID, targets, commandID, expiresAt.UTC().Format(time.RFC3339))
	return nil
}

// errJobNoLongerQueued is the dispatch transaction's guard refusing a job that
// left `queued` after this delivery read it: another delivery dispatched it.
var errJobNoLongerQueued = errors.New("job is no longer queued; not dispatching twice")

// failDispatch records why a `sensors` job did not run, and tells the tenant.
func (jp *JobProcessor) failDispatch(job *models.DiscoveryJob, reason string) {
	jp.failDispatchWith(job, reason, true)
}

// failDispatchWith is failDispatch with the tenant alert optional. Only the
// quiet sensor-busy path (sweepStaleDispatches) passes alert=false.
func (jp *JobProcessor) failDispatchWith(job *models.DiscoveryJob, reason string, alert bool) {
	log.Printf("Discovery job %s not dispatched: %s", job.ID, reason)
	if err := jp.discoveryService.UpdateJobStatus(job.ID, "failed", &reason); err != nil {
		log.Printf("Failed to mark job %s failed — job may be stuck in %q: %v", job.ID, job.Status, err)
	}
	if alert && jp.alertService != nil {
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
	// Planned: a scan-plan job, held to the progress lease rather than the
	// execution timeout; LastProgress is its last report (or its pickup).
	Planned      bool
	LastProgress *time.Time
	// Origin is the job's server-written options.origin ("manual",
	// "auto_scan", "identity_enrichment").
	Origin string
}

// identityEnrichmentOrigin is the options.origin inventory-service's identity
// enrichment coordinator stamps on its probes. Server authority: the handler
// strips `origin` from any request that is not an HMAC-verified internal call.
const identityEnrichmentOrigin = "identity_enrichment"

// sensorBusy reports whether a stale dispatch is a command the sensor refused
// only because its queue was full.
func (d staleDispatch) sensorBusy() bool {
	return d.CommandStatus == "failed" && d.CommandError != nil && sensordispatch.IsSensorBusyRefusal(*d.CommandError)
}

// quietBusyRefusal reports whether a stale dispatch is an identity-enrichment
// probe its sensor refused only for want of room. That job's producer sends it
// again with backoff (inventory-service reads the failure code), so the
// refusal is back-pressure, not a failure anyone has to act on: the job is
// failed without the tenant-facing job_failed alert. Every other refusal — and
// every person-initiated or automatic scan — keeps its loud failure.
func (d staleDispatch) quietBusyRefusal() bool {
	return d.sensorBusy() && d.Origin == identityEnrichmentOrigin
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
		if d.Planned {
			// Collected, then no progress report for the lease.
			return planStallReason(d.SensorName, d.LastProgress, planProgressLease)
		}
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
// collected and then not completed within the execution timeout — or, for a
// scan-plan job, (d) was collected and then went without a progress report
// for the progress lease. A scan-plan job that keeps reporting is never
// failed for running long: every report renews its row's updated_at
// (shared/jobunits.RecordSensorBatch), and that is what (d) reads.
//
// Platform-wide by design — it spans every tenant — so it runs on the bypass
// handle like the stuck-job sweep beside it.
func (jp *JobProcessor) findStaleDispatches(ctx context.Context) ([]staleDispatch, error) {
	args := []interface{}{sensordispatch.CommandType, sensordispatch.StatusAwaitingSensor, int(sensordispatch.ExecutionTimeout.Seconds()),
		planProgressLease.Seconds(), shareddisc.ScanPlanMetadataKey}
	scope := ""
	if jp.sweepTenant != "" {
		// Tests only, as in sweepScope: a shared test database holds other
		// suites' jobs, which a sweep with a test-sized lease must not touch.
		scope, args = " AND j.tenant_id = $6", append(args, jp.sweepTenant)
	}
	rows, err := jp.bypassDB.QueryContext(ctx, `
		SELECT j.id, j.tenant_id, c.id, c.status, c.error_message,
		       COALESCE(s.name, ''), s.last_heartbeat,
		       COALESCE(j.metadata ? $5, false), GREATEST(COALESCE(c.delivered_at, c.created_at), j.updated_at),
		       COALESCE(j.metadata->'options'->>'origin', '')
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
		     OR (c.status IN ('delivered', 'acknowledged') AND NOT COALESCE(j.metadata ? $5, false)
		         AND COALESCE(c.delivered_at, c.created_at) < NOW() - make_interval(secs => $3))
		     OR (c.status IN ('delivered', 'acknowledged') AND COALESCE(j.metadata ? $5, false)
		         AND GREATEST(COALESCE(c.delivered_at, c.created_at), j.updated_at) < NOW() - make_interval(secs => $4))
		  )`+scope+`
		ORDER BY j.created_at ASC
		LIMIT 50`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []staleDispatch
	for rows.Next() {
		var d staleDispatch
		if err := rows.Scan(&d.JobID, &d.TenantID, &d.CommandID, &d.CommandStatus, &d.CommandError, &d.SensorName, &d.LastHeartbeat, &d.Planned, &d.LastProgress, &d.Origin); err != nil {
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
		if d.sensorBusy() {
			// Machine-readable, and written before the status flips so a reader
			// that sees the job failed always sees why: the sensor had no room,
			// nothing was scanned, and the same job sent later would be accepted.
			if _, err := jp.bypassDB.ExecContext(ctx, `
				UPDATE discovery_jobs
				SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{`+sensordispatch.FailureCodeKey+`}', to_jsonb($2::text))
				WHERE id = $1 AND status = $3`,
				d.JobID, sensordispatch.FailureCodeSensorBusy, sensordispatch.StatusAwaitingSensor); err != nil {
				log.Printf("Failed to record the sensor-busy failure code on job %s: %v", d.JobID, err)
			}
		}
		job := &models.DiscoveryJob{ID: d.JobID, TenantID: d.TenantID, Status: sensordispatch.StatusAwaitingSensor}
		if d.quietBusyRefusal() {
			jp.failDispatchWith(job, reason+" — identity enrichment will send it again when the sensor has room", false)
		} else {
			jp.failDispatch(job, reason)
		}
		if d.Planned {
			// Its targets with hosts left read failed, not in progress. The
			// hosts themselves stay pending — the record of what is left —
			// and a Retry dispatches exactly those; finished hosts keep their
			// findings.
			if _, err := jp.bypassDB.ExecContext(ctx, `
				UPDATE discovery_targets SET status = 'failed', error_message = COALESCE(error_message, $2),
				       completed_at = COALESCE(completed_at, NOW()), updated_at = NOW()
				WHERE job_id = $1 AND status IN ('pending', 'running')`, d.JobID, reason); err != nil {
				log.Printf("Failed to settle the targets of stalled job %s: %v", d.JobID, err)
			}
		}
	}
}
