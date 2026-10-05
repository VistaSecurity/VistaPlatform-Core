package services

// A scan-plan job on a tenant sensor ( WP2b; holes H10, H16, H31).
//
// The sensor runs the plan on the shared engine (shared/sensordispatch/planrun)
// and reports each host as a work unit, which sensor-manager stores with the
// same commit this service uses for its own units (shared/jobunits). What this
// file owns is the platform's half of the hand-over:
//
//   - units, created and authorized HERE before dispatch — the same
//     ensureUnits the Platform Sensor runs, so every address the sensor may
//     touch was cleared by dispatchguard first, and a refused one is a failed
//     unit the sensor is told to skip;
//   - the attempt: every pending unit is stamped with this dispatch's number,
//     and only a report of that attempt is stored (a sensor that outlived its
//     lease cannot overwrite a Retry);
//   - the payload: the per-target plan, the addresses a hostname was pinned
//     to, and the addresses already answered for (a Retry runs only the rest);
//   - the progress lease that replaces the fixed execution timeout for these
//     jobs (findStaleDispatches);
//   - cancel: a command not yet collected is withdrawn, one being run is
//     followed by a cancel_discovery_job command (CancelJob).

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// planProgressLease is how long a scan-plan job on a sensor may go without a
// progress report before the sweep fails it (sensordispatch.PlanProgressLease;
// a variable only so a test can shorten it).
var planProgressLease = sensordispatch.PlanProgressLease

// planDispatch is a scan-plan job's units, ready to be stamped with a dispatch.
type planDispatch struct {
	job      *models.DiscoveryJob
	targets  []*planTarget
	otProbes []string
}

// preparePlanDispatch creates the job's units (each address authorized first)
// and re-authorizes every unit still pending — a Retry puts refused units back
// to pending, and the tenant's networks may have changed since — so the sensor
// is handed only addresses dispatchguard cleared NOW.
func (jp *JobProcessor) preparePlanDispatch(job *models.DiscoveryJob) (*planDispatch, error) {
	targets, err := jp.loadPlanTargets(job)
	if err != nil {
		return nil, err
	}
	otProbes, err := jp.jobOTProbes(job)
	if err != nil {
		return nil, err
	}
	// No options: an automatic plan is judged here on target authorization
	// only. Its automatic-scan policy is judged on the whole plan inside the
	// dispatch transaction (dispatchToSensor), as a legacy payload is — so a
	// paused policy leaves the job queued with its units pending rather than
	// failing them — and again when the sensor collects the command.
	auth := &unitAuthorizer{jp: jp, tenantID: job.TenantID}
	if err := jp.ensureUnits(job, targets, auth); err != nil {
		return nil, err
	}
	units, err := jp.pendingUnits(job)
	if err != nil {
		return nil, fmt.Errorf("list units: %w", err)
	}
	byRow := targetByRow(targets)
	for _, u := range units {
		t := byRow[u.TargetID]
		if t == nil {
			jp.failUnit(job, u, &planTarget{rowID: u.TargetID}, unitPending, "not scanned: its target is not in the job's scan plan")
			continue
		}
		if err := auth.authorize(u.Address, t.grant.consent); err != nil {
			jp.failUnit(job, u, t, unitPending, refusalReason(err))
		}
	}
	return &planDispatch{job: job, targets: targets, otProbes: otProbes}, nil
}

// stamp gives every pending unit this dispatch's attempt and builds the plan
// the sensor runs, inside the dispatch transaction (so a dispatch that loses
// the race to another changes nothing).
func (d *planDispatch) stamp(tx *sqlx.Tx) (*sensordispatch.PlanPayload, error) {
	var attempt int
	if err := tx.Get(&attempt, `SELECT COALESCE(MAX(attempts), 0) + 1 FROM discovery_job_units WHERE job_id = $1`, d.job.ID); err != nil {
		return nil, fmt.Errorf("next attempt: %w", err)
	}
	if _, err := tx.Exec(`UPDATE discovery_job_units SET attempts = $2 WHERE job_id = $1 AND status = 'pending'`, d.job.ID, attempt); err != nil {
		return nil, fmt.Errorf("stamp units: %w", err)
	}
	var answered []struct {
		TargetID string `db:"target_id"`
		Address  string `db:"address"`
	}
	if err := tx.Select(&answered, `SELECT target_id, address FROM discovery_job_units WHERE job_id = $1 AND status <> 'pending' ORDER BY target_id, address`, d.job.ID); err != nil {
		return nil, fmt.Errorf("read answered units: %w", err)
	}
	skip := map[string][]string{}
	for _, a := range answered {
		skip[a.TargetID] = append(skip[a.TargetID], a.Address)
	}
	planned := make(map[string]shareddisc.PlanTarget, len(d.job.Plan.Targets))
	for _, pt := range d.job.Plan.Targets {
		planned[pt.Target] = pt
	}
	plan := &sensordispatch.PlanPayload{
		Version: sensordispatch.PlanPayloadVersion, Attempt: attempt,
		Pace: d.job.Plan.Pace, OTProbeProtocols: d.otProbes,
	}
	for _, t := range d.targets {
		pt := planned[t.input]
		udp, err := shareddisc.NewPortSet(t.udp...)
		if err != nil {
			return nil, fmt.Errorf("plan for %s: %w", t.input, err)
		}
		// The ports the sensor probes: the plan's, with the OT opt-in's
		// standard ports folded in exactly as the Platform Sensor folds them
		// (loadPlanTargets).
		pt.TCPPorts, pt.TCPPortCount = t.tcp.String(), t.tcp.Len()
		pt.UDPPorts, pt.UDPPortCount = udp.String(), udp.Len()
		work := sensordispatch.PlanTargetWork{PlanTarget: pt, TargetID: t.rowID, SkipAddresses: skip[t.rowID]}
		if t.hostname != "" {
			work.PinnedAddresses = append([]string(nil), t.grant.pinned...)
		}
		plan.Targets = append(plan.Targets, work)
	}
	return plan, nil
}

// planStallReason is the error_message of a scan-plan job whose sensor stopped
// reporting progress. Pure, so the wording is pinned by a test.
func planStallReason(sensorName string, lastProgress *time.Time, lease time.Duration) string {
	who := "the sensor"
	if sensorName != "" {
		who = "sensor " + sensorName
	}
	msg := fmt.Sprintf("%s stopped reporting progress on this scan (nothing for over %s", who, lease)
	if lastProgress != nil && !lastProgress.IsZero() {
		msg += ", last at " + lastProgress.UTC().Format(time.RFC3339)
	}
	return msg + "); hosts it finished are kept — retry to scan the rest"
}

// revokeSensorPlanDispatch tells the sensor a cancelled scan-plan job is over.
// A command it has not collected is withdrawn, so it never starts; one it has
// collected is followed by a cancel_discovery_job command, so an idle sensor
// (or one between reports) stops at its next heartbeat — a reporting sensor
// learns it sooner, from its next report's answer. Legacy jobs are untouched.
func (s *DiscoveryService) revokeSensorPlanDispatch(jobID string) error {
	// RLS: cross-tenant — bypass role, keyed by job id, as CancelJob.
	var (
		assigned *string
		planned  bool
	)
	if err := s.bypassDB.QueryRow(`SELECT assigned_sensor_id::text, COALESCE(metadata ? $2, false) FROM discovery_jobs WHERE id = $1`,
		jobID, shareddisc.ScanPlanMetadataKey).Scan(&assigned, &planned); err != nil {
		return err
	}
	if !planned || assigned == nil {
		return nil
	}
	res, err := s.bypassDB.Exec(`
		UPDATE sensor_commands SET status = 'failed', error_message = 'job cancelled before the sensor collected it', updated_at = NOW()
		WHERE command_type = $1 AND payload ->> 'job_id' = $2 AND status = 'pending'`, sensordispatch.CommandType, jobID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var delivered bool
	if err := s.bypassDB.Get(&delivered, `SELECT EXISTS (SELECT 1 FROM sensor_commands WHERE command_type = $1 AND payload ->> 'job_id' = $2 AND status = 'delivered')`,
		sensordispatch.CommandType, jobID); err != nil {
		return err
	}
	if !delivered {
		return nil
	}
	now := time.Now()
	_, err = s.bypassDB.Exec(`
		INSERT INTO sensor_commands (id, sensor_id, command_type, payload, status, created_at, expires_at)
		VALUES ($1, $2, $3, jsonb_build_object('job_id', $4::text), 'pending', $5, $6)`,
		uuid.New(), *assigned, sensordispatch.CancelCommandType, jobID, now, now.Add(planProgressLease))
	if err == nil {
		log.Printf("Discovery job %s cancelled: told sensor %s to stop", jobID, *assigned)
	}
	return err
}
