package jobunits

// A tenant sensor's per-host reports of a planned job ( WP2b, hole H10).
//
// The sensor runs a planned job on the shared engine and, after each host,
// reports that host's unit. RecordSensorBatch stores it with the same Commit
// the Platform Sensor uses — same rows, same mapping, same fence — so coverage,
// progress and grouped results come out of the existing readers unchanged
// whichever executor ran the job.
//
// The fence for a sensor unit is (status pending, attempts = the dispatch's
// attempt). The dispatcher stamps every unit it hands over with the dispatch's
// attempt; the unit stays pending until a report of THAT attempt lands. So:
//
//   - a re-sent batch finds its units done under the same attempt: counted
//     Duplicate, nothing stored twice;
//   - a report from an earlier dispatch (a sensor that came back after its
//     lease expired and a person's Retry re-dispatched) is Stale;
//   - a unit cancelled with its job is no longer pending: Stale.
//
// Every report — an empty one too, which is how the sensor pings — renews the
// job's progress lease (discovery_jobs.updated_at, which the dispatcher's
// sweep reads; see sensordispatch.PlanProgressLease), and every answer tells
// the sensor whether to go on: a cancelled or ended job gets a code and has
// nothing stored.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// ErrJobNotAssignedToSensor: unknown job, another tenant's, assigned to a
// different sensor, or run by the platform. One answer for all of them, so a
// sensor cannot probe which is which.
var ErrJobNotAssignedToSensor = errors.New("discovery job is not assigned to this sensor")

// ErrNotPlannedJob: the job is this sensor's but is not a planned scan; its
// results go through the discovery batch route.
var ErrNotPlannedJob = errors.New("discovery job is not a planned scan; it has no units to report")

// RecordSensorBatch takes one progress report from sensorID for jobID. See the
// file comment for what it stores and answers.
func RecordSensorBatch(ctx context.Context, db *sql.DB, tenantID, sensorID, jobID uuid.UUID, batch sensordispatch.UnitBatch) (sensordispatch.UnitBatchResponse, error) {
	var resp sensordispatch.UnitBatchResponse
	if err := batch.Validate(); err != nil {
		return resp, err
	}
	var activeScan bool
	// The lease and the verdict, under the job's row lock: a cancel that
	// commits first is seen here; one that comes after waits for this.
	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		status, opts, err := lockSensorJob(ctx, tx, tenantID, sensorID, jobID, "FOR UPDATE")
		if err != nil {
			return err
		}
		resp.JobStatus, activeScan = status, opts
		if code := stopCode(status); code != "" {
			resp.Code = code
			return nil
		}
		// The first report — a host or an empty ping — is when the sensor
		// began the work, so it is the job's started_at ( V13). The
		// command's delivered_at, which CompleteSensorJob back-fills when
		// nothing set this, is only when the sensor COLLECTED it, and a
		// queued job is collected long before it starts. The status stays
		// awaiting_sensor: that is what a planned sensor job reads while it
		// runs, and what the stale-dispatch sweep and stopCode key on.
		_, err = tx.ExecContext(ctx, `UPDATE discovery_jobs SET updated_at = NOW(), started_at = COALESCE(started_at, NOW()) WHERE id = $1 AND tenant_id = $2`, jobID, tenantID)
		return err
	})
	if err != nil || resp.Code != "" {
		return resp, err
	}

	// One transaction per host: a host's findings, their queueing and its
	// `done` are atomic, and one host that cannot be stored does not cost the
	// others. Each re-reads the job under a share lock, so a unit is never
	// stored into a job that ended a moment ago.
	for _, r := range batch.Units {
		outcome, err := recordSensorUnit(ctx, db, tenantID, sensorID, jobID, r, activeScan)
		if err != nil {
			return resp, fmt.Errorf("host %s: %w", r.Address, err)
		}
		switch outcome {
		case unitAccepted:
			resp.Accepted++
		case unitDuplicate:
			resp.Duplicate++
		case unitStale:
			resp.Stale++
		case unitUnknown:
			resp.Unknown++
		case unitJobStopped:
			// The job ended between the lease write and this host.
			var status string
			if err := db.QueryRowContext(ctx, `SELECT status FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status); err == nil {
				resp.JobStatus = status
			}
			resp.Code = stopCode(resp.JobStatus)
			if resp.Code == "" {
				resp.Code = sensordispatch.UnitsCodeJobEnded
			}
			return resp, nil
		}
	}
	return resp, nil
}

type unitOutcome int

const (
	unitAccepted unitOutcome = iota
	unitDuplicate
	unitStale
	unitUnknown
	unitJobStopped
)

func stopCode(status string) string {
	switch status {
	case sensordispatch.StatusAwaitingSensor:
		return ""
	case "cancelled":
		return sensordispatch.UnitsCodeJobCancelled
	default:
		return sensordispatch.UnitsCodeJobEnded
	}
}

// lockSensorJob reads the job's status for a sensor report under lock, and
// refuses one that is not this sensor's planned job.
func lockSensorJob(ctx context.Context, tx *sql.Tx, tenantID, sensorID, jobID uuid.UUID, lock string) (string, bool, error) {
	var (
		status   string
		assigned sql.NullString
		planned  bool
		active   sql.NullString
	)
	err := tx.QueryRowContext(ctx, `
		SELECT status, assigned_sensor_id, COALESCE(metadata ? $3, false), metadata -> 'options' ->> 'active_scan'
		FROM discovery_jobs WHERE id = $1 AND tenant_id = $2 `+lock,
		jobID, tenantID, shareddisc.ScanPlanMetadataKey).Scan(&status, &assigned, &planned, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrJobNotAssignedToSensor
	}
	if err != nil {
		return "", false, fmt.Errorf("read job: %w", err)
	}
	if !assigned.Valid || assigned.String != sensorID.String() {
		return "", false, ErrJobNotAssignedToSensor
	}
	if !planned {
		return "", false, ErrNotPlannedJob
	}
	return status, active.Valid && active.String == "true", nil
}

func recordSensorUnit(ctx context.Context, db *sql.DB, tenantID, sensorID, jobID uuid.UUID, r sensordispatch.UnitResult, activeScan bool) (unitOutcome, error) {
	outcome := unitAccepted
	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		status, _, err := lockSensorJob(ctx, tx, tenantID, sensorID, jobID, "FOR SHARE")
		if err != nil {
			return err
		}
		if status != sensordispatch.StatusAwaitingSensor {
			outcome = unitJobStopped
			return nil
		}
		u := Unit{JobID: jobID.String(), TenantID: tenantID.String(), TargetID: r.TargetID, Address: r.Address}
		var (
			unitStatus string
			attempts   int
		)
		err = tx.QueryRowContext(ctx, `
			SELECT u.id, u.status, u.attempts, t.input
			FROM discovery_job_units u JOIN discovery_targets t ON t.id = u.target_id
			WHERE u.job_id = $1 AND u.target_id = $2 AND u.address = $3`,
			jobID, r.TargetID, r.Address).Scan(&u.ID, &unitStatus, &attempts, &u.TargetInput)
		if errors.Is(err, sql.ErrNoRows) {
			outcome = unitUnknown
			return nil
		}
		if err != nil {
			return err
		}
		u.Hostname = shareddisc.PlanTargetHostname(u.TargetInput)
		switch {
		case attempts != r.Attempt:
			outcome = unitStale
			return nil
		case unitStatus != "pending":
			// Already settled under this attempt: done or failed by an
			// earlier copy of this report, or cancelled with the job.
			if unitStatus == "cancelled" {
				outcome = unitStale
			} else {
				outcome = unitDuplicate
			}
			return nil
		}
		if r.Failed {
			reason := r.Error
			if reason == "" {
				reason = "not scanned: the sensor gave no reason"
			}
			res, err := tx.ExecContext(ctx, `
				UPDATE discovery_job_units SET status = 'failed', error_message = $4, finished_at = NOW()
				WHERE id = $1 AND status = $2 AND attempts = $3`, u.ID, "pending", r.Attempt, reason)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return ErrFenced
			}
			return SettleTarget(tx, u.JobID, u.TargetID, u.TargetInput)
		}
		out, err := r.Output()
		if err != nil {
			return err
		}
		return Commit(tx, u, out, CommitOptions{
			From: "pending", Attempt: r.Attempt, ActiveScan: activeScan,
			// Labelled as the sensor's legacy results are, so a planned
			// re-scan updates the configuration the legacy path recorded
			// instead of adding a second ( WP4).
			DiscoveryMethod: sensordispatch.DiscoveryMethodActive,
			// The reporting sensor is the one the findings are queued under,
			// as its own observations are.
			MirrorSensorID: func(Tx) (string, error) { return sensorID.String(), nil },
		})
	})
	if errors.Is(err, ErrFenced) {
		return unitStale, nil
	}
	return outcome, err
}

// FinishSensorPlanUnits settles a planned job's units when its sensor reports
// the job finished: every unit still pending was never reported — the sensor
// could not deliver its result, or never reached it — and is failed with
// reason so the job's coverage says so and a Retry scans it again. Returns how
// many were failed. Runs in the caller's (tenant) transaction.
func FinishSensorPlanUnits(ctx context.Context, tx *sql.Tx, jobID uuid.UUID, reason string) (int, error) {
	rows, err := tx.QueryContext(ctx, `
		UPDATE discovery_job_units u SET status = 'failed', error_message = $2, finished_at = NOW()
		FROM discovery_targets t
		WHERE u.job_id = $1 AND u.status = 'pending' AND t.id = u.target_id
		RETURNING u.target_id, t.input`, jobID, reason)
	if err != nil {
		return 0, err
	}
	failed := 0
	targets := map[string]string{}
	for rows.Next() {
		var id, input string
		if err := rows.Scan(&id, &input); err != nil {
			_ = rows.Close()
			return 0, err
		}
		targets[id] = input
		failed++
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for id, input := range targets {
		if err := SettleTarget(tx, jobID.String(), id, input); err != nil {
			return 0, err
		}
	}
	return failed, nil
}
