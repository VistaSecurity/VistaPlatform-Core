package services

// The discovery job lifecycle ( H1/H2/H3): who may move a job between
// states, how the processor claims one, how a cancel reaches a running scan,
// and how much of a job is done.
//
// The rules, all enforced in SQL rather than by reading a row and then writing
// it, because the service runs as several replicas and the same job can be
// delivered to two of them at once (NATS redelivery, the stuck-job sweep's
// republish, a person's Retry):
//
//   - completed, failed and cancelled are TERMINAL. Nothing moves a job out of
//     one except RequeueJobForRetry (failed → queued, a person's Retry).
//   - Only one processor runs a job: ClaimJob is queued → running in a single
//     conditional UPDATE, and a delivery that loses the claim does nothing.
//   - A cancel is a terminal write PLUS a signal: the replica running the job
//     cancels its context at once; any other replica's processor sees the row
//     change on its next between-host check.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

// terminalJobStatuses are sticky. A late "completed" from a scan that outlived
// its cancel, or a redelivered message re-running a finished job, must not
// rewrite the verdict a person already saw.
var terminalJobStatuses = []string{"completed", "failed", "cancelled"}

// IsTerminalJobStatus reports whether a job in status has ended.
func IsTerminalJobStatus(status string) bool {
	for _, terminal := range terminalJobStatuses {
		if status == terminal {
			return true
		}
	}
	return false
}

// ErrJobNotFound is returned by a status change for a job id with no row.
var ErrJobNotFound = errors.New("job not found")

// ErrJobStatusConflict is returned when a status change is refused because the
// job is not in a state the change may leave from — usually because it has
// already ended. Nothing was written.
var ErrJobStatusConflict = errors.New("job status conflict")

// errJobNoLongerRunning is the cause a running job's context is cancelled
// with, and what the processor returns, when the job's row stopped being
// `running` underneath it — a cancel, here or on another replica.
var errJobNoLongerRunning = errors.New("discovery job is no longer running")

// guardJobStatusUpdate appends the from-state predicate to a status UPDATE
// whose last placeholder is the job id: `status = ANY(from)`, or, when from is
// empty, "not terminal".
func guardJobStatusUpdate(query string, args []interface{}, from []string) (string, []interface{}) {
	if len(from) > 0 {
		return query + fmt.Sprintf(" AND status = ANY($%d)", len(args)+1), append(args, pq.Array(from))
	}
	return query + fmt.Sprintf(" AND status <> ALL($%d)", len(args)+1), append(args, pq.Array(terminalJobStatuses))
}

// jobStatusRefused explains a status UPDATE that matched no row.
func (s *DiscoveryService) jobStatusRefused(jobID, wanted string) error {
	var current string
	if err := s.bypassDB.Get(&current, `SELECT status FROM discovery_jobs WHERE id = $1`, jobID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrJobNotFound
		}
		return fmt.Errorf("failed to read job status: %w", err)
	}
	return &JobStatusConflict{JobID: jobID, Current: current, Wanted: wanted}
}

// JobStatusConflict carries the state a refused change found the job in, so a
// handler can say "already completed" rather than "conflict".
type JobStatusConflict struct {
	JobID, Current, Wanted string
}

func (e *JobStatusConflict) Error() string {
	return fmt.Sprintf("job %s is %s; not marking it %s", e.JobID, e.Current, e.Wanted)
}

func (e *JobStatusConflict) Unwrap() error { return ErrJobStatusConflict }

// ClaimJob moves a queued job to running and reports whether THIS caller did
// it. false means someone else already claimed it, or it has ended — either
// way the caller must not scan.
func (s *DiscoveryService) ClaimJob(jobID string) (bool, error) {
	err := s.UpdateJobStatusFrom(jobID, "running", nil, "queued")
	if errors.Is(err, ErrJobStatusConflict) {
		return false, nil
	}
	return err == nil, err
}

// CancelJob ends a job as cancelled and stops its scan if this replica is
// running it. Targets the job never reached are marked cancelled so they do
// not read as still queued; the target in flight is settled by the processor,
// and targets already finished keep their outcome and their findings.
//
// A job that has already ended is refused with a *JobStatusConflict.
func (s *DiscoveryService) CancelJob(jobID string) error {
	if err := s.UpdateJobStatus(jobID, "cancelled", nil); err != nil {
		return err
	}
	s.runningJobs().cancel(jobID)
	// RLS: cross-tenant — bypass role, keyed by job id, as UpdateJobStatus.
	if _, err := s.bypassDB.Exec(`
		UPDATE discovery_targets
		SET status = 'cancelled', completed_at = NOW(), updated_at = NOW()
		WHERE job_id = $1 AND status = 'pending'`, jobID); err != nil {
		// The job's own row is the record that matters, and it is written.
		return fmt.Errorf("job %s cancelled, but its unstarted targets could not be marked: %w", jobID, err)
	}
	// A scan-plan job's units the scan never reached, likewise (the unit in
	// flight is settled by its worker; done units keep their findings).
	if _, err := s.bypassDB.Exec(`
		UPDATE discovery_job_units SET status = 'cancelled', finished_at = NOW()
		WHERE job_id = $1 AND status = 'pending'`, jobID); err != nil {
		return fmt.Errorf("job %s cancelled, but its unstarted hosts could not be marked: %w", jobID, err)
	}
	// A scan-plan job on a tenant sensor: tell the sensor ( WP2b).
	if err := s.revokeSensorPlanDispatch(jobID); err != nil {
		return fmt.Errorf("job %s cancelled, but its sensor could not be told: %w", jobID, err)
	}
	return nil
}

// RequeueJobForRetry is the one legitimate exit from a terminal state: a
// person's Retry of a failed job (or a nudge of a queued one) puts it back to
// queued so the next processor can claim it. Its unfinished targets go back to
// pending; completed targets keep their findings and are not scanned again.
// A scan-plan job's units likewise: every unit that is not done goes back to
// pending (a refused address is authorized afresh), and done units keep their
// findings and are not scanned again.
func (s *DiscoveryService) RequeueJobForRetry(jobID string) error {
	// RLS: cross-tenant — bypass role, keyed by job id, as UpdateJobStatus.
	tx, err := s.bypassDB.Beginx()
	if err != nil {
		return fmt.Errorf("failed to requeue job: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`
		UPDATE discovery_jobs
		SET status = 'queued', error_message = NULL, started_at = NULL, completed_at = NULL, updated_at = NOW()
		WHERE id = $1 AND status IN ('queued', 'failed')`, jobID)
	if err != nil {
		return fmt.Errorf("failed to requeue job: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return s.jobStatusRefused(jobID, "queued")
	}
	if _, err := tx.Exec(`
		UPDATE discovery_targets
		SET status = 'pending', started_at = NULL, completed_at = NULL, error_message = NULL, updated_at = NOW()
		WHERE job_id = $1 AND status <> 'completed'`, jobID); err != nil {
		return fmt.Errorf("failed to reset job targets: %w", err)
	}
	if _, err := tx.Exec(`
		UPDATE discovery_job_units
		SET status = 'pending', started_at = NULL, finished_at = NULL, error_message = NULL
		WHERE job_id = $1 AND status <> 'done'`, jobID); err != nil {
		return fmt.Errorf("failed to reset job hosts: %w", err)
	}
	return tx.Commit()
}

// JobTargetCounts reads a job's targets by status, for honest progress.
func (s *DiscoveryService) JobTargetCounts(tenantID, jobID string) (models.JobTargetCounts, error) {
	var counts models.JobTargetCounts
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return counts, fmt.Errorf("invalid tenant_id: %w", err)
	}
	err = s.withTenantTxx(context.Background(), tenant, func(tx *sqlx.Tx) error {
		return tx.Get(&counts, `
			SELECT COUNT(*) AS total,
			       COUNT(*) FILTER (WHERE status = 'pending')   AS pending,
			       COUNT(*) FILTER (WHERE status = 'running')   AS running,
			       COUNT(*) FILTER (WHERE status = 'completed') AS completed,
			       COUNT(*) FILTER (WHERE status = 'failed')    AS failed,
			       COUNT(*) FILTER (WHERE status = 'cancelled') AS cancelled
			FROM discovery_targets WHERE job_id = $1 AND tenant_id = $2`, jobID, tenant)
	})
	return counts, err
}

// TargetProgress is the integer percent of a job's targets the scanner is
// finished with: scanned (completed) or refused with a reason (failed). It
// replaces a number that was 0 / 50 / 100 by status alone.
//
// It is per TARGET, not per host — see models.JobTargetCounts. A cancelled
// target was never reached, so it does not count as done: a job cancelled
// after one of ten targets reads 10%, not 100%.
//
// A job with no target rows has nothing to count: it reads 100 once completed
// and 0 otherwise.
func TargetProgress(c models.JobTargetCounts, jobStatus string) int {
	if c.Total <= 0 {
		if jobStatus == "completed" {
			return 100
		}
		return 0
	}
	done := c.Completed + c.Failed
	if done > c.Total {
		done = c.Total
	}
	return done * 100 / c.Total
}

// runningJobRegistry is this replica's index of the jobs it is executing, so a
// cancel handled here can stop the scan immediately instead of at the next
// between-host status read.
type runningJobRegistry struct {
	mu      sync.Mutex
	cancels map[string]context.CancelCauseFunc
}

// runningJobs returns the registry, creating it on first use so a
// DiscoveryService built as a literal (tests) still works.
func (s *DiscoveryService) runningJobs() *runningJobRegistry {
	s.runningMu.Lock()
	defer s.runningMu.Unlock()
	if s.running == nil {
		s.running = &runningJobRegistry{cancels: map[string]context.CancelCauseFunc{}}
	}
	return s.running
}

// start registers jobID as running here and returns its context, which is
// cancelled with errJobNoLongerRunning by a cancel of that job, or with
// parent's cause when parent ends. release must be called when the run ends.
func (r *runningJobRegistry) start(parent context.Context, jobID string) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	r.mu.Lock()
	r.cancels[jobID] = cancel
	r.mu.Unlock()
	return ctx, func() {
		r.mu.Lock()
		delete(r.cancels, jobID)
		r.mu.Unlock()
		cancel(nil)
	}
}

// has reports whether jobID is running on this replica.
func (r *runningJobRegistry) has(jobID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.cancels[jobID]
	return ok
}

// cancel stops jobID's run on this replica, if there is one.
func (r *runningJobRegistry) cancel(jobID string) bool {
	r.mu.Lock()
	cancel, ok := r.cancels[jobID]
	r.mu.Unlock()
	if ok {
		cancel(errJobNoLongerRunning)
	}
	return ok
}
