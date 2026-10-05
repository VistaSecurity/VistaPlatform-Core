package services

// The stuck-job reaper: a `running` job whose owner died.
//
// The claim (job_lifecycle.go) makes a redelivered message a no-op, so a
// replica that is killed mid-scan — OOM, SIGKILL, a lost node — leaves its job
// `running` with nothing running it. Nothing else would ever end it, and
// RateLimiter.CheckRateLimit counts `running` jobs against the tenant's
// concurrent_jobs: five such jobs and the tenant cannot start a scan.
//
// The owner proves it is alive by touching the row's updated_at — from the
// message-lease ticker every jobLeaseInterval, and at every target and host
// boundary. The stuck-job poll, on every replica, ends a `running` job whose
// updated_at is older than jobHeartbeatLease: a scan-plan job is put back in
// the queue and published, to resume after the hosts already done (up to
// planAutoResumeLimit times); any other job is failed for a person to Retry.
// Both the selection and the transition carry the staleness predicate, so a
// job whose owner beats in between is never touched, whichever replica's poll
// got there.

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// reapableExecutionModes excludes the jobs this processor does not run and so
// never heartbeats: `sensors` (a tenant sensor or device-interrogation runs it)
// and `cloud` (device-interrogation-service marks it running and completed).
// Normalised the way isSensorExecutionMode reads it.
const reapableExecutionModes = `lower(btrim(execution_mode)) NOT IN ('sensors', 'cloud')`

// stalledJobMessage is the error_message a reaped job carries, formatted in SQL
// from the row's last heartbeat.
const stalledJobMessage = `format('scan stopped responding; no heartbeat since %s — retry to resume', to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))`

// sweepScope narrows a platform-wide sweep query to jp.sweepTenant when one is
// set. Only tests set it: a shared test database holds other suites' jobs,
// which a sweep with a test-sized lease must not touch. args is the query's
// existing arguments; the returned clause uses the next placeholder.
func (jp *JobProcessor) sweepScope(args []interface{}) (string, []interface{}) {
	if jp.sweepTenant == "" {
		return "", args
	}
	return fmt.Sprintf(" AND tenant_id = $%d", len(args)+1), append(args, jp.sweepTenant)
}

func (jp *JobProcessor) heartbeatLeaseOrDefault() time.Duration {
	if jp.heartbeatLease > 0 {
		return jp.heartbeatLease
	}
	return jobHeartbeatLease
}

// TouchRunningJob is a running job's heartbeat: it sets updated_at on the row
// if, and only if, the job is still `running`, and reports whether it was.
func (s *DiscoveryService) TouchRunningJob(jobID string) (bool, error) {
	// RLS: cross-tenant — bypass role, keyed by job id, as UpdateJobStatus.
	res, err := s.bypassDB.Exec(`UPDATE discovery_jobs SET updated_at = NOW() WHERE id = $1 AND status = 'running'`, jobID)
	if err != nil {
		return false, fmt.Errorf("heartbeat job %s: %w", jobID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("heartbeat job %s: %w", jobID, err)
	}
	return n == 1, nil
}

// planAutoResumeLimit is how many times a scan-plan job whose owner died is
// put back in the queue automatically before it is failed instead.
//
// Resuming is safe — units that are done stay done, the attempt fence keeps a
// dead owner's late commit out — so a crash (an OOM kill, a lost node) need not
// cost the person a Retry that no screen offers. But a job that KILLS its owner
// (a scan that drives the pod out of memory) would, resumed for ever, take down
// replica after replica and every other tenant's scan on them. Three resumes
// survive the crashes that are not the job's fault — a node drain or eviction
// that was not graceful, an unrelated OOM — while bounding a poison job to four
// owner deaths, about twenty minutes of heartbeat leases, before it stops. A
// graceful shutdown hands the job back without counting (Stop), so this counts
// crashes only. A variable only so a test can set it.
var planAutoResumeLimit = 3

// autoResumesKey is where a job's count of automatic resumes lives in
// discovery_jobs.metadata (server-written, beside scan_plan).
const autoResumesKey = "auto_resumes"

// reapOutcome is what the reaper did with one job.
type reapOutcome int

const (
	reapNone    reapOutcome = iota // live, ended, or not reapable: untouched
	reapFailed                     // failed: a person's Retry resumes it
	reapResumed                    // a scan-plan job, back in the queue
)

// ReapStalledJob ends the abandonment of jobID if it is still `running` and
// its last heartbeat is older than lease, and reports whether it did. A job
// that heartbeat since the caller looked, or that ended, is left alone.
//
// What "ends" means depends on the job (see reapStalledJob): a scan-plan job
// is resumed — put back in the queue — up to planAutoResumeLimit times; every
// other job, and a plan job past the limit, is failed.
func (s *DiscoveryService) ReapStalledJob(jobID string, lease time.Duration) (bool, error) {
	out, err := s.reapStalledJob(jobID, lease)
	return out != reapNone, err
}

// reapStalledJob makes the transition in ONE statement guarded on the job still
// being `running` with a stale heartbeat, so of two replicas racing the reaper
// exactly one moves it, and an owner that beats in between keeps it.
//
// Failed: its unfinished targets become `failed` with the same message, so the
// Jobs page does not show them in progress; completed targets keep their
// outcome and findings, which is what lets a person's Retry
// (RequeueJobForRetry: every non-completed target back to pending) resume
// without scanning them again. A scan-plan job's unit in flight is failed too,
// which fences out its owner should it be alive after all.
//
// Resumed (scan-plan jobs only): status back to `queued`, metadata.auto_resumes
// counted up; the unit in flight goes back to pending — its owner's attempt
// number is then stale, so that owner can never commit it — and the targets it
// had started back to pending. Done units, their findings and finished targets
// are untouched: the next run scans only what is left. The caller publishes the
// job so another replica claims it.
func (s *DiscoveryService) reapStalledJob(jobID string, lease time.Duration) (reapOutcome, error) {
	// RLS: cross-tenant — bypass role, keyed by job id, as UpdateJobStatus.
	tx, err := s.bypassDB.Beginx()
	if err != nil {
		return reapNone, fmt.Errorf("reap job %s: %w", jobID, err)
	}
	defer func() { _ = tx.Rollback() }()
	var row struct {
		Status  string `db:"status"`
		Message string `db:"message"`
	}
	// resume: a plan job under the limit. The CTE locks the row with the
	// same predicate the UPDATE re-checks, so a concurrent reaper waiting on
	// the lock re-reads it, finds it no longer running, and moves nothing.
	err = tx.Get(&row, `
		WITH j AS (
			SELECT id, (metadata ? '`+shareddisc.ScanPlanMetadataKey+`') AND COALESCE((metadata->>'`+autoResumesKey+`')::int, 0) < $3 AS resume,
			       metadata ? '`+shareddisc.ScanPlanMetadataKey+`' AS plan,
			       COALESCE((metadata->>'`+autoResumesKey+`')::int, 0) AS resumes
			FROM discovery_jobs
			WHERE id = $1 AND status = 'running' AND `+reapableExecutionModes+`
			  AND updated_at < NOW() - make_interval(secs => $2)
			FOR UPDATE
		)
		UPDATE discovery_jobs d
		SET status = CASE WHEN j.resume THEN 'queued' ELSE 'failed' END,
		    started_at = CASE WHEN j.resume THEN NULL ELSE d.started_at END,
		    completed_at = CASE WHEN j.resume THEN NULL ELSE NOW() END,
		    error_message = CASE
		        WHEN j.resume THEN NULL
		        WHEN j.plan THEN `+stalledJobMessage+` || format(' — stopped after %s automatic resumes', j.resumes)
		        ELSE `+stalledJobMessage+` END,
		    metadata = CASE WHEN j.resume
		        THEN jsonb_set(COALESCE(d.metadata, '{}'::jsonb), '{`+autoResumesKey+`}', to_jsonb(j.resumes + 1))
		        ELSE d.metadata END
		FROM j
		WHERE d.id = j.id AND d.status = 'running' AND d.updated_at < NOW() - make_interval(secs => $2)
		RETURNING d.status, COALESCE(d.error_message, '') AS message`, jobID, lease.Seconds(), planAutoResumeLimit)
	if errors.Is(err, sql.ErrNoRows) {
		return reapNone, nil
	}
	if err != nil {
		return reapNone, fmt.Errorf("reap job %s: %w", jobID, err)
	}

	if row.Status == "queued" {
		if _, err := tx.Exec(`UPDATE discovery_job_units SET status = 'pending', started_at = NULL WHERE job_id = $1 AND status = 'running'`, jobID); err != nil {
			return reapNone, fmt.Errorf("resume job %s: hosts: %w", jobID, err)
		}
		if _, err := tx.Exec(`UPDATE discovery_targets SET status = 'pending', started_at = NULL, updated_at = NOW() WHERE job_id = $1 AND status = 'running'`, jobID); err != nil {
			return reapNone, fmt.Errorf("resume job %s: targets: %w", jobID, err)
		}
		if err := tx.Commit(); err != nil {
			return reapNone, fmt.Errorf("resume job %s: %w", jobID, err)
		}
		return reapResumed, nil
	}

	if _, err := tx.Exec(`
		UPDATE discovery_targets
		SET status = 'failed', completed_at = COALESCE(completed_at, NOW()),
		    error_message = COALESCE(error_message, $2), updated_at = NOW()
		WHERE job_id = $1 AND status NOT IN ('completed', 'failed')`, jobID, row.Message); err != nil {
		return reapNone, fmt.Errorf("reap job %s: settle targets: %w", jobID, err)
	}
	if _, err := tx.Exec(`
		UPDATE discovery_job_units
		SET status = 'failed', finished_at = NOW(), error_message = COALESCE(error_message, $2)
		WHERE job_id = $1 AND status = 'running'`, jobID, row.Message); err != nil {
		return reapNone, fmt.Errorf("reap job %s: settle hosts: %w", jobID, err)
	}
	if err := tx.Commit(); err != nil {
		return reapNone, fmt.Errorf("reap job %s: %w", jobID, err)
	}
	return reapFailed, nil
}

// reapStalledJobs ends every abandoned `running` job (see the file comment)
// and returns how many it moved. A scan-plan job it resumed is handed to
// publish (the NATS publish, from stuckJobPass) so another replica claims it
// now; without one — or if the publish fails — the queued-job sweep
// republishes it a minute later. Platform-wide by design, so it runs on the
// bypass handle like the rest of the stuck-job poll.
func (jp *JobProcessor) reapStalledJobs(publish ...func(jobID string) error) int {
	lease := jp.heartbeatLeaseOrDefault()
	scope, args := jp.sweepScope([]interface{}{lease.Seconds()})
	var stalled []string
	if err := jp.bypassDB.Select(&stalled, `
		SELECT id FROM discovery_jobs
		WHERE status = 'running' AND `+reapableExecutionModes+`
		  AND updated_at < NOW() - make_interval(secs => $1)`+scope+`
		ORDER BY updated_at ASC
		LIMIT 50`, args...); err != nil {
		log.Printf("Error checking for abandoned running jobs: %v", err)
		return 0
	}
	moved := 0
	for _, jobID := range stalled {
		out, err := jp.discoveryService.reapStalledJob(jobID, lease)
		if err != nil {
			log.Printf("Failed to reap abandoned job %s: %v", jobID, err)
			continue
		}
		switch out {
		case reapFailed:
			moved++
			log.Printf("Discovery job %s failed: no heartbeat for over %s — its processor stopped; retry to resume", jobID, lease)
		case reapResumed:
			moved++
			log.Printf("Discovery job %s resumed: no heartbeat for over %s — its processor stopped; queued again to continue after the hosts already done", jobID, lease)
			for _, p := range publish {
				if err := p(jobID); err != nil {
					log.Printf("Resumed job %s could not be published now (the queued-job sweep will): %v", jobID, err)
				}
			}
		}
	}
	return moved
}

// findQueuedJobsToRepublish lists queued jobs the stuck-job poll republishes.
//
// The window is keyed on the row's last activity (updated_at), not its
// creation: a job handed back to `queued` by a stopping processor, or retried
// by a person, can be days old and must still be picked up. A job untouched
// for 24 hours stays out, as before, so deploying this republishes nothing
// that was not already being republished.
//
// created_at keeps a 7-day ceiling: a job that keeps returning to the queue on
// its own (an automatic scan held by a pause refreshes updated_at each attempt)
// is not republished for ever. Ordering by updated_at rotates such a job to
// the back after each attempt, so it cannot starve the others, and LIMIT keeps
// each poll to at most 10 republishes per replica.
func (jp *JobProcessor) findQueuedJobsToRepublish() ([]queuedJob, error) {
	scope, args := jp.sweepScope(nil)
	var jobs []queuedJob
	err := jp.bypassDB.Select(&jobs, `
		SELECT id, updated_at FROM discovery_jobs
		WHERE status = 'queued'
		  AND updated_at < NOW() - INTERVAL '1 minute'
		  AND updated_at > NOW() - INTERVAL '24 hours'
		  AND created_at > NOW() - INTERVAL '7 days'`+scope+`
		ORDER BY updated_at ASC
		LIMIT 10`, args...)
	return jobs, err
}

// queuedJob is one row of findQueuedJobsToRepublish.
type queuedJob struct {
	ID        string    `db:"id"`
	UpdatedAt time.Time `db:"updated_at"`
}

// republishInterval is how long the stuck-job poll waits before republishing,
// again, a queued job it already republished and that nobody has touched since.
//
// "Queued for over a minute" does not mean "its message was lost". The
// subscription hands each replica one message at a time and a legacy platform
// job runs in the handler, so every job behind an eleven-minute scan sits
// queued with its message waiting in the stream — and the poll, which runs
// every 30 seconds, republished each of them every 30 seconds. On a lab deployment
// four identity probes queued behind one automatic scan picked up
// ~16 copies each; when the scan ended the backlog drained in a burst, one copy
// per job dispatched and the other ~70 were each read, re-checked and refused
// by the dispatch guard. Harmless, because the guard holds, but it buried the
// log and spent a database round trip per copy.
//
// One AckWait is the broker's own horizon for "this delivery is not coming
// back", so it is the horizon here too. A row that HAS been touched since —
// handed back by a stopping processor, put back by a pause, retried by a
// person — is a new episode and is republished on the usual one-minute rule.
const republishInterval = jobAckWait

// republishMark is what this replica remembers about its last republish of a
// job: when, and the row's updated_at at that moment.
type republishMark struct {
	at        time.Time
	updatedAt time.Time
}

func (jp *JobProcessor) clockNow() time.Time {
	if jp.clock != nil {
		return jp.clock()
	}
	return time.Now()
}

// republishDue narrows the queued jobs the poll found to the ones this replica
// should republish now (see republishInterval), and forgets jobs that are no
// longer queued so the memory stays as small as the queue.
func (jp *JobProcessor) republishDue(jobs []queuedJob) []queuedJob {
	now := jp.clockNow()
	jp.republishMu.Lock()
	defer jp.republishMu.Unlock()
	still := make(map[string]bool, len(jobs))
	var due []queuedJob
	for _, j := range jobs {
		still[j.ID] = true
		mark, seen := jp.republished[j.ID]
		if seen && mark.updatedAt.Equal(j.UpdatedAt) && now.Sub(mark.at) < republishInterval {
			continue
		}
		due = append(due, j)
	}
	for id := range jp.republished {
		if !still[id] {
			delete(jp.republished, id)
		}
	}
	return due
}

// markRepublished records a successful republish of j.
func (jp *JobProcessor) markRepublished(j queuedJob) {
	jp.republishMu.Lock()
	defer jp.republishMu.Unlock()
	if jp.republished == nil {
		jp.republished = map[string]republishMark{}
	}
	jp.republished[j.ID] = republishMark{at: jp.clockNow(), updatedAt: j.UpdatedAt}
}
