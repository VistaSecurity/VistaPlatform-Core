package services

// Running a scan-plan job ( WP2, holes H10/H16/H21). Every scan the
// platform runs comes here: since WP5 there is no other executor (a
// protocols × ports job reaching the processor is failed with the reason, see
// processDiscoveryJob), and a job for a tenant sensor never reaches this
// processor's scan path at all.
//
// One run of a job, on the replica that claimed it:
//
//  1. Units. Every target is expanded to its addresses and EACH ADDRESS IS
//     AUTHORIZED before it becomes a unit (ensureUnits); a refused address is
//     a failed unit with the reason. A resumed run keeps the units it finds.
//  2. Liveness sweep, for range targets only, in chunks: an address is
//     authorized again (the tenant's networks are re-read every minute), then
//     probed; one that gave no answer is finished there and then, one that
//     answered goes on to the port scan.
//  3. Port phase: a pool of unitWorkers(pace) workers runs each remaining
//     unit through the engine (work_unit_engine.go) — authorized once more
//     immediately before its first packet — and commits its findings, their
//     ingestion-queue mirror and its `done` in ONE transaction fenced on the
//     attempt that claimed it.
//
// Cancel and shutdown arrive through the job's context (this replica) or the
// row (another replica), checked before every unit — each check is also the
// job's heartbeat. On a cancel the unit in flight is abandoned (cancelled) and
// findings already stored stay; on shutdown it goes back to pending, so the
// next run resumes after the units that are done.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
)

// livenessChunk is how many addresses one liveness sweep call covers: enough
// to keep the pace's whole budget busy (the engine spreads a call over many
// hosts), small enough that results are committed — and progress moves — every
// few seconds.
const livenessChunk = 256

// errUnitFenced is a unit commit refused because this run no longer owns the
// unit (it was reset and claimed again by a later run).
var errUnitFenced = jobunits.ErrFenced

// planRun is one run of one scan-plan job.
type planRun struct {
	jp       *JobProcessor
	job      *models.DiscoveryJob
	targets  map[string]*planTarget
	auth     *unitAuthorizer
	engine   *shareddisc.UnitEngine
	liveness *shareddisc.Scanner
	// sweepSlots is how many unit-scheduler slots one liveness sweep takes —
	// and so how many hosts' worth of connections it may use.
	sweepSlots int
	activeScan bool
}

// processPlanJob runs a scan-plan job through its units. It returns nil when
// every unit has finished (the caller then completes the job, guarded), or the
// stop error (errJobNoLongerRunning / errProcessorStopping) when the job was
// cancelled or the processor is stopping.
func (jp *JobProcessor) processPlanJob(ctx context.Context, job *models.DiscoveryJob, opts map[string]interface{}) error {
	run, targets, err := jp.newPlanRun(job, opts)
	if err != nil {
		return err
	}
	if err := jp.checkStillRunning(ctx, job); err != nil {
		return err
	}
	if err := jp.ensureUnits(job, targets, run.auth); err != nil {
		return err
	}
	if err := jp.resetOrphanedUnits(job); err != nil {
		return fmt.Errorf("reset abandoned units: %w", err)
	}

	err = run.livenessPhase(ctx)
	if err == nil {
		err = run.portPhase(ctx)
	}
	if isJobStop(err) {
		jp.settleStoppedJob(job, errors.Is(err, errJobNoLongerRunning))
		return err
	}
	if err != nil {
		return err
	}
	if err := jp.ensurePlanUnitsTerminal(job); err != nil {
		return err
	}

	var findingCount int
	if err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&findingCount, `SELECT COUNT(*) FROM discovery_findings WHERE job_id = $1`, job.ID)
	}); err != nil {
		return fmt.Errorf("failed to count findings: %w", err)
	}
	if findingCount > 0 && jp.alertService != nil {
		if alertErr := jp.alertService.SendNewFindingsAlert(job.TenantID, job.ID, findingCount); alertErr != nil {
			log.Printf("Failed to send new-findings alert for job %s: %v", job.ID, alertErr)
		}
	}
	return nil
}

// ensurePlanUnitsTerminal is the job-level completion fence: a plan job is
// successful only if every durable per-host unit reached a terminal status.
func (jp *JobProcessor) ensurePlanUnitsTerminal(job *models.DiscoveryJob) error {
	var unfinished []struct {
		Status string `db:"status"`
		Count  int64  `db:"count"`
	}
	if err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&unfinished, `
			SELECT status, COUNT(*) AS count
			FROM discovery_job_units
			WHERE job_id = $1 AND status IN ('pending', 'running')
			GROUP BY status
			ORDER BY status`, job.ID)
	}); err != nil {
		return fmt.Errorf("verify scan-plan completion: %w", err)
	}
	if len(unfinished) == 0 {
		return nil
	}
	parts := make([]string, 0, len(unfinished))
	for _, row := range unfinished {
		parts = append(parts, fmt.Sprintf("%d %s", row.Count, row.Status))
	}
	return fmt.Errorf("scan plan left unfinished work units (%s); refusing to complete job", strings.Join(parts, ", "))
}

// newPlanRun reads what a run of job needs: its targets as planned, its OT
// opt-in, and an engine at its pace.
func (jp *JobProcessor) newPlanRun(job *models.DiscoveryJob, opts map[string]interface{}) (*planRun, []*planTarget, error) {
	targets, err := jp.loadPlanTargets(job)
	if err != nil {
		return nil, nil, err
	}
	otProbes, err := jp.jobOTProbes(job)
	if err != nil {
		return nil, nil, err
	}
	engine, err := newUnitEngine(job.Plan.Pace, otProbes, jp.planEngineOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("scan engine: %w", err)
	}
	sweepSlots := jp.units.grant(shareddisc.UnitWorkers(engine.Pace()))
	live, err := livenessScanner(job.Plan.Pace, sweepSlots, jp.planEngineOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("scan engine: %w", err)
	}
	activeScan, _ := opts["active_scan"].(bool)
	return &planRun{
		jp: jp, job: job, targets: targetByRow(targets),
		auth:   &unitAuthorizer{jp: jp, tenantID: job.TenantID, options: opts, otProbes: otProbes, platformExecutor: true},
		engine: engine, liveness: live, sweepSlots: sweepSlots, activeScan: activeScan,
	}, targets, nil
}

// jobOTProbes reads the job's OT opt-in — the audit column, which holds only
// protocols the switch allowed and a standard port exists for.
func (jp *JobProcessor) jobOTProbes(job *models.DiscoveryJob) ([]string, error) {
	var protos pq.StringArray
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&protos, `SELECT COALESCE(ot_probe_protocols, '{}') FROM discovery_jobs WHERE id = $1`, job.ID)
	})
	if err != nil {
		return nil, fmt.Errorf("read the job's OT opt-in: %w", err)
	}
	return []string(protos), nil
}

// livenessPhase sweeps the pending units of range targets that have no
// liveness verdict yet.
func (r *planRun) livenessPhase(ctx context.Context) error {
	units, err := r.jp.pendingUnits(r.job)
	if err != nil {
		return fmt.Errorf("list units: %w", err)
	}
	var sweep []jobUnit
	for _, u := range units {
		t := r.targets[u.TargetID]
		if t == nil || t.assumeUp || t.tcp.Len() == 0 || u.LivenessState.Valid {
			continue
		}
		sweep = append(sweep, u)
	}
	for lo := 0; lo < len(sweep); lo += livenessChunk {
		if err := r.jp.checkStillRunning(ctx, r.job); err != nil {
			return err
		}
		chunk := sweep[lo:min(lo+livenessChunk, len(sweep))]
		var cleared []jobUnit
		var addrs []netip.Addr
		for _, u := range chunk {
			t := r.targets[u.TargetID]
			if err := r.auth.authorizeUnit(t, u.Address); err != nil {
				r.jp.failUnit(r.job, u, t, unitPending, refusalReason(err))
				continue
			}
			a, err := netip.ParseAddr(u.Address)
			if err != nil {
				r.jp.failUnit(r.job, u, t, unitPending, "not scanned: "+u.Address+" is not an address")
				continue
			}
			cleared = append(cleared, u)
			addrs = append(addrs, a)
		}
		if len(addrs) == 0 {
			continue
		}
		release, ok := r.jp.units.acquire(ctx, r.job.TenantID, r.sweepSlots)
		if !ok {
			return stopReason(ctx)
		}
		results, err := r.liveness.Liveness(ctx, addrs)
		release()
		if err != nil {
			return fmt.Errorf("liveness: %w", err)
		}
		if err := stopReason(ctx); err != nil {
			// Verdicts cut short by the stop are not verdicts; the units
			// stay pending and the next run sweeps them again.
			return err
		}
		if err := r.recordLiveness(cleared, results); err != nil {
			return err
		}
	}
	return nil
}

// recordLiveness stores a chunk's verdicts. An address that answered keeps its
// verdict and stays pending for the port scan; one that gave no answer — or
// no verdict at all, every probe having failed on this side — is finished:
// its ports are counted not probed, and it never becomes a finding.
func (r *planRun) recordLiveness(units []jobUnit, results []shareddisc.LivenessResult) error {
	byAddr := make(map[netip.Addr]shareddisc.LivenessResult, len(results))
	for _, lv := range results {
		byAddr[lv.Addr] = lv
	}
	return r.jp.withTenantTxx(context.Background(), r.job.TenantID, func(tx *sqlx.Tx) error {
		settle := map[string]*planTarget{}
		for _, u := range units {
			a, _ := netip.ParseAddr(u.Address)
			lv, ok := byAddr[a.Unmap()]
			if !ok {
				continue
			}
			t := r.targets[u.TargetID]
			if lv.State == shareddisc.LivenessUp {
				if _, err := tx.Exec(`UPDATE discovery_job_units SET liveness_state = $2, liveness_evidence = $3 WHERE id = $1 AND status = 'pending'`,
					u.ID, lv.State.String(), lv.Evidence); err != nil {
					return err
				}
				continue
			}
			var note interface{}
			if lv.State == shareddisc.LivenessUndetermined {
				note = "no verdict: every liveness probe failed on the scanner's side (resource limits); its ports were not probed"
			}
			if _, err := tx.Exec(`
				UPDATE discovery_job_units
				SET status = 'done', attempts = attempts + 1, started_at = COALESCE(started_at, NOW()), finished_at = NOW(),
				    liveness_state = $2, liveness_evidence = NULLIF($3, ''), error_message = $4,
				    ports_requested = $5, not_probed_count = $5
				WHERE id = $1 AND status = 'pending'`,
				u.ID, lv.State.String(), lv.Evidence, note, t.tcp.Len()); err != nil {
				return err
			}
			settle[t.rowID] = t
		}
		for _, t := range settle {
			if err := settleTargetTx(tx, r.job.ID, t); err != nil {
				return err
			}
		}
		return nil
	})
}

// portPhase runs every remaining pending unit through the engine.
func (r *planRun) portPhase(ctx context.Context) error {
	units, err := r.jp.pendingUnits(r.job)
	if err != nil {
		return fmt.Errorf("list units: %w", err)
	}
	if len(units) == 0 {
		return nil
	}
	// A stop seen by one worker (a cancel read from the row, on a replica
	// that did not handle it) stops them all.
	pctx, stopPool := context.WithCancelCause(ctx)
	defer stopPool(nil)

	feed := make(chan jobUnit)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	fail := func(err error) {
		once.Do(func() { firstErr = err })
		stopPool(err)
	}
	for range min(shareddisc.UnitWorkers(r.engine.Pace()), len(units)) {
		wg.Go(func() {
			for u := range feed {
				if err := r.runUnit(pctx, u); err != nil {
					fail(err)
					return
				}
			}
		})
	}
feed:
	for _, u := range units {
		select {
		case feed <- u:
		case <-pctx.Done():
			break feed
		}
	}
	close(feed)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return stopReason(ctx)
}

// runUnit takes one unit from pending to finished. It returns only a stop
// error; anything that goes wrong with the unit itself is recorded on it.
func (r *planRun) runUnit(ctx context.Context, u jobUnit) error {
	jp, job := r.jp, r.job
	t := r.targets[u.TargetID]
	if t == nil {
		jp.failUnit(job, u, &planTarget{rowID: u.TargetID}, unitPending, "not scanned: its target is not in the job's scan plan")
		return nil
	}
	// A slot of the tenant's share, and of the replica's (unit_scheduler.go),
	// before anything else: waiting for one can take a while, and what
	// follows must be judged at the moment the unit really starts.
	release, ok := jp.units.acquire(ctx, job.TenantID, 1)
	if !ok {
		return stopReason(ctx)
	}
	defer release()

	// Before the unit's first packet: the job still running (this is also
	// its heartbeat), and the address still authorized NOW — for an automatic
	// scan, by the automatic-scan policy too (authorizeUnit).
	if err := jp.checkStillRunning(ctx, job); err != nil {
		return err
	}
	if err := r.auth.authorizeUnit(t, u.Address); err != nil {
		jp.failUnit(job, u, t, unitPending, refusalReason(err))
		return nil
	}
	addr, err := netip.ParseAddr(u.Address)
	if err != nil {
		jp.failUnit(job, u, t, unitPending, "not scanned: "+u.Address+" is not an address")
		return nil
	}

	attempt, ok, err := jp.claimUnit(job, u, t)
	if err != nil {
		log.Printf("Discovery job %s: could not claim unit %s (%s), skipping it this run: %v", job.ID, u.ID, u.Address, err)
		return nil
	}
	if !ok {
		return nil
	}

	in := shareddisc.UnitInput{Addr: addr, Hostname: t.hostname, SNICandidates: t.sniCandidates, TCP: t.tcp, UDP: t.udp}
	if u.LivenessState.Valid {
		in.Liveness = &shareddisc.LivenessResult{Addr: addr, State: shareddisc.LivenessUp, Evidence: u.LivenessEvidence.String}
	}
	out, runErr := r.engine.Run(ctx, in)
	if stop := stopReason(ctx); stop != nil {
		jp.releaseUnit(job, u.ID, attempt, errors.Is(stop, errJobNoLongerRunning))
		return stop
	}
	if runErr != nil {
		jp.failUnit(job, u, t, unitRunning, "scan failed: "+runErr.Error())
		return nil
	}
	if err := r.commitUnit(u, t, attempt, out); err != nil {
		if errors.Is(err, errUnitFenced) {
			log.Printf("Discovery job %s: unit %s (%s) was taken over by a later run; its results here are discarded", job.ID, u.ID, u.Address)
			return nil
		}
		jp.failUnit(job, u, t, unitRunning, "results could not be stored: "+err.Error())
	}
	return nil
}

// claimUnit moves a unit from pending to running, counting the attempt, and
// marks its target running. ok=false: the unit was not pending any more.
func (jp *JobProcessor) claimUnit(job *models.DiscoveryJob, u jobUnit, t *planTarget) (int, bool, error) {
	var attempt int
	found := false
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.Query(`
			UPDATE discovery_job_units
			SET status = 'running', attempts = attempts + 1, started_at = NOW(), finished_at = NULL, error_message = NULL
			WHERE id = $1 AND status = 'pending'
			RETURNING attempts`, u.ID)
		if err != nil {
			return err
		}
		for rows.Next() {
			if err := rows.Scan(&attempt); err != nil {
				_ = rows.Close()
				return err
			}
			found = true
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if !found {
			return nil
		}
		_, err = tx.Exec(`UPDATE discovery_targets SET status = 'running', started_at = COALESCE(started_at, NOW()), updated_at = NOW() WHERE job_id = $1 AND input = $2 AND status = 'pending'`,
			job.ID, t.input)
		return err
	})
	return attempt, found, err
}

// commitUnit stores a finished unit — its findings, their mirror into the
// ingestion queue, its counts and `done`, and its target's settlement — in one
// transaction fenced on the attempt this run claimed (jobunits.Commit, the
// commit a tenant sensor's reported units get too). errUnitFenced: a later run
// owns the unit, and nothing was stored.
func (r *planRun) commitUnit(u jobUnit, t *planTarget, attempt int, out shareddisc.UnitOutput) error {
	jp, job := r.jp, r.job
	unit := jobunits.Unit{ID: u.ID, JobID: job.ID, TenantID: job.TenantID, TargetID: t.rowID, TargetInput: t.input, Address: u.Address, Hostname: t.hostname}
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		return jobunits.Commit(tx, unit, out, jobunits.CommitOptions{
			From: unitRunning, Attempt: attempt, ActiveScan: r.activeScan,
			MirrorSensorID: func(jobunits.Tx) (string, error) { return jp.platformSensorIDTx(tx, job.TenantID) },
			MirrorErr: func(err error) {
				log.Printf("Discovery job %s: %v — unit %s's findings are recorded on the job but not queued for inventory", job.ID, err, u.Address)
			},
		})
	})
	if err != nil {
		return err
	}
	// The unit's findings are committed and mirrored into sensor_discoveries
	// under the job's id: wake discovery-processor now rather than leaving the
	// host's findings to its fallback poll. After the commit, never inside it
	// (jobunits.Commit runs in the caller's transaction and must not publish).
	if tenant, perr := uuid.Parse(job.TenantID); perr == nil {
		_ = events.PublishDiscoveryQueueReady(context.Background(), jp.queuePublisher, tenant, job.ID, "cluster-sensor.commit_unit")
	}
	return nil
}
