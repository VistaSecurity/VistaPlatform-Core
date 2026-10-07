package services

// Work units ( WP2, hole H10): the durable record of a scan-plan job's
// work, one row per address its targets expand to. See the
// discovery_job_units block in scripts/database/schema.sql for the table, and
// work_unit_executor.go for how a job runs through them.
//
// What a unit buys a long scan:
//
//   - real progress — finished units over total, not a number per target;
//   - incremental results — a host's findings are stored, and queued for
//     inventory, the moment that host is done;
//   - resume — a person's Retry, or a hand-back on shutdown, runs only the
//     units that are not done;
//   - bounded memory — nothing is held past the unit that produced it.
//
// The job-owner model of/ is unchanged: one replica claims the job
// and owns its heartbeat, its cancel registry entry and its reaper protection.
// Units are that owner's local work list, not a distribution mechanism.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// Unit statuses. done and failed are finished; cancelled was never run (or
// was stopped) because the job was cancelled.
const (
	unitPending   = "pending"
	unitRunning   = "running"
	unitDone      = "done"
	unitFailed    = "failed"
	unitCancelled = "cancelled"
)

// unitInsertBatch bounds one INSERT's arrays: a /18 is 16,384 units.
const unitInsertBatch = 2000

// unitScopeTTL is how long one read of the tenant's registered networks and
// exclusions is trusted while a job runs. The legacy path reads it once per
// target, which for a /24 is hours; re-reading every minute means a segment
// withdrawn, or an exclusion added, mid-scan stops the scan of those
// addresses within a minute. A variable only so a test can make every unit
// re-read it.
var unitScopeTTL = time.Minute

// planTarget is one scan-plan target as the executor runs it.
type planTarget struct {
	rowID string
	input string
	// hostname is the name presented as SNI: the input when it is a
	// hostname, "" for an address or a range.
	hostname string
	// sniCandidates are names this address target is known by, offered as SNI
	// to a TLS port that refuses the nameless attempt. Taken from the plan
	// (already sanitized when it was built) and sanitized again here, since the
	// plan is a stored document.
	sniCandidates []string
	// assumeUp skips the liveness sweep: a target that names one host (an
	// address, or a hostname a person typed) was asked for by name, so there
	// is nothing to prune, and a host that answers on none of the liveness
	// ports must still be port-scanned. Ranges and CIDRs are swept first.
	assumeUp bool
	tcp      shareddisc.PortSet
	udp      []int
	grant    jobTargetGrant
	// depth is the depth the plan applied to this target.
	depth shareddisc.ScanDepth
}

// jobUnit is one row of discovery_job_units as the executor reads it.
type jobUnit struct {
	ID               string         `db:"id"`
	TargetID         string         `db:"target_id"`
	Address          string         `db:"address"`
	Status           string         `db:"status"`
	LivenessState    sql.NullString `db:"liveness_state"`
	LivenessEvidence sql.NullString `db:"liveness_evidence"`
}

// targetRow is a discovery_targets row of a scan-plan job.
type targetRow struct {
	ID        string         `db:"id"`
	Input     string         `db:"input"`
	Protocols pq.StringArray `db:"protocols"`
	Ports     pq.Int32Array  `db:"ports"`
	Status    string         `db:"status"`
}

// loadPlanTargets turns a scan-plan job's target rows into the executor's
// targets. Each plan row (no protocols) carries its planned TCP ports; the
// plan carries its UDP ports. An OT target row of the same input (the job's
// ot_probe_protocols opt-in, one row per protocol at its standard port) is
// folded into that target: its port joins the TCP set when the protocol has a
// TCP prober and the UDP set when it is a UDP one, so the opt-in is probed by
// identification rather than by a separate legacy pass. Nothing else widens
// the plan.
func (jp *JobProcessor) loadPlanTargets(job *models.DiscoveryJob) ([]*planTarget, error) {
	var rows []targetRow
	if err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&rows, `SELECT id, input, protocols, ports, status FROM discovery_targets WHERE job_id = $1 ORDER BY created_at, id`, job.ID)
	}); err != nil {
		return nil, fmt.Errorf("failed to get job targets: %w", err)
	}
	planned := make(map[string]shareddisc.PlanTarget, len(job.Plan.Targets))
	for _, pt := range job.Plan.Targets {
		planned[pt.Target] = pt
	}
	var out []*planTarget
	byInput := map[string]*planTarget{}
	for _, r := range rows {
		if len(r.Protocols) > 0 {
			continue
		}
		pt, ok := planned[r.Input]
		if !ok {
			return nil, fmt.Errorf("target %q is not in the job's scan plan", r.Input)
		}
		tcp, err := pt.TCPPortSet()
		if err != nil {
			return nil, fmt.Errorf("plan for %s: %w", r.Input, err)
		}
		udp, err := pt.UDPPortSet()
		if err != nil {
			return nil, fmt.Errorf("plan for %s: %w", r.Input, err)
		}
		t := &planTarget{rowID: r.ID, input: r.Input, tcp: tcp, udp: udp.Ports(), depth: pt.Depth,
			sniCandidates: shareddisc.SanitizeSNICandidates(pt.SNICandidates)}
		if net.ParseIP(r.Input) == nil && !shareddisc.IsNetworkRange(r.Input) {
			t.hostname = r.Input
		}
		t.assumeUp = !shareddisc.IsNetworkRange(r.Input)
		out = append(out, t)
		byInput[r.Input] = t
	}
	for _, r := range rows {
		t, ok := byInput[r.Input]
		if len(r.Protocols) == 0 || !ok {
			continue
		}
		for _, p := range r.Ports {
			port := int(p)
			if shareddisc.IsUDPProtocol(r.Protocols[0]) {
				if !containsInt(t.udp, port) {
					t.udp = append(t.udp, port)
				}
				continue
			}
			extra, err := shareddisc.NewPortSet(port)
			if err != nil {
				return nil, fmt.Errorf("OT target %s: %w", r.Input, err)
			}
			t.tcp = t.tcp.Union(extra)
		}
	}
	return out, nil
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// unitAuthorizer is the per-address authorization a unit passes before ANY
// packet is sent to its address — the liveness probe included (hole H16). It
// is the dispatchguard judgement every scan passes before contact (the same the
// removed legacy executor applied: registered networks, exclusions, reserved and platform
// ranges, and an external address only inside what a person confirmed with the
// operator switch on NOW), asked one address at a time so a refused address
// fails only its own unit.
type unitAuthorizer struct {
	jp       *JobProcessor
	tenantID string
	// options are the job's options; for an automatic scan (origin
	// "auto_scan") every unit also passes the automatic-scan policy NOW
	// (authorizeUnit).
	options map[string]interface{}
	// otProbes is the job's OT opt-in, which an automatic scan may not have.
	otProbes []string
	// platformExecutor is true when the in-cluster Platform Sensor will scan
	// these addresses itself (processPlanJob), and false when the units only
	// record what a tenant's own sensor was handed (dispatchToSensor). Only the
	// former refuses the cluster's own pod and Service CIDRs: to a tenant's
	// on-premises sensor those numbers are the customer's address space.
	platformExecutor bool

	mu     sync.Mutex
	scope  dispatchguard.TargetScope
	loaded time.Time
}

func (a *unitAuthorizer) current() (dispatchguard.TargetScope, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.loaded.IsZero() && time.Since(a.loaded) < unitScopeTTL {
		return a.scope, nil
	}
	var scope dispatchguard.TargetScope
	if err := a.jp.withTenantTxx(context.Background(), a.tenantID, func(tx *sqlx.Tx) error {
		s, err := dispatchguard.LoadTargetScope(tx, a.tenantID)
		if a.platformExecutor {
			s = s.ForPlatformSensor()
		}
		scope = s
		return err
	}); err != nil {
		return dispatchguard.TargetScope{}, err
	}
	a.scope, a.loaded = scope, time.Now()
	return scope, nil
}

// authorize returns nil when addr may be contacted for this job, or the
// refusal. A failed scope read refuses: an address nothing could authorize is
// not an authorized one.
func (a *unitAuthorizer) authorize(addr string, consent dispatchguard.DispatchConsent) error {
	scope, err := a.current()
	if err != nil {
		return fmt.Errorf("could not read the networks this tenant may scan: %w", err)
	}
	return scope.AuthorizeDispatch([]string{addr}, consent, dispatchguard.ExternalPolicyFromEnv())
}

// authorizeUnit is the check every unit passes before any packet to addr:
// the target authorization above and, for an automatic scan, the
// automatic-scan policy re-read NOW ( WP2) — switched on, the address
// still in the tenant's scope and not excluded, still a tenant asset that is
// not sensitive, and the target's TCP ports still ones the policy allows, with
// no UDP port, no OT probe and a custom or quick depth. It is the planned
// counterpart of the AuthorizeAutomaticScan each legacy target passed (the
// executor was removed in WP5), asked one address at a time so a refused address fails only
// its own unit.
func (a *unitAuthorizer) authorizeUnit(t *planTarget, addr string) error {
	if err := a.authorize(addr, t.grant.consent); err != nil {
		return err
	}
	if !dispatchguard.IsAutomaticScan(a.options) {
		return nil
	}
	udp, err := shareddisc.NewPortSet(t.udp...)
	if err != nil {
		return err
	}
	payload := sensordispatch.Payload{TenantID: a.tenantID, Options: a.options, Plan: &sensordispatch.PlanPayload{
		Version: sensordispatch.PlanPayloadVersion, Attempt: 1, OTProbeProtocols: a.otProbes,
		Targets: []sensordispatch.PlanTargetWork{{PlanTarget: shareddisc.PlanTarget{
			Target: addr, Depth: t.depth, TCPPorts: t.tcp.String(), UDPPorts: udp.String(),
		}}},
	}}
	return a.jp.withTenantTxx(context.Background(), a.tenantID, func(tx *sqlx.Tx) error {
		return dispatchguard.AuthorizeAutomaticScan(tx, payload)
	})
}

// refusalReason is the sentence a refused unit carries.
func refusalReason(err error) string {
	var refused *dispatchguard.RefusedTargetsError
	if errors.As(err, &refused) && len(refused.Targets) == 1 {
		return "not scanned: " + refused.Targets[0].Reason
	}
	return "not scanned: " + err.Error()
}

// ensureUnits creates the units of every target that has none yet, each
// address authorized first: a cleared address becomes a pending unit, a
// refused one a failed unit carrying the reason. A target that already has
// units (a resumed run) is left as it is — its units, done or not, are the
// record. Re-running this adds nothing ((job_id, target_id, address) is
// unique).
func (jp *JobProcessor) ensureUnits(job *models.DiscoveryJob, targets []*planTarget, auth *unitAuthorizer) error {
	for _, t := range targets {
		var has bool
		if err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
			g, err := loadJobTargetGrant(tx, job.ID, t.input)
			if err != nil {
				return err
			}
			t.grant = g
			return tx.Get(&has, `SELECT EXISTS (SELECT 1 FROM discovery_job_units WHERE target_id = $1)`, t.rowID)
		}); err != nil {
			return fmt.Errorf("read units of %s: %w", t.input, err)
		}
		if has {
			continue
		}
		addresses := jp.expandTarget(t.input, t.grant.pinned)
		if len(addresses) == 0 {
			addresses = []string{t.input}
		}
		statuses := make([]string, len(addresses))
		reasons := make([]string, len(addresses))
		for i, addr := range addresses {
			statuses[i] = unitPending
			if err := auth.authorizeUnit(t, addr); err != nil {
				statuses[i], reasons[i] = unitFailed, refusalReason(err)
			}
		}
		for lo := 0; lo < len(addresses); lo += unitInsertBatch {
			hi := min(lo+unitInsertBatch, len(addresses))
			if err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
				_, err := tx.Exec(`
					INSERT INTO discovery_job_units (tenant_id, job_id, target_id, address, status, error_message, finished_at)
					SELECT $1, $2, $3, u.address, u.status, NULLIF(u.reason, ''), CASE WHEN u.status = 'failed' THEN NOW() END
					FROM unnest($4::text[], $5::text[], $6::text[]) AS u(address, status, reason)
					ON CONFLICT (job_id, target_id, address) DO NOTHING`,
					job.TenantID, job.ID, t.rowID, pq.Array(addresses[lo:hi]), pq.Array(statuses[lo:hi]), pq.Array(reasons[lo:hi]))
				return err
			}); err != nil {
				return fmt.Errorf("create units of %s: %w", t.input, err)
			}
		}
		// A target every address of which was refused is finished already.
		if err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
			return settleTargetTx(tx, job.ID, t)
		}); err != nil {
			return err
		}
	}
	return nil
}

// settleTargetTx finishes a target's row(s) once none of its units is pending
// or running (jobunits.SettleTarget — the same settlement a tenant sensor's
// reported units get).
func settleTargetTx(tx *sqlx.Tx, jobID string, t *planTarget) error {
	return jobunits.SettleTarget(tx, jobID, t.rowID, t.input)
}

// resetOrphanedUnits puts back to pending any unit still `running` when a run
// starts. The claim on the job means nobody else is running it, so such a unit
// was abandoned by an earlier owner (a crash, a kill); its attempt number moves
// on when it is claimed again, so that owner — if it is in fact alive — can no
// longer commit it.
func (jp *JobProcessor) resetOrphanedUnits(job *models.DiscoveryJob) error {
	return jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		_, err := tx.Exec(`UPDATE discovery_job_units SET status = 'pending', started_at = NULL WHERE job_id = $1 AND status = 'running'`, job.ID)
		return err
	})
}

// pendingUnits lists the job's units still to run, in target then address
// order.
func (jp *JobProcessor) pendingUnits(job *models.DiscoveryJob) ([]jobUnit, error) {
	var units []jobUnit
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&units, `
			SELECT id, target_id, address, status, liveness_state, liveness_evidence
			FROM discovery_job_units WHERE job_id = $1 AND status = 'pending'
			ORDER BY target_id, address`, job.ID)
	})
	return units, err
}

// failUnit settles a unit that never ran (refused at run time) or could not be
// stored, with the reason. from is the status it must still be in.
func (jp *JobProcessor) failUnit(job *models.DiscoveryJob, u jobUnit, t *planTarget, from, reason string) {
	if err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		if _, err := tx.Exec(`UPDATE discovery_job_units SET status = 'failed', error_message = $2, finished_at = NOW() WHERE id = $1 AND status = $3`,
			u.ID, reason, from); err != nil {
			return err
		}
		return settleTargetTx(tx, job.ID, t)
	}); err != nil {
		log.Printf("Discovery job %s: could not record unit %s (%s) as failed: %v", job.ID, u.ID, u.Address, err)
	}
}

// releaseUnit hands a unit this run claimed back after the job stopped under
// it: to pending on shutdown (a later run resumes it), to cancelled on a
// cancel. Guarded on the attempt this run claimed, so it never touches a unit
// a later owner has since claimed.
func (jp *JobProcessor) releaseUnit(job *models.DiscoveryJob, unitID string, attempt int, cancelled bool) {
	status := unitPending
	if cancelled {
		status = unitCancelled
	}
	if err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		_, err := tx.Exec(`
			UPDATE discovery_job_units
			SET status = $2, started_at = CASE WHEN $2 = 'pending' THEN NULL ELSE started_at END,
			    finished_at = CASE WHEN $2 = 'cancelled' THEN NOW() ELSE NULL END
			WHERE id = $1 AND status = 'running' AND attempts = $3`, unitID, status, attempt)
		return err
	}); err != nil {
		log.Printf("Discovery job %s: could not release unit %s: %v", job.ID, unitID, err)
	}
}

// settleStoppedJob tidies the job's rows after a run stopped part way. On a
// cancel, units and targets not reached become cancelled (CancelJob did the
// same for the replica that handled the cancel; a cancel seen only through the
// row, from another replica, did not). On shutdown, targets this run had
// started go back to pending, like the legacy path's.
func (jp *JobProcessor) settleStoppedJob(job *models.DiscoveryJob, cancelled bool) {
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		if cancelled {
			if _, err := tx.Exec(`UPDATE discovery_job_units SET status = 'cancelled', finished_at = NOW() WHERE job_id = $1 AND status = 'pending'`, job.ID); err != nil {
				return err
			}
			_, err := tx.Exec(`UPDATE discovery_targets SET status = 'cancelled', completed_at = NOW(), updated_at = NOW() WHERE job_id = $1 AND status IN ('pending', 'running')`, job.ID)
			return err
		}
		_, err := tx.Exec(`UPDATE discovery_targets SET status = 'pending', started_at = NULL, updated_at = NOW() WHERE job_id = $1 AND status = 'running'`, job.ID)
		return err
	})
	if err != nil {
		log.Printf("Discovery job %s: could not settle units after stopping: %v", job.ID, err)
	}
}

// targetByRow indexes targets by their row id.
func targetByRow(targets []*planTarget) map[string]*planTarget {
	out := make(map[string]*planTarget, len(targets))
	for _, t := range targets {
		out[t.rowID] = t
	}
	return out
}
