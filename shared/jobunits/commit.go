package jobunits

// Storing a finished unit ( WP2). See the discovery_job_units block in
// scripts/database/schema.sql for the table.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// Tx is the transaction a unit is stored in: *sql.Tx and *sqlx.Tx both are
// one. The caller has set the tenant context on it (every table here is
// RLS-scoped).
type Tx interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// ErrFenced is a unit commit refused because the caller no longer owns the
// unit: it is not in the status the caller left it in, or a later attempt has
// claimed it. Nothing was stored; the caller's transaction must roll back.
var ErrFenced = errors.New("unit is no longer owned by this attempt")

// Unit is one discovery_job_units row as a commit names it.
type Unit struct {
	ID       string
	JobID    string
	TenantID string
	// TargetID and TargetInput are the plan target the unit belongs to.
	TargetID    string
	TargetInput string
	Address     string
	// Hostname is the target's name when it named one ("" otherwise).
	Hostname string
}

// CommitOptions says which attempt the caller holds, and how to queue the
// unit's findings for inventory.
type CommitOptions struct {
	// From is the status the unit must still be in: "running" for a unit the
	// Platform Sensor claimed, "pending" for one a tenant sensor reports.
	From string
	// Attempt is the attempt the caller holds the unit under.
	Attempt int
	// MirrorSensorID returns the sensor the findings are queued under
	// (sensor_discoveries.sensor_id). It is asked only when a finding is to
	// be queued; an error records the findings on the job without queueing
	// them, and is logged by the caller through MirrorErr.
	MirrorSensorID func(Tx) (string, error)
	// MirrorErr, when set, is told why findings were not queued.
	MirrorErr func(error)
	// ActiveScan selects the mirror's provenance stamp (MirrorMetadata).
	ActiveScan bool
	// DiscoveryMethod is the discovery_method the mirrored rows carry
	// (ExecutorMirrorMetadata): sensordispatch.DiscoveryMethodActive for a
	// unit a tenant sensor ran, "" for the platform's.
	DiscoveryMethod string
}

// Commit stores a finished unit: its findings, their mirror into the ingestion
// queue, its counts and `done`, and its target's settlement — in the caller's
// ONE transaction, so a unit is never done without its findings or the
// reverse.
//
// Idempotency (a unit's findings are stored once however often it runs or is
// reported):
//
//   - the `done` transition is fenced on the status and attempt the caller
//     holds, and ErrFenced is returned when it matches nothing — the caller
//     rolls back, so of two writers of the same unit (a replica presumed dead
//     that was not, and the run that replaced it; a sensor re-sending a report
//     already stored) at most one stores, and the loser stores nothing;
//   - findings are deleted by unit_id before they are inserted, so even a
//     commit that got past the fence could not leave two copies in the job
//     record.
func Commit(tx Tx, u Unit, out shareddisc.UnitOutput, o CommitOptions) error {
	findings := Findings(u.Address, u.Hostname, out)
	c := CountsOf(out)
	res, err := tx.Exec(`
		UPDATE discovery_job_units
		SET status = 'done', finished_at = NOW(), started_at = COALESCE(started_at, NOW()), error_message = $4,
		    liveness_state = $5, liveness_evidence = NULLIF($6, ''),
		    ports_requested = $7, open_count = $8, closed_count = $9, filtered_count = $10,
		    local_error_count = $11, not_probed_count = $12, responds_on_all_ports = $13,
		    ot_suspect = $14, udp_answered_count = $15
		WHERE id = $1 AND status = $2 AND attempts = $3`,
		u.ID, o.From, o.Attempt, Note(out), c.LivenessState, c.LivenessEvidence,
		c.PortsRequested, c.Open, c.Closed, c.Filtered, c.LocalErrors, c.NotProbed, c.Tarpit, c.OTSuspect, c.UDPAnswered)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrFenced
	}
	if _, err := tx.Exec(`DELETE FROM discovery_findings WHERE unit_id = $1`, u.ID); err != nil {
		return err
	}
	sensorID := ""
	if len(findings) > 0 && o.MirrorSensorID != nil {
		id, err := o.MirrorSensorID(tx)
		if err == nil {
			sensorID = id
		} else if o.MirrorErr != nil {
			o.MirrorErr(err)
		}
	}
	for i := range findings {
		f := &findings[i]
		if err := InsertFinding(tx, u, f); err != nil {
			return err
		}
		if f.Mirror && sensorID != "" {
			if err := InsertMirror(tx, sensorID, u, f, o.ActiveScan, o.DiscoveryMethod); err != nil {
				return err
			}
		}
	}
	return SettleTarget(tx, u.JobID, u.TargetID, u.TargetInput)
}

// InsertFinding is the job record of one finding, carrying its unit.
func InsertFinding(tx Tx, u Unit, f *Finding) error {
	var details interface{}
	if len(f.Data) > 0 {
		raw, err := json.Marshal(f.Data)
		if err != nil {
			return fmt.Errorf("marshal finding data: %w", err)
		}
		details = string(raw)
	}
	var resolved, hostname interface{}
	if f.ResolvedIP != "" {
		resolved = f.ResolvedIP
	}
	if f.Hostname != "" {
		hostname = f.Hostname
	}
	_, err := tx.Exec(`
		INSERT INTO discovery_findings (job_id, target_id, tenant_id, unit_id, executed_via, protocol, port, resolved_ip, hostname, confidence_score, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		u.JobID, u.TargetID, u.TenantID, u.ID, f.ExecutedVia, cryptoparse.NormalizeProtocol(f.Protocol),
		f.Port, resolved, hostname, f.Confidence, details, f.CreatedAt)
	return err
}

// InsertMirror queues one finding for inventory: the row enters
// sensor_discoveries — the ingestion queue every observation goes through —
// as the host finishes, not when the job ends.
func InsertMirror(tx Tx, sensorID string, u Unit, f *Finding, activeScan bool, discoveryMethod string) error {
	if f.ResolvedIP == "" {
		return nil // sensor_discoveries.dest_ip is NOT NULL — nothing to anchor on
	}
	meta, err := json.Marshal(ExecutorMirrorMetadata(f.Data, activeScan, u.JobID, discoveryMethod))
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	var hostname interface{}
	if f.Hostname != "" {
		hostname = f.Hostname
	}
	_, err = tx.Exec(`
		INSERT INTO sensor_discoveries
			(sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, hostname, "timestamp", created_at)
		VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8::jsonb, $9, NOW(), NOW())`,
		sensorID, u.TenantID, u.JobID, cryptoparse.NormalizeProtocol(f.Protocol), f.ResolvedIP, f.Port,
		f.Confidence, string(meta), hostname)
	return err
}

// SettleTarget finishes a target's row(s) — the plan row and any OT row of
// the same input — once none of its units is pending or running: cancelled if
// any unit was cancelled, completed if any finished done, otherwise failed with
// the first refusal's reason. A target with work left is not touched.
func SettleTarget(tx Tx, jobID, targetID, input string) error {
	_, err := tx.Exec(`
		WITH u AS (
			SELECT COUNT(*) FILTER (WHERE status IN ('pending', 'running')) AS open,
			       COUNT(*) FILTER (WHERE status = 'cancelled')            AS cancelled,
			       COUNT(*) FILTER (WHERE status = 'done')                 AS done,
			       (SELECT error_message FROM discovery_job_units
			         WHERE target_id = $2 AND status = 'failed' AND error_message IS NOT NULL
			         ORDER BY address LIMIT 1)                            AS reason
			FROM discovery_job_units WHERE target_id = $2
		)
		UPDATE discovery_targets t
		SET status = CASE WHEN u.cancelled > 0 THEN 'cancelled' WHEN u.done > 0 THEN 'completed' ELSE 'failed' END,
		    error_message = CASE WHEN u.cancelled = 0 AND u.done = 0 THEN COALESCE(t.error_message, u.reason) ELSE t.error_message END,
		    completed_at = COALESCE(t.completed_at, NOW()), updated_at = NOW()
		FROM u
		WHERE t.job_id = $1 AND t.input = $3 AND t.status IN ('pending', 'running') AND u.open = 0`,
		jobID, targetID, input)
	if err != nil {
		return fmt.Errorf("settle target %s: %w", input, err)
	}
	return nil
}
