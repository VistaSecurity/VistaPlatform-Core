package services

// Coverage and progress of a scan-plan job, from its work units ( H3,
// H10, H21; spec §1 "Job detail — coverage"). A legacy job has no units and
// keeps TargetProgress.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

// unitTally is the units of one job, summed in SQL.
type unitTally struct {
	Total        int            `db:"total"`
	Pending      int            `db:"pending"`
	Cancelled    int            `db:"cancelled"`
	Failed       int            `db:"failed"`
	Responded    int            `db:"responded"`
	NoAnswer     int            `db:"no_answer"`
	Undetermined int            `db:"undetermined"`
	Incomplete   int            `db:"incomplete"`
	NoVerdict    int            `db:"no_verdict"`
	Requested    int64          `db:"requested"`
	Open         int64          `db:"open"`
	Closed       int64          `db:"closed"`
	Filtered     int64          `db:"filtered"`
	LocalErrors  int64          `db:"local_errors"`
	NotProbed    int64          `db:"not_probed"`
	Tarpits      int            `db:"tarpits"`
	OTSuspect    int            `db:"ot_suspect"`
	UDPAnswered  int            `db:"udp_answered"`
	FirstFailure sql.NullString `db:"first_failure"`
}

// unitRespondedSQL is when a unit "responded", over discovery_job_units'
// columns: exactly as the engine's HostScan.Responded says — a port open or
// refused, or a TCP liveness answer — or when a UDP service replied. The
// coverage count and the hosts "Results by host" lists (job_results_by_host.go)
// both use it, so the two can never disagree about who answered.
const unitRespondedSQL = `(open_count > 0 OR closed_count > 0 OR udp_answered_count > 0
		        OR COALESCE(liveness_evidence, '') LIKE 'tcp-%')`

// unitTallySQL sums a job's units. A finished unit "responded" per
// unitRespondedSQL; "no answer" when it was probed and nothing came back;
// anything else finished is undetermined.
const unitTallySQL = `
	WITH u AS (
		SELECT status, error_message, address,
		       ` + unitRespondedSQL + ` AS responded,
		       -- A UDP-only unit (no TCP port asked for) whose services all
		       -- stayed silent was probed and nothing answered, too.
		       (filtered_count > 0 OR liveness_state = 'no_answer' OR ports_requested = 0) AS probed,
		       liveness_state,
		       ports_requested, open_count, closed_count, filtered_count, local_error_count,
		       not_probed_count, responds_on_all_ports, ot_suspect, udp_answered_count
		FROM discovery_job_units WHERE job_id = $1 AND tenant_id = $2
	)
	SELECT COUNT(*) AS total,
	       COUNT(*) FILTER (WHERE status IN ('pending', 'running')) AS pending,
	       COUNT(*) FILTER (WHERE status = 'cancelled') AS cancelled,
	       COUNT(*) FILTER (WHERE status = 'failed') AS failed,
	       COUNT(*) FILTER (WHERE status = 'done' AND responded) AS responded,
	       COUNT(*) FILTER (WHERE status = 'done' AND NOT responded AND probed) AS no_answer,
	       COUNT(*) FILTER (WHERE status = 'done' AND NOT responded AND NOT probed) AS undetermined,
	       COUNT(*) FILTER (WHERE status = 'done' AND error_message IS NOT NULL AND COALESCE(liveness_state, '') <> 'undetermined') AS incomplete,
	       COUNT(*) FILTER (WHERE status = 'done' AND liveness_state = 'undetermined') AS no_verdict,
	       COALESCE(SUM(ports_requested) FILTER (WHERE status = 'done'), 0) AS requested,
	       COALESCE(SUM(open_count) FILTER (WHERE status = 'done'), 0) AS open,
	       COALESCE(SUM(closed_count) FILTER (WHERE status = 'done'), 0) AS closed,
	       COALESCE(SUM(filtered_count) FILTER (WHERE status = 'done'), 0) AS filtered,
	       COALESCE(SUM(local_error_count) FILTER (WHERE status = 'done'), 0) AS local_errors,
	       COALESCE(SUM(not_probed_count) FILTER (WHERE status = 'done'), 0) AS not_probed,
	       COUNT(*) FILTER (WHERE status = 'done' AND responds_on_all_ports) AS tarpits,
	       COUNT(*) FILTER (WHERE status = 'done' AND ot_suspect) AS ot_suspect,
	       COALESCE(SUM(udp_answered_count) FILTER (WHERE status = 'done'), 0) AS udp_answered,
	       (SELECT error_message FROM u WHERE status = 'failed' AND error_message IS NOT NULL ORDER BY address LIMIT 1) AS first_failure
	FROM u`

// JobUnitCoverage reads a job's units and returns its coverage and its
// progress — finished units (done, or failed with a reason) over all units.
// ok is false when the job has no units (a legacy job, a job for a tenant
// sensor, or a scan-plan job not yet started): the caller keeps its per-target
// progress then.
func (s *DiscoveryService) JobUnitCoverage(tenantID, jobID, jobStatus, executor string) (*models.JobCoverage, int, bool, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, 0, false, fmt.Errorf("invalid tenant_id: %w", err)
	}
	var t unitTally
	if err := s.withTenantTxx(context.Background(), tenant, func(tx *sqlx.Tx) error {
		return tx.Get(&t, unitTallySQL, jobID, tenant)
	}); err != nil {
		return nil, 0, false, err
	}
	if t.Total == 0 {
		return nil, 0, false, nil
	}
	return coverageFrom(t, jobStatus, executor), unitProgress(t), true, nil
}

// unitProgress is the integer percent of a job's hosts the scanner is
// finished with. A cancelled unit was never reached and does not count as done.
func unitProgress(t unitTally) int {
	if t.Total <= 0 {
		return 0
	}
	finished := t.Total - t.Pending - t.Cancelled
	return finished * 100 / t.Total
}

// coverageFrom turns a tally into the coverage a person reads, with the
// warnings the numbers alone would hide.
func coverageFrom(t unitTally, jobStatus, executor string) *models.JobCoverage {
	c := &models.JobCoverage{
		HostsTotal: t.Total, HostsResponded: t.Responded, HostsNoAnswer: t.NoAnswer,
		HostsUndetermined: t.Undetermined, HostsFailed: t.Failed, HostsPending: t.Pending, HostsCancelled: t.Cancelled,
		PortsRequested: t.Requested, PortsOpen: t.Open, PortsClosed: t.Closed, PortsFiltered: t.Filtered,
		PortsLocalErrors: t.LocalErrors, PortsNotProbed: t.NotProbed,
		TarpitHosts: t.Tarpits, OTSuspectHosts: t.OTSuspect, UDPAnswered: t.UDPAnswered,
		Warnings: []string{},
	}
	scanned := t.Responded + t.NoAnswer + t.Undetermined
	if t.Pending == 0 && scanned > 0 && t.Responded == 0 {
		w := fmt.Sprintf("0 of %d scanned addresses responded", scanned)
		if executor == "platform" {
			w += " — the platform sensor may not be able to reach this network; run the scan from a sensor on that network"
		} else {
			w += " — check that the sensor can reach this network"
		}
		c.Warnings = append(c.Warnings, w)
	}
	if t.LocalErrors > 0 || t.NoVerdict > 0 {
		c.Warnings = append(c.Warnings, fmt.Sprintf(
			"scanner resource limits were hit: %d port probe(s) failed on the scanner's own side and %d address(es) could not be checked at all; those were not tested — run the scan again at a slower pace",
			t.LocalErrors, t.NoVerdict))
	}
	if t.Tarpits > 0 {
		c.Warnings = append(c.Warnings, fmt.Sprintf(
			"%d host(s) accepted connections on almost every port probed (a tarpit, or a firewall answering for everything); their open ports are a sample, not a list",
			t.Tarpits))
	}
	if t.Incomplete > 0 {
		c.Warnings = append(c.Warnings, fmt.Sprintf("%d host(s) stopped at their time limit; ports they did not reach are counted not probed", t.Incomplete))
	}
	if t.Failed > 0 {
		w := fmt.Sprintf("%d address(es) could not be scanned", t.Failed)
		if t.FirstFailure.Valid {
			w += " (e.g. " + t.FirstFailure.String + ")"
		}
		c.Warnings = append(c.Warnings, w)
	}
	if jobStatus == "cancelled" && t.Cancelled > 0 {
		c.Warnings = append(c.Warnings, fmt.Sprintf("stopped at %d of %d hosts: the scan was cancelled", t.Total-t.Pending-t.Cancelled, t.Total))
	}
	return c
}
