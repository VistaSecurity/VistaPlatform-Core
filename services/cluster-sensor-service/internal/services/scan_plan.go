package services

// Scan-plan jobs ( WP3): the half of CreateJob that turns scan_depth,
// ports, pace and run_from into the job's ScanPlan. The rules are in
// shared/discovery (the request and the plan) and shared/sensordispatch (Auto);
// this file reads what they need from the database inside the job-creation
// transaction and records the answer on the job.
//
// The job's target rows carry each target's planned TCP ports and no
// protocols; the plan in metadata is the full record (UDP, depth, pace). A
// platform-run plan job is executed from it in work units
// (work_unit_executor.go, WP2).

import (
	"database/sql"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// There is no switch to refuse the scan-plan shape any more ( WP5): the
// shared engine is the only executor in either runtime, so turning plans off
// would leave every scan with nothing to run it.

// platformExecutionMode is the execution_mode a job run in-cluster is stored
// with — what Active Scan's platform jobs already carry.
const platformExecutionMode = "async"

// normalizeLegacyExecutionMode is hole H37's fix. cluster-sensor's job
// processor reads a STORED execution_mode of "cloud" as a cloud-ACCOUNT
// discovery and hands it to device-interrogation-service, which then fails it
// with "no integration_id in job metadata" — while the Discover wizard's
// "Cloud — platform sensor" option sends exactly "cloud" to mean "run from the
// platform". Real cloud-account jobs never come through here:
// device-interrogation-service inserts its own discovery_jobs rows directly.
// So on this endpoint "cloud" is an alias of run_from "platform" and is stored
// as the in-cluster mode; it must never be stored as "cloud".
func normalizeLegacyExecutionMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "cloud") {
		return platformExecutionMode
	}
	return mode
}

// applyRunFrom sets the request's dispatch fields from a scan-plan run_from,
// so the existing sensor checks (unknown 404, platform's own or air-gapped
// 400, offline 409) apply unchanged. Auto starts on the platform and may be
// moved to a sensor once the targets are classified (planScanJob).
func applyRunFrom(req *models.CreateDiscoveryJobRequest, shape shareddisc.JobRequestShape) {
	switch shape.RunFrom {
	case shareddisc.RunFromSensor:
		req.ExecutionMode = "sensors"
		req.PreferredSensorIDs = []string{shape.SensorID}
	default:
		req.ExecutionMode = platformExecutionMode
		req.PreferredSensorIDs = nil
	}
}

// planScanJob builds the job's plan inside the creation transaction: the
// per-target depth (the external cap is applied where the guard's verdicts
// say a target is external), the executor, and the budget. On success the
// request and job carry the resolved dispatch fields and metadata carries the
// plan.
func planScanJob(tx *sql.Tx, tenantID string, req *models.CreateDiscoveryJobRequest, job *models.DiscoveryJob, shape shareddisc.JobRequestShape,
	chosen *dispatchSensor, resolved []dispatchguard.ResolvedTarget, verdicts []dispatchguard.TargetVerdict, metadata map[string]interface{}, now time.Time) (*shareddisc.ScanPlan, error) {
	inputs := make([]shareddisc.PlanTargetInput, len(verdicts))
	for i, v := range verdicts {
		inputs[i] = shareddisc.PlanTargetInput{Target: v.Target, Class: shareddisc.TargetClass(v.Class), SegmentID: v.SegmentID,
			SNICandidates: sniCandidatesForTarget(req.SNICandidates, v.Target)}
	}
	// req.Ports holds only what a target named explicitly (a URL's :8443),
	// added by normalisedScanShape; the scan-plan path requests no other.
	plan, err := shareddisc.BuildScanPlan(shape.Spec, req.Ports, inputs)
	if err != nil {
		return nil, err
	}
	plan.RunFromRequested = shape.RunFrom

	switch shape.RunFrom {
	case shareddisc.RunFromSensor:
		plan.ExecutorResolved = shareddisc.ExecutorSensor
		if chosen != nil {
			plan.SensorID, plan.SensorName = chosen.ID.String(), chosen.Name
			plan.ExecutorReason = fmt.Sprintf("requested: sensor %s", chosen.Name)
		} else {
			plan.SensorID = shape.SensorID
			plan.ExecutorReason = "requested: the named tenant sensor"
		}
	case shareddisc.RunFromPlatform:
		plan.ExecutorResolved = shareddisc.ExecutorPlatform
		plan.ExecutorReason = "requested: the platform sensor"
	default:
		decision, err := chooseAutoExecutor(tx, tenantID, resolved, verdicts, now)
		if err != nil {
			return nil, err
		}
		plan.ExecutorReason = decision.Reason
		if decision.Sensor != nil {
			plan.ExecutorResolved = shareddisc.ExecutorSensor
			plan.SensorID, plan.SensorName = decision.Sensor.ID.String(), decision.Sensor.Name
			req.ExecutionMode, req.PreferredSensorIDs = "sensors", []string{decision.Sensor.ID.String()}
		} else {
			plan.ExecutorResolved = shareddisc.ExecutorPlatform
			req.ExecutionMode, req.PreferredSensorIDs = platformExecutionMode, nil
		}
		job.ExecutionMode, job.RequestedSensorIDs = req.ExecutionMode, req.PreferredSensorIDs
	}

	// Hole H19: the budget is read here and only here, and fails closed.
	if err := plan.CheckBudget(shareddisc.MaxJobProbesFromEnv()); err != nil {
		return nil, err
	}
	metadata[shareddisc.ScanPlanMetadataKey] = plan
	return &plan, nil
}

// sniCandidatesForTarget is the names the request supplied for one target, and
// only for a single ADDRESS: a hostname target already presents its own name and
// a range names no one host. The names are not validated here; BuildScanPlan
// sanitizes them, so the plan never holds an invalid or oversize list.
func sniCandidatesForTarget(byTarget map[string][]string, target string) []string {
	if len(byTarget) == 0 || net.ParseIP(target) == nil {
		return nil
	}
	if names, ok := byTarget[target]; ok {
		return names
	}
	for k, names := range byTarget {
		if strings.EqualFold(strings.TrimSpace(k), target) {
			return names
		}
	}
	return nil
}

// chooseAutoExecutor reads the tenant's fleet and who observed the job's
// single addresses, and applies sensordispatch.ChooseAutoExecutor.
func chooseAutoExecutor(tx *sql.Tx, tenantID string, resolved []dispatchguard.ResolvedTarget, verdicts []dispatchguard.TargetVerdict, now time.Time) (sensordispatch.AutoDecision, error) {
	targets := make([]sensordispatch.AutoTarget, len(resolved))
	var singles []netip.Addr
	for i, r := range resolved {
		t := sensordispatch.AutoTarget{Target: r.Input, External: i < len(verdicts) && verdicts[i].Class == dispatchguard.ClassExternal}
		if r.Host != "" {
			for _, s := range r.ScanAddresses() {
				if a, err := netip.ParseAddr(s); err == nil {
					t.Addresses = append(t.Addresses, a)
					singles = append(singles, a)
				}
			}
		} else if lo, hi, ok := dispatchguard.TargetInterval(r.Input); ok {
			t.Lo, t.Hi = lo, hi
			if lo == hi {
				singles = append(singles, lo)
			}
		}
		targets[i] = t
	}
	fleet, err := loadAutoFleet(tx, tenantID)
	if err != nil {
		return sensordispatch.AutoDecision{}, err
	}
	observed, err := lastObservingSensors(tx, tenantID, singles)
	if err != nil {
		return sensordispatch.AutoDecision{}, err
	}
	return sensordispatch.ChooseAutoExecutor(targets, observed, fleet, now), nil
}

// loadAutoFleet reads the tenant's sensors with their networks and own host
// addresses. Same sources as inventory-service's sensorrouting store (which
// Active Scan routes by): agent_addresses for networks, the self-reported
// asset's ip_address identifiers for the host, the primary address as the
// fallback for both.
func loadAutoFleet(tx *sql.Tx, tenantID string) ([]sensordispatch.FleetSensor, error) {
	rows, err := tx.Query(`
		SELECT s.id, s.name, s.status, s.last_heartbeat, COALESCE(s.reporting_interval, 0),
		       s.air_gapped, COALESCE(s.platform, ''), COALESCE(s.tags, '{}'::text[]),
		       COALESCE(s.reported_capabilities, '{}'::text[]),
		       COALESCE(s.ip_address, ''),
		       COALESCE((
		           SELECT array_agg(host(a.address) || '/' || a.prefix_length)
		           FROM agent_addresses a
		           WHERE a.sensor_id = s.id AND a.prefix_length IS NOT NULL
		       ), '{}'::text[]),
		       COALESCE((
		           SELECT array_agg(DISTINCT ai.value)
		           FROM asset_identifiers ai
		           WHERE ai.tenant_id = s.tenant_id AND ai.asset_id = s.asset_id AND ai.kind = 'ip_address'
		       ), '{}'::text[])
		FROM sensors s
		WHERE s.tenant_id = $1 AND s.deleted_at IS NULL
		ORDER BY s.name, s.id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read the tenant's sensors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []sensordispatch.FleetSensor
	for rows.Next() {
		var (
			s         sensordispatch.FleetSensor
			platform  string
			tags      pq.StringArray
			caps      pq.StringArray
			primary   string
			bound     pq.StringArray
			selfAddrs pq.StringArray
		)
		if err := rows.Scan(&s.ID, &s.Name, &s.Status, &s.LastHeartbeat, &s.ReportingInterval,
			&s.AirGapped, &platform, &tags, &caps, &primary, &bound, &selfAddrs); err != nil {
			return nil, fmt.Errorf("read the tenant's sensors: %w", err)
		}
		s.System = dispatchSensor{Platform: platform, Tags: []string(tags)}.system()
		// Auto exists only for scan-plan jobs: a sensor that cannot run one
		// is not a candidate ( WP2b).
		s.ScanPlan = sensordispatch.HasCapability([]string(caps), sensordispatch.ScanPlanCapability)
		s.Prefixes = sensordispatch.CoveragePrefixes(bound, primary)
		s.SelfAddresses = map[netip.Addr]bool{}
		for _, raw := range selfAddrs {
			if a, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
				s.SelfAddresses[a.Unmap()] = true
			}
		}
		if len(s.SelfAddresses) == 0 {
			if a, err := netip.ParseAddr(strings.TrimSpace(primary)); err == nil {
				s.SelfAddresses[a.Unmap()] = true
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// lastObservingSensors maps each address to the TENANT sensor that most
// recently recorded a discovery against it (the platform's own sensors are
// excluded). Same query as sensorrouting's LastObservingSensor.
func lastObservingSensors(tx *sql.Tx, tenantID string, addrs []netip.Addr) (map[netip.Addr]uuid.UUID, error) {
	out := map[netip.Addr]uuid.UUID{}
	if len(addrs) == 0 {
		return out, nil
	}
	ips := make([]string, len(addrs))
	for i, a := range addrs {
		ips[i] = a.Unmap().String()
	}
	rows, err := tx.Query(`
		SELECT DISTINCT ON (host(d.dest_ip)) host(d.dest_ip), d.sensor_id
		FROM sensor_discoveries d
		JOIN sensors s ON s.id = d.sensor_id AND s.tenant_id = d.tenant_id
		WHERE d.tenant_id = $1
		  AND d.dest_ip = ANY($2::inet[])
		  AND s.deleted_at IS NULL
		  AND COALESCE(s.platform, '') <> 'platform'
		  AND NOT ('system' = ANY(COALESCE(s.tags, '{}'::text[])))
		ORDER BY host(d.dest_ip), d."timestamp" DESC NULLS LAST`, tenantID, pq.Array(ips))
	if err != nil {
		return nil, fmt.Errorf("read which sensor last observed each address: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var raw string
		var id uuid.UUID
		if err := rows.Scan(&raw, &id); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			out[a.Unmap()] = id
		}
	}
	return out, rows.Err()
}
