package services

// One scan path ( WP2): automatic scans and identity probes as planned
// jobs, the legacy request shape translated to a plan, and the legacy payload
// kept for sensors that cannot run a plan.
//
//   - An automatic scan (options.origin "auto_scan") or identity probe
//     (options.identity_enrichment_request_id) may be a planned job. The
//     authorizations that guarded its legacy payload read the plan instead
//     (shared/identity/dispatchguard planned.go): at creation, at platform
//     execution (per unit, unitAuthorizer) and at dispatch and sensor pickup.
//   - A legacy protocols × ports request, or an OT-only one, is rewritten as a
// custom plan on its ports (owner decision D2; OT since WP5).
//   - An automatic or identity job, a person's Active Scan, or a translated
//     job, routed to a tenant sensor that does not report scan_plan_v1 is
//     created as the legacy job it would have been, rather than refused
//     (owner decision D3). Any other planned job a person asks for (Discover
//     Assets) keeps the refusal (ErrSensorScanPlanUnsupported).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// jobRequestFields is the part of a create-job request that decides its shape.
func jobRequestFields(req models.CreateDiscoveryJobRequest, dryRun bool) shareddisc.JobRequestFields {
	return shareddisc.JobRequestFields{
		ScanDepth: req.ScanDepth, TCPPorts: req.TCPPorts, UDPPorts: req.UDPPorts, Pace: req.Pace,
		RunFrom: req.RunFrom, SensorID: req.SensorID,
		Protocols: req.Protocols, Ports: req.Ports, OTProbeProtocols: req.OTProbeProtocols,
		ExecutionMode: req.ExecutionMode, PreferredSensorIDs: req.PreferredSensorIDs,
		DryRun: dryRun,
	}
}

// translateLegacyRequest applies owner decision D2 to req: a create-job
// request that names `ports` (with or without `protocols`), or only an OT
// opt-in, is run as a scan-depth "custom" plan on the shared engine
// (shareddisc.TranslateLegacyJobRequest). Its protocols are accepted and
// ignored (still validated, so an unknown name is refused). otProtocols is the
// OT opt-in as it will be dispatched (dispatchedOTProtocols): each adds its
// standard port, and req keeps ot_probe_protocols so the engine probes them.
// It reports whether it translated.
//
// It is unconditional since WP5: the protocols × ports executors are
// gone from both runtimes, so an untranslated request is either refused or —
// only for a tenant sensor that cannot run a plan — sent in the legacy shape
// that sensor's own (older) software executes (D3, in CreateJob). There is no
// switch to turn it off: with no legacy executor, its off position would
// create jobs nothing could run.
func translateLegacyRequest(req *models.CreateDiscoveryJobRequest, dryRun bool, otProtocols []string) bool {
	f, ok := shareddisc.TranslateLegacyJobRequest(jobRequestFields(*req, dryRun), otProbePorts(otProtocols))
	if !ok {
		return false
	}
	req.Protocols, req.Ports = nil, nil
	req.ExecutionMode, req.PreferredSensorIDs = "", nil
	req.ScanDepth, req.TCPPorts, req.UDPPorts, req.Pace = f.ScanDepth, f.TCPPorts, f.UDPPorts, f.Pace
	req.RunFrom, req.SensorID = f.RunFrom, f.SensorID
	return true
}

// storedIdentityProbeSQL reads the job an identity probe's request ID already
// names: its row, the fingerprint of the request that created it, the sensor
// it was for, the observation it serves, and (aggregated over its target
// rows) the targets and TCP ports it probes. Legacy and planned jobs both
// write one discovery_targets row per input carrying its ports.
const storedIdentityProbeSQL = `SELECT j.id,j.status,j.created_at,j.updated_at,COALESCE(j.metadata->>'identity_enrichment_fingerprint',''),
       COALESCE(j.requested_sensor_ids,'{}'),COALESCE(j.metadata->'options'->>'identity_observation_id',''),
       COALESCE((SELECT array_agg(DISTINCT t.input ORDER BY t.input) FROM discovery_targets t WHERE t.job_id=j.id),'{}'),
       COALESCE((SELECT array_agg(DISTINCT p ORDER BY p) FROM discovery_targets t, unnest(t.ports) p WHERE t.job_id=j.id),'{}')
  FROM discovery_jobs j WHERE j.tenant_id=$1 AND j.metadata->'options'->>'identity_enrichment_request_id'=$2`

// storedIdentityProbe is the job an identity probe's request ID already names.
type storedIdentityProbe struct {
	fingerprint string
	sensors     pq.StringArray
	observation string
	targets     pq.StringArray
	ports       pq.Int64Array
}

// scanDest is the Scan destination list after the job row's own columns.
func (s *storedIdentityProbe) scanDest() []any {
	return []any{&s.fingerprint, &s.sensors, &s.observation, &s.targets, &s.ports}
}

// identityProbeRequest is what an incoming identity probe probes, for
// comparing with a stored one: from which sensor, for which observation,
// which addresses on which TCP ports.
type identityProbeRequest struct {
	sensor      string
	observation string
	targets     []string
	ports       []int
}

// incomingIdentityProbe reads req (as translated, before the D3 fallback) and
// its resolved shape: a planned request names its sensor through run_from /
// execution_mode (shape.SensorID) and its ports in the plan; a legacy one
// names them in preferred_sensor_ids and ports.
func incomingIdentityProbe(shape shareddisc.JobRequestShape, req models.CreateDiscoveryJobRequest) identityProbeRequest {
	in := identityProbeRequest{targets: append([]string(nil), req.Targets...)}
	in.observation, _ = req.Options["identity_observation_id"].(string)
	if shape.Plan {
		in.sensor = shape.SensorID
		in.ports = append(shape.Spec.TCP.Ports(), req.Ports...)
	} else {
		if len(req.PreferredSensorIDs) == 1 {
			in.sensor = strings.TrimSpace(req.PreferredSensorIDs[0])
		}
		in.ports = append([]int(nil), req.Ports...)
	}
	for i := range in.targets {
		in.targets[i] = strings.TrimSpace(in.targets[i])
	}
	sort.Strings(in.targets)
	in.targets = slices.Compact(in.targets)
	sort.Ints(in.ports)
	in.ports = slices.Compact(in.ports)
	return in
}

// answers reports whether the stored job is the answer to a request carrying
// its request ID: the request that created it had the same fingerprint, or it
// is the same probe — the same addresses, on the same TCP ports, from the same
// sensor, for the same observation.
//
// The second rule exists for the upgrade that moved identity probes onto the
// shared engine ( WP4). inventory-service persists the request ID before
// dispatching and retries with it after a lost answer or a restart. A probe a
// pre-upgrade build dispatched in the legacy protocols × ports shape and an
// upgraded build retries in the planned shape (or the reverse, after a
// rollback) has a different fingerprint for the same probe. Refusing it as
// "reused with different inputs" would strand the observation: the
// coordinator keeps the request ID on a failed dispatch, so every retry would
// be refused the same way. The stored job is the probe already running, so it
// is the answer. The protocol list is not compared: the engine names no
// protocols, and the probe the stored job runs is the one asked for.
func (s storedIdentityProbe) answers(fingerprint string, in identityProbeRequest) bool {
	if s.fingerprint == fingerprint {
		return true
	}
	if in.sensor == "" || in.observation == "" || len(s.sensors) != 1 || strings.TrimSpace(s.sensors[0]) != in.sensor || s.observation != in.observation {
		return false
	}
	if !slices.Equal([]string(s.targets), in.targets) || len(s.ports) != len(in.ports) {
		return false
	}
	for i, p := range s.ports {
		if int(p) != in.ports[i] {
			return false
		}
	}
	return len(in.ports) > 0
}

// isUnattendedProbe reports whether a request is an automatic scan or an
// identity probe: work no person asked for in the moment.
func isUnattendedProbe(requestID string, options map[string]interface{}) bool {
	return requestID != "" || dispatchguard.IsAutomaticScan(options)
}

// isActiveScanRequest reports whether a request is an Active Scan: the
// re-scan of known assets that inventory-service sends with options
// active_scan (Inventory → an asset → Active Scan). Since WP4 it is a
// custom-depth plan on the assets' ports; on a sensor without plan support it
// falls back to the legacy job it used to be (D3). The option is the caller's,
// and that is enough here: the fallback grants nothing a legacy request on the
// same ports would not, and the legacy job is authorized like any other.
func isActiveScanRequest(options map[string]interface{}) bool {
	v, _ := options["active_scan"].(bool)
	return v
}

// activeScanFallbackProtocols is what an Active Scan's legacy fallback probes
// on each of its ports: the TLS and SSH pair every legacy executor has a
// prober for (autoscan.SupportedProtocols, the list Active Scan chose from).
func activeScanFallbackProtocols() []string {
	return append([]string(nil), autoscan.SupportedProtocols...)
}

// unattendedPlanPayload is the payload the authorizations judge for a planned
// automatic or identity job at creation: the plan's targets with their TCP and
// UDP ports and depth, and the job's OT opt-in — exactly what the executor
// will be handed. Target ids do not exist yet and are not judged.
func unattendedPlanPayload(tenantID string, options map[string]interface{}, plan *shareddisc.ScanPlan, otProtocols []string) sensordispatch.Payload {
	p := &sensordispatch.PlanPayload{
		Version: sensordispatch.PlanPayloadVersion, Attempt: 1, Pace: plan.Pace,
		OTProbeProtocols: otProtocols,
	}
	for _, t := range plan.Targets {
		p.Targets = append(p.Targets, sensordispatch.PlanTargetWork{PlanTarget: t})
	}
	return sensordispatch.Payload{TenantID: tenantID, Options: options, Plan: p}
}

// sensorLacksScanPlan reports whether a `sensors` request names exactly one of
// the tenant's own deployed sensors, and that sensor does not report
// sensordispatch.ScanPlanCapability. Anything else (no such sensor, the
// platform's own, more than one named) is false and left to
// resolveDispatchSensor, which refuses it with the usual reason.
func (s *DiscoveryService) sensorLacksScanPlan(ctx context.Context, tenantID string, preferred []string) (bool, error) {
	if len(preferred) != 1 {
		return false, nil
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return false, fmt.Errorf("invalid tenant_id: %w", err)
	}
	id, err := uuid.Parse(strings.TrimSpace(preferred[0]))
	if err != nil {
		return false, nil
	}
	lacks := false
	err = s.withTenantTxx(ctx, tenantUUID, func(tx *sqlx.Tx) error {
		sensor, ok := lookupTenantSensor(tx, tenantUUID, id)
		lacks = ok && !sensor.system() && !sensordispatch.HasCapability(sensor.Capabilities, sensordispatch.ScanPlanCapability)
		return nil
	})
	return lacks, err
}

// automaticScanProtocols is what a legacy automatic or identity payload probes
// when a planned request has to fall back to one: the tenant's policy
// protocols, which the legacy authorization checks it against. A missing or
// unreadable policy gives the supported pair, which the authorization then
// judges against the policy as always.
func (s *DiscoveryService) automaticScanProtocols(ctx context.Context, tenantID string) ([]string, error) {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}
	var raw []byte
	err = s.withTenantTxx(ctx, tenantUUID, func(tx *sqlx.Tx) error {
		e := tx.QueryRow(`SELECT config FROM tenant_admin_settings WHERE tenant_id = $1`, tenantUUID).Scan(&raw)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	config := map[string]interface{}{}
	if len(raw) > 0 && json.Unmarshal(raw, &config) != nil {
		return append([]string(nil), autoscan.SupportedProtocols...), nil
	}
	policy, err := autoscan.Normalize(autoscan.FromConfig(config))
	if err != nil {
		return append([]string(nil), autoscan.SupportedProtocols...), nil
	}
	return policy.Protocols, nil
}

// legacyFallbackRequest turns a planned automatic or identity request into the
// legacy protocols × ports request an old sensor can run (D3): the plan's TCP
// ports, the policy's protocols. A plan no legacy payload can express (UDP, or
// a depth an unattended scan may not use) is refused here with the same rule
// the authorization would apply.
func legacyFallbackRequest(req models.CreateDiscoveryJobRequest, spec shareddisc.ScanSpec, protocols []string) (models.CreateDiscoveryJobRequest, error) {
	switch spec.Depth {
	case shareddisc.DepthCustom, shareddisc.DepthQuick:
	default:
		return req, &shareddisc.ScanRequestError{Message: "automatic scans and identity probes run at custom or quick depth only, not " + string(spec.Depth)}
	}
	if spec.UDP.Len() > 0 {
		return req, &shareddisc.ScanRequestError{Message: "automatic scans and identity probes cannot probe UDP ports"}
	}
	out := req
	out.ScanDepth, out.TCPPorts, out.UDPPorts, out.Pace, out.RunFrom, out.SensorID = "", "", "", "", "", ""
	out.Ports = spec.TCP.Ports()
	out.Protocols = append([]string(nil), protocols...)
	return out, nil
}
