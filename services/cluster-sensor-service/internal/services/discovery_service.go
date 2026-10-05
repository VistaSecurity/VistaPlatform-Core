package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// otProbeAllowed is the canonical allowlist of OT probes the platform supports
// in active-probing mode. Values from the request are normalized (uppercased,
// punctuation stripped) and matched against this set; anything outside it is
// dropped silently. Kept in sync with the registrations in
// sensor/internal/discovery/ot_probers.go init().
var otProbeAllowed = map[string]string{
	"MODBUS":     "Modbus",
	"OPCUA":      "OPC_UA",
	"ETHERNETIP": "EtherNet_IP",
	"BACNET":     "BACnet",
}

// canonicalizeOTProbeProtocols filters and normalizes the operator's per-job
// OT probe selection. Returns the canonical protocol names the sensor
// understands, with duplicates and unknown values removed.
func canonicalizeOTProbeProtocols(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(input))
	for _, raw := range input {
		key := strings.ToUpper(raw)
		key = strings.ReplaceAll(key, "-", "")
		key = strings.ReplaceAll(key, "_", "")
		key = strings.ReplaceAll(key, " ", "")
		key = strings.ReplaceAll(key, "/", "")
		canonical, ok := otProbeAllowed[key]
		if !ok || seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	return out
}

// otProbeDefaultPort returns the well-known port the sensor's OT prober
// uses for each protocol. Keeping the OT cross-product to a single
// (protocol, port) pair per target avoids the operator's "scan all ports"
// configuration accidentally probing PLCs on dozens of irrelevant ports.
func otProbeDefaultPort(canonical string) int {
	switch canonical {
	case "Modbus":
		return 502
	case "OPC_UA":
		return 4840
	case "EtherNet_IP":
		return 44818
	case "BACnet":
		return 47808
	}
	return 0
}

// dispatchableOTProtocols keeps only the OT protocols that will actually be
// turned into a discovery target — i.e. those with a known standard port. It is
// the filter that keeps discovery_jobs.ot_probe_protocols ("these probes were
// dispatched") from asserting something that never happened.
func dispatchableOTProtocols(canonical []string) []string {
	if len(canonical) == 0 {
		return nil
	}
	out := make([]string, 0, len(canonical))
	for _, proto := range canonical {
		if otProbeDefaultPort(proto) == 0 {
			log.Printf("CreateJob: OT protocol %q has no standard port — not dispatched, not recorded as probed", proto)
			continue
		}
		out = append(out, proto)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dispatchedOTProtocols is the job's OT opt-in as it will be dispatched and
// recorded: the request's names canonicalised against the allowlist, dropped
// entirely when the tenant's `ot_active_probing` switch is off (or cannot be
// read), and kept only where a standard port exists. This is what the plan's
// OT ports are derived from (translateLegacyRequest), what the engine is told
// to probe, and what discovery_jobs.ot_probe_protocols records.
func (s *DiscoveryService) dispatchedOTProtocols(tenantID string, requested []string) ([]string, error) {
	otProtocols := canonicalizeOTProbeProtocols(requested)
	if len(otProtocols) > 0 {
		tenantUUID, parseErr := uuid.Parse(tenantID)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid tenant_id: %w", parseErr)
		}
		limitSvc := sharedservices.NewLimitEnforcementService(s.db.DB)
		allowed, ferr := limitSvc.CheckFeatureAccess(tenantUUID, "ot_active_probing")
		if ferr != nil {
			log.Printf("CreateJob: ot_active_probing switch check failed for tenant %s: %v — dropping OT probes", tenantID, ferr)
			otProtocols = nil
		} else if !allowed {
			log.Printf("CreateJob: ot_active_probing is switched off for tenant %s, dropping OT probes %v", tenantID, otProtocols)
			otProtocols = nil
		}
	}
	// ot_probe_protocols is an audit column whose documented meaning is "these
	// probes were dispatched". Keep it honest: drop any protocol we would not
	// actually probe, so the column can never claim a probe that never left
	// the cluster. (otProbeDefaultPort covers every allowlisted protocol
	// today, so this normally filters nothing — it is here so that a future
	// protocol added to the allowlist without a port cannot silently re-open
	// the "recorded as probed, never probed" gap B-60 was.)
	return dispatchableOTProtocols(otProtocols), nil
}

// otProbePorts pairs each dispatched OT protocol with its standard port, the
// shape the shared translation takes.
func otProbePorts(otProtocols []string) []shareddisc.OTProbePort {
	out := make([]shareddisc.OTProbePort, 0, len(otProtocols))
	for _, proto := range otProtocols {
		if port := otProbeDefaultPort(proto); port != 0 {
			out = append(out, shareddisc.OTProbePort{Protocol: proto, Port: port})
		}
	}
	return out
}

// createdByOrNull renders a caller identity for the nullable `created_by`
// column: the uuid when the caller is a person, NULL otherwise.
//
// "Otherwise" is a real case, not a defensive one. The automatic active-scan
// sweep reaches this service over the HMAC service-auth path, where the shared
// middleware sets userID to the literal string "system".
func createdByOrNull(userID string) interface{} {
	if uid, err := uuid.Parse(strings.TrimSpace(userID)); err == nil {
		return uid
	}
	return nil
}

func valueOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func valueOrDefaultFloat(f *float64, def float64) float64 {
	if f == nil {
		return def
	}
	return *f
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type DiscoveryService struct {
	db *sqlx.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) handle used only by the
	// `// RLS: cross-tenant — runs on the bypass role (Phase 4)` methods on
	// this service (GetJob / UpdateJobStatus / GetJobResults), which are keyed
	// by job id with no tenant threaded. Under crypto_app these queries FAIL
	// CLOSED; on the bypass handle they run cross-tenant as intended.
	bypassDB *sqlx.DB
	// resolver turns a hostname target into the addresses that are
	// authorized and then PINNED on the job ( W5.13b). The job processor
	// uses the same resolver for a hostname that was not pinned (a job created
	// before pinning existed), so one seam covers both lookups.
	resolver dispatchguard.Resolver
	// running indexes the jobs THIS replica is executing, so CancelJob can
	// stop one at once (job_lifecycle.go). Created on first use.
	runningMu sync.Mutex
	running   *runningJobRegistry
}

func NewDiscoveryService(db, bypassDB *sqlx.DB) *DiscoveryService {
	return &DiscoveryService{db: db, bypassDB: bypassDB, resolver: net.DefaultResolver}
}

// WithResolver swaps the DNS resolver — for tests that stage a rebinding.
func (s *DiscoveryService) WithResolver(r dispatchguard.Resolver) *DiscoveryService {
	s.resolver = r
	return s
}

// resolveTimeout bounds the DNS lookups a job creation makes before its
// transaction opens.
const resolveTimeout = 10 * time.Second

// Tenant-sensor dispatch rules (which sensor a `sensors` job may be handed to,
// and why a request is refused) live in sensor_dispatch.go.

// CreateJob validates, authorizes, plans and persists a job. A request that
// asks for a dry run must go through PreviewJob: this refuses it rather than
// create the job the caller asked not to create.
func (s *DiscoveryService) CreateJob(tenantID, userID string, req models.CreateDiscoveryJobRequest) (*models.DiscoveryJob, error) {
	if req.DryRun {
		return nil, &shareddisc.ScanRequestError{Message: "dry_run previews a job and creates none: it is answered by PreviewJob, not CreateJob"}
	}
	job, _, err := s.createJob(tenantID, userID, req, false)
	return job, err
}

// PreviewJob is POST /discovery/jobs with `dry_run`: it runs the SAME function
// CreateJob does — createJob, one code path — and stops, inside the creation
// transaction, after the plan is built and checked and before the first write.
// Every refusal a real create would give is given here with the same type
// (so the handler answers the same status and code), except an unconfirmed
// external target, which is reported on the preview instead of refused.
//
// It writes nothing: the transaction is rolled back, never committed. (It
// cannot be declared READ ONLY: the target-scope read takes a row lock, SELECT
// … FOR SHARE, so a segment withdrawn a moment ago wins the race, and Postgres
// refuses that in a read-only transaction. The lock is released by the
// rollback.)
func (s *DiscoveryService) PreviewJob(tenantID, userID string, req models.CreateDiscoveryJobRequest) (*shareddisc.ScanPreview, error) {
	_, preview, err := s.createJob(tenantID, userID, req, true)
	return preview, err
}

// errDryRunDone ends a dry run's transaction after the plan is built. It is
// returned from inside the transaction so the transaction rolls back, and is
// swallowed by createJob.
var errDryRunDone = errors.New("dry run complete")

func (s *DiscoveryService) createJob(tenantID, userID string, req models.CreateDiscoveryJobRequest, dryRun bool) (*models.DiscoveryJob, *shareddisc.ScanPreview, error) {
	// `protocols` is allowlisted (TLS, SSH, SMB and the TLS-wrapped names) so an
	// OT/ICS name cannot reach the OT probers from here: those run only from
	// `ot_probe_protocols`, canonicalised and recorded below, which is what keeps
	// the explicit opt-in, the audit column and the one-standard-port restriction
	// in force. First, before any lookup, so a refused request touches nothing.
	if err := shareddisc.ValidateJobProtocols(req.Protocols); err != nil {
		return nil, nil, err
	}
	// The request exactly as the caller sent it: the identity-probe
	// fingerprint is taken from it (so a replay matches whichever path the
	// job took), and it is what a translated request falls back to.
	original := req

	// OT active probes: each requested OT protocol probes its standard port.
	// The `ot_active_probing` switch (Core, on by default; an operator can
	// turn it off per plan or per tenant) gates the capability — when off,
	// requested OT probes are dropped and logged so the operator gets the rest
	// of the job rather than a hard 4xx. Read BEFORE the translation below, so
	// a probe the switch drops never adds its port to the plan: a switched-off
	// OT protocol's port is not even connected to.
	otProtocols, err := s.dispatchedOTProtocols(tenantID, req.OTProbeProtocols)
	if err != nil {
		return nil, nil, err
	}

	// A legacy protocols × ports request — or an OT-only one — runs as a
	// custom plan on its ports ( D2, WP5): there is no other executor.
	translated := translateLegacyRequest(&req, dryRun, otProtocols)
	// Scan-plan or legacy ( WP3): which path this request takes, and the
	// scan-plan fields validated — the same function inventory-service runs.
	// A request still legacy here is created only for a tenant sensor without
	// plan support (the D3 fallback below) or refused.
	shape, err := shareddisc.ResolveJobRequest(jobRequestFields(req, dryRun))
	if err != nil {
		return nil, nil, err
	}

	// The coordinator persists this token before dispatch. A retry after remote
	// commit must return the same job rather than perform another network probe.
	requestID := ""
	requestFingerprint := ""
	if raw, exists := req.Options["identity_enrichment_request_id"]; exists {
		value, ok := raw.(string)
		parsed, parseErr := uuid.Parse(value)
		if !ok || parseErr != nil || parsed == uuid.Nil {
			return nil, nil, fmt.Errorf("invalid identity enrichment request ID")
		}
		requestID = parsed.String()
		encoded, encodeErr := json.Marshal(original)
		if encodeErr != nil {
			return nil, nil, encodeErr
		}
		sum := sha256.Sum256(encoded)
		requestFingerprint = hex.EncodeToString(sum[:])
	}
	// What a stored probe under the same request ID must match besides the
	// fingerprint when the two differ only by request shape (see
	// storedIdentityProbe.answers): read now, before the D3 fallback below can
	// rewrite req and shape.
	incoming := incomingIdentityProbe(shape, req)

	// The automatic sweep and identity enrichment may be planned jobs (
	// WP2): their authorizations below read the plan, which they keep to
	// individual addresses, TCP ports the policy allows, no OT probes and
	// custom or quick depth (dispatchguard planned.go).
	unattended := isUnattendedProbe(requestID, req.Options)
	// They are never previewed: a dry run is a person's question, and an
	// identity probe's replay token must not be read or reserved by one.
	if unattended && dryRun {
		return nil, nil, &shareddisc.ScanRequestError{Message: "dry_run previews a scan a person asks for; automatic scans and identity probes are not previewed"}
	}

	if requestID != "" {
		tenant, err := uuid.Parse(tenantID)
		if err != nil {
			return nil, nil, err
		}
		replay := &models.DiscoveryJob{TenantID: tenantID, ExecutionMode: req.ExecutionMode, RequestedSensorIDs: req.PreferredSensorIDs}
		var stored storedIdentityProbe
		err = shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenant, func(tx *sql.Tx) error {
			return tx.QueryRow(storedIdentityProbeSQL, tenant, requestID).
				Scan(append([]any{&replay.ID, &replay.Status, &replay.CreatedAt, &replay.UpdatedAt}, stored.scanDest()...)...)
		})
		if err == nil {
			if !stored.answers(requestFingerprint, incoming) {
				return nil, nil, fmt.Errorf("identity enrichment request ID reused with different inputs")
			}
			return replay, nil, nil
		}
		if err != sql.ErrNoRows {
			return nil, nil, err
		}
	}
	// A `sensors` job is refused HERE, with a reason, when the sensor it names
	// is unknown, the platform's own, air-gapped or offline. Refusing at
	// creation is what keeps "the job was created" meaning "the job can run":
	// a row waiting on a sensor that will never collect it is the silent
	// failure this path used to produce, in a different costume.
	// Hole H37: "cloud" on this endpoint means "run from the platform"; see
	// normalizeLegacyExecutionMode. Never stored as "cloud".
	req.ExecutionMode = normalizeLegacyExecutionMode(req.ExecutionMode)
	if shape.Plan {
		applyRunFrom(&req, shape)
	}
	// D3: an automatic or identity job, a person's Active Scan — or a legacy
	// request translated to a plan — that names a tenant sensor too old to run
	// a plan is created as the legacy job that sensor can run, rather than
	// refused. Any other planned job a person asks for (Discover Assets) is
	// still refused (ErrSensorScanPlanUnsupported).
	activeScan := !unattended && isActiveScanRequest(req.Options)
	if shape.Plan && (unattended || translated || activeScan) && isSensorExecutionMode(req.ExecutionMode) {
		lacks, lerr := s.sensorLacksScanPlan(context.Background(), tenantID, req.PreferredSensorIDs)
		if lerr != nil {
			return nil, nil, lerr
		}
		if lacks {
			switch {
			case translated:
				req = original
				req.ExecutionMode = normalizeLegacyExecutionMode(req.ExecutionMode)
			case activeScan:
				// The Active Scan the sensor ran before WP4 asked for TLS
				// and/or SSH per asset. Its ports are the plan's; both probes
				// run on each, which is what the plan's identification would
				// have tried.
				if req, err = legacyFallbackRequest(req, shape.Spec, activeScanFallbackProtocols()); err != nil {
					return nil, nil, err
				}
			default:
				protocols, perr := s.automaticScanProtocols(context.Background(), tenantID)
				if perr != nil {
					return nil, nil, perr
				}
				if req, err = legacyFallbackRequest(req, shape.Spec, protocols); err != nil {
					return nil, nil, err
				}
			}
			if dryRun {
				return nil, nil, &shareddisc.ScanRequestError{Message: "dry_run previews a scan plan, and the sensor named cannot run one: this scan would run there as protocols × ports, which has no plan to preview"}
			}
			shape = shareddisc.JobRequestShape{}
		}
	}
	chosenSensor, err := s.resolveDispatchSensor(context.Background(), tenantID, req.ExecutionMode, req.PreferredSensorIDs, shape.Plan, time.Now())
	if err != nil {
		return nil, nil, err
	}
	if len(req.Targets) == 0 {
		return nil, nil, fmt.Errorf("at least one target is required")
	}
	if len(req.Targets) > 1000 {
		return nil, nil, fmt.Errorf("too many targets; limit is 1000 per job")
	}

	// Normalise every target (a URL becomes its host, an explicit port joins
	// the job's ports) and resolve each hostname ONCE, outside the
	// transaction below — a DNS lookup must not be held inside one. The
	// addresses a name resolved to are what authorization judges AND what the
	// scanner is pinned to (metadata.pinned_addresses), so a second DNS answer
	// cannot redirect a checked scan. A name that cannot be resolved is refused
	// rather than accepted unchecked — an unauthorizable target is not an
	// authorized one.
	parsedTargets, err := dispatchguard.ParseManualTargets(req.Targets)
	if err != nil {
		return nil, nil, err
	}
	resolveCtx, cancelResolve := context.WithTimeout(context.Background(), resolveTimeout)
	resolvedTargets, err := dispatchguard.ResolveManualTargets(resolveCtx, s.resolver, parsedTargets)
	cancelResolve()
	if err != nil {
		return nil, nil, err
	}
	req.Targets, req.Ports = normalisedScanShape(resolvedTargets, req.Ports)
	pinned := pinnedAddresses(resolvedTargets)

	// The scanner expands a CIDR or range to at most shareddisc.MaxTargetAddresses
	// hosts and used to drop the rest without a word, so a /19 was scanned as
	// its first /20 and the job still ended "completed". A job it cannot
	// fully expand is refused here, naming the numbers, rather than accepted and
	// quietly under-scanned.
	if err := shareddisc.CheckTargetSizes(req.Targets); err != nil {
		return nil, nil, err
	}

	// Explicit external targets are a PERSON's to confirm. The automatic
	// sweep, identity enrichment and service callers (no user behind them)
	// never scan outside the registered networks, whatever flag they send.
	personInitiated := createdByOrNull(userID) != nil && !unattended
	manualOpts := dispatchguard.ManualOptions{
		Policy: dispatchguard.ExternalPolicyFromEnv(),
		// A dry run is judged as if confirmed, so that every refusal that does
		// NOT depend on the confirmation is still given and the plan shows the
		// downgrades that will apply once the person confirms. The
		// confirmation is the LAST check AuthorizeManual makes, so this
		// changes no other verdict; whether it is still owed is reported on
		// the preview (confirmation_required).
		Confirmed:       req.ExternalTargetsConfirmed || dryRun,
		PersonInitiated: personInitiated,
	}

	// A scan-plan job always probes (its depth names the ports); the
	// protocol/port pair rule is the legacy path's.
	itProbing := !shape.Plan && len(req.Protocols) > 0 && len(req.Ports) > 0
	if !shape.Plan && !itProbing && len(otProtocols) == 0 {
		return nil, nil, fmt.Errorf("at least one protocol/port pair or OT probe is required")
	}
	if itProbing {
		if len(req.Protocols) == 0 {
			return nil, nil, fmt.Errorf("at least one protocol is required")
		}
		if len(req.Ports) == 0 {
			return nil, nil, fmt.Errorf("at least one port is required")
		}
	}

	// Set defaults
	retentionCapMB := 25
	if req.RetentionCapMB != nil {
		retentionCapMB = *req.RetentionCapMB
	}
	retentionTTLHours := 24
	if req.RetentionTTLHours != nil {
		retentionTTLHours = *req.RetentionTTLHours
	}

	// Create job
	job := &models.DiscoveryJob{
		TenantID:           tenantID,
		CreatedBy:          userID,
		ExecutionMode:      req.ExecutionMode,
		Status:             "queued",
		RequestedSensorIDs: req.PreferredSensorIDs,
		Fanout:             true,
		RetentionCapMB:     retentionCapMB,
		RetentionTTLHours:  retentionTTLHours,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	// Build metadata JSON with scanning options
	metadata := map[string]interface{}{}
	if requestID != "" {
		metadata["identity_enrichment_fingerprint"] = requestFingerprint
	}
	if req.Options != nil {
		metadata["options"] = req.Options
	}
	// Server-written, beside `options` rather than inside it: `options` is
	// caller-supplied, and the addresses a scan is pinned to must never be.
	if len(pinned) > 0 {
		metadata["pinned_addresses"] = pinned
	}

	// RLS-scoped writes: discovery_jobs and discovery_targets both carry a
	// tenant_isolation policy. The whole job creation (job row + its target
	// rows) runs inside one WithTenantTx so app.tenant_id is set on the same
	// connection as every INSERT, satisfying each WITH CHECK. Explicit
	// tenant_id values are kept as the primary control (belt-and-suspenders).
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid tenant_id: %w", err)
	}

	// created_by is NULLABLE, and a job the platform created on its own
	// initiative has nobody behind it. Internal service-to-service callers
	// arrive with the literal userID "system" (shared middleware sets it), which
	// is not a uuid — inserting it would fail the whole INSERT, and inventing a
	// user id would attribute an unattended act to a person who did not perform
	// it. NULL is the honest value and the column already accepts it.
	createdBy := createdByOrNull(userID)

	var preview *shareddisc.ScanPreview
	err = shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantUUID, func(tx *sql.Tx) error {
		if requestID != "" {
			if _, lockErr := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,72047))`, tenantID+":"+requestID); lockErr != nil {
				return lockErr
			}
			var stored storedIdentityProbe
			replayErr := tx.QueryRow(storedIdentityProbeSQL, tenantID, requestID).
				Scan(append([]any{&job.ID, &job.Status, &job.CreatedAt, &job.UpdatedAt}, stored.scanDest()...)...)
			if replayErr == nil {
				if !stored.answers(requestFingerprint, incoming) {
					return fmt.Errorf("identity enrichment request ID reused with different inputs")
				}
				return nil
			}
			if replayErr != sql.ErrNoRows {
				return replayErr
			}
			if !isSensorExecutionMode(req.ExecutionMode) || len(req.PreferredSensorIDs) != 1 || len(req.OTProbeProtocols) != 0 {
				return fmt.Errorf("identity probes require one scoped sensor and TLS/SSH only")
			}
			selectedSensor, err := uuid.Parse(req.PreferredSensorIDs[0])
			if err != nil {
				return err
			}
			// A planned probe is judged below, on the plan, once it is built.
			if !shape.Plan {
				if err := authorizeEnrichmentDispatch(tx, sensordispatch.Payload{TenantID: tenantID, Targets: req.Targets, Protocols: req.Protocols, Ports: req.Ports, Options: req.Options}, selectedSensor); err != nil {
					return err
				}
			}
		}
		// TARGET AUTHORIZATION — every path, every origin (#H5).
		//
		// AuthorizeAutomaticScan below short-circuits on an option the CALLER
		// supplies, so before this line a manually-created job was authorized
		// by nothing: loopback, the cluster's own Service CIDR,
		// 169.254.169.254 and arbitrary public hosts were all reachable from
		// the Discover wizard. This check does not look at the origin at all.
		// It runs inside the job-creation transaction so a segment withdrawn a
		// moment ago wins the race, and it is repeated at dispatch time in
		// each work unit (unitAuthorizer) against the EXPANDED addresses.
		//
		// Since W5.13b a person may also name targets OUTSIDE the
		// registered networks, confirmed in this request; reserved and
		// platform-excluded ranges stay refused whatever is confirmed.
		external, verdicts, err := dispatchguard.AuthorizeAndClassifyManualTargets(tx, tenantID, resolvedTargets, manualOpts)
		if err != nil {
			return err
		}
		// A scan-plan job is planned HERE, at the point the guard has just
		// classified each target: the per-target external depth cap (D3) is
		// applied on these verdicts, Auto is resolved (an external target
		// keeps the job on the platform), and the budget is checked — all
		// before anything is written.
		if shape.Plan {
			plan, perr := planScanJob(tx, tenantID, &req, job, shape, chosenSensor, resolvedTargets, verdicts, metadata, time.Now())
			if perr != nil {
				return perr
			}
			job.Plan = plan
			// A planned identity probe's authorization, judged on the plan
			// just built: every address the sensor will scan, every port.
			if requestID != "" {
				selectedSensor, err := uuid.Parse(req.PreferredSensorIDs[0])
				if err != nil {
					return err
				}
				if err := authorizeEnrichmentDispatch(tx, unattendedPlanPayload(tenantID, req.Options, plan, otProtocols), selectedSensor); err != nil {
					return err
				}
			}
		}
		// A tenant sensor is handed the TARGETS, not the addresses they were
		// authorized on: it would resolve a name again on its own network
		// (defeating the pin) and it scans without the platform's per-address
		// re-check or a fresh read of the operator switch. Until the sensor
		// payload carries pinned addresses, confirmed external targets run
		// from the platform sensor only ( W5.13b review, item 2).
		if len(external) > 0 && isSensorExecutionMode(req.ExecutionMode) {
			refused := make([]dispatchguard.RefusedTarget, 0, len(external))
			for _, e := range external {
				refused = append(refused, dispatchguard.RefusedTarget{Target: e.Target,
					Reason: "targets outside your registered networks can only be scanned from the platform sensor, not a tenant sensor; run this scan from the platform"})
			}
			return &dispatchguard.RefusedTargetsError{Targets: refused}
		}
		// A dry run ends HERE: everything a refusal can depend on has run, and
		// nothing has been written. The transaction is rolled back.
		if dryRun {
			confirmationRequired := len(external) > 0 && !req.ExternalTargetsConfirmed
			listed := make([]shareddisc.PreviewExternalTarget, 0, len(external))
			for _, e := range external {
				listed = append(listed, shareddisc.PreviewExternalTarget{Target: e.Target, Addresses: e.Addresses})
			}
			if job.Plan == nil {
				return errors.New("dry run: the request produced no scan plan")
			}
			p, perr := shareddisc.NewScanPreview(*job.Plan, confirmationRequired, listed)
			if perr != nil {
				return perr
			}
			preview = &p
			return errDryRunDone
		}
		if len(external) > 0 {
			// The job's record of the consent. The processor reads
			// `confirmed` at scan time; the rest is provenance.
			metadata["external_targets"] = map[string]interface{}{
				"confirmed":    true,
				"confirmed_by": userID,
				"confirmed_at": time.Now().UTC().Format(time.RFC3339),
				"targets":      external,
				// Re-checked against the operator's CURRENT job bound at
				// scan time (review N2).
				"total_addresses": dispatchguard.ExternalAddressTotal(external),
			}
			job.ExternalTargets = make([]models.ExternalScanTarget, 0, len(external))
			for _, e := range external {
				job.ExternalTargets = append(job.ExternalTargets, models.ExternalScanTarget{Target: e.Target, Addresses: e.Addresses})
			}
		}
		metadataJSON, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		if dispatchguard.IsAutomaticScan(req.Options) {
			if len(req.OTProbeProtocols) > 0 {
				return fmt.Errorf("automatic scanning cannot request OT probes")
			}
			// A planned job is judged on its plan: the addresses and TCP ports
			// the executor will be handed, with no protocol list.
			payload := sensordispatch.Payload{TenantID: tenantID, Targets: req.Targets, Protocols: req.Protocols, Ports: req.Ports, Options: req.Options}
			if job.Plan != nil {
				payload = unattendedPlanPayload(tenantID, req.Options, job.Plan, otProtocols)
			}
			if err := dispatchguard.AuthorizeAutomaticScan(tx, payload); err != nil {
				return err
			}
		}
		// Insert job. ot_probe_protocols is the audit column — captures which
		// OT probes the operator opted in to for forensic traceability, even
		// after the per-target rows have been pruned by retention.
		query := `
			INSERT INTO discovery_jobs (tenant_id, created_by, execution_mode, status, requested_sensor_ids, fanout, retention_cap_mb, retention_ttl_hours, metadata, ot_probe_protocols, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			RETURNING id`

		if err := tx.QueryRow(query,
			job.TenantID, createdBy, job.ExecutionMode, job.Status,
			pq.Array(job.RequestedSensorIDs), job.Fanout, job.RetentionCapMB,
			job.RetentionTTLHours, metadataJSON, pq.Array(otProtocols),
			job.CreatedAt, job.UpdatedAt).Scan(&job.ID); err != nil {
			return fmt.Errorf("failed to create discovery job: %w", err)
		}

		// Create IT targets (one row per input × all protocols × all ports).
		if itProbing {
			for _, target := range req.Targets {
				ports := make([]int32, len(req.Ports))
				for i, port := range req.Ports {
					ports[i] = int32(port) //nolint:gosec // intentional — TCP/UDP port range 0-65535 fits comfortably in int32
				}

				targetRecord := &models.DiscoveryTarget{
					JobID:     job.ID,
					Input:     target,
					Protocols: req.Protocols,
					Ports:     ports,
					Status:    "pending",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}

				targetQuery := `
					INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports, status, created_at, updated_at)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
					RETURNING id`

				if err := tx.QueryRow(targetQuery,
					targetRecord.JobID, tenantID, targetRecord.Input, pq.Array(targetRecord.Protocols),
					pq.Array(targetRecord.Ports), targetRecord.Status, targetRecord.CreatedAt, targetRecord.UpdatedAt).Scan(&targetRecord.ID); err != nil {
					return fmt.Errorf("failed to create discovery target: %w", err)
				}
			}
		}

		// Create scan-plan targets: one row per input carrying that target's
		// PLANNED TCP ports (after any external cap) and no protocols — a
		// scan-plan job identifies services from what answers. The plan in
		// metadata is the full record (UDP, depth, pace) for the executor.
		if job.Plan != nil {
			for i, target := range req.Targets {
				tcp, perr := job.Plan.Targets[i].TCPPortSet()
				if perr != nil {
					return fmt.Errorf("plan for %s: %w", target, perr)
				}
				ports := make([]int32, 0, tcp.Len())
				for _, port := range tcp.Ports() {
					ports = append(ports, int32(port)) //nolint:gosec // 1-65535
				}
				if _, err := tx.Exec(`
					INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports, status, created_at, updated_at)
					VALUES ($1, $2, $3, $4, $5, 'pending', $6, $6)`,
					job.ID, tenantID, target, pq.Array([]string{}), pq.Array(ports), time.Now()); err != nil {
					return fmt.Errorf("failed to create discovery target: %w", err)
				}
			}
		}

		// Create OT targets (one row per input × OT-protocol, with that
		// protocol's standard port only). Keeping them as separate rows means
		// the sensor's existing target-loop logic handles them with no code
		// changes — the cartesian product per row stays small.
		for _, target := range req.Targets {
			for _, otProto := range otProtocols {
				port := otProbeDefaultPort(otProto)
				if port == 0 {
					continue // canonicalizeOTProbeProtocols already filtered, defensive
				}
				otRecord := &models.DiscoveryTarget{
					JobID:     job.ID,
					Input:     target,
					Protocols: []string{otProto},
					Ports:     []int32{int32(port)}, //nolint:gosec
					Status:    "pending",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				targetQuery := `
					INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports, status, created_at, updated_at)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
					RETURNING id`
				if err := tx.QueryRow(targetQuery,
					otRecord.JobID, tenantID, otRecord.Input, pq.Array(otRecord.Protocols),
					pq.Array(otRecord.Ports), otRecord.Status, otRecord.CreatedAt, otRecord.UpdatedAt).Scan(&otRecord.ID); err != nil {
					return fmt.Errorf("failed to create OT discovery target: %w", err)
				}
			}
		}

		return nil
	})
	if dryRun && errors.Is(err, errDryRunDone) {
		return nil, preview, nil
	}
	if err != nil {
		return nil, nil, err
	}

	return job, nil, nil
}

func (s *DiscoveryService) GetJob(jobID string) (*models.DiscoveryJob, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Keyed by job id
	// only, and the tenant is the query OUTPUT (job.TenantID), so app.tenant_id
	// cannot be set to a tenant we are still discovering. The job_processor
	// resolves the tenant from the row this method returns.
	job := &models.DiscoveryJob{}
	// Select only columns that exist in the database table
	// Note: Targets, Progress, ResultsSummary, AssignedSensorID, DeletedAt don't exist in DB
	// Use pq.Array wrapper for PostgreSQL array types
	var requestedSensorIDs pq.StringArray
	// created_by is NULL for a job the platform created on its own (the
	// automatic active-scan sweep, or any HMAC service caller) — see
	// createdByOrNull. Scanning that NULL straight into a string fails the
	// whole read, and this is the read the job processor does FIRST, so every
	// such job was unreadable and sat in `queued` forever. COALESCE, and the
	// same in GetJobs below.
	query := `SELECT j.id, j.tenant_id, COALESCE(j.created_by::text, ''), j.execution_mode, j.status, j.requested_sensor_ids, j.fanout,
	          j.retention_cap_mb, j.retention_ttl_hours, j.created_at, j.updated_at, j.started_at, j.completed_at,
	          j.error_message, j.assigned_sensor_id, j.dispatched_at, s.name, s.last_heartbeat, c.delivered_at,
	          COALESCE(j.metadata -> 'options' ->> 'origin', ''),
	          j.metadata -> '` + shareddisc.ScanPlanMetadataKey + `'
	          FROM discovery_jobs j` + jobExecutorJoins + ` WHERE j.id = $1`
	var planJSON []byte

	err := s.bypassDB.QueryRow(query, jobID).Scan(
		&job.ID,
		&job.TenantID,
		&job.CreatedBy,
		&job.ExecutionMode,
		&job.Status,
		// pq.StringArray is its own sql.Scanner; wrapping it in pq.Array made
		// a GenericArray that cannot scan into plain strings, so this read
		// failed for any job that actually named a sensor.
		&requestedSensorIDs,
		&job.Fanout,
		&job.RetentionCapMB,
		&job.RetentionTTLHours,
		&job.CreatedAt,
		&job.UpdatedAt,
		&job.StartedAt,
		&job.CompletedAt,
		&job.ErrorMessage,
		&job.AssignedSensorID,
		&job.DispatchedAt,
		&job.AssignedSensorName,
		&job.AssignedSensorLastHeartbeat,
		&job.PickedUpAt,
		&job.Origin,
		&planJSON,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("job not found")
		}
		return nil, fmt.Errorf("failed to get job: %w", err)
	}

	job.Plan = decodeJobPlan(jobID, planJSON)

	// Convert pq.StringArray to []string
	job.RequestedSensorIDs = []string(requestedSensorIDs)
	job.Executor = executorFor(job.ExecutionMode, job.AssignedSensorID)

	// Get targets separately since they're stored in discovery_targets table
	var targets []string
	targetQuery := `SELECT input FROM discovery_targets WHERE job_id = $1`
	err = s.bypassDB.Select(&targets, targetQuery, jobID)
	if err == nil {
		job.Targets = targets
	}

	return job, nil
}

// decodeJobPlan reads a scan-plan job's plan ( WP3) from its
// metadata.scan_plan, nil for a legacy job. An unreadable plan is logged and
// left off rather than failing the read: the processor reads jobs through
// GetJob too.
func decodeJobPlan(jobID string, planJSON []byte) *shareddisc.ScanPlan {
	if len(planJSON) == 0 || string(planJSON) == "null" {
		return nil
	}
	var plan shareddisc.ScanPlan
	if err := json.Unmarshal(planJSON, &plan); err != nil {
		log.Printf("job %s: unreadable metadata.%s: %v", jobID, shareddisc.ScanPlanMetadataKey, err)
		return nil
	}
	return &plan
}

// UpdateJobStatus moves a job that has not ended to status. A job that has
// ended — completed, failed or cancelled — is never moved: the call returns
// ErrJobStatusConflict and writes nothing (see terminalJobStatuses). The one
// way out of a terminal state is RequeueJobForRetry.
func (s *DiscoveryService) UpdateJobStatus(jobID, status string, errorMessage *string) error {
	return s.UpdateJobStatusFrom(jobID, status, errorMessage)
}

// UpdateJobStatusFrom is UpdateJobStatus restricted to a job currently in one
// of from (any non-terminal status when from is empty). The check and the
// write are one UPDATE, so two writers racing for the same job cannot both
// win — which is what makes ClaimJob a claim.
func (s *DiscoveryService) UpdateJobStatusFrom(jobID, status string, errorMessage *string, from ...string) error {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Keyed by job id
	// only; no tenant is threaded to this call site (the job_processor calls it
	// with only the job id during the NATS-driven lifecycle). Wrapping requires
	// threading tenantID from every caller — deferred to Phase 4.
	now := time.Now()
	var query string
	var args []interface{}

	switch status {
	case "running":
		query = `UPDATE discovery_jobs SET status = $1, started_at = $2, updated_at = $3 WHERE id = $4`
		args = []interface{}{status, now, now, jobID}
	case "completed", "failed":
		query = `UPDATE discovery_jobs SET status = $1, completed_at = $2, updated_at = $3, error_message = $4 WHERE id = $5`
		args = []interface{}{status, now, now, errorMessage, jobID}
	default:
		query = `UPDATE discovery_jobs SET status = $1, updated_at = $2 WHERE id = $3`
		args = []interface{}{status, now, jobID}
	}
	query, args = guardJobStatusUpdate(query, args, from)

	res, err := s.bypassDB.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	} else if n == 0 {
		return s.jobStatusRefused(jobID, status)
	}

	// A job that ends has no unfinished targets left. Without this a job that
	// dies before the executor ever picks it up — a sensor that refuses the
	// command, a dispatch that fails, a stale command the sweep reaps — leaves
	// its `discovery_targets` rows at 'pending' for ever, and the Jobs page
	// shows targets still queued underneath a job that finished minutes ago.
	// Only the in-cluster executor (job_processor.go) and the sensor's own
	// completion report (sensor-manager) ever settled them, and neither of
	// those runs on this path.
	//
	// The job's own error_message is copied onto each target: a target row that
	// merely says 'failed' cannot tell an operator whether the address refused
	// the connection or the scan never started.
	//
	// Terminal rows are left alone, so a job that scanned half its targets and
	// then failed keeps the outcomes it earned.
	if status == "completed" || status == "failed" {
		if _, e := s.bypassDB.Exec(`
			UPDATE discovery_targets
			SET status = $2,
			    completed_at = COALESCE(completed_at, NOW()),
			    error_message = COALESCE(error_message, $3),
			    updated_at = NOW()
			WHERE job_id = $1 AND status NOT IN ('completed', 'failed')`,
			jobID, status, errorMessage); e != nil {
			// Not fatal: the job's own status is the record that matters, and
			// the next sweep is not blocked by a stale target row. Loudly
			// logged, because a silent failure here is what leaves the page
			// lying.
			log.Printf("Job %s marked %s but its unfinished targets could not be settled — the Jobs page will show them queued: %v", jobID, status, e)
		}
	}
	return nil
}

func (s *DiscoveryService) GetJobResults(jobID string, page, pageSize int) (*models.DiscoveryResultsResponse, error) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). Reads
	// discovery_findings keyed by job id only; no tenant is threaded to this
	// call site (handler passes only the job id). Wrapping requires threading
	// tenantID from the handler — deferred to Phase 4.
	offset := (page - 1) * pageSize

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM discovery_findings WHERE job_id = $1`
	err := s.bypassDB.Get(&total, countQuery, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to count results: %w", err)
	}

	// Get findings - use a struct that matches the database schema
	// Database columns: id, job_id, target_id, executed_via, protocol, port, resolved_ip, hostname, details, raw_blob_ref, raw_blob_size, error_code, confidence_score, created_at
	type FindingRow struct {
		ID              string    `db:"id"`
		JobID           string    `db:"job_id"`
		TargetID        string    `db:"target_id"`
		ExecutedVia     string    `db:"executed_via"`
		Protocol        string    `db:"protocol"`
		Port            int       `db:"port"`
		ResolvedIP      *string   `db:"resolved_ip"`
		Hostname        *string   `db:"hostname"`
		Details         *string   `db:"details"`
		RawBlobRef      *string   `db:"raw_blob_ref"`
		RawBlobSize     *int      `db:"raw_blob_size"`
		ErrorCode       *string   `db:"error_code"`
		ConfidenceScore *float64  `db:"confidence_score"`
		CreatedAt       time.Time `db:"created_at"`
	}

	var findingRows []FindingRow
	query := `
		SELECT id, job_id, target_id, executed_via, protocol, port, resolved_ip, hostname, details,
		       raw_blob_ref, raw_blob_size, error_code, confidence_score, created_at
		FROM discovery_findings
		WHERE job_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	err = s.bypassDB.Select(&findingRows, query, jobID, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get results: %w", err)
	}

	log.Printf("[DiscoveryService] GetJobResults: Retrieved %d findings for job %s", len(findingRows), jobID)

	// Convert to DiscoveryFinding models
	findings := make([]models.DiscoveryFinding, len(findingRows))
	for i, row := range findingRows {
		// Parse details JSONB field
		var detailsData map[string]interface{}
		if row.Details != nil && *row.Details != "" {
			log.Printf("[DiscoveryService] Finding %s: details length=%d, protocol=%s, port=%d",
				row.ID, len(*row.Details), row.Protocol, row.Port)
			if err := json.Unmarshal([]byte(*row.Details), &detailsData); err != nil {
				log.Printf("Warning: failed to parse details JSON for finding %s: %v, raw=%s", row.ID, err, (*row.Details)[:min(100, len(*row.Details))])
				detailsData = make(map[string]interface{})
			} else {
				log.Printf("[DiscoveryService] Finding %s: Successfully parsed details, keys=%v", row.ID, getMapKeys(detailsData))
			}
		} else {
			log.Printf("[DiscoveryService] Finding %s: No details data (nil or empty), protocol=%s, port=%d", row.ID, row.Protocol, row.Port)
			detailsData = make(map[string]interface{})
		}

		// Log data extraction for debugging
		if len(detailsData) > 0 && (row.Protocol == "TLS" || row.Protocol == "HTTPS") {
			keys := make([]string, 0, len(detailsData))
			for k := range detailsData {
				keys = append(keys, k)
			}
			log.Printf("[DiscoveryService] Returning finding with data: id=%s, protocol=%s, port=%d, dataKeys=%v, hasCertificates=%v, hasCipherSuite=%v",
				row.ID, row.Protocol, row.Port, keys,
				detailsData["certificates"] != nil, detailsData["cipher_suite"] != nil)
		}

		findings[i] = models.DiscoveryFinding{
			ID:              row.ID,
			JobID:           row.JobID,
			TargetID:        row.TargetID,
			ExecutedVia:     row.ExecutedVia,
			Protocol:        row.Protocol,
			Port:            row.Port,
			ResolvedIP:      valueOrEmpty(row.ResolvedIP),
			Hostname:        valueOrEmpty(row.Hostname),
			ConfidenceScore: valueOrDefaultFloat(row.ConfidenceScore, 0.0),
			Data:            detailsData, // Include parsed details as Data field
			CreatedAt:       row.CreatedAt,
		}
	}

	return &models.DiscoveryResultsResponse{
		JobID:           jobID,
		Findings:        findings,
		Total:           total,
		Page:            page,
		PageSize:        pageSize,
		Materialization: s.getJobMaterialization(jobID, total),
	}, nil
}

// getJobMaterialization counts what became of the job's findings once they were
// mirrored into the ingestion queue.
//
// `total` (rows in discovery_findings) and the queue counts answer different
// questions, so they are reported side by side under distinct names rather than
// as one "results" number that silently means whichever the reader assumes.
//
// Returns nil — not a zeroed struct — when the counts cannot be read, so a
// consumer can distinguish "nothing materialized" from "unknown".
func (s *DiscoveryService) getJobMaterialization(jobID string, total int) *models.DiscoveryMaterialization {
	// RLS: cross-tenant — runs on the bypass role, keyed by batch_id (the job id
	// the mirror stamps), consistent with the rest of this service's job reads.
	var row struct {
		Queued             int `db:"queued"`
		AutoApproved       int `db:"auto_approved"`
		PendingApproval    int `db:"pending_approval"`
		AwaitingProcessing int `db:"awaiting_processing"`
		Suppressed         int `db:"suppressed"`
		Observed           int `db:"observed"`
		ObservedHosts      int `db:"observed_hosts"`
		FindingHosts       int `db:"finding_hosts"`
	}
	// pending_approval is `= 'pending'`, not `<> 'auto_approved'`. The column
	// grew two more terminal values that are not auto_approved and are not
	// awaiting anything either: `observed` (host observations — identity
	// evidence, never a finding awaiting approval) and `suppressed` (the
	// matched asset is archived or denied, so nothing was materialized and no
	// approval decision will ever be made). The old predicate counted both as
	// "pending", so Discovery → Approvals' own summary permanently overstated
	// how much of a job was actually awaiting a human.
	err := s.bypassDB.Get(&row, `
		SELECT
			COUNT(*)                                                                                AS queued,
			COUNT(*) FILTER (WHERE processed_at IS NOT NULL AND approval_status = 'auto_approved')  AS auto_approved,
			COUNT(*) FILTER (WHERE processed_at IS NOT NULL AND approval_status = 'pending')         AS pending_approval,
			COUNT(*) FILTER (WHERE processed_at IS NULL)                                             AS awaiting_processing,
			COUNT(*) FILTER (WHERE processed_at IS NOT NULL AND approval_status = 'suppressed')      AS suppressed,
			COUNT(*) FILTER (WHERE processed_at IS NOT NULL AND approval_status = 'observed')        AS observed,
			COUNT(DISTINCT dest_ip) FILTER (WHERE processed_at IS NOT NULL AND approval_status = 'observed') AS observed_hosts,
			(SELECT COUNT(DISTINCT `+hostKeySQL+`) FROM discovery_findings WHERE job_id = $2::uuid) AS finding_hosts
		FROM sensor_discoveries
		WHERE batch_id = $1`, jobID, jobID)
	if err != nil {
		log.Printf("[DiscoveryService] getJobMaterialization: failed to count queue rows for job %s: %v", jobID, err)
		return nil
	}
	return &models.DiscoveryMaterialization{
		Findings:           total,
		Queued:             row.Queued,
		AutoApproved:       row.AutoApproved,
		PendingApproval:    row.PendingApproval,
		AwaitingProcessing: row.AwaitingProcessing,
		Suppressed:         row.Suppressed,
		Observed:           row.Observed,
		ObservedHosts:      row.ObservedHosts,
		FindingHosts:       row.FindingHosts,
	}
}

// GetJobs retrieves discovery jobs with pagination and filtering
// kind values: "" (no filter), "automatic" (the automatic-scan sweep —
// metadata.options.origin = autoscan.Origin), "manual" (everything else:
// Active Scan, the Discover wizard, any operator-started run).
func (s *DiscoveryService) GetJobs(tenantID string, page, pageSize int, status, kind, startDate, endDate string) ([]models.DiscoveryJob, int, error) {
	// Build WHERE clause
	whereClause := "WHERE j.tenant_id = $1"
	args := []interface{}{tenantID}
	argIndex := 2

	if status != "" {
		whereClause += fmt.Sprintf(" AND j.status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	switch kind {
	case "automatic":
		// Mirrors autoscan.originFilterJSON in inventory-service — kept as an
		// inline literal rather than importing inventory-service's package
		// (cluster-sensor-service does not depend on it), matched by a
		// dedicated test so the two cannot silently diverge.
		whereClause += fmt.Sprintf(" AND j.metadata @> $%d::jsonb", argIndex)
		args = append(args, `{"options":{"origin":"auto_scan"}}`)
		argIndex++
	case "manual":
		whereClause += fmt.Sprintf(" AND NOT (j.metadata @> $%d::jsonb)", argIndex)
		args = append(args, `{"options":{"origin":"auto_scan"}}`)
		argIndex++
	}

	if startDate != "" {
		whereClause += fmt.Sprintf(" AND j.created_at >= $%d", argIndex)
		args = append(args, startDate)
		argIndex++
	}

	if endDate != "" {
		whereClause += fmt.Sprintf(" AND j.created_at <= $%d", argIndex)
		args = append(args, endDate)
		argIndex++
	}

	// Get jobs with pagination
	offset := (page - 1) * pageSize
	jobsQuery := fmt.Sprintf(`
		SELECT j.id, j.tenant_id, COALESCE(j.created_by::text, '') AS created_by, j.execution_mode, j.status, j.requested_sensor_ids,
		       j.fanout, j.retention_cap_mb, j.retention_ttl_hours, j.created_at, j.updated_at,
		       j.started_at, j.completed_at, j.error_message,
		       j.assigned_sensor_id, j.dispatched_at,
		       s.name AS assigned_sensor_name, s.last_heartbeat AS assigned_sensor_last_heartbeat,
		       c.delivered_at AS picked_up_at,
		       COALESCE(j.metadata -> 'options' ->> 'origin', '') AS origin,
		       j.metadata -> '`+shareddisc.ScanPlanMetadataKey+`' AS plan_json
		FROM discovery_jobs j %s %s
		ORDER BY j.created_at DESC
		LIMIT $%d OFFSET $%d`, jobExecutorJoins, whereClause, argIndex, argIndex+1)

	// RLS-scoped reads over discovery_jobs. Both the count and the page run on
	// one tenant-scoped sqlx transaction so app.tenant_id is set on the same
	// connection as the queries; the explicit WHERE tenant_id = $1 stays as the
	// primary control. sqlx's struct-scan (Get/Select) is preserved by using a
	// *sqlx.Tx and setting tenant context on its embedded *sql.Tx.
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid tenant_id: %w", err)
	}

	// The plan rides along as raw JSON (models.DiscoveryJob.Plan is not a
	// column) so the Jobs page can show a scan-plan job's depth and executor
	// on its row ( WP4b).
	type listRow struct {
		models.DiscoveryJob
		PlanJSON []byte `db:"plan_json"`
	}
	var total int
	var rows []listRow
	err = s.withTenantTxx(context.Background(), tenantUUID, func(tx *sqlx.Tx) error {
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM discovery_jobs j %s", whereClause)
		if e := tx.Get(&total, countQuery, args...); e != nil {
			return fmt.Errorf("failed to count jobs: %w", e)
		}

		pageArgs := append(append([]interface{}{}, args...), pageSize, offset)
		if e := tx.Select(&rows, jobsQuery, pageArgs...); e != nil {
			return fmt.Errorf("failed to get jobs: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	jobs := make([]models.DiscoveryJob, len(rows))
	for i, r := range rows {
		jobs[i] = r.DiscoveryJob
		jobs[i].Executor = executorFor(jobs[i].ExecutionMode, jobs[i].AssignedSensorID)
		jobs[i].Plan = decodeJobPlan(jobs[i].ID, r.PlanJSON)
	}

	return jobs, total, nil
}

// jobExecutorJoins attaches the executor columns to a discovery_jobs read: the
// assigned sensor's name and last heartbeat, and when the sensor collected the
// job's command. LEFT joins, so a platform-run job reads exactly as before with
// NULLs in the new columns. The command is found through its payload's job_id
// (served by idx_sensor_commands_discovery_job_id) — the newest one, should a
// retry ever write a second.
const jobExecutorJoins = `
		LEFT JOIN sensors s ON s.id = j.assigned_sensor_id
		LEFT JOIN LATERAL (
			SELECT c.delivered_at
			FROM sensor_commands c
			WHERE c.command_type = 'discovery_job' AND c.payload ->> 'job_id' = j.id::text
			ORDER BY c.created_at DESC
			LIMIT 1
		) c ON true`

// withTenantTxx runs fn inside a tenant-scoped sqlx transaction. It mirrors
// shareddatabase.WithTenantTx but yields a *sqlx.Tx so callers keep sqlx's
// struct-scanning (Get/Select); tenant context is set on the embedded *sql.Tx
// via shareddatabase.SetTenantContext.
func (s *DiscoveryService) withTenantTxx(ctx context.Context, tenantID uuid.UUID, fn func(*sqlx.Tx) error) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// normalisedScanShape is what the job stores once its targets are parsed: each
// target's literal or hostname (a URL reduced to its host), and the requested
// ports plus any port a URL or host:port named explicitly — a person who typed
// https://host:8443/ expects 8443 scanned.
func normalisedScanShape(targets []dispatchguard.ResolvedTarget, ports []int) ([]string, []int) {
	inputs := make([]string, 0, len(targets))
	seen := make(map[int]bool, len(ports))
	outPorts := append([]int{}, ports...)
	for _, p := range ports {
		seen[p] = true
	}
	for _, t := range targets {
		inputs = append(inputs, t.Input)
		if t.Port > 0 && !seen[t.Port] {
			seen[t.Port] = true
			outPorts = append(outPorts, t.Port)
		}
	}
	return inputs, outPorts
}

// pinnedAddresses maps each hostname target to the addresses it resolved to
// when it was authorized — the only addresses the scanner may connect to for
// it. Literal targets need no pin: an address cannot rebind.
func pinnedAddresses(targets []dispatchguard.ResolvedTarget) map[string][]string {
	out := map[string][]string{}
	for _, t := range targets {
		if addrs := t.ScanAddresses(); len(addrs) > 0 {
			out[t.Input] = addrs
		}
	}
	return out
}
