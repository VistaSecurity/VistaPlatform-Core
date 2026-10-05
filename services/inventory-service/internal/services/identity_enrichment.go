package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// IdentityEnrichmentBackend uses the same authenticated source, command and
// discovery queues as operator-triggered work. It never tries credentials.
type IdentityEnrichmentBackend struct {
	assets    *AssetService
	discovery *DiscoveryService
	sourceURL string
}

func NewIdentityEnrichmentBackend(assets *AssetService, discovery *DiscoveryService) *IdentityEnrichmentBackend {
	return &IdentityEnrichmentBackend{assets: assets, discovery: discovery, sourceURL: sharedconfig.PeerURL("device-interrogation-service", sharedconfig.MTLSEnabled())}
}
func (b *IdentityEnrichmentBackend) Dispatch(ctx context.Context, j identityenrichment.Job, o identityenrichment.Observation) (identityenrichment.Result, error) {
	policy, err := (&identityenrichment.Store{DB: b.assets.db}).Policy(ctx, j.TenantID)
	if err != nil {
		return identityenrichment.Result{}, err
	}
	if !policy.Active() {
		return identityenrichment.Result{State: "waiting", Reason: "admission_or_enrichment_paused", RemoteID: j.RemoteID}, nil
	}
	switch j.Plan.Action {
	case "configured_source":
		return b.sourceRequest(ctx, http.MethodPost, j, o)
	case "dns":
		var command uuid.UUID
		err := database.WithTenantTx(ctx, b.assets.db, j.TenantID, func(tx *sqlx.Tx) error {
			active, err := enrichmentActiveTx(ctx, tx.Tx, j.TenantID)
			if err != nil {
				return err
			}
			if !active {
				return errEnrichmentPaused
			}
			command, err = pgidentity.EnqueueIdentityDNS(ctx, tx.Tx, j.TenantID, j.Plan.SensorID, sensordispatch.IdentityDNSRequest{
				RequestID: j.RequestID.String(), ObservationID: o.ID.String(), Hostname: j.Plan.Hostname, NetworkScope: j.Plan.SegmentID.String(), SegmentCIDR: j.Plan.SegmentCIDR, TimeoutMS: 2000, MaxAddresses: 8})
			return err
		})
		if errors.Is(err, errEnrichmentPaused) {
			return identityenrichment.Result{State: "waiting", Reason: "admission_or_enrichment_paused"}, nil
		}
		return identityenrichment.Result{State: "queued", RemoteID: command.String()}, err
	case "probe":
		// Back-pressure: hand the executor nothing while it already holds its
		// share of work (identityenrichment.MaxCollectorJobsInFlight). A full
		// sensor refuses what it cannot queue, and on a lab deployment that refusal
		// became a blocked observation plus a tenant-facing job_failed alert.
		// Counted against EVERY origin, because the queue is shared. Two
		// workers can both pass this check at once, so it can overshoot by the
		// worker count; the sensor-busy path in Poll absorbs that.
		var inFlight int
		if err := database.WithTenantTx(ctx, b.assets.db, j.TenantID, func(tx *sqlx.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM discovery_jobs
   WHERE tenant_id=$1 AND status IN ('queued','awaiting_sensor','running')
    AND (assigned_sensor_id=$2 OR (assigned_sensor_id IS NULL AND $2::text=ANY(requested_sensor_ids)))
    AND updated_at>now()-interval '24 hours'`, j.TenantID, j.Plan.SensorID).Scan(&inFlight)
		}); err != nil {
			return identityenrichment.Result{}, err
		}
		if inFlight >= identityenrichment.MaxCollectorJobsInFlight {
			return identityenrichment.Result{State: "waiting", Reason: identityenrichment.ReasonCollectorBusy}, nil
		}
		// A planned job on the shared scan engine ( WP4): scan depth
		// "custom" on the plan's ports, no protocol list — the engine
		// identifies TLS and SSH from what answers. cluster-sensor-service
		// falls back to the legacy job for a sensor without plan support
		// (owner decision D3), and answers with the stored job for a request
		// ID a pre-upgrade build already dispatched in the legacy shape.
		job, err := b.discovery.CreateJobInternal(j.TenantID.String(), models.CreateDiscoveryJobInput{
			Targets: j.Plan.Addresses, ExecutionMode: "sensors", PreferredSensorIDs: []string{j.Plan.SensorID.String()},
			ScanDepth: string(shareddisc.DepthCustom), TCPPorts: shareddisc.CustomPortList(j.Plan.Ports),
			Options: map[string]interface{}{"origin": "identity_enrichment", "active_scan": true, "identity_enrichment_request_id": j.RequestID.String(), "identity_observation_id": o.ID.String(), "identity_network_scope": j.Plan.SegmentID.String()},
		})
		if err != nil {
			return identityenrichment.Result{}, err
		}
		return identityenrichment.Result{State: "queued", RemoteID: job.ID}, nil
	default:
		return identityenrichment.Result{}, fmt.Errorf("unsupported identity enrichment action")
	}
}
func (b *IdentityEnrichmentBackend) Poll(ctx context.Context, j identityenrichment.Job, o identityenrichment.Observation) (identityenrichment.Result, error) {
	switch j.Plan.Action {
	case "configured_source":
		if j.State == "failed" || j.State == "blocked" {
			return b.sourceRequest(ctx, http.MethodPost, j, o)
		}
		return b.sourceRequest(ctx, http.MethodGet, j, o)
	case "dns":
		return b.pollDNS(ctx, j, o)
	case "probe":
		var status, failureCode string
		ready := false
		err := database.WithTenantTx(ctx, b.assets.db, j.TenantID, func(tx *sqlx.Tx) error {
			var submitted *int
			var planned bool
			if err := tx.QueryRowContext(ctx, `SELECT status,(metadata->'sensor_result'->>'discoveries_submitted')::integer,COALESCE(metadata->>$4,''),COALESCE(metadata ? $5,false) FROM discovery_jobs WHERE tenant_id=$1 AND id=$2 AND metadata->'options'->>'identity_enrichment_request_id'=$3`, j.TenantID, j.RemoteID, j.RequestID.String(), sensordispatch.FailureCodeKey, shareddisc.ScanPlanMetadataKey).Scan(&status, &submitted, &failureCode, &planned); err != nil {
				return err
			}
			if status != "completed" {
				return nil
			}
			if planned {
				var err error
				ready, err = plannedProbeResultsIngested(ctx, tx, j.TenantID, j.RemoteID)
				return err
			}
			if submitted == nil {
				return nil
			}
			var total, pending int
			if err := tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE processed_at IS NULL) FROM sensor_discoveries
    WHERE tenant_id=$1 AND sensor_id=$2 AND (metadata->'raw_metadata'->>'job_id'=$3 OR metadata->>'job_id'=$3)`, j.TenantID, j.Plan.SensorID, j.RemoteID).Scan(&total, &pending); err != nil {
				return err
			}
			ready = total >= *submitted && pending == 0
			return nil
		})
		result := identityenrichment.Result{State: "running", RemoteID: j.RemoteID}
		if status == "completed" && ready {
			result.State = "completed"
			result.Reason = "probe_results_ingested"
		}
		if status == "failed" || status == "cancelled" {
			result.State = "blocked"
			result.Reason = "probe_failed_review_collector_before_retry"
		}
		if status == "failed" && failureCode == sensordispatch.FailureCodeSensorBusy {
			// The sensor refused it only because its queue was full: nothing
			// ran, and nothing about the collector needs review. Send a new
			// request later, with backoff (Store.Finish).
			result = identityenrichment.Result{State: "waiting", Reason: identityenrichment.ReasonCollectorBusy, Redispatch: true}
		}
		return result, err
	default:
		return identityenrichment.Result{}, fmt.Errorf("unsupported identity enrichment action")
	}
}

// plannedProbeResultsIngested reports whether every result a completed PLANNED
// probe job queued for inventory has been processed ( WP3, spec V5).
//
// A planned job's results do not arrive the legacy way. The legacy sensor
// counted what it pushed (sensor_result.discoveries_submitted) and stamped the
// job id into each row's metadata; a planned job's hosts are stored one by one
// through shared/jobunits, which mirrors each finding into sensor_discoveries
// with batch_id = the job id, and its completion carries no submitted count —
// so the legacy test read 0 >= 0 and declared the probe ingested the moment the
// job completed, before the discovery processor had looked at a single row.
//
// The count is complete by the time the job is: a unit's mirror rows commit in
// the same transaction as its `done`, and a report that arrives after the job
// ended is refused (jobunits.RecordSensorBatch), so "every mirrored row of this
// job has processed_at" is exactly "the results are ingested" — and zero rows
// (a probe that found nothing) is ingested at once.
//
// The rows are queued under the executor: the tenant sensor the job was
// assigned to, or the tenant's platform discovery sensor when the platform ran
// it (assigned_sensor_id NULL; cluster-sensor-service's platformSensorIDTx).
// Matching the executor, not just the batch, keeps a row some other sensor
// submitted under a batch id that happens to equal the job id out of the count.
func plannedProbeResultsIngested(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, jobID string) (bool, error) {
	var pending int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE sd.processed_at IS NULL) FROM sensor_discoveries sd
   JOIN discovery_jobs j ON j.tenant_id=sd.tenant_id AND j.id::text=sd.batch_id
  WHERE sd.tenant_id=$1 AND sd.batch_id=$2
    AND sd.sensor_id=COALESCE(j.assigned_sensor_id,(SELECT s.id FROM sensors s
          WHERE s.tenant_id=$1 AND s.profile='discovery' AND 'system'=ANY(s.tags) ORDER BY s.id LIMIT 1))`, tenant, jobID).Scan(&pending)
	return pending == 0, err
}

func (b *IdentityEnrichmentBackend) sourceRequest(ctx context.Context, method string, j identityenrichment.Job, o identityenrichment.Observation) (identityenrichment.Result, error) {
	payload := map[string]interface{}{"request_id": j.RequestID, "tenant_id": j.TenantID, "observation_id": o.ID, "evidence": j.RequestEvidence}
	raw, err := json.Marshal(payload)
	if err != nil {
		return identityenrichment.Result{}, err
	}
	path := "/internal/enrichment/refresh"
	var body io.Reader = bytes.NewReader(raw)
	if method == http.MethodGet {
		path += "/" + j.RemoteID + "?tenant_id=" + j.TenantID.String()
		body = nil
	}
	req, err := http.NewRequestWithContext(ctx, method, b.sourceURL+path, body)
	if err != nil {
		return identityenrichment.Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", j.TenantID.String())
	serviceauth.SignRequestFromEnv(req)
	response, err := b.discovery.httpClient.Do(req)
	if err != nil {
		return identityenrichment.Result{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return identityenrichment.Result{}, fmt.Errorf("configured source refresh returned %d", response.StatusCode)
	}
	var out struct {
		JobID  string `json:"job_id"`
		State  string `json:"state"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&out); err != nil {
		return identityenrichment.Result{}, err
	}
	id, err := uuid.Parse(out.JobID)
	if err != nil || id != j.RequestID {
		return identityenrichment.Result{}, fmt.Errorf("source refresh returned mismatched request")
	}
	return identityenrichment.Result{State: out.State, Reason: out.Reason, RemoteID: out.JobID}, nil
}

func (b *IdentityEnrichmentBackend) pollDNS(ctx context.Context, j identityenrichment.Job, o identityenrichment.Observation) (identityenrichment.Result, error) {
	command, err := uuid.Parse(j.RemoteID)
	if err != nil {
		return identityenrichment.Result{}, err
	}
	var state string
	var result *sensordispatch.IdentityDNSResult
	err = database.WithTenantTx(ctx, b.assets.db, j.TenantID, func(tx *sqlx.Tx) error {
		var err error
		state, result, err = pgidentity.PollIdentityDNS(ctx, tx.Tx, j.TenantID, j.Plan.SensorID, command)
		return err
	})
	out := identityenrichment.Result{State: "running", RemoteID: j.RemoteID}
	if err != nil {
		return out, err
	}
	if state == "failed" || state == "expired" {
		out.State = "blocked"
		out.Reason = "dns_collector_failed"
		return out, nil
	}
	if state != "completed" || result == nil {
		return out, nil
	}
	if result.ErrorCode != "" {
		out.State = "blocked"
		out.Reason = result.ErrorCode
		return out, nil
	}
	if result.RequestID != j.RequestID.String() || result.ObservationID != o.ID.String() || result.NetworkScope != j.Plan.SegmentID.String() || result.Hostname != j.Plan.Hostname || result.ObservedAt.IsZero() || result.CollectorVersion == "" || result.CollectorVersion != j.Plan.CollectorVersion {
		return out, fmt.Errorf("DNS result does not match requested scope")
	}
	prefix, err := netip.ParsePrefix(j.Plan.SegmentCIDR)
	if err != nil {
		return out, err
	}
	if len(result.Addresses) > identityenrichment.MaxAddresses || result.ObservedAt.After(time.Now().Add(2*time.Minute)) {
		return out, fmt.Errorf("DNS result exceeds response bounds")
	}
	for _, raw := range result.Addresses {
		a, err := netip.ParseAddr(raw)
		if err != nil || !prefix.Contains(a.Unmap()) || !a.IsGlobalUnicast() || a.IsLoopback() {
			return out, fmt.Errorf("DNS response address outside requested scope")
		}
	}
	store := &identityenrichment.Store{DB: b.assets.db}
	policy, err := store.Policy(ctx, j.TenantID)
	if err != nil {
		return out, err
	}
	scope, excluded, err := store.Scope(ctx, j.TenantID, o, time.Now())
	if err != nil {
		return out, err
	}
	authorized, reason := identityenrichment.NetworkPlan(o, policy, scope, result.Addresses, append(excluded, autoscan.PlatformExcludedPrefixes()...))
	if reason != "" {
		out.State = "blocked"
		out.Reason = reason
		return out, nil
	}
	retained := *result
	if authorized.Action == "probe" {
		retained.Addresses = authorized.Addresses
	} else {
		retained.Addresses = []string{}
	}
	result = &retained
	// The DNS answer as a sighting (dnsEvidenceSighting): name-to-address
	// context, never direct device or interface proof, scoped and graded by
	// the intake like every other sighting.
	intake, err := b.assets.assessSighting(ctx, "DNS answer for "+result.Hostname, dnsEvidenceSighting(j, o, result))
	if err != nil {
		return out, err
	}
	evidence := intake.Observation
	// The plan authorised addresses inside ONE segment. If the topology moved
	// between planning and ingesting — the segment edited or deleted — the
	// answer no longer means what was asked, and it is refused rather than
	// filed under whatever segment the address is in now.
	for _, id := range evidence.Identifiers {
		if id.Kind == identity.KindIPAddress && id.Scope != j.Plan.SegmentID.String() {
			return out, fmt.Errorf("DNS address scope changed before ingestion")
		}
	}
	// Hold the tenant policy decision through the evidence transaction; a
	// disable that commits first cannot be overtaken by a queued DNS result.
	engine, err := b.assets.identityEngine()
	if err != nil {
		return out, err
	}
	err = b.assets.identityRepo.RunInTx(ctx, j.TenantID.String(), func(repo *pgidentity.Repository) error {
		active, err := enrichmentActiveTx(ctx, repo.Tx(), j.TenantID)
		if err != nil {
			return err
		}
		if !active {
			return errEnrichmentPaused
		}
		res, err := engine.WithAutoAcceptThreshold(0).WithRepository(repo).Resolve(ctx, evidence)
		if err != nil {
			return err
		}
		tx := b.assets.sqlxOver(repo.Tx())
		// The DNS answer put the sighting's name and address in front of two
		// different owners and the engine opened a merge proposal. The
		// proposal names the DNS evidence row, not the sighting `o` that
		// asked the question, and a later Reevaluate/Materialize re-resolves
		// `o`'s bare stored evidence — which may now name only ONE of the
		// owners and would link, silently picking a side of the conflict the
		// system just flagged. Record the proposal on `o`; those two
		// paths skip an observation whose proposal is still pending.
		if res.Outcome == identity.OutcomeConflict && res.Proposal.ID != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE identity_observations SET proposal_id=$3::uuid,updated_at=now()
 WHERE tenant_id=$1 AND id=$2 AND state='unresolved' AND asset_id IS NULL AND proposal_id IS NULL`, j.TenantID, o.ID, res.Proposal.ID); err != nil {
				return err
			}
		}
		if res.ObservationID == "" {
			return nil
		}
		_, err = tx.ExecContext(ctx, `UPDATE identity_observations SET enrichment_state='completed',enrichment_reason='dns_context_only',next_attempt_at=$3 WHERE tenant_id=$1 AND id=$2`, j.TenantID, res.ObservationID, time.Now().Add(90*24*time.Hour))
		return err
	})
	if err != nil {
		return out, err
	}
	out.State = "completed"
	out.Data, err = json.Marshal(result)
	return out, err
}

func (b *IdentityEnrichmentBackend) Reevaluate(ctx context.Context, tenant uuid.UUID, o identityenrichment.Observation) error {
	policy, policyErr := (&identityenrichment.Store{DB: b.assets.db}).Policy(ctx, tenant)
	if policyErr != nil {
		return policyErr
	}
	if !policy.Active() {
		return nil
	}
	if o.Evidence.TenantID != tenant.String() {
		return fmt.Errorf("observation tenant mismatch")
	}
	// A completed responsive probe may now recognize prior DNS context. Re-feed
	// that exact source receipt through the same matcher, without promoting DNS
	// to direct evidence or assigning the original observation to an IP by hand.
	var dnsJobs []identityenrichment.Job
	err := database.WithTenantTx(ctx, b.assets.db, tenant, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id,request_id,remote_id,plan,result FROM identity_enrichment_jobs
   WHERE tenant_id=$1 AND observation_id=$2 AND action='dns' AND state='completed'
    AND updated_at>now()-interval '1 day' ORDER BY updated_at DESC LIMIT 1`, tenant, o.ID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			j := identityenrichment.Job{TenantID: tenant, ObservationID: o.ID}
			var raw []byte
			if err := rows.Scan(&j.ID, &j.RequestID, &j.RemoteID, &raw, &j.Result); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &j.Plan); err != nil {
				return err
			}
			dnsJobs = append(dnsJobs, j)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, j := range dnsJobs {
		result, err := b.pollDNS(ctx, j, o)
		if err != nil {
			return err
		}
		if result.State == "completed" {
			j.Result = result.Data
			if err := b.corroborateDNS(ctx, tenant, o, j); err != nil {
				return err
			}
		}
	}
	engine, err := b.assets.identityEngine()
	if err != nil {
		return err
	}
	return b.assets.identityRepo.RunInTx(ctx, tenant.String(), func(repo *pgidentity.Repository) error {
		active, err := enrichmentActiveTx(ctx, repo.Tx(), tenant)
		if err != nil {
			return err
		}
		if !active {
			return nil
		}
		if err := repo.LockIdentifiers(ctx, tenant.String(), o.Evidence.Identifiers); err != nil {
			return err
		}
		var state string
		var raw []byte
		var underReview bool
		if err := repo.Tx().QueryRowContext(ctx, `SELECT state,evidence,`+observationUnderReviewSQL+` FROM identity_observations o WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, o.ID).Scan(&state, &raw, &underReview); err != nil {
			return err
		}
		// A pending merge proposal is a question for a person; re-resolving the
		// bare evidence must not answer it by linking one side.
		if state != "unresolved" || underReview {
			return nil
		}
		var current identity.Observation
		if err := json.Unmarshal(raw, &current); err != nil {
			return err
		}
		original := o
		original.Cycle = ""
		if identityenrichment.Generation(original) != identityenrichment.Generation(identityenrichment.Observation{Evidence: current}) {
			return nil
		}
		_, err = engine.WithAutoAcceptThreshold(0).WithRepository(repo).Resolve(ctx, current)
		return err
	})
}

// Materialize implements D5: re-resolve ONE retained observation that
// never produced an asset, and stamp when it was looked at.
//
// It is the tail of [IdentityEnrichmentBackend.Reevaluate] with one deliberate
// difference: the gate is ADMISSION, not enrichment. Enrichment is work the
// platform does on a tenant's network and a tenant may switch it off; this is
// the platform re-reading evidence it already stored, and gating it on the
// enrichment switch would leave those tenants' retained observations invisible
// in the inventory for ever — which is the exact defect the pass exists to
// repair, since the rows it is for were blocked precisely BECAUSE no collector
// could reach their network.
//
// `materialized_at` is written whether or not an asset resulted, and it is a
// CLOCK rather than a fingerprint of the evidence. Whether an observation can
// become a provisional item is not a question about the evidence — the
// identifiers and the scope are fixed — it is a question about tenant state
// that keeps moving. An observation refused for an overlapping segment must be
// reconsidered once the operator resolves the overlap, and nothing about the
// stored evidence changes when they do. See
// [identityenrichment.MaterializationInterval].
//
// The interval is re-checked HERE as well as in the candidate query, under the
// row lock: the candidate list is read outside the transaction, so two workers
// can both see the same row as due, and without this the loser would re-run
// Resolve on a row the winner had just finished.
func (b *IdentityEnrichmentBackend) Materialize(ctx context.Context, tenant uuid.UUID, o identityenrichment.Observation) error {
	if o.Evidence.TenantID != tenant.String() {
		return fmt.Errorf("observation tenant mismatch")
	}
	engine, err := b.assets.identityEngine()
	if err != nil {
		return err
	}
	return b.assets.identityRepo.RunInTx(ctx, tenant.String(), func(repo *pgidentity.Repository) error {
		enforcing, err := admissionEnforcingTx(ctx, repo.Tx(), tenant)
		if err != nil {
			return err
		}
		if !enforcing {
			return nil
		}
		if err := repo.LockIdentifiers(ctx, tenant.String(), o.Evidence.Identifiers); err != nil {
			return err
		}
		var state string
		var assetID sql.NullString
		var raw []byte
		var due, underReview bool
		if err := repo.Tx().QueryRowContext(ctx, `SELECT state,asset_id::text,evidence,
   (materialized_at IS NULL OR materialized_at<now()-$3::interval),`+observationUnderReviewSQL+`
   FROM identity_observations o WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
			tenant, o.ID, identityenrichment.MaterializationInterval.String()).Scan(&state, &assetID, &raw, &due, &underReview); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		// Anything that already has an asset, or that a reviewer has decided,
		// is not this pass's business. Re-resolving a dismissed observation
		// would resurrect a decision somebody made on purpose.
		if state != "unresolved" || assetID.Valid || !due || underReview {
			return nil
		}
		var current identity.Observation
		if err := json.Unmarshal(raw, &current); err != nil {
			return err
		}
		if _, err := engine.WithAutoAcceptThreshold(0).WithRepository(repo).Resolve(ctx, current); err != nil {
			return err
		}
		_, err = repo.Tx().ExecContext(ctx, `UPDATE identity_observations SET materialized_at=now(),updated_at=now()
   WHERE tenant_id=$1 AND id=$2`, tenant, o.ID)
		return err
	})
}

// observationUnderReviewSQL is true while the observation (aliased `o`) is the
// subject of a merge proposal nobody has decided. identity_observations.
// proposal_id is the durable link; a decided proposal no longer holds the
// observation, so a resolved review lets re-evaluation resume.
const observationUnderReviewSQL = `EXISTS (SELECT 1 FROM public.asset_history h
   WHERE h.tenant_id=o.tenant_id AND h.id=o.proposal_id AND h.action='merge_proposed'
     AND COALESCE(h.changes_json->>'status','pending')='pending')`

var errEnrichmentPaused = errors.New("identity enrichment is paused")

// admissionEnforcingTx reads the tenant's admission mode under the same FOR
// SHARE lock enrichmentActiveTx uses, so a policy change that commits first
// cannot be overtaken by work already in flight.
//
// It asks a DIFFERENT question from enrichmentActiveTx: only whether admission
// is enforcing. Materialization has nothing to do with the enrichment switch —
// see [IdentityEnrichmentBackend.Materialize].
func admissionEnforcingTx(ctx context.Context, tx *sql.Tx, tenant uuid.UUID) (bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT config FROM tenant_admin_settings WHERE tenant_id=$1 FOR SHARE`, tenant).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	policy, err := identityenrichment.ParsePolicy(raw)
	return policy.AdmissionMode == "enforce", err
}

func enrichmentActiveTx(ctx context.Context, tx *sql.Tx, tenant uuid.UUID) (bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT config FROM tenant_admin_settings WHERE tenant_id=$1 FOR SHARE`, tenant).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	policy, err := identityenrichment.ParsePolicy(raw)
	return policy.Active(), err
}

// dnsEvidenceSighting is what a DNS lookup SAW: a name, and the addresses it
// resolved to inside the requested segment.
//
// A DNS answer is name-to-address context, never device or interface proof,
// so the channel is `advertisement` and the answer can neither bind an
// interface nor inflate corroboration.
//
// The name is scoped with the address of the sighting that asked the question
// — the first address the original observation held in the requested segment
// — so a lookup that returned nothing in scope still names the host where it
// was asked about, instead of drifting to the tenant default.
func dnsEvidenceSighting(j identityenrichment.Job, o identityenrichment.Observation, result *sensordispatch.IdentityDNSResult) identity.Sighting {
	segment := j.Plan.SegmentID.String()
	asked := ""
	for _, id := range o.Evidence.Identifiers {
		if id.Kind == identity.KindIPAddress && id.Scope == segment {
			asked = id.Value
			break
		}
	}
	sg := identity.Sighting{
		TenantID:         j.TenantID.String(),
		Source:           identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:identity-dns:" + j.Plan.SensorID.String(), Mode: identity.ModeActive},
		Channel:          identity.ChannelAdvertisement,
		ObservedAt:       result.ObservedAt,
		ReceiptID:        j.RequestID.String(),
		CollectorVersion: result.CollectorVersion,
		Ownership:        o.Evidence.Network.Ownership,
		NetworkType:      o.Evidence.Network.Type,
		Identifiers:      []identity.SightedIdentifier{{Kind: identity.KindHostname, Value: result.Hostname, Address: asked}},
	}
	for _, address := range result.Addresses {
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: address})
	}
	return sg
}
