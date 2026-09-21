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
		job, err := b.discovery.CreateJobInternal(j.TenantID.String(), models.CreateDiscoveryJobInput{
			Targets: j.Plan.Addresses, ExecutionMode: "sensors", PreferredSensorIDs: []string{j.Plan.SensorID.String()}, Protocols: j.Plan.Protocols, Ports: j.Plan.Ports,
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
		var status string
		ready := false
		err := database.WithTenantTx(ctx, b.assets.db, j.TenantID, func(tx *sqlx.Tx) error {
			var submitted *int
			if err := tx.QueryRowContext(ctx, `SELECT status,(metadata->'sensor_result'->>'discoveries_submitted')::integer FROM discovery_jobs WHERE tenant_id=$1 AND id=$2 AND metadata->'options'->>'identity_enrichment_request_id'=$3`, j.TenantID, j.RemoteID, j.RequestID.String()).Scan(&status, &submitted); err != nil {
				return err
			}
			if status != "completed" || submitted == nil {
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
		return result, err
	default:
		return identityenrichment.Result{}, fmt.Errorf("unsupported identity enrichment action")
	}
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
	evidence := identity.Observation{TenantID: j.TenantID.String(), ObservedAt: result.ObservedAt, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:identity-dns:" + j.Plan.SensorID.String(), Mode: identity.ModeActive}, Network: o.Evidence.Network,
		Admission: identity.AdmissionEvidence{CollectorVersion: result.CollectorVersion, ReceiptID: j.RequestID.String()}, DynamicScopes: o.Evidence.DynamicScopes}
	// DNS is name-to-address context, never direct device/interface proof. Keep
	// it separate from the original source and never inflate corroboration.
	kind, nameScope := identity.KindHostname, j.Plan.SegmentID.String()
	for _, id := range o.Evidence.Identifiers {
		if id.Value == result.Hostname && id.Kind == identity.KindFQDN {
			kind = identity.KindFQDN
			nameScope = id.Scope
		}
	}
	evidence.DynamicScopes = make(map[string]bool, len(o.Evidence.DynamicScopes))
	for key, value := range o.Evidence.DynamicScopes {
		evidence.DynamicScopes[key] = value
	}
	if _, err := b.assets.identityEngine(); err != nil {
		return out, err
	}
	for _, address := range result.Addresses {
		matchedScope, dynamic, err := b.assets.identityRepo.ScopeForAddress(ctx, j.TenantID.String(), netip.MustParseAddr(address), "")
		if err != nil {
			return out, err
		}
		if matchedScope != j.Plan.SegmentID.String() {
			return out, fmt.Errorf("DNS address scope changed before ingestion")
		}
		evidence.DynamicScopes[matchedScope] = evidence.DynamicScopes[matchedScope] || dynamic
	}
	evidence.Identifiers = append(evidence.Identifiers, identity.Identifier{Kind: kind, Value: result.Hostname, Scope: nameScope})
	for _, address := range result.Addresses {
		evidence.Identifiers = append(evidence.Identifiers, identity.Identifier{Kind: identity.KindIPAddress, Value: address, Scope: j.Plan.SegmentID.String()})
	}
	evidence, _ = evidence.Sanitize()
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
		if err := repo.Tx().QueryRowContext(ctx, `SELECT state,evidence FROM identity_observations WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, o.ID).Scan(&state, &raw); err != nil {
			return err
		}
		if state != "unresolved" {
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
		var due bool
		if err := repo.Tx().QueryRowContext(ctx, `SELECT state,asset_id::text,evidence,
   (materialized_at IS NULL OR materialized_at<now()-$3::interval)
   FROM identity_observations WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
			tenant, o.ID, identityenrichment.MaterializationInterval.String()).Scan(&state, &assetID, &raw, &due); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		// Anything that already has an asset, or that a reviewer has decided,
		// is not this pass's business. Re-resolving a dismissed observation
		// would resurrect a decision somebody made on purpose.
		if state != "unresolved" || assetID.Valid || !due {
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
