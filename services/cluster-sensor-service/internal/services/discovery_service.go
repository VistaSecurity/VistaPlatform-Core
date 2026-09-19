package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
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
}

func NewDiscoveryService(db, bypassDB *sqlx.DB) *DiscoveryService {
	return &DiscoveryService{db: db, bypassDB: bypassDB}
}

// Tenant-sensor dispatch rules (which sensor a `sensors` job may be handed to,
// and why a request is refused) live in sensor_dispatch.go.

func (s *DiscoveryService) CreateJob(tenantID, userID string, req models.CreateDiscoveryJobRequest) (*models.DiscoveryJob, error) {
	// The coordinator persists this token before dispatch. A retry after remote
	// commit must return the same job rather than perform another network probe.
	requestID := ""
	requestFingerprint := ""
	if raw, exists := req.Options["identity_enrichment_request_id"]; exists {
		value, ok := raw.(string)
		parsed, parseErr := uuid.Parse(value)
		if !ok || parseErr != nil || parsed == uuid.Nil {
			return nil, fmt.Errorf("invalid identity enrichment request ID")
		}
		requestID = parsed.String()
		encoded, encodeErr := json.Marshal(req)
		if encodeErr != nil {
			return nil, encodeErr
		}
		sum := sha256.Sum256(encoded)
		requestFingerprint = hex.EncodeToString(sum[:])
	}

	if requestID != "" {
		tenant, err := uuid.Parse(tenantID)
		if err != nil {
			return nil, err
		}
		replay := &models.DiscoveryJob{TenantID: tenantID, ExecutionMode: req.ExecutionMode, RequestedSensorIDs: req.PreferredSensorIDs}
		var storedFingerprint string
		err = shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenant, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT id,status,created_at,updated_at,COALESCE(metadata->>'identity_enrichment_fingerprint','')
    FROM discovery_jobs WHERE tenant_id=$1 AND metadata->'options'->>'identity_enrichment_request_id'=$2`, tenant, requestID).
				Scan(&replay.ID, &replay.Status, &replay.CreatedAt, &replay.UpdatedAt, &storedFingerprint)
		})
		if err == nil {
			if storedFingerprint != requestFingerprint {
				return nil, fmt.Errorf("identity enrichment request ID reused with different inputs")
			}
			return replay, nil
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	// A `sensors` job is refused HERE, with a reason, when the sensor it names
	// is unknown, the platform's own, air-gapped or offline. Refusing at
	// creation is what keeps "the job was created" meaning "the job can run":
	// a row waiting on a sensor that will never collect it is the silent
	// failure this path used to produce, in a different costume.
	if _, err := s.resolveDispatchSensor(context.Background(), tenantID, req.ExecutionMode, req.PreferredSensorIDs, time.Now()); err != nil {
		return nil, err
	}
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	if len(req.Targets) > 1000 {
		return nil, fmt.Errorf("too many targets; limit is 1000 per job")
	}

	// OT active probes are an independent per-target cross-product:
	// each requested OT protocol probes its standard port. Tier flag
	// `ot_active_probing` gates the capability — when off, requested OT
	// probes are dropped silently and logged so the operator gets the
	// rest of the job rather than a hard 4xx.
	otProtocols := canonicalizeOTProbeProtocols(req.OTProbeProtocols)
	if len(otProtocols) > 0 {
		tenantUUID, parseErr := uuid.Parse(tenantID)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid tenant_id: %w", parseErr)
		}
		limitSvc := sharedservices.NewLimitEnforcementService(s.db.DB)
		allowed, ferr := limitSvc.CheckFeatureAccess(tenantUUID, "ot_active_probing")
		if ferr != nil {
			log.Printf("CreateJob: tier flag check ot_active_probing failed for tenant %s: %v — dropping OT probes", tenantID, ferr)
			otProtocols = nil
		} else if !allowed {
			log.Printf("CreateJob: tenant %s lacks ot_active_probing tier flag, dropping OT probes %v", tenantID, otProtocols)
			otProtocols = nil
		}
	}
	// ot_probe_protocols is an audit column whose documented meaning is "these
	// probes were dispatched". Keep it honest: drop any protocol we would not
	// actually create a target row for, so the column can never claim a probe
	// that never left the cluster. (otProbeDefaultPort covers every allowlisted
	// protocol today, so this normally filters nothing — it is here so that a
	// future protocol added to the allowlist without a port cannot silently
	// re-open the "recorded as probed, never probed" gap B-60 was.)
	otProtocols = dispatchableOTProtocols(otProtocols)

	itProbing := len(req.Protocols) > 0 && len(req.Ports) > 0
	if !itProbing && len(otProtocols) == 0 {
		return nil, fmt.Errorf("at least one protocol/port pair or OT probe is required")
	}
	if itProbing {
		if len(req.Protocols) == 0 {
			return nil, fmt.Errorf("at least one protocol is required")
		}
		if len(req.Ports) == 0 {
			return nil, fmt.Errorf("at least one port is required")
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
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// RLS-scoped writes: discovery_jobs and discovery_targets both carry a
	// tenant_isolation policy. The whole job creation (job row + its target
	// rows) runs inside one WithTenantTx so app.tenant_id is set on the same
	// connection as every INSERT, satisfying each WITH CHECK. Explicit
	// tenant_id values are kept as the primary control (belt-and-suspenders).
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}

	// created_by is NULLABLE, and a job the platform created on its own
	// initiative has nobody behind it. Internal service-to-service callers
	// arrive with the literal userID "system" (shared middleware sets it), which
	// is not a uuid — inserting it would fail the whole INSERT, and inventing a
	// user id would attribute an unattended act to a person who did not perform
	// it. NULL is the honest value and the column already accepts it.
	createdBy := createdByOrNull(userID)

	err = shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantUUID, func(tx *sql.Tx) error {
		if requestID != "" {
			if _, lockErr := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,72047))`, tenantID+":"+requestID); lockErr != nil {
				return lockErr
			}
			var fingerprint string
			replayErr := tx.QueryRow(`SELECT id,status,created_at,updated_at,COALESCE(metadata->>'identity_enrichment_fingerprint','')
    FROM discovery_jobs WHERE tenant_id=$1 AND metadata->'options'->>'identity_enrichment_request_id'=$2`, tenantID, requestID).
				Scan(&job.ID, &job.Status, &job.CreatedAt, &job.UpdatedAt, &fingerprint)
			if replayErr == nil {
				if fingerprint != requestFingerprint {
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
			if err := authorizeEnrichmentDispatch(tx, sensordispatch.Payload{TenantID: tenantID, Targets: req.Targets, Protocols: req.Protocols, Ports: req.Ports, Options: req.Options}, selectedSensor); err != nil {
				return err
			}
		}
		if dispatchguard.IsAutomaticScan(req.Options) {
			if len(req.OTProbeProtocols) > 0 {
				return fmt.Errorf("automatic scanning cannot request OT probes")
			}
			if err := dispatchguard.AuthorizeAutomaticScan(tx, sensordispatch.Payload{TenantID: tenantID, Targets: req.Targets, Protocols: req.Protocols, Ports: req.Ports, Options: req.Options}); err != nil {
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
	if err != nil {
		return nil, err
	}

	return job, nil
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
	          COALESCE(j.metadata -> 'options' ->> 'origin', '')
	          FROM discovery_jobs j` + jobExecutorJoins + ` WHERE j.id = $1`

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
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("job not found")
		}
		return nil, fmt.Errorf("failed to get job: %w", err)
	}

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

func (s *DiscoveryService) UpdateJobStatus(jobID, status string, errorMessage *string) error {
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

	_, err := s.bypassDB.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
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
			COUNT(*) FILTER (WHERE processed_at IS NOT NULL AND approval_status = 'suppressed')      AS suppressed
		FROM sensor_discoveries
		WHERE batch_id = $1`, jobID)
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
		       COALESCE(j.metadata -> 'options' ->> 'origin', '') AS origin
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

	var total int
	var jobs []models.DiscoveryJob
	err = s.withTenantTxx(context.Background(), tenantUUID, func(tx *sqlx.Tx) error {
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM discovery_jobs j %s", whereClause)
		if e := tx.Get(&total, countQuery, args...); e != nil {
			return fmt.Errorf("failed to count jobs: %w", e)
		}

		pageArgs := append(append([]interface{}{}, args...), pageSize, offset)
		if e := tx.Select(&jobs, jobsQuery, pageArgs...); e != nil {
			return fmt.Errorf("failed to get jobs: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	for i := range jobs {
		jobs[i].Executor = executorFor(jobs[i].ExecutionMode, jobs[i].AssignedSensorID)
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
