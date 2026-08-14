package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/events"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/nats-io/nats.go"
)

type JobProcessor struct {
	db *sqlx.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) handle used only by the
	// platform-wide `pollForStuckJobs` sweep, which scans queued jobs across
	// ALL tenants with no tenant filter. Under crypto_app that sweep FAILS
	// CLOSED (RLS returns zero rows); on the bypass handle it sees every
	// tenant's stuck jobs as intended.
	bypassDB         *sqlx.DB
	discoveryService *DiscoveryService
	rateLimiter      *RateLimiter
	alertService     *AlertService
	portScanner      *PortScanner
	natsClient       *events.NATSClient
	subscriber       *events.Subscriber
	ctx              context.Context
	cancel           context.CancelFunc
}

// NewJobProcessor creates a new job processor using the shared NATSClient.
func NewJobProcessor(db, bypassDB *sqlx.DB, discoveryService *DiscoveryService, rateLimiter *RateLimiter, alertService *AlertService, natsClient *events.NATSClient) *JobProcessor {
	ctx, cancel := context.WithCancel(context.Background())
	return &JobProcessor{
		db:               db,
		bypassDB:         bypassDB,
		discoveryService: discoveryService,
		rateLimiter:      rateLimiter,
		alertService:     alertService,
		portScanner:      NewPortScanner(),
		natsClient:       natsClient,
		subscriber:       events.NewSubscriber(natsClient),
		ctx:              ctx,
		cancel:           cancel,
	}
}

// withTenantTxx runs fn inside a tenant-scoped sqlx transaction, preserving
// sqlx's helpers (Select/Get/Exec/QueryRow). Mirrors
// shareddatabase.WithTenantTx but yields a *sqlx.Tx; tenant context is set on
// the embedded *sql.Tx. tenantID is the string form carried on the job/finding.
func (jp *JobProcessor) withTenantTxx(ctx context.Context, tenantID string, fn func(*sqlx.Tx) error) error {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant_id: %w", err)
	}
	tx, err := jp.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantUUID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (jp *JobProcessor) Start() {
	if jp.natsClient == nil || !jp.natsClient.IsConnected() {
		log.Printf("NATS client not available, job processor cannot start")
		return
	}

	// Subscribe to discovery jobs via JetStream with durable consumer
	err := jp.subscriber.Subscribe(events.SubscriptionConfig{
		Stream:            "DISCOVERY_JOBS",
		Subject:           events.SubjectDiscoveryJobsSubmit,
		Durable:           "discovery-job-processor",
		QueueGroup:        "cluster-sensor",
		MaxDeliver:        3,
		AckWait:           5 * time.Minute,
		ProcessingTimeout: 4 * time.Minute,
	}, jp.handleDiscoveryJobJS)
	if err != nil {
		log.Printf("Failed to subscribe to discovery jobs: %v", err)
		return
	}

	log.Println("Job processor started, listening for discovery jobs via JetStream...")

	// Start background poller to check for stuck queued jobs
	go jp.pollForStuckJobs()

	// Keep running until context is cancelled
	<-jp.ctx.Done()
}

// pollForStuckJobs periodically checks for queued jobs that haven't been processed
// and republishes them to NATS. This handles cases where jobs were published but
// failed to process due to temporary errors.
// Note: Only retries 'queued' jobs, not 'failed' jobs. Failed jobs have already
// been processed and marked as failed — retrying them indefinitely would cause
// duplicate notifications and spam downstream channels.
func (jp *JobProcessor) pollForStuckJobs() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// RLS: cross-tenant — runs on the bypass role (Phase 4). This is a
			// platform-wide background sweep across ALL tenants' queued jobs (no
			// tenant filter), so it cannot set a single app.tenant_id. Belongs
			// on bypassDB once the non-owner role split lands.
			// Find queued jobs older than 1 minute that haven't been picked up yet
			var stuckJobs []string
			query := `SELECT id FROM discovery_jobs
			          WHERE status = 'queued'
			          AND created_at < NOW() - INTERVAL '1 minute'
			          AND created_at > NOW() - INTERVAL '24 hours'
			          ORDER BY created_at ASC
			          LIMIT 10`

			err := jp.bypassDB.Select(&stuckJobs, query)
			if err != nil {
				log.Printf("Error checking for stuck jobs: %v", err)
				continue
			}

			if len(stuckJobs) > 0 {
				log.Printf("Found %d stuck queued jobs, republishing to NATS...", len(stuckJobs))
				for _, jobID := range stuckJobs {
					if err := events.PublishJSON(jp.natsClient, events.SubjectDiscoveryJobsSubmit, events.DiscoveryJobEvent{
						JobID: jobID,
					}); err != nil {
						log.Printf("Failed to republish job %s: %v", jobID, err)
					} else {
						log.Printf("Republished stuck job %s to NATS", jobID)
					}
				}
			}
		case <-jp.ctx.Done():
			return
		}
	}
}

func (jp *JobProcessor) Stop() {
	log.Println("Stopping job processor...")
	jp.cancel()
	if jp.subscriber != nil {
		jp.subscriber.Drain()
	}
}

// handleDiscoveryJobJS processes discovery jobs from JetStream with ack/nack.
func (jp *JobProcessor) handleDiscoveryJobJS(ctx context.Context, msg *nats.Msg) error {
	var jobEvent events.DiscoveryJobEvent
	if err := events.UnmarshalMsg(msg, &jobEvent); err != nil {
		log.Printf("Failed to unmarshal discovery job event: %v", err)
		return nil // Don't redeliver bad data
	}
	return jp.processDiscoveryJobByID(jobEvent.JobID)
}

func (jp *JobProcessor) processDiscoveryJobByID(jobID string) error {
	log.Printf("Processing discovery job: %s", jobID)

	// Get job details
	job, err := jp.discoveryService.GetJob(jobID)
	if err != nil {
		return fmt.Errorf("failed to get job %s: %w", jobID, err)
	}

	// Check rate limits
	err = jp.rateLimiter.CheckRateLimit(job.TenantID)
	if err != nil {
		log.Printf("Rate limit exceeded for tenant %s: %v", job.TenantID, err)
		jp.alertService.SendRateLimitExceededAlert(job.TenantID)
		errorMsg := err.Error()
		jp.discoveryService.UpdateJobStatus(jobID, "failed", &errorMsg)
		return nil // Permanent failure, don't redeliver
	}

	// Update job status to running
	err = jp.discoveryService.UpdateJobStatus(jobID, "running", nil)
	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	// Process the job
	err = jp.processDiscoveryJob(job)
	if err != nil {
		log.Printf("Failed to process job %s: %v", jobID, err)
		jp.alertService.SendJobFailedAlert(job.TenantID, jobID, err.Error())
		errorMsg := err.Error()
		jp.discoveryService.UpdateJobStatus(jobID, "failed", &errorMsg)
		return nil // Job marked as failed, don't redeliver
	}

	// Update job status to completed
	err = jp.discoveryService.UpdateJobStatus(jobID, "completed", nil)
	if err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	jp.alertService.SendJobCompletedAlert(job.TenantID, jobID)
	log.Printf("Discovery job %s completed successfully", jobID)
	return nil
}

// getJobOptions reads scanning options from the job's metadata JSONB.
// RLS-scoped read over discovery_jobs; tenantID is threaded from the job so the
// read runs inside a tenant-scoped transaction.
func (jp *JobProcessor) getJobOptions(tenantID, jobID string) map[string]interface{} {
	var metadataJSON []byte
	err := jp.withTenantTxx(context.Background(), tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&metadataJSON, `SELECT COALESCE(metadata, '{}'::jsonb) FROM discovery_jobs WHERE id = $1`, jobID)
	})
	if err != nil || len(metadataJSON) == 0 {
		return nil
	}
	var metadata map[string]interface{}
	if json.Unmarshal(metadataJSON, &metadata) != nil {
		return nil
	}
	if opts, ok := metadata["options"].(map[string]interface{}); ok {
		return opts
	}
	return nil
}

func (jp *JobProcessor) processDiscoveryJob(job *models.DiscoveryJob) error {
	// Check execution mode - cloud jobs should be handled by device-interrogation-service
	if job.ExecutionMode == "cloud" {
		log.Printf("Job %s is a cloud discovery job, delegating to device-interrogation-service", job.ID)
		return jp.delegateToDeviceInterrogation(job)
	}

	// Read scanning options from job metadata
	opts := jp.getJobOptions(job.TenantID, job.ID)

	// If active scanning is explicitly disabled, skip all scanning
	if activeScanning, ok := opts["active_scanning"].(bool); ok && !activeScanning {
		log.Printf("Active scanning disabled for job %s, skipping all probes", job.ID)
		return nil
	}

	// For sensor/network mode, proceed with port scanning
	// Get job targets - handle PostgreSQL arrays properly
	type TargetRow struct {
		ID          string         `db:"id"`
		JobID       string         `db:"job_id"`
		Input       string         `db:"input"`
		Protocols   pq.StringArray `db:"protocols"`
		Ports       pq.Int32Array  `db:"ports"`
		Status      string         `db:"status"`
		CreatedAt   time.Time      `db:"created_at"`
		UpdatedAt   time.Time      `db:"updated_at"`
		CompletedAt *time.Time     `db:"completed_at"`
	}
	var targetRows []TargetRow
	query := `SELECT id, job_id, input, protocols, ports, status, created_at, updated_at, completed_at
	          FROM discovery_targets WHERE job_id = $1`
	// RLS-scoped read over discovery_targets; job.TenantID scopes the tx.
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&targetRows, query, job.ID)
	})
	if err != nil {
		return fmt.Errorf("failed to get job targets: %w", err)
	}

	// Convert to DiscoveryTarget models
	targets := make([]*models.DiscoveryTarget, len(targetRows))
	for i, row := range targetRows {
		targets[i] = &models.DiscoveryTarget{
			ID:          row.ID,
			JobID:       row.JobID,
			Input:       row.Input,
			Protocols:   []string(row.Protocols),
			Ports:       []int32(row.Ports),
			Status:      row.Status,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,
			CompletedAt: row.CompletedAt,
		}
	}

	// Process each target
	for _, target := range targets {
		err := jp.processTarget(job, target, opts)
		if err != nil {
			log.Printf("Failed to process target %s: %v", target.Input, err)
			// Continue with other targets
		}
	}

	// Count findings and send alert if any. RLS-scoped read over
	// discovery_findings; job.TenantID scopes the tx.
	var findingCount int
	countQuery := `SELECT COUNT(*) FROM discovery_findings WHERE job_id = $1`
	err = jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&findingCount, countQuery, job.ID)
	})
	if err != nil {
		return fmt.Errorf("failed to count findings: %w", err)
	}

	if findingCount > 0 {
		jp.alertService.SendNewFindingsAlert(job.TenantID, job.ID, findingCount)
	}

	return nil
}

// delegateToDeviceInterrogation creates device_jobs for cloud discovery
// to be processed by device-interrogation-service
func (jp *JobProcessor) delegateToDeviceInterrogation(job *models.DiscoveryJob) error {
	// device_jobs and discovery_jobs are both RLS-scoped; the whole delegation
	// (existence check, metadata read, insert) runs inside one tenant-scoped
	// transaction keyed by job.TenantID so app.tenant_id is set on the same
	// connection as every query.
	var deviceJobID, integrationID string
	skip := false
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		// Check if a device_job already exists for this discovery_job
		// This prevents duplicate device_jobs when device-interrogation-service
		// has already created one via /cloud/discover endpoint
		var existingJobID string
		checkQuery := `SELECT id FROM device_jobs WHERE parameters->>'discovery_job_id' = $1 LIMIT 1`
		if e := tx.QueryRow(checkQuery, job.ID).Scan(&existingJobID); e == nil {
			// A device_job already exists for this discovery_job
			log.Printf("⚠️ Device_job %s already exists for discovery job %s, skipping delegation", existingJobID, job.ID)
			skip = true
			return nil
		}
		// If error is sql.ErrNoRows, continue to create the device_job
		// For any other error, fall through and try to create (best effort)

		// Get metadata from discovery_jobs table
		var metadata []byte
		query := `SELECT COALESCE(metadata, '{}'::jsonb) FROM discovery_jobs WHERE id = $1`
		if e := tx.QueryRow(query, job.ID).Scan(&metadata); e != nil {
			return fmt.Errorf("failed to get job metadata: %w", e)
		}

		var meta map[string]interface{}
		if e := json.Unmarshal(metadata, &meta); e != nil {
			return fmt.Errorf("failed to parse job metadata: %w", e)
		}

		integrationID, _ = meta["integration_id"].(string)
		if integrationID == "" {
			return fmt.Errorf("no integration_id in job metadata for cloud discovery")
		}

		// Parse integration UUID
		integrationUUID := integrationID // Already a string

		// Create device_job for device-interrogation-service
		// Set parameters with discovery job context
		parameters := map[string]interface{}{
			"discovery_job_id": job.ID,
			"resource_types":   meta["resource_types"],
			"regions":          meta["regions"],
		}
		parametersJSON, e := json.Marshal(parameters)
		if e != nil {
			return fmt.Errorf("failed to marshal parameters: %w", e)
		}

		insertQuery := `
			INSERT INTO device_jobs (tenant_id, job_type, integration_id, parameters, status, created_at, updated_at)
			VALUES ($1, 'cloud_discovery', $2, $3, 'pending', NOW(), NOW())
			RETURNING id`

		if e := tx.QueryRow(insertQuery, job.TenantID, integrationUUID, parametersJSON).Scan(&deviceJobID); e != nil {
			return fmt.Errorf("failed to create device_job: %w", e)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if skip {
		return nil
	}

	log.Printf("✅ Created device_job %s for cloud discovery job %s (integration: %s)", deviceJobID, job.ID, integrationID)

	// The device-interrogation-service's platform agent worker will pick up this job
	// and update the discovery_job status when complete
	return nil
}

func (jp *JobProcessor) processTarget(job *models.DiscoveryJob, target *models.DiscoveryTarget, probeOpts map[string]interface{}) error {
	// Update target status to running. RLS-scoped UPDATE over discovery_targets;
	// job.TenantID scopes the tx.
	query := `UPDATE discovery_targets SET status = 'running', started_at = NOW(), updated_at = NOW() WHERE id = $1`
	err := jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, target.ID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to update target status: %w", err)
	}

	// Expand the target input to individual IP addresses (CIDR / range /
	// hostname) via the shared discovery expander — same logic the standalone
	// sensor uses.
	expandedTargets := shareddisc.ExpandTargets([]string{target.Input})
	if len(expandedTargets) == 0 {
		expandedTargets = []string{target.Input}
	}

	// Perform real port scanning for each expanded target
	var allFindings []models.DiscoveryFinding
	// Preserve original hostname for SNI and display (use original input if it's not an IP)
	originalHostname := target.Input
	if net.ParseIP(target.Input) != nil {
		// If input is already an IP, don't use it as hostname
		originalHostname = ""
	}

	for _, expandedTarget := range expandedTargets {
		log.Printf("Scanning target: %s with ports: %v and protocols: %v (original hostname: %s)", expandedTarget, target.Ports, target.Protocols, originalHostname)

		// Perform actual port scanning - pass original hostname for SNI and display
		var originalHostnamePtr *string
		if originalHostname != "" {
			originalHostnamePtr = &originalHostname
		}
		findings, err := jp.portScanner.ScanTarget(expandedTarget, target.Ports, target.Protocols, originalHostnamePtr, probeOpts)
		if err != nil {
			log.Printf("Port scanning failed for target %s: %v", expandedTarget, err)
			// Continue with other targets even if one fails
			continue
		}

		// Set job and target IDs for all findings
		for i := range findings {
			findings[i].JobID = job.ID
			findings[i].TargetID = target.ID
			findings[i].TenantID = job.TenantID
		}

		allFindings = append(allFindings, findings...)
		log.Printf("Found %d open ports for target %s", len(findings), expandedTarget)
	}

	// Every discovery job's findings are written to BOTH sinks, unconditionally:
	//
	//   discovery_findings  — the job's inspection record ("what did this run see?")
	//   sensor_discoveries  — the ingestion queue every sensor already feeds, from
	//                         which discovery-processor classifies, evaluates the
	//                         tenant's segment auto-approval rules, and materializes
	//                         inventory.
	//
	// The mirror used to be gated on a probe-option result sink, which only Active
	// Scan ever set — so a wizard-created job produced findings
	// that reached inventory only if a browser POSTed them back. That client-side
	// round-trip is gone; the mirror is the only path, and it is the same one for
	// every job.
	//
	// Provenance is carried in the mirrored row's metadata (discovery_source), not
	// by which jobs get mirrored.
	activeScan := false
	if v, ok := probeOpts["active_scan"].(bool); ok {
		activeScan = v
	}

	// Store findings
	for i := range allFindings {
		finding := allFindings[i]
		// Use the original target ID for all findings
		finding.TargetID = target.ID
		err := jp.storeFinding(&finding)
		if err != nil {
			log.Printf("Failed to store finding: %v", err)
			continue
		}

		if err := jp.mirrorFindingToSensorDiscoveries(job, &finding, activeScan); err != nil {
			log.Printf("[JobProcessor] failed to mirror finding to sensor_discoveries (job %s, %s:%d): %v",
				job.ID, finding.ResolvedIP, finding.Port, err)
		}
	}

	// Update target status to completed. RLS-scoped UPDATE over discovery_targets.
	query = `UPDATE discovery_targets SET status = 'completed', completed_at = NOW(), updated_at = NOW() WHERE id = $1`
	err = jp.withTenantTxx(context.Background(), job.TenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, target.ID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to update target status: %w", err)
	}

	return nil
}

func (jp *JobProcessor) resolveHostname(hostname string) *string {
	// If it's already an IP address, return it
	if net.ParseIP(hostname) != nil {
		return &hostname
	}

	// Try to resolve the hostname to an IP address
	ips, err := net.LookupIP(hostname)
	if err != nil || len(ips) == 0 {
		// If resolution fails, return nil (will be stored as NULL in database)
		return nil
	}

	// Return the first IPv4 address found
	for _, ip := range ips {
		if ip.To4() != nil {
			ipStr := ip.String()
			return &ipStr
		}
	}

	// If no IPv4 found, return the first IP (IPv6)
	if len(ips) > 0 {
		ipStr := ips[0].String()
		return &ipStr
	}

	return nil
}

func (jp *JobProcessor) isInternalTarget(input string) bool {
	// Simple heuristic: if it contains internal IP patterns, consider it internal
	return len(input) > 0 && (input[0] == '1' || input[0] == '2')
}

func (jp *JobProcessor) storeFinding(finding *models.DiscoveryFinding) error {
	// Serialize Data field to JSON for storage in details column
	var detailsJSON *string
	if finding.Data != nil && len(finding.Data) > 0 {
		jsonBytes, err := json.Marshal(finding.Data)
		if err != nil {
			log.Printf("Warning: Failed to marshal finding data to JSON: %v", err)
		} else {
			jsonStr := string(jsonBytes)
			detailsJSON = &jsonStr
			// Extract keys for logging
			keys := make([]string, 0, len(finding.Data))
			for k := range finding.Data {
				keys = append(keys, k)
			}
			log.Printf("[JobProcessor] Storing finding with data: protocol=%s, port=%d, dataKeys=%v, hasCertificates=%v, hasCipherSuite=%v",
				finding.Protocol, finding.Port, keys,
				finding.Data["certificates"] != nil, finding.Data["cipher_suite"] != nil)
		}
	} else {
		dataLen := 0
		if finding.Data != nil {
			dataLen = len(finding.Data)
		}
		log.Printf("[JobProcessor] Storing finding without data: protocol=%s, port=%d, dataLen=%d",
			finding.Protocol, finding.Port, dataLen)
	}

	query := `
		INSERT INTO discovery_findings (job_id, target_id, tenant_id, executed_via, protocol, port, resolved_ip, hostname, confidence_score, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id`

	// resolved_ip is `inet` and nullable: an empty string is not a valid inet
	// literal, so an unresolvable target must be stored as NULL rather than ''.
	var resolvedIP interface{}
	if finding.ResolvedIP != "" {
		resolvedIP = finding.ResolvedIP
	}

	// RLS-scoped INSERT over discovery_findings; finding.TenantID scopes the tx
	// so the row's tenant_id satisfies the policy WITH CHECK.
	err := jp.withTenantTxx(context.Background(), finding.TenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query,
			finding.JobID, finding.TargetID, finding.TenantID, finding.ExecutedVia, finding.Protocol,
			finding.Port, resolvedIP, finding.Hostname, finding.ConfidenceScore, detailsJSON, finding.CreatedAt).Scan(&finding.ID)
	})
	if err != nil {
		return fmt.Errorf("failed to store finding: %w", err)
	}
	return nil
}

// mirrorMetadata builds the metadata envelope of a mirrored sensor_discoveries row:
// the finding's own probe data plus a provenance stamp. Pure, so the stamp is
// unit-tested directly.
//
// The stamp is the ONLY thing activeScan decides. It is not a routing switch —
// every discovery job's findings are mirrored.
func mirrorMetadata(data map[string]interface{}, activeScan bool) map[string]interface{} {
	meta := make(map[string]interface{}, len(data)+1)
	for k, v := range data {
		meta[k] = v
	}
	if activeScan {
		meta["discovery_source"] = "active_scan"
	} else {
		meta["discovery_source"] = "discovery_job"
	}
	return meta
}

// mirrorFindingToSensorDiscoveries writes a discovery-job finding into sensor_discoveries
// so it flows through the unified discovery-processor → IngestFindings pipeline, which
// classifies it, evaluates the tenant's segment auto-approval rules and materializes the
// asset. finding.Data already carries the canonical certificate/cipher metadata (the shared
// TLS prober produces it), so we pass it through as the discovery metadata.
//
// activeScan only selects the provenance stamp (discovery_source), which is what the UI
// reads to tell "re-scan of a known asset" from "wizard discovery". It does NOT decide
// whether the mirror happens — every job is mirrored.
func (jp *JobProcessor) mirrorFindingToSensorDiscoveries(job *models.DiscoveryJob, finding *models.DiscoveryFinding, activeScan bool) error {
	if finding.ResolvedIP == "" {
		return nil // sensor_discoveries.dest_ip is NOT NULL — nothing to anchor on
	}

	meta := mirrorMetadata(finding.Data, activeScan)
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	var hostname interface{}
	if finding.Hostname != "" {
		hostname = finding.Hostname
	}

	// Both the sensors lookup and the sensor_discoveries write are RLS-scoped
	// (sensors has a tenant_isolation policy; sensor_discoveries is a
	// security_invoker view over the partitioned table whose partitions carry
	// the policy). Run them on one tenant-scoped transaction keyed by
	// finding.TenantID so app.tenant_id is set on the same connection.
	return jp.withTenantTxx(context.Background(), finding.TenantID, func(tx *sqlx.Tx) error {
		sensorID, e := jp.platformSensorIDTx(tx, finding.TenantID)
		if e != nil {
			return e
		}
		_, e = tx.Exec(`
			INSERT INTO sensor_discoveries
				(sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, hostname, "timestamp", created_at)
			VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8::jsonb, $9, NOW(), NOW())
		`, sensorID, finding.TenantID, job.ID, finding.Protocol, finding.ResolvedIP, finding.Port,
			finding.ConfidenceScore, string(metaJSON), hostname)
		return e
	})
}

// platformSensorIDTx returns the tenant's system "Platform Discovery Sensor" id
// (registered by cluster-sensor's auto-registration with profile='discovery' +
// 'system' tag), reading inside the caller's tenant-scoped transaction. Used as
// the sensor_id when mirroring active-scan findings into sensor_discoveries.
func (jp *JobProcessor) platformSensorIDTx(tx *sqlx.Tx, tenantID string) (string, error) {
	var id string
	err := tx.QueryRow(
		`SELECT id FROM sensors WHERE tenant_id = $1 AND profile = 'discovery' AND 'system' = ANY(tags) LIMIT 1`,
		tenantID,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("platform discovery sensor not found for tenant %s: %w", tenantID, err)
	}
	return id, nil
}

// expandTarget expands a target input into individual IP addresses
// Supports CIDR notation (192.168.1.0/24), IP ranges (10.0.0.1-10.0.0.10),
// single IPs, and hostnames
