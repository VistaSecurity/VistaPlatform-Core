package jobs

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	auditjoblogger "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// StaleAssetDetector periodically detects and updates stale assets
type StaleAssetDetector struct {
	db *database.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) handle. Only the cross-tenant
	// enumerator uses it; the per-tenant work stays on the RLS-scoped handle.
	bypassDB         *sql.DB
	lifecycleService *services.AssetLifecycleService
	logger           *log.Logger
	interval         time.Duration
	auditServiceURL  string
	natsClient       *events.NATSClient
}

// NewStaleAssetDetector creates a new stale asset detector job
func NewStaleAssetDetector(
	db *database.DB,
	bypassDB *sql.DB,
	lifecycleService *services.AssetLifecycleService,
) *StaleAssetDetector {
	interval := 24 * time.Hour // Default: run daily
	if intervalStr := os.Getenv("STALE_ASSET_DETECTION_INTERVAL"); intervalStr != "" {
		if parsed, err := time.ParseDuration(intervalStr); err == nil && parsed > 0 {
			interval = parsed
		}
	}

	auditServiceURL := os.Getenv("AUDIT_SERVICE_URL")
	if auditServiceURL == "" {
		auditServiceURL = sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled())
	}

	return &StaleAssetDetector{
		db:               db,
		bypassDB:         bypassDB,
		lifecycleService: lifecycleService,
		logger:           log.New(log.Writer(), "[StaleAssetDetector] ", log.LstdFlags),
		interval:         interval,
		auditServiceURL:  auditServiceURL,
	}
}

// SetNATSClient wires a NATS client for event-driven audit job logging.
func (j *StaleAssetDetector) SetNATSClient(client *events.NATSClient) {
	j.natsClient = client
}

// Start begins the stale asset detection process
func (j *StaleAssetDetector) Start(ctx context.Context) {
	j.logger.Printf("Starting stale asset detector (interval: %v)", j.interval)

	// Run immediately on start
	j.detectStaleAssets(ctx)

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			j.logger.Println("Stopping stale asset detector")
			return
		case <-ticker.C:
			j.detectStaleAssets(ctx)
		}
	}
}

// publishAuditJobEvent publishes an audit job execution event via NATS.
// Returns true if successful (caller can skip HTTP fallback).
func (j *StaleAssetDetector) publishAuditJobEvent(jobID, logID uuid.UUID, phase string, itemsProcessed, itemsSucceeded, itemsFailed int, status string, errorMessage *string, metadata map[string]interface{}) bool {
	if j.natsClient == nil || !j.natsClient.IsConnected() {
		return false
	}

	evt := events.AuditJobExecutionEvent{
		EventID:        uuid.New(),
		JobID:          jobID,
		LogID:          logID,
		JobType:        "stale_asset_detection",
		JobName:        "Stale Asset Detection",
		Phase:          phase,
		Status:         status,
		ItemsProcessed: itemsProcessed,
		ItemsSucceeded: itemsSucceeded,
		ItemsFailed:    itemsFailed,
		ErrorMessage:   errorMessage,
		Timestamp:      time.Now(),
		Metadata:       metadata,
	}

	if err := events.PublishJSON(j.natsClient, events.SubjectAuditJobExecution, evt); err != nil {
		j.logger.Printf("NATS audit job event publish failed: %v", err)
		return false
	}

	j.logger.Printf("Audit job %s event published via NATS (phase=%s)", jobID, phase)
	return true
}

// detectStaleAssets runs the detection cycle for all tenants
func (j *StaleAssetDetector) detectStaleAssets(ctx context.Context) {
	jobID := uuid.New()
	logID := uuid.New() // Client-generated log ID for NATS correlation

	// Try NATS for job start, fall back to HTTP JobLogger
	useNATS := j.publishAuditJobEvent(jobID, logID, "start", 0, 0, 0, "", nil, map[string]interface{}{
		"interval": j.interval.String(),
	})

	var jobLogger *auditjoblogger.JobLogger
	if !useNATS {
		// Fallback: HTTP-based audit job logger
		jobLogger = auditjoblogger.NewJobLogger(j.auditServiceURL, jobID, "stale_asset_detection", "Stale Asset Detection", nil, nil)
		httpLogID, err := jobLogger.LogStart(ctx, map[string]interface{}{
			"interval": j.interval.String(),
		})
		if err != nil {
			j.logger.Printf("WARNING: Failed to log job start: %v", err)
		} else {
			j.logger.Printf("Job execution logged with ID: %s", httpLogID)
		}
	}

	j.logger.Println("Running stale asset detection cycle")

	tenantIDs, err := j.tenantsToProcess()
	if err != nil {
		j.logger.Printf("ERROR: Failed to query tenants: %v", err)
		return
	}

	if len(tenantIDs) == 0 {
		j.logger.Println("No tenants with assets to age")
		return
	}

	j.logger.Printf("Processing %d tenants", len(tenantIDs))

	totalProcessed := 0
	totalSucceeded := 0
	totalFailed := 0

	// Process each tenant
	for _, tenantID := range tenantIDs {
		select {
		case <-ctx.Done():
			if useNATS {
				j.publishAuditJobEvent(jobID, logID, "complete", totalProcessed, totalSucceeded, totalFailed, "cancelled", nil, nil)
			} else if jobLogger != nil {
				_ = jobLogger.LogCompletion(ctx, "cancelled", totalProcessed, totalSucceeded, totalFailed, nil, nil)
			}
			return
		default:
			totalProcessed++
			if err := j.processTenant(ctx, tenantID); err != nil {
				totalFailed++
				j.logger.Printf("ERROR: Failed to process tenant %s: %v", tenantID, err)
			} else {
				totalSucceeded++
			}
			// Log progress periodically
			if totalProcessed%10 == 0 {
				if useNATS {
					j.publishAuditJobEvent(jobID, logID, "progress", totalProcessed, totalSucceeded, totalFailed, "", nil, nil)
				} else if jobLogger != nil {
					_ = jobLogger.LogProgress(ctx, totalProcessed, totalSucceeded, totalFailed)
				}
			}
		}
	}

	j.logger.Println("Completed stale asset detection cycle")
	completionMeta := map[string]interface{}{
		"tenants_processed": len(tenantIDs),
	}
	if useNATS {
		j.publishAuditJobEvent(jobID, logID, "complete", totalProcessed, totalSucceeded, totalFailed, "completed", nil, completionMeta)
	} else if jobLogger != nil {
		_ = jobLogger.LogCompletion(ctx, "completed", totalProcessed, totalSucceeded, totalFailed, nil, completionMeta)
	}
}

// tenantsToProcess returns every tenant that has inventory to age — i.e. any
// non-deleted asset.
//
// It used to enumerate `asset_lifecycle_policies WHERE auto_archive_enabled`,
// which was a silent staleness bug: a lifecycle-policy row is created only when
// a tenant opens Settings and saves one (and by the seed, only for tenants that
// existed at seed time). Every tenant onboarded through signup therefore had NO
// row, so this enumerator skipped them entirely and their assets never aged —
// while the UI showed the in-memory default policy (30/60-day auto-archive) via
// GetLifecyclePolicy, so it *looked* enabled. Nothing ran.
//
// Enumerating by "has assets" fixes that: the per-tenant work below fetches the
// effective policy through GetLifecyclePolicy (the real row, or the documented
// default when none exists) and processTenant returns early when a tenant has
// explicitly set auto_archive_enabled = false. So an opted-out tenant is still
// skipped; a tenant that never touched the setting now gets the default it was
// always told it had.
//
// RLS: cross-tenant — runs on the bypass role. The per-tenant work below goes
// through AssetLifecycleService, which sets app.tenant_id per tenant.
//
// `network_assets` is a security_invoker VIEW over the RLS-protected
// network_assets_partitioned, so RLS applies to the caller here just as it would
// on a table — the view is not an escape hatch. On the RLS-scoped handle with no
// app.tenant_id this enumerator returns ZERO tenants and the whole detector
// no-ops: nothing ages, nothing archives, and the run logs success.
func (j *StaleAssetDetector) tenantsToProcess() ([]uuid.UUID, error) {
	if j.bypassDB == nil {
		return nil, nil
	}
	rows, err := j.bypassDB.Query(`SELECT DISTINCT tenant_id FROM network_assets WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var tenantIDs []uuid.UUID
	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil {
			continue
		}
		tenantIDs = append(tenantIDs, tenantID)
	}
	return tenantIDs, rows.Err()
}

// processTenant processes stale assets for a single tenant
func (j *StaleAssetDetector) processTenant(ctx context.Context, tenantID uuid.UUID) error {
	policy, err := j.lifecycleService.GetLifecyclePolicy(tenantID)
	if err != nil {
		j.logger.Printf("ERROR: Failed to get policy for tenant %s: %v", tenantID, err)
		return err
	}

	if !policy.AutoArchiveEnabled {
		return nil
	}

	// Detect stale assets
	staleAssets, err := j.lifecycleService.DetectStaleAssets(tenantID)
	if err != nil {
		j.logger.Printf("ERROR: Failed to detect stale assets for tenant %s: %v", tenantID, err)
		return err
	}

	if len(staleAssets) == 0 {
		return nil
	}

	j.logger.Printf("Found %d stale assets for tenant %s", len(staleAssets), tenantID)

	// Group assets by status
	warningAssets := []uuid.UUID{}
	archivedAssets := []uuid.UUID{}

	for _, asset := range staleAssets {
		if asset.StaleStatus != nil {
			switch *asset.StaleStatus {
			case "warning":
				warningAssets = append(warningAssets, asset.ID)
			case "archived":
				archivedAssets = append(archivedAssets, asset.ID)
			}
		} else {
			// Determine status based on days since last seen
			if asset.DaysSinceLastSeen >= policy.StaleArchivedDays {
				archivedAssets = append(archivedAssets, asset.ID)
			} else if asset.DaysSinceLastSeen >= policy.StaleWarningDays {
				warningAssets = append(warningAssets, asset.ID)
			}
		}
	}

	// Update statuses
	var lastErr error
	if len(warningAssets) > 0 {
		if err := j.lifecycleService.UpdateStaleStatus(tenantID, warningAssets, "warning"); err != nil {
			j.logger.Printf("ERROR: Failed to update warning status for tenant %s: %v", tenantID, err)
			lastErr = err
		} else {
			j.logger.Printf("Updated %d assets to warning status for tenant %s", len(warningAssets), tenantID)
		}
	}

	if len(archivedAssets) > 0 {
		if err := j.lifecycleService.UpdateStaleStatus(tenantID, archivedAssets, "archived"); err != nil {
			j.logger.Printf("ERROR: Failed to update archived status for tenant %s: %v", tenantID, err)
			lastErr = err
		} else {
			j.logger.Printf("Updated %d assets to archived status for tenant %s", len(archivedAssets), tenantID)
		}
	}

	// Send notifications if enabled
	if policy.NotificationsEnabled {
		// TODO: Integrate with notification service
		// For now, just log
		if len(warningAssets) > 0 {
			j.logger.Printf("Would send warning notification for %d assets (tenant %s)", len(warningAssets), tenantID)
		}
		if len(archivedAssets) > 0 {
			j.logger.Printf("Would send archived notification for %d assets (tenant %s)", len(archivedAssets), tenantID)
		}
	}

	return lastErr
}
