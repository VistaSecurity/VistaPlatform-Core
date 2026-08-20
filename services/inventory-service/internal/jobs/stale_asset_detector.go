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
	auditjoblogger "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// jobExecutionLog is the narrow slice of the shared audit JobLogger this job
// uses. *auditjoblogger.JobLogger satisfies it; tests substitute a recorder.
type jobExecutionLog interface {
	LogStart(ctx context.Context, metadata map[string]interface{}) (uuid.UUID, error)
	LogProgress(ctx context.Context, itemsProcessed, itemsSucceeded, itemsFailed int) error
	LogCompletion(ctx context.Context, status string, itemsProcessed, itemsSucceeded, itemsFailed int, errorMessage *string, metadata map[string]interface{}) error
}

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
	// newJobLogger builds the audit job logger for one cycle. Overridable in
	// tests so the run can be observed without an audit-service.
	newJobLogger func(jobID uuid.UUID) jobExecutionLog
	// listTenants enumerates the tenants to age. Overridable in tests so the
	// early-return paths can be exercised without a database.
	listTenants func() ([]uuid.UUID, error)
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

	d := &StaleAssetDetector{
		db:               db,
		bypassDB:         bypassDB,
		lifecycleService: lifecycleService,
		logger:           log.New(log.Writer(), "[StaleAssetDetector] ", log.LstdFlags),
		interval:         interval,
		auditServiceURL:  auditServiceURL,
	}
	d.newJobLogger = func(jobID uuid.UUID) jobExecutionLog {
		return auditjoblogger.NewJobLogger(d.auditServiceURL, jobID, "stale_asset_detection", "Stale Asset Detection", nil, nil)
	}
	d.listTenants = d.tenantsToProcess
	return d
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

// detectStaleAssets runs the detection cycle for all tenants.
//
// Job execution is logged over HTTP to audit-service, which is the ONLY
// transport that reaches audit.job_execution_logs (and therefore Discovery →
// Job Logs / the job-execution-logs API). This job used to try NATS
// (audit.job-execution) first and treat a successful publish as a reason to
// skip the HTTP logger — but nothing has ever subscribed to that subject, and
// the publish always succeeds, so the working transport was disabled precisely
// when the dead one worked and no row was ever written for this job.
//
// Every path out of this function emits a completion, including the two early
// returns: a start with no completion is an execution that reads as still
// running forever.
func (j *StaleAssetDetector) detectStaleAssets(ctx context.Context) {
	jobID := uuid.New()

	jobLogger := j.newJobLogger(jobID)
	logID, err := jobLogger.LogStart(ctx, map[string]interface{}{
		"interval": j.interval.String(),
	})
	if err != nil {
		j.logger.Printf("WARNING: Failed to log job start: %v", err)
	} else {
		j.logger.Printf("Job execution logged with ID: %s", logID)
	}

	j.logger.Println("Running stale asset detection cycle")

	tenantIDs, err := j.listTenants()
	if err != nil {
		j.logger.Printf("ERROR: Failed to query tenants: %v", err)
		errMsg := err.Error()
		_ = jobLogger.LogCompletion(ctx, "failed", 0, 0, 0, &errMsg, nil)
		return
	}

	if len(tenantIDs) == 0 {
		j.logger.Println("No tenants with assets to age")
		_ = jobLogger.LogCompletion(ctx, "completed", 0, 0, 0, nil, map[string]interface{}{
			"tenants_processed": 0,
		})
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
			_ = jobLogger.LogCompletion(ctx, "cancelled", totalProcessed, totalSucceeded, totalFailed, nil, nil)
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
				_ = jobLogger.LogProgress(ctx, totalProcessed, totalSucceeded, totalFailed)
			}
		}
	}

	j.logger.Println("Completed stale asset detection cycle")
	_ = jobLogger.LogCompletion(ctx, "completed", totalProcessed, totalSucceeded, totalFailed, nil, map[string]interface{}{
		"tenants_processed": len(tenantIDs),
	})
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
