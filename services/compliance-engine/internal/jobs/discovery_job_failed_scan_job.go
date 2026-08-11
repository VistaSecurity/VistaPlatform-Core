package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

const (
	discoveryJobFailedAlertType = "discovery_job_failed"
	discoveryFailureWindow      = "7 days" // ignore failures older than this on first observation
	discoveryFailureCap         = 25       // max failed-job alerts raised per tenant per scan
)

// DiscoveryJobFailedScanJob raises a fixed medium alert per failed discovery
// job that has not yet been superseded by a later successful run, and
// auto-resolves those alerts once a subsequent discovery run succeeds (or the
// job ages out / is removed). Discovery jobs are one-shot rows with unique ids
// and no completion NATS event, so this polls `discovery_jobs`. Mirrors
// CertLadderScanJob's structure.
type DiscoveryJobFailedScanJob struct {
	db           *sqlx.DB
	bypassDB     *sqlx.DB
	catalog      *services.AlertCatalogService
	alertEngine  *services.AlertEngineService
	interval     time.Duration
	initialDelay time.Duration
	stop         chan struct{}
}

func NewDiscoveryJobFailedScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *DiscoveryJobFailedScanJob {
	return &DiscoveryJobFailedScanJob{
		db: db, bypassDB: bypassDB, catalog: catalog, alertEngine: alertEngine,
		interval: interval, initialDelay: 90 * time.Second, stop: make(chan struct{}),
	}
}

func (j *DiscoveryJobFailedScanJob) Start() {
	go func() {
		initial := time.NewTimer(j.initialDelay)
		defer initial.Stop()
		select {
		case <-j.stop:
			return
		case <-initial.C:
			j.ScanAll()
		}
		ticker := time.NewTicker(j.interval)
		defer ticker.Stop()
		for {
			select {
			case <-j.stop:
				return
			case <-ticker.C:
				j.ScanAll()
			}
		}
	}()
}

func (j *DiscoveryJobFailedScanJob) Stop() { close(j.stop) }

func (j *DiscoveryJobFailedScanJob) ScanAll() {
	tenants, err := j.tenants()
	if err != nil {
		log.Printf("[DiscoveryJobFailedScan] Tenant listing failed: %v", err)
		return
	}
	for _, tenantID := range tenants {
		if err := j.scanTenant(context.Background(), tenantID); err != nil {
			log.Printf("[DiscoveryJobFailedScan] Tenant %s scan failed: %v", tenantID, err)
		}
	}
}

func (j *DiscoveryJobFailedScanJob) tenants() ([]uuid.UUID, error) {
	rows, err := j.bypassDB.Query(`
		SELECT DISTINCT tenant_id FROM discovery_jobs WHERE status = 'failed'
		UNION
		SELECT DISTINCT tenant_id FROM alerts WHERE alert_type = $1 AND status <> 'resolved'
	`, discoveryJobFailedAlertType)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

type failedJob struct {
	id            uuid.UUID
	executionMode string
	errorMessage  string
	completedAt   time.Time
}

func (j *DiscoveryJobFailedScanJob) scanTenant(ctx context.Context, tenantID uuid.UUID) error {
	if !j.catalog.IsTypeEnabled(ctx, tenantID, discoveryJobFailedAlertType) {
		return nil
	}

	var lastSuccess time.Time
	var failures []failedJob
	openSubjects := map[uuid.UUID]bool{}
	err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(MAX(completed_at), 'epoch'::timestamptz)
			FROM discovery_jobs WHERE tenant_id = $1 AND status = 'completed'
		`, tenantID).Scan(&lastSuccess); err != nil {
			return err
		}

		// Failures since the last success, within the observation window.
		rows, qErr := tx.QueryContext(ctx, `
			SELECT id, execution_mode, COALESCE(error_message, ''), completed_at
			FROM discovery_jobs
			WHERE tenant_id = $1 AND status = 'failed' AND completed_at IS NOT NULL
			  AND completed_at > $2
			  AND completed_at > NOW() - INTERVAL '`+discoveryFailureWindow+`'
			ORDER BY completed_at DESC
			LIMIT $3
		`, tenantID, lastSuccess, discoveryFailureCap+1)
		if qErr != nil {
			return qErr
		}
		for rows.Next() {
			var f failedJob
			if err := rows.Scan(&f.id, &f.executionMode, &f.errorMessage, &f.completedAt); err != nil {
				_ = rows.Close()
				return err
			}
			failures = append(failures, f)
		}
		_ = rows.Close()

		aRows, aErr := tx.QueryContext(ctx, `
			SELECT subject_id FROM alerts
			WHERE tenant_id = $1 AND alert_type = $2 AND status <> 'resolved' AND subject_id IS NOT NULL
		`, tenantID, discoveryJobFailedAlertType)
		if aErr != nil {
			return aErr
		}
		defer func() { _ = aRows.Close() }()
		for aRows.Next() {
			var sid uuid.UUID
			if err := aRows.Scan(&sid); err == nil {
				openSubjects[sid] = true
			}
		}
		return aRows.Err()
	})
	if err != nil {
		return err
	}

	if len(failures) > discoveryFailureCap {
		log.Printf("[DiscoveryJobFailedScan] Tenant %s has more than %d unresolved discovery failures; alerting on the most recent %d",
			tenantID, discoveryFailureCap, discoveryFailureCap)
		failures = failures[:discoveryFailureCap]
	}

	current := make(map[uuid.UUID]bool, len(failures))
	for _, f := range failures {
		current[f.id] = true
		j.raise(ctx, tenantID, f)
	}
	// Open alerts whose failed job is no longer "current" → a later run
	// succeeded, the failure aged out, or the job was removed.
	for sid := range openSubjects {
		if current[sid] {
			continue
		}
		j.resolve(ctx, tenantID, sid, lastSuccess)
	}
	return nil
}

func (j *DiscoveryJobFailedScanJob) raise(ctx context.Context, tenantID uuid.UUID, f failedJob) {
	jobID := f.id
	label := fmt.Sprintf("%s job %s", f.executionMode, f.id.String()[:8])
	msg := fmt.Sprintf("A discovery job (%s) failed", f.executionMode)
	if f.errorMessage != "" {
		msg += ": " + f.errorMessage
	}
	msg += "."
	if _, err := j.alertEngine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenantID,
		AlertType:    discoveryJobFailedAlertType,
		Source:       "cluster-sensor-service",
		SubjectType:  "job",
		SubjectID:    &jobID,
		SubjectLabel: label,
		Severity:     "medium",
		Title:        "Discovery job failed",
		Message:      msg,
		Metadata: map[string]interface{}{
			"job_id":         f.id.String(),
			"execution_mode": f.executionMode,
			"error_message":  f.errorMessage,
			"completed_at":   f.completedAt.Format(time.RFC3339),
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[DiscoveryJobFailedScan] Raise failed (job=%s tenant=%s): %v", f.id, tenantID, err)
	}
}

func (j *DiscoveryJobFailedScanJob) resolve(ctx context.Context, tenantID, jobID uuid.UUID, lastSuccess time.Time) {
	// Craft an accurate observation: a later success, an aged-out failure, or
	// a removed job.
	var completedAt sql.NullTime
	exists := false
	if err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT completed_at FROM discovery_jobs WHERE id = $1 AND tenant_id = $2`, jobID, tenantID)
		if scanErr := row.Scan(&completedAt); scanErr == sql.ErrNoRows {
			return nil
		} else if scanErr != nil {
			return scanErr
		}
		exists = true
		return nil
	}); err != nil {
		log.Printf("[DiscoveryJobFailedScan] Resolve lookup failed (job=%s tenant=%s): %v", jobID, tenantID, err)
		return
	}

	observation := map[string]interface{}{"observed_at": time.Now().Format(time.RFC3339)}
	switch {
	case !exists:
		observation["observed"] = "discovery job removed"
	case completedAt.Valid && !completedAt.Time.After(lastSuccess):
		observation["observed"] = "a subsequent discovery run succeeded"
	default:
		observation["observed"] = "discovery failure aged out of the alerting window"
	}

	sid := jobID
	if err := j.alertEngine.ResolveAuto(ctx, events.AlertResolveEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertType:   discoveryJobFailedAlertType,
		SubjectID:   &sid,
		Observation: observation,
		Timestamp:   time.Now(),
	}); err != nil {
		log.Printf("[DiscoveryJobFailedScan] Auto-resolve failed (job=%s tenant=%s): %v", jobID, tenantID, err)
	}
}
