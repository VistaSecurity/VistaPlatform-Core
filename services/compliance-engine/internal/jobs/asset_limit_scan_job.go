package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
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
	assetLimitAlertType          = "asset_limit_approaching"
	assetLimitWarnPercentDefault = 80 // registry baseline rung (severity info)
	assetLimitHighPercent        = 95 // product high rung (severity high)
)

// assetSeverity returns the fixed rung severity for an asset-usage percentage,
// or "" when usage is below the warning rung (no alert / auto-resolve). The
// warn rung defaults to 80% (registry baseline, severity info) and can be
// moved by a tenant preference; the high rung is a fixed product rung at 95%.
// Severity only ever escalates while an alert is open (the engine never
// de-escalates), so a tenant that drops from 96% to 82% keeps the high alert
// until usage falls below the warn rung and the alert auto-resolves.
func assetSeverity(pct float64, warnPercent, highPercent int) string {
	switch {
	case pct >= float64(highPercent):
		return "high"
	case pct >= float64(warnPercent):
		return "info"
	default:
		return ""
	}
}

// AssetLimitScanJob compares each tenant's live infrastructure-asset count
// against its plan's max_assets entitlement and drives a per-tenant stateful
// alert as usage approaches the limit (80% info → 95% high). It auto-resolves
// when usage falls back below the warn rung or the plan becomes unlimited.
// One alert per tenant (subject_type=tenant, subject_id=tenant_id).
type AssetLimitScanJob struct {
	db           *sqlx.DB
	bypassDB     *sqlx.DB
	catalog      *services.AlertCatalogService
	alertEngine  *services.AlertEngineService
	interval     time.Duration
	initialDelay time.Duration
	stop         chan struct{}
}

func NewAssetLimitScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *AssetLimitScanJob {
	return &AssetLimitScanJob{
		db: db, bypassDB: bypassDB, catalog: catalog, alertEngine: alertEngine,
		interval: interval, initialDelay: 3 * time.Minute, stop: make(chan struct{}),
	}
}

// Start runs an initial scan shortly after boot, then on the interval.
func (j *AssetLimitScanJob) Start() {
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

func (j *AssetLimitScanJob) Stop() { close(j.stop) }

// ScanAll evaluates every tenant with assets or an open limit alert.
func (j *AssetLimitScanJob) ScanAll() {
	tenants, err := j.tenants()
	if err != nil {
		log.Printf("[AssetLimitScan] Tenant listing failed: %v", err)
		return
	}
	for _, tenantID := range tenants {
		if err := j.scanTenant(context.Background(), tenantID); err != nil {
			log.Printf("[AssetLimitScan] Tenant %s scan failed: %v", tenantID, err)
		}
	}
}

// tenants lists tenants with at least one asset OR an open asset-limit alert
// (a tenant with zero assets is at 0% and can't be approaching a limit, but an
// open alert still needs a chance to auto-resolve). Cross-tenant — bypass role.
func (j *AssetLimitScanJob) tenants() ([]uuid.UUID, error) {
	rows, err := j.bypassDB.Query(`
		SELECT DISTINCT tenant_id FROM network_assets WHERE deleted_at IS NULL
		UNION
		SELECT DISTINCT tenant_id FROM alerts WHERE alert_type = $1 AND status <> 'resolved'
	`, assetLimitAlertType)
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

func (j *AssetLimitScanJob) scanTenant(ctx context.Context, tenantID uuid.UUID) error {
	if !j.catalog.IsTypeEnabled(ctx, tenantID, assetLimitAlertType) {
		return nil
	}

	// Plan asset limit. tenants + subscription_tiers are GLOBAL reference
	// tables (no RLS policy) — read via bypass, filter by tenant explicitly.
	var maxAssets sql.NullInt64
	err := j.bypassDB.QueryRowContext(ctx, `
		SELECT st.max_assets FROM tenants t
		JOIN subscription_tiers st ON t.subscription_tier_id = st.id
		WHERE t.id = $1
	`, tenantID).Scan(&maxAssets)
	if err == sql.ErrNoRows {
		return nil // tenant has no tier — nothing to measure against
	}
	if err != nil {
		return fmt.Errorf("load tier limit: %w", err)
	}
	if !maxAssets.Valid || maxAssets.Int64 <= 0 {
		// Unlimited plan — resolve any open alert, nothing to warn about.
		j.resolve(ctx, tenantID, map[string]interface{}{
			"observed":    "plan asset limit is unlimited",
			"observed_at": time.Now().Format(time.RFC3339),
		})
		return nil
	}

	var used int64
	if err := j.bypassDB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND deleted_at IS NULL
	`, tenantID).Scan(&used); err != nil {
		return fmt.Errorf("count assets: %w", err)
	}

	warnPercent := j.warnPercent(ctx, tenantID)
	pct := float64(used) / float64(maxAssets.Int64) * 100
	severity := assetSeverity(pct, warnPercent, assetLimitHighPercent)
	if severity == "" {
		j.resolve(ctx, tenantID, map[string]interface{}{
			"observed":     "asset usage fell below the warning threshold",
			"used":         used,
			"limit":        maxAssets.Int64,
			"percent":      int(pct),
			"warn_percent": warnPercent,
			"observed_at":  time.Now().Format(time.RFC3339),
		})
		return nil
	}
	j.raise(ctx, tenantID, used, maxAssets.Int64, pct, severity, warnPercent)
	return nil
}

// warnPercent returns the tenant's warn rung, honoring a {"percent": N}
// preference_rung override, else the registry baseline (80%).
func (j *AssetLimitScanJob) warnPercent(ctx context.Context, tenantID uuid.UUID) int {
	warn := assetLimitWarnPercentDefault
	_ = shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		var pref []byte
		if err := tx.QueryRowContext(ctx,
			`SELECT preference_rung FROM tenant_alert_settings WHERE tenant_id = $1 AND alert_type = $2`,
			tenantID, assetLimitAlertType).Scan(&pref); err != nil {
			return nil // no setting row — use default
		}
		var m map[string]interface{}
		if json.Unmarshal(pref, &m) == nil {
			if p, ok := m["percent"].(float64); ok && p > 0 && p < 100 {
				warn = int(p)
			}
		}
		return nil
	})
	return warn
}

func (j *AssetLimitScanJob) raise(ctx context.Context, tenantID uuid.UUID, used, limit int64, pct float64, severity string, warnPercent int) {
	subjectID := tenantID
	title := fmt.Sprintf("Asset usage at %.0f%% of plan limit", pct)
	message := fmt.Sprintf("Using %d of %d infrastructure assets (%.0f%%). Approaching the plan limit — add capacity or upgrade before new assets are rejected.",
		used, limit, pct)
	if _, err := j.alertEngine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenantID,
		AlertType:    assetLimitAlertType,
		Source:       "auth-service",
		SubjectType:  "tenant",
		SubjectID:    &subjectID,
		SubjectLabel: "asset usage",
		Severity:     severity,
		Title:        title,
		Message:      message,
		Metadata: map[string]interface{}{
			"used":         used,
			"limit":        limit,
			"percent":      int(pct),
			"warn_percent": warnPercent,
			"high_percent": assetLimitHighPercent,
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[AssetLimitScan] Raise failed (tenant=%s): %v", tenantID, err)
	}
}

func (j *AssetLimitScanJob) resolve(ctx context.Context, tenantID uuid.UUID, observation map[string]interface{}) {
	subjectID := tenantID
	if err := j.alertEngine.ResolveAuto(ctx, events.AlertResolveEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertType:   assetLimitAlertType,
		SubjectID:   &subjectID,
		Observation: observation,
		Timestamp:   time.Now(),
	}); err != nil {
		log.Printf("[AssetLimitScan] Auto-resolve failed (tenant=%s): %v", tenantID, err)
	}
}
