package jobs

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

const (
	tenantHealthDegradedAlertType = "tenant_health_degraded"
	tenantHealthDegradedThreshold = 60 // overall_score below this = degraded
	tenantHealthCriticalThreshold = 40 // below this escalates to high
)

// healthDegradedSeverity maps a health score to alert severity: medium for a
// degraded score, high for the critical band.
func healthDegradedSeverity(score float64) string {
	if score < tenantHealthCriticalThreshold {
		return "high"
	}
	return "medium"
}

// TenantHealthDegradedScanJob raises a PLATFORM-track alert (one per tenant)
// when a tenant's health score falls below the degraded threshold, and
// auto-resolves when it recovers. Platform-scoped: raises under the sentinel
// platform tenant (services.PlatformAlertTenantID) with subject = the degraded
// tenant. Source: tenant_health.overall_score (tenant-health-service).
type TenantHealthDegradedScanJob struct {
	db           *sqlx.DB
	bypassDB     *sqlx.DB
	catalog      *services.AlertCatalogService
	alertEngine  *services.AlertEngineService
	interval     time.Duration
	initialDelay time.Duration
	stop         chan struct{}
}

func NewTenantHealthDegradedScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *TenantHealthDegradedScanJob {
	return &TenantHealthDegradedScanJob{
		db: db, bypassDB: bypassDB, catalog: catalog, alertEngine: alertEngine,
		interval: interval, initialDelay: 2 * time.Minute, stop: make(chan struct{}),
	}
}

func (j *TenantHealthDegradedScanJob) Start() {
	go func() {
		initial := time.NewTimer(j.initialDelay)
		defer initial.Stop()
		select {
		case <-j.stop:
			return
		case <-initial.C:
			j.Scan()
		}
		ticker := time.NewTicker(j.interval)
		defer ticker.Stop()
		for {
			select {
			case <-j.stop:
				return
			case <-ticker.C:
				j.Scan()
			}
		}
	}()
}

func (j *TenantHealthDegradedScanJob) Stop() { close(j.stop) }

type degradedTenant struct {
	tenantID uuid.UUID
	name     string
	score    float64
}

func (j *TenantHealthDegradedScanJob) Scan() {
	ctx := context.Background()
	sentinel := services.PlatformAlertTenantID
	if !j.catalog.IsTypeEnabled(ctx, sentinel, tenantHealthDegradedAlertType) {
		return
	}

	// Degraded tenants (global read via bypass; tenant_health is RLS-isolated).
	rows, err := j.bypassDB.QueryContext(ctx, `
		SELECT th.tenant_id, COALESCE(t.name, ''), th.overall_score
		FROM tenant_health th
		LEFT JOIN tenants t ON t.id = th.tenant_id
		WHERE th.overall_score < $1
	`, tenantHealthDegradedThreshold)
	if err != nil {
		log.Printf("[TenantHealthDegradedScan] query failed: %v", err)
		return
	}
	var degraded []degradedTenant
	for rows.Next() {
		var d degradedTenant
		if err := rows.Scan(&d.tenantID, &d.name, &d.score); err != nil {
			_ = rows.Close()
			log.Printf("[TenantHealthDegradedScan] scan failed: %v", err)
			return
		}
		degraded = append(degraded, d)
	}
	_ = rows.Close()

	openSubjects, err := openAlertSubjects(ctx, j.bypassDB, sentinel, tenantHealthDegradedAlertType)
	if err != nil {
		log.Printf("[TenantHealthDegradedScan] open-alert query failed: %v", err)
		return
	}

	current := make(map[uuid.UUID]bool, len(degraded))
	for _, d := range degraded {
		current[d.tenantID] = true
		j.raise(ctx, sentinel, d)
	}
	for sid := range openSubjects {
		if current[sid] {
			continue
		}
		j.resolve(ctx, sentinel, sid)
	}
}

func (j *TenantHealthDegradedScanJob) raise(ctx context.Context, sentinel uuid.UUID, d degradedTenant) {
	subjectID := d.tenantID
	label := d.name
	if label == "" {
		label = "tenant " + d.tenantID.String()[:8]
	}
	if _, err := j.alertEngine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     sentinel,
		AlertType:    tenantHealthDegradedAlertType,
		Source:       "tenant-health-service",
		SubjectType:  "tenant",
		SubjectID:    &subjectID,
		SubjectLabel: label,
		Severity:     healthDegradedSeverity(d.score),
		Title:        fmt.Sprintf("Tenant health degraded: %s", label),
		Message:      fmt.Sprintf("Tenant %q health score is %.0f (below %d).", label, d.score, tenantHealthDegradedThreshold),
		Metadata: map[string]interface{}{
			"tenant_id":     d.tenantID.String(),
			"overall_score": d.score,
			"threshold":     tenantHealthDegradedThreshold,
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[TenantHealthDegradedScan] Raise failed (tenant=%s): %v", d.tenantID, err)
	}
}

func (j *TenantHealthDegradedScanJob) resolve(ctx context.Context, sentinel, subjectTenantID uuid.UUID) {
	sid := subjectTenantID
	if err := j.alertEngine.ResolveAuto(ctx, events.AlertResolveEvent{
		EventID:   uuid.New(),
		TenantID:  sentinel,
		AlertType: tenantHealthDegradedAlertType,
		SubjectID: &sid,
		Observation: map[string]interface{}{
			"observed":    "tenant health score recovered",
			"observed_at": time.Now().Format(time.RFC3339),
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[TenantHealthDegradedScan] Auto-resolve failed (tenant=%s): %v", subjectTenantID, err)
	}
}
