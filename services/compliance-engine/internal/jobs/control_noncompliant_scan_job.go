package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

const controlNoncompliantAlertType = "control_noncompliant"

// controlSeverityToAlert maps a control's baseline_severity (Low/Med/High/
// Critical) to the alert severity vocabulary (low/medium/high/critical).
func controlSeverityToAlert(baseline string) string {
	switch strings.ToLower(strings.TrimSpace(baseline)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "med", "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// ControlNoncompliantScanJob raises one stateful alert per control that has
// active compliance findings in an activated framework (severity taken from
// the control's baseline_severity, hence "from-control"), and auto-resolves
// when the control's findings clear on re-evaluation. It reads the ADR-0014
// materialized `compliance_findings` state rather than re-evaluating, and
// mirrors CertLadderScanJob's structure.
type ControlNoncompliantScanJob struct {
	db           *sqlx.DB
	bypassDB     *sqlx.DB
	catalog      *services.AlertCatalogService
	alertEngine  *services.AlertEngineService
	interval     time.Duration
	initialDelay time.Duration
	stop         chan struct{}
}

func NewControlNoncompliantScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *ControlNoncompliantScanJob {
	return &ControlNoncompliantScanJob{
		db: db, bypassDB: bypassDB, catalog: catalog, alertEngine: alertEngine,
		interval: interval, initialDelay: 2 * time.Minute, stop: make(chan struct{}),
	}
}

func (j *ControlNoncompliantScanJob) Start() {
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

func (j *ControlNoncompliantScanJob) Stop() { close(j.stop) }

func (j *ControlNoncompliantScanJob) ScanAll() {
	tenants, err := j.tenants()
	if err != nil {
		log.Printf("[ControlNoncompliantScan] Tenant listing failed: %v", err)
		return
	}
	for _, tenantID := range tenants {
		if err := j.scanTenant(context.Background(), tenantID); err != nil {
			log.Printf("[ControlNoncompliantScan] Tenant %s scan failed: %v", tenantID, err)
		}
	}
}

// tenants lists tenants with active findings OR an open control alert.
func (j *ControlNoncompliantScanJob) tenants() ([]uuid.UUID, error) {
	rows, err := j.bypassDB.Query(`
		SELECT DISTINCT tenant_id FROM compliance_findings WHERE detection_state = 'ACTIVE'
		UNION
		SELECT DISTINCT tenant_id FROM alerts WHERE alert_type = $1 AND status <> 'resolved'
	`, controlNoncompliantAlertType)
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

type noncompliantControl struct {
	controlUUID uuid.UUID
	controlCode string
	baseline    string
	framework   string
	assets      int
}

func (j *ControlNoncompliantScanJob) scanTenant(ctx context.Context, tenantID uuid.UUID) error {
	if !j.catalog.IsTypeEnabled(ctx, tenantID, controlNoncompliantAlertType) {
		return nil
	}

	var controls []noncompliantControl
	openSubjects := map[uuid.UUID]bool{}
	err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		// Noncompliant controls in ACTIVATED frameworks, with affected-asset
		// counts. SUPPRESSED findings are excluded (tenant muted them).
		rows, qErr := tx.QueryContext(ctx, `
			SELECT pfc.id, pfc.control_id, pfc.baseline_severity, pf.name,
			       COUNT(DISTINCT cf.asset_id)
			FROM compliance_findings cf
			JOIN platform_framework_controls pfc ON pfc.id = cf.control_id
			JOIN platform_frameworks pf ON pf.id = pfc.framework_id
			JOIN tenant_framework_licenses tfl
			  ON tfl.platform_framework_id = pfc.framework_id AND tfl.tenant_id = cf.tenant_id
			WHERE cf.tenant_id = $1
			  AND cf.detection_state = 'ACTIVE'
			  AND cf.workflow_status <> 'SUPPRESSED'
			  AND tfl.subscription_status = 'active'
			  AND (tfl.subscription_expires_at IS NULL OR tfl.subscription_expires_at > NOW())
			GROUP BY pfc.id, pfc.control_id, pfc.baseline_severity, pf.name
		`, tenantID)
		if qErr != nil {
			return qErr
		}
		for rows.Next() {
			var c noncompliantControl
			if err := rows.Scan(&c.controlUUID, &c.controlCode, &c.baseline, &c.framework, &c.assets); err != nil {
				_ = rows.Close()
				return err
			}
			controls = append(controls, c)
		}
		_ = rows.Close()

		aRows, aErr := tx.QueryContext(ctx, `
			SELECT subject_id FROM alerts
			WHERE tenant_id = $1 AND alert_type = $2 AND status <> 'resolved' AND subject_id IS NOT NULL
		`, tenantID, controlNoncompliantAlertType)
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

	current := make(map[uuid.UUID]bool, len(controls))
	for _, c := range controls {
		current[c.controlUUID] = true
		j.raise(ctx, tenantID, c)
	}
	// Open alerts whose control is no longer noncompliant → findings cleared.
	for sid := range openSubjects {
		if current[sid] {
			continue
		}
		j.resolve(ctx, tenantID, sid)
	}
	return nil
}

func (j *ControlNoncompliantScanJob) raise(ctx context.Context, tenantID uuid.UUID, c noncompliantControl) {
	controlUUID := c.controlUUID
	severity := controlSeverityToAlert(c.baseline)
	title := fmt.Sprintf("Control noncompliant: %s", c.controlCode)
	message := fmt.Sprintf("Control %s (%s) is noncompliant — %d asset(s) affected.",
		c.controlCode, c.framework, c.assets)
	if _, err := j.alertEngine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenantID,
		AlertType:    controlNoncompliantAlertType,
		Source:       "compliance-engine",
		SubjectType:  "control",
		SubjectID:    &controlUUID,
		SubjectLabel: c.controlCode,
		Severity:     severity,
		Title:        title,
		Message:      message,
		Metadata: map[string]interface{}{
			"control_uuid":      c.controlUUID.String(),
			"control_id":        c.controlCode,
			"framework":         c.framework,
			"baseline_severity": c.baseline,
			"affected_assets":   c.assets,
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[ControlNoncompliantScan] Raise failed (control=%s tenant=%s): %v", c.controlUUID, tenantID, err)
	}
}

func (j *ControlNoncompliantScanJob) resolve(ctx context.Context, tenantID, controlUUID uuid.UUID) {
	sid := controlUUID
	if err := j.alertEngine.ResolveAuto(ctx, events.AlertResolveEvent{
		EventID:   uuid.New(),
		TenantID:  tenantID,
		AlertType: controlNoncompliantAlertType,
		SubjectID: &sid,
		Observation: map[string]interface{}{
			"observed":    "control findings cleared on re-evaluation",
			"observed_at": time.Now().Format(time.RFC3339),
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[ControlNoncompliantScan] Auto-resolve failed (control=%s tenant=%s): %v", controlUUID, tenantID, err)
	}
}
