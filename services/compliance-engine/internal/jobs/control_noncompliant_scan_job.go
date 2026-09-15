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
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
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
// materialized findings — the compliance producer's rows in the one `findings`
// table — rather than re-evaluating, and mirrors CertLadderScanJob's structure.
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

// tenants lists tenants with an OPEN compliance finding OR an open control
// alert. "Open" is sharedfindings.OpenSQL, the one generated definition — the
// same predicate the per-tenant read below compiles, so the listing can never
// include a tenant the read will then find nothing for, or skip one it would.
func (j *ControlNoncompliantScanJob) tenants() ([]uuid.UUID, error) {
	rows, err := j.bypassDB.Query(`
		SELECT DISTINCT tenant_id FROM findings f
		 WHERE `+complianceFindingScope("f")+`
		   AND `+sharedfindings.OpenSQL("f")+`
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
	openAlerts := map[uuid.UUID]string{} // controlUUID -> open alert's current severity
	err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		// Noncompliant controls in ACTIVATED frameworks, with affected-asset
		// counts, over the control's OPEN findings.
		//
		// Open is sharedfindings.OpenSQL — the registry's ONE definition
		// (`detection_state:ACTIVE and workflow_status not in (RESOLVED,
		// SUPPRESSED)`, ADR-0005 D3), not a second spelling of it. This read
		// used to say `detection_state = 'ACTIVE' AND workflow_status <>
		// 'SUPPRESSED'`, which agrees with the definition on three of its four
		// values and disagrees on the one that matters: a person who works every
		// finding on a control and marks them RESOLVED still counted as
		// noncompliant, so the alert stayed open with nothing behind it.
		rows, qErr := tx.QueryContext(ctx, `
			SELECT pfc.id, pfc.control_id, pfc.baseline_severity, pf.name,
			       COUNT(DISTINCT cf.subject_id)
			FROM findings cf
			JOIN platform_framework_controls pfc ON pfc.id = cf.control_id
			JOIN platform_frameworks pf ON pf.id = pfc.framework_id
			JOIN tenant_framework_licenses tfl
			  ON tfl.platform_framework_id = pfc.framework_id AND tfl.tenant_id = cf.tenant_id
			WHERE cf.tenant_id = $1
			  AND `+complianceFindingScope("cf")+`
			  AND `+sharedfindings.OpenSQL("cf")+`
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
			SELECT subject_id, severity FROM alerts
			WHERE tenant_id = $1 AND alert_type = $2 AND status <> 'resolved' AND subject_id IS NOT NULL
		`, tenantID, controlNoncompliantAlertType)
		if aErr != nil {
			return aErr
		}
		defer func() { _ = aRows.Close() }()
		for aRows.Next() {
			var sid uuid.UUID
			var sev string
			if err := aRows.Scan(&sid, &sev); err == nil {
				openAlerts[sid] = sev
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
		// Raise-on-change (mirrors FindingsAlertScanJob): only call Raise when
		// the alert is NEW or this pass's severity has risen above the open
		// alert's. Every noncompliant control matched the query above on EVERY
		// pass regardless of whether anything changed, so this Raise used to run
		// unconditionally every interval — on a tenant with hundreds of
		// noncompliant controls, hundreds of pointless UPDATEs an hour that also
		// moved the alert's `updated_at` (and last_event_at) for nothing.
		// Nothing de-escalates: the engine never lowers an open alert's
		// severity, and this job does not ask it to.
		severity := controlSeverityToAlert(c.baseline)
		if existing, isOpen := openAlerts[c.controlUUID]; isOpen && !severityWorse(severity, existing) {
			continue
		}
		j.raise(ctx, tenantID, c)
	}
	// Open alerts whose control is no longer noncompliant → findings cleared.
	for sid := range openAlerts {
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

// complianceFindingScope selects the compliance producer's rows out of the one
// findings table. The jobs package cannot reach services.complianceProducerScope
// (services imports jobs' siblings, not the other way round), so it is spelled
// here from the same generated registry constants — never from literals, which
// is how two copies of a predicate come to disagree.
func complianceFindingScope(alias string) string {
	q := ""
	if alias != "" {
		q = alias + "."
	}
	return "(" + q + "producer = '" + sharedfindings.ProducerCompliance + "'" +
		" AND " + q + "kind = '" + sharedfindings.KindControlNoncompliant + "')"
}
