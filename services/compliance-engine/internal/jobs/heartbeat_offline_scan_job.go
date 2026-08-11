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

// heartbeatSpec describes one heartbeat-driven operational alert type. All
// string fields (table name, extra predicate) are compile-time constants
// supplied by the constructors below — never user input — so interpolating
// them into the query text is safe from injection.
type heartbeatSpec struct {
	alertType   string        // registry alert_type
	source      string        // alert_source label on the rails
	subjectType string        // subject_type on the alert ("sensor" | "agent")
	table       string        // source table: (id, tenant_id, name, last_heartbeat, deleted_at)
	extraWhere  string        // additional predicate, e.g. platform/status filters
	severity    string        // fixed severity at open
	dwell       time.Duration // silence before a subject counts as offline
	noun        string        // human noun for titles/messages ("Sensor" / "Discovery agent")
	logTag      string        // log prefix
}

// HeartbeatOfflineScanJob raises a fixed-severity operational alert for every
// subject (sensor or discovery agent) that has stopped sending heartbeats for
// longer than the dwell window, and auto-resolves it when the heartbeat
// returns or the subject is removed. It mirrors CertLadderScanJob's structure:
// a periodic cross-tenant sweep that drives the stateful alert engine, with
// per-tenant RLS reads and cross-tenant enumeration via the bypass pool.
//
// Offline is computed directly from last_heartbeat (not the source table's
// status column), so the two runtimes stay symmetric even though only
// sensor-manager has a status reaper. Subjects that never reported
// (last_heartbeat IS NULL) are intentionally excluded — a never-provisioned
// subject is an enrollment concern, not an offline one.
type HeartbeatOfflineScanJob struct {
	db           *sqlx.DB
	bypassDB     *sqlx.DB
	catalog      *services.AlertCatalogService
	alertEngine  *services.AlertEngineService
	interval     time.Duration
	initialDelay time.Duration
	spec         heartbeatSpec
	stop         chan struct{}
}

func newHeartbeatOfflineScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration, spec heartbeatSpec) *HeartbeatOfflineScanJob {
	if spec.dwell <= 0 {
		spec.dwell = 15 * time.Minute
	}
	return &HeartbeatOfflineScanJob{
		db: db, bypassDB: bypassDB, catalog: catalog, alertEngine: alertEngine,
		interval: interval, initialDelay: 90 * time.Second, spec: spec, stop: make(chan struct{}),
	}
}

// NewSensorOfflineScanJob detects sensors that stopped reporting. Platform
// sensors (platform = 'platform') are excluded — they serve all tenants and
// are not a tenant-owned subject. Intentionally pending/inactive sensors are
// excluded so admin-disabled or never-activated sensors don't alarm.
func NewSensorOfflineScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *HeartbeatOfflineScanJob {
	return newHeartbeatOfflineScanJob(db, bypassDB, catalog, alertEngine, interval, heartbeatSpec{
		alertType:   "sensor_offline",
		source:      "sensor-manager",
		subjectType: "sensor",
		table:       "sensors",
		extraWhere:  "AND platform <> 'platform' AND status NOT IN ('pending', 'inactive')",
		severity:    "high",
		dwell:       15 * time.Minute,
		noun:        "Sensor",
		logTag:      "SensorOfflineScan",
	})
}

// NewDiscoveryAgentOfflineScanJob detects discovery/interrogation agents that
// stopped reporting. Admin-disabled (inactive) agents are excluded.
func NewDiscoveryAgentOfflineScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *HeartbeatOfflineScanJob {
	return newHeartbeatOfflineScanJob(db, bypassDB, catalog, alertEngine, interval, heartbeatSpec{
		alertType:   "discovery_agent_offline",
		source:      "device-interrogation-service",
		subjectType: "agent",
		table:       "device_agents",
		extraWhere:  "AND status <> 'inactive'",
		severity:    "high",
		dwell:       15 * time.Minute,
		noun:        "Discovery agent",
		logTag:      "AgentOfflineScan",
	})
}

// Start runs an initial scan shortly after boot, then on the interval.
func (j *HeartbeatOfflineScanJob) Start() {
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

func (j *HeartbeatOfflineScanJob) Stop() { close(j.stop) }

// ScanAll evaluates every tenant. Errors are logged per tenant, never fatal.
func (j *HeartbeatOfflineScanJob) ScanAll() {
	tenants, err := j.tenants()
	if err != nil {
		log.Printf("[%s] Tenant listing failed: %v", j.spec.logTag, err)
		return
	}
	for _, tenantID := range tenants {
		if err := j.scanTenant(context.Background(), tenantID); err != nil {
			log.Printf("[%s] Tenant %s scan failed: %v", j.spec.logTag, tenantID, err)
		}
	}
}

// tenants lists every tenant with a subject in the source table OR an open
// alert of this type (so a removed subject's alert still auto-resolves).
// Cross-tenant listing — bypass role.
func (j *HeartbeatOfflineScanJob) tenants() ([]uuid.UUID, error) {
	q := fmt.Sprintf(`
		SELECT DISTINCT tenant_id FROM %s WHERE deleted_at IS NULL
		UNION
		SELECT DISTINCT tenant_id FROM alerts WHERE alert_type = $1 AND status <> 'resolved'
	`, j.spec.table)
	rows, err := j.bypassDB.Query(q, j.spec.alertType)
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

type offlineSubject struct {
	id    uuid.UUID
	label string
	last  time.Time
}

func (j *HeartbeatOfflineScanJob) scanTenant(ctx context.Context, tenantID uuid.UUID) error {
	if !j.catalog.IsTypeEnabled(ctx, tenantID, j.spec.alertType) {
		return nil // tenant disabled this alert type
	}

	dwellMins := int(j.spec.dwell.Minutes())
	var offline []offlineSubject
	openSubjects := map[uuid.UUID]bool{}
	err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		offQ := fmt.Sprintf(`
			SELECT id, COALESCE(name, ''), last_heartbeat
			FROM %s
			WHERE tenant_id = $1 AND deleted_at IS NULL %s
			  AND last_heartbeat IS NOT NULL
			  AND last_heartbeat < NOW() - make_interval(mins => $2)
		`, j.spec.table, j.spec.extraWhere)
		rows, qErr := tx.QueryContext(ctx, offQ, tenantID, dwellMins)
		if qErr != nil {
			return qErr
		}
		for rows.Next() {
			var s offlineSubject
			if err := rows.Scan(&s.id, &s.label, &s.last); err != nil {
				_ = rows.Close()
				return err
			}
			offline = append(offline, s)
		}
		_ = rows.Close()

		aRows, aErr := tx.QueryContext(ctx, `
			SELECT subject_id FROM alerts
			WHERE tenant_id = $1 AND alert_type = $2 AND status <> 'resolved' AND subject_id IS NOT NULL
		`, tenantID, j.spec.alertType)
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

	offlineSet := make(map[uuid.UUID]bool, len(offline))
	for _, s := range offline {
		offlineSet[s.id] = true
		j.raise(ctx, tenantID, s)
	}
	// Open alerts whose subject is no longer offline → condition cleared
	// (heartbeat resumed, subject removed, or intentionally deactivated).
	for sid := range openSubjects {
		if offlineSet[sid] {
			continue
		}
		j.resolve(ctx, tenantID, sid)
	}
	return nil
}

func (j *HeartbeatOfflineScanJob) raise(ctx context.Context, tenantID uuid.UUID, s offlineSubject) {
	label := s.label
	if label == "" {
		label = fmt.Sprintf("%s %s", j.spec.noun, s.id.String()[:8])
	}
	silence := time.Since(s.last).Round(time.Minute)
	subjectID := s.id
	title := fmt.Sprintf("%s offline: %s", j.spec.noun, label)
	message := fmt.Sprintf("%s %q has not sent a heartbeat since %s (%s ago).",
		j.spec.noun, label, s.last.Format("2006-01-02 15:04 MST"), silence)
	if _, err := j.alertEngine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenantID,
		AlertType:    j.spec.alertType,
		Source:       j.spec.source,
		SubjectType:  j.spec.subjectType,
		SubjectID:    &subjectID,
		SubjectLabel: label,
		Severity:     j.spec.severity,
		Title:        title,
		Message:      message,
		Metadata: map[string]interface{}{
			"subject_id":     s.id.String(),
			"last_heartbeat": s.last.Format(time.RFC3339),
			"dwell_minutes":  int(j.spec.dwell.Minutes()),
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[%s] Raise failed (subject=%s tenant=%s): %v", j.spec.logTag, s.id, tenantID, err)
	}
}

func (j *HeartbeatOfflineScanJob) resolve(ctx context.Context, tenantID, subjectID uuid.UUID) {
	var last sql.NullTime
	exists := false
	if err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		q := fmt.Sprintf(`SELECT last_heartbeat FROM %s WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`, j.spec.table)
		row := tx.QueryRowContext(ctx, q, subjectID, tenantID)
		if scanErr := row.Scan(&last); scanErr == sql.ErrNoRows {
			return nil
		} else if scanErr != nil {
			return scanErr
		}
		exists = true
		return nil
	}); err != nil {
		log.Printf("[%s] Resolve lookup failed (subject=%s tenant=%s): %v", j.spec.logTag, subjectID, tenantID, err)
		return
	}

	observation := map[string]interface{}{"observed_at": time.Now().Format(time.RFC3339)}
	switch {
	case !exists:
		observation["observed"] = fmt.Sprintf("%s removed from inventory", j.spec.subjectType)
	case last.Valid && time.Since(last.Time) <= j.spec.dwell:
		observation["observed"] = "heartbeat resumed"
		observation["last_heartbeat"] = last.Time.Format(time.RFC3339)
	default:
		observation["observed"] = fmt.Sprintf("%s no longer monitored", j.spec.subjectType)
	}

	sid := subjectID
	if err := j.alertEngine.ResolveAuto(ctx, events.AlertResolveEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertType:   j.spec.alertType,
		SubjectID:   &sid,
		Observation: observation,
		Timestamp:   time.Now(),
	}); err != nil {
		log.Printf("[%s] Auto-resolve failed (subject=%s tenant=%s): %v", j.spec.logTag, subjectID, tenantID, err)
	}
}
