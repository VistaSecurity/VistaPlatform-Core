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
// Offline is computed from COALESCE(last_heartbeat, created_at) (not the source
// table's status column), so the two runtimes stay symmetric even though only
// sensor-manager has a status reaper — and so a subject that registered and
// then never checked in goes offline once its registration is older than the
// dwell, exactly like one that checked in and stopped.
//
// This used to read last_heartbeat alone, behind an `AND last_heartbeat IS NOT
// NULL` guard, which excluded precisely the rows that most need the alert: an
// agent that registers successfully and whose service then fails to start or is
// firewalled showed status='active' in the console forever and raised nothing.
// sensor-manager's reaper (internal/services/sensor_reaper.go) has always used
// the COALESCE form, so the two code paths disagreed — the reaper flipped such
// sensors to 'offline' while the alert path stayed silent about them.
//
// Subjects that are intentionally quiet are excluded by spec.extraWhere, which
// is where that decision belongs: pending/inactive sensors, inactive agents,
// platform sensors, and sensors an operator flagged air_gapped (which by
// definition are not expected to check in at all).
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

// NewSensorOfflineScanJob detects sensors that stopped reporting — or that
// registered and never reported at all. Platform sensors (platform =
// 'platform') are excluded — they serve all tenants and are not a tenant-owned
// subject. Intentionally pending/inactive sensors are excluded so admin-disabled
// or never-activated sensors don't alarm: a 'pending' row is a registration key
// that nothing has claimed yet, and 'inactive' is an operator switching a sensor
// off. Air-gapped sensors are excluded too — the column's whole meaning is "this
// sensor is not expected to check in, heartbeat, or stream discoveries", so an
// offline alert for one is noise by construction. That exclusion only started to
// matter when the never-reported rows came into scope: before, an air-gapped
// sensor that had never heartbeated was hidden by the NULL test.
func NewSensorOfflineScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *HeartbeatOfflineScanJob {
	return newHeartbeatOfflineScanJob(db, bypassDB, catalog, alertEngine, interval, heartbeatSpec{
		alertType:   "sensor_offline",
		source:      "sensor-manager",
		subjectType: "sensor",
		table:       "sensors",
		extraWhere:  "AND platform <> 'platform' AND status NOT IN ('pending', 'inactive') AND air_gapped = false",
		severity:    "high",
		dwell:       15 * time.Minute,
		noun:        "Sensor",
		logTag:      "SensorOfflineScan",
	})
}

// NewDiscoveryAgentOfflineScanJob detects discovery/interrogation agents that
// stopped reporting — or that registered and never reported at all, which is
// the ordinary shape of a failed agent install: AgentService's registration
// INSERT writes status='active' and leaves last_heartbeat NULL, and only the
// agent's own heartbeat loop ever fills it in.
//
// Admin-disabled (inactive) agents are excluded; device_agents has no 'pending'
// state to exclude (its CHECK allows active/inactive/error only). New platform
// identities live in sensors and are monitored by the system-sensor health
// service. A legacy platform device_agents row can remain until an operator
// removes it through the ordinary agent lifecycle.
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
	// last is NULL for a subject that has never reported. created is the
	// registration instant, and is what the dwell is measured from in that case.
	// Both are NullTime deliberately: created_at is nullable in both source
	// tables, so a stale-heartbeat row can still carry a NULL created_at.
	last    sql.NullTime
	created sql.NullTime
}

// silenceSince returns the instant the subject was last known to be alive, and
// whether it has ever reported. For a subject that never reported, the clock
// starts at registration — the same COALESCE the SQL predicate uses, and the
// same one sensor-manager's reaper has always used. ok is false only when
// neither timestamp is known, which the query cannot produce (a row with both
// NULL fails the predicate) but which callers must still render honestly rather
// than as a zero time.
func (s offlineSubject) silenceSince() (since time.Time, ok bool, everReported bool) {
	if s.last.Valid {
		return s.last.Time, true, true
	}
	if s.created.Valid {
		return s.created.Time, true, false
	}
	return time.Time{}, false, false
}

// offlineQuery is the predicate that decides "offline". It is built here, and
// only here, so the shape can be asserted without a database; scanTenant is its
// only caller.
//
// COALESCE(last_heartbeat, created_at) — NOT `last_heartbeat IS NOT NULL AND
// last_heartbeat < ...`, which is what shipped through v1.0.0 and which made a
// subject that never reported permanently unalertable. The exclusions that DO
// belong here are the intentional-quiet ones, and they live in spec.extraWhere.
func (j *HeartbeatOfflineScanJob) offlineQuery() string {
	return fmt.Sprintf(`
		SELECT id, COALESCE(name, ''), last_heartbeat, created_at
		FROM %s
		WHERE tenant_id = $1 AND deleted_at IS NULL %s
		  AND COALESCE(last_heartbeat, created_at) < NOW() - make_interval(mins => $2)
	`, j.spec.table, j.spec.extraWhere)
}

func (j *HeartbeatOfflineScanJob) scanTenant(ctx context.Context, tenantID uuid.UUID) error {
	if !j.catalog.IsTypeEnabled(ctx, tenantID, j.spec.alertType) {
		return nil // tenant disabled this alert type
	}

	dwellMins := int(j.spec.dwell.Minutes())
	var offline []offlineSubject
	openSubjects := map[uuid.UUID]bool{}
	err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, j.offlineQuery(), tenantID, dwellMins)
		if qErr != nil {
			return qErr
		}
		for rows.Next() {
			var s offlineSubject
			if err := rows.Scan(&s.id, &s.label, &s.last, &s.created); err != nil {
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
	if _, err := j.alertEngine.Raise(ctx, j.buildRaiseEvent(tenantID, s, time.Now())); err != nil {
		log.Printf("[%s] Raise failed (subject=%s tenant=%s): %v", j.spec.logTag, s.id, tenantID, err)
	}
}

// buildRaiseEvent renders the alert for one offline subject. Split out of raise
// so the never-reported wording is provable without a database: a NULL
// last_heartbeat must never surface as a zero time, an empty string, or "last
// seen 0001-01-01" — it has to read as "has never reported", because the
// operator's next move differs (check the install, not the network).
//
// Metadata carries an explicit never_reported bool rather than an absent key.
// An explicit false is an answer; and last_heartbeat is omitted entirely when
// there is none, so a consumer reading it gets "missing", never a fabricated
// timestamp.
func (j *HeartbeatOfflineScanJob) buildRaiseEvent(tenantID uuid.UUID, s offlineSubject, now time.Time) events.AlertRaiseEvent {
	label := s.label
	if label == "" {
		label = fmt.Sprintf("%s %s", j.spec.noun, s.id.String()[:8])
	}
	subjectID := s.id
	metadata := map[string]interface{}{
		"subject_id":    s.id.String(),
		"dwell_minutes": int(j.spec.dwell.Minutes()),
	}

	since, ok, everReported := s.silenceSince()
	metadata["never_reported"] = !everReported

	var title, message string
	switch {
	case everReported:
		title = fmt.Sprintf("%s offline: %s", j.spec.noun, label)
		message = fmt.Sprintf("%s %q has not sent a heartbeat since %s (%s ago).",
			j.spec.noun, label, since.Format("2006-01-02 15:04 MST"), now.Sub(since).Round(time.Minute))
		metadata["last_heartbeat"] = since.Format(time.RFC3339)
	case ok:
		title = fmt.Sprintf("%s never reported: %s", j.spec.noun, label)
		message = fmt.Sprintf("%s %q has never sent a heartbeat. It registered %s (%s ago) and has not been heard from since.",
			j.spec.noun, label, since.Format("2006-01-02 15:04 MST"), now.Sub(since).Round(time.Minute))
		metadata["registered_at"] = since.Format(time.RFC3339)
	default:
		// Unreachable from offlineQuery (a row with both timestamps NULL fails
		// the predicate), but rendering a zero time here is exactly the failure
		// this function exists to prevent.
		title = fmt.Sprintf("%s never reported: %s", j.spec.noun, label)
		message = fmt.Sprintf("%s %q has never sent a heartbeat, and its registration time is unknown.",
			j.spec.noun, label)
	}

	return events.AlertRaiseEvent{
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
		Metadata:     metadata,
		Timestamp:    now,
	}
}

// resolveObservation is the "why did this clear?" note written onto the alert.
// Split out of resolve for the same reason buildRaiseEvent is split out of
// raise: the never-reported case has to read honestly, and proving it should
// not need a database.
//
// The never-reported ordering matters. A subject that finally checks in lands on
// "heartbeat resumed" — the first heartbeat clears a never-reported alert exactly
// like a returning one clears a stale-heartbeat alert, which is what the
// catalog's auto_resolve promises. A never-reported subject that clears WITHOUT
// ever checking in did so because it left the predicate some other way
// (deactivated, flagged air-gapped), and says so rather than claiming a
// heartbeat it never got.
func (j *HeartbeatOfflineScanJob) resolveObservation(exists bool, last sql.NullTime, now time.Time) map[string]interface{} {
	observation := map[string]interface{}{"observed_at": now.Format(time.RFC3339)}
	switch {
	case !exists:
		observation["observed"] = fmt.Sprintf("%s removed from inventory", j.spec.subjectType)
	case last.Valid && now.Sub(last.Time) <= j.spec.dwell:
		observation["observed"] = "heartbeat resumed"
		observation["last_heartbeat"] = last.Time.Format(time.RFC3339)
	case !last.Valid:
		observation["observed"] = fmt.Sprintf("%s no longer monitored (still has never reported)", j.spec.subjectType)
		observation["never_reported"] = true
	default:
		observation["observed"] = fmt.Sprintf("%s no longer monitored", j.spec.subjectType)
	}
	return observation
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

	observation := j.resolveObservation(exists, last, time.Now())

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
