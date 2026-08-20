package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/alertcatalog"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// CertLadderScanJob evaluates every tenant's certificates against that
// tenant's effective expiry ladder (baseline/preference + policy rungs,
// §8.3) and drives the stateful alert engine:
//
//   - days remaining crossed a rung → Raise (engine opens or escalates; a
//     re-scan at the same severity is a silent touch)
//   - days remaining above every rung while an alert is open (the cert was
// renewed) → auto-resolve with the renewal observation
//   - certificate deleted while an alert is open → auto-resolve with a
//     deletion observation
//
// This subsumes the fixed 30/14/7/0 tiers: the inventory-service lifecycle
// events still arrive as a redundant floor (the engine dedupes), but the
// ladder is what makes 90/60/45-day rungs fire at all.
type CertLadderScanJob struct {
	db          *sqlx.DB
	bypassDB    *sqlx.DB
	catalog     *services.AlertCatalogService
	alertEngine *services.AlertEngineService
	interval    time.Duration
	stop        chan struct{}
}

func NewCertLadderScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *CertLadderScanJob {
	return &CertLadderScanJob{
		db: db, bypassDB: bypassDB, catalog: catalog, alertEngine: alertEngine,
		interval: interval, stop: make(chan struct{}),
	}
}

// Start runs an initial scan shortly after boot, then on the interval.
func (j *CertLadderScanJob) Start() {
	go func() {
		initial := time.NewTimer(2 * time.Minute)
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

func (j *CertLadderScanJob) Stop() { close(j.stop) }

// ScanAll evaluates every tenant. Errors are logged per tenant, never fatal.
func (j *CertLadderScanJob) ScanAll() {
	tenants, err := j.tenantsWithCerts()
	if err != nil {
		log.Printf("[CertLadderScan] Tenant listing failed: %v", err)
		return
	}
	for _, tenantID := range tenants {
		if err := j.scanTenant(context.Background(), tenantID); err != nil {
			log.Printf("[CertLadderScan] Tenant %s scan failed: %v", tenantID, err)
		}
	}
}

func (j *CertLadderScanJob) tenantsWithCerts() ([]uuid.UUID, error) {
	// Cross-tenant listing — bypass role. Includes tenants with open cert
	// alerts but no remaining certs so deletions still auto-resolve.
	rows, err := j.bypassDB.Query(`
		SELECT DISTINCT tenant_id FROM certificates WHERE not_after IS NOT NULL
		UNION
		SELECT DISTINCT tenant_id FROM alerts WHERE alert_type = 'certificate_expiring' AND status <> 'resolved'
	`)
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

type scanCert struct {
	id         uuid.UUID
	commonName string
	notAfter   time.Time
}

func (j *CertLadderScanJob) scanTenant(ctx context.Context, tenantID uuid.UUID) error {
	ladder, err := j.catalog.CertLadder(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("build ladder: %w", err)
	}
	maxDays := alertcatalog.MaxDays(ladder)

	// Certificates inside the warning window (or expired), plus every cert
	// with an open alert (for renewal/deletion auto-resolve).
	var certs []scanCert
	openAlertSubjects := map[uuid.UUID]bool{}
	err = shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, `
			SELECT id, COALESCE(common_name, ''), not_after
			FROM certificates
			WHERE tenant_id = $1 AND not_after IS NOT NULL AND not_after <= NOW() + ($2 || ' days')::interval
		`, tenantID, fmt.Sprint(maxDays+1))
		if qErr != nil {
			return qErr
		}
		for rows.Next() {
			var c scanCert
			if err := rows.Scan(&c.id, &c.commonName, &c.notAfter); err != nil {
				_ = rows.Close()
				return err
			}
			certs = append(certs, c)
		}
		_ = rows.Close()

		aRows, aErr := tx.QueryContext(ctx, `
			SELECT subject_id FROM alerts
			WHERE tenant_id = $1 AND alert_type = 'certificate_expiring'
			  AND status <> 'resolved' AND subject_id IS NOT NULL
		`, tenantID)
		if aErr != nil {
			return aErr
		}
		defer func() { _ = aRows.Close() }()
		for aRows.Next() {
			var sid uuid.UUID
			if err := aRows.Scan(&sid); err == nil {
				openAlertSubjects[sid] = true
			}
		}
		return aRows.Err()
	})
	if err != nil {
		return err
	}

	now := time.Now()
	scanned := map[uuid.UUID]bool{}
	for _, c := range certs {
		scanned[c.id] = true
		daysRemaining := int(time.Until(c.notAfter).Hours() / 24)
		if c.notAfter.After(now) && time.Until(c.notAfter).Hours() > float64(daysRemaining*24) {
			// partial day still counts as a remaining day
			daysRemaining++
		}
		severity := alertcatalog.EffectiveSeverity(ladder, daysRemaining)
		if severity == "" {
			// Above every rung. If an alert is open, the cert was renewed.
			if openAlertSubjects[c.id] {
				j.resolveCertAlert(ctx, tenantID, c.id, map[string]interface{}{
					"observed":       "certificate renewed",
					"not_after":      c.notAfter.Format(time.RFC3339),
					"days_remaining": daysRemaining,
					"observed_at":    now.Format(time.RFC3339),
				})
			}
			continue
		}
		j.raiseCertAlert(ctx, tenantID, c, daysRemaining, severity)
	}

	// Open alerts whose certificate was NOT in the scan window. Two cases,
	// both auto-resolve: the cert still exists but its not_after moved
	// beyond every rung — that IS the renewal (the common resolution; a
	// renewed cert leaves the window entirely, so the in-window renewal
	// branch above never sees it) — or the cert is gone from inventory.
	for sid := range openAlertSubjects {
		if scanned[sid] {
			continue
		}
		notAfter, exists, exErr := j.certNotAfter(ctx, tenantID, sid)
		if exErr != nil {
			log.Printf("[CertLadderScan] Cert lookup failed (cert=%s tenant=%s): %v", sid, tenantID, exErr)
			continue
		}
		if !exists {
			j.resolveCertAlert(ctx, tenantID, sid, map[string]interface{}{
				"observed":    "certificate removed from inventory",
				"observed_at": now.Format(time.RFC3339),
			})
			continue
		}
		observation := map[string]interface{}{
			"observed":    "certificate renewed",
			"observed_at": now.Format(time.RFC3339),
		}
		if notAfter != nil {
			observation["not_after"] = notAfter.Format(time.RFC3339)
			observation["days_remaining"] = int(time.Until(*notAfter).Hours() / 24)
		}
		j.resolveCertAlert(ctx, tenantID, sid, observation)
	}
	return nil
}

// certNotAfter fetches a certificate's expiry; exists=false when the row is
// gone. A NULL not_after reports exists=true with a nil time (treated as
// renewed/no-longer-monitorable by the caller).
func (j *CertLadderScanJob) certNotAfter(ctx context.Context, tenantID, certID uuid.UUID) (*time.Time, bool, error) {
	var notAfter sql.NullTime
	exists := false
	err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT not_after FROM certificates WHERE id = $1 AND tenant_id = $2`, certID, tenantID)
		if scanErr := row.Scan(&notAfter); scanErr == sql.ErrNoRows {
			return nil
		} else if scanErr != nil {
			return scanErr
		}
		exists = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	if notAfter.Valid {
		t := notAfter.Time
		return &t, true, nil
	}
	return nil, true, nil
}

func (j *CertLadderScanJob) raiseCertAlert(ctx context.Context, tenantID uuid.UUID, c scanCert, daysRemaining int, severity string) {
	commonName := c.commonName
	if commonName == "" {
		commonName = "unknown"
	}
	title := fmt.Sprintf("Certificate expiring: %s", commonName)
	message := fmt.Sprintf("Certificate %s expires in %d days (on %s)", commonName, daysRemaining, c.notAfter.Format("2006-01-02"))
	if daysRemaining <= 0 {
		title = fmt.Sprintf("Certificate expired: %s", commonName)
		message = fmt.Sprintf("Certificate %s expired on %s", commonName, c.notAfter.Format("2006-01-02"))
	}
	certID := c.id
	// RaisePolicyRung, not Raise: with the type disabled BuildLadder has already
	// dropped the baseline/preference rungs, so anything still reaching here is a
	// rung contributed by an ACTIVATED framework, which §8.3 says must keep
	// opening/escalating the alert ("you can control noise; you can't fake
	// posture"). Gating it again in the engine would silence exactly the rungs
	// that are supposed to survive a disable.
	if _, err := j.alertEngine.RaisePolicyRung(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenantID,
		AlertType:    "certificate_expiring",
		Source:       "inventory-service",
		SubjectType:  "certificate",
		SubjectID:    &certID,
		SubjectLabel: commonName,
		Severity:     severity,
		Title:        title,
		Message:      message,
		Metadata: map[string]interface{}{
			"certificate_id": c.id.String(),
			"common_name":    commonName,
			"not_after":      c.notAfter.Format(time.RFC3339),
			"days_remaining": daysRemaining,
			"rung_source":    "ladder",
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[CertLadderScan] Raise failed (cert=%s tenant=%s): %v", c.id, tenantID, err)
	}
}

func (j *CertLadderScanJob) resolveCertAlert(ctx context.Context, tenantID, certID uuid.UUID, observation map[string]interface{}) {
	subjectID := certID
	if err := j.alertEngine.ResolveAuto(ctx, events.AlertResolveEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertType:   "certificate_expiring",
		SubjectID:   &subjectID,
		Observation: observation,
		Timestamp:   time.Now(),
	}); err != nil {
		log.Printf("[CertLadderScan] Auto-resolve failed (cert=%s tenant=%s): %v", certID, tenantID, err)
	}
}
