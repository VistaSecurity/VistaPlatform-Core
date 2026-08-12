package jobs

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
)

// expiryTiers are the day thresholds at which a certificate-expiry alert escalates,
// widest first; 0 means expired. A certificate alerts at most once per tier it
// crosses (tracked by certificates.expiry_alert_tier), so a daily/12h scan never
// re-notifies the same tier — only escalations and the expired transition fire.
var expiryTiers = []int{30, 14, 7, 0}

// CertificateExpiryScanJob (ADR-0015 §6) periodically scans every tenant's
// certificates for upcoming or elapsed expiry. It:
//
//   - publishes inventory.lifecycle.certificate.expiring at each escalating tier,
//     reusing the existing notification path (notification-service's
//     CertificateExpirySubscriber turns it into an owner-facing alert); and
//   - on the day a certificate crosses not_after, transitions it to
//     certificate_state='expired' and emits certificate.changed — the bridge that
//     makes compliance-engine re-evaluate that one certificate the same day
//     (event-driven, bounded; no scheduled re-evaluation).
//
// This closes the gap where expiry events fired only during asset upsert, leaving a
// long-idle deployment blind to certificates lapsing with no discovery activity.
type CertificateExpiryScanJob struct {
	db *database.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) handle. The nightly scan spans
	// every tenant's certificates, so it has no app.tenant_id to set and must not
	// run on the RLS-scoped handle.
	bypassDB       *sql.DB
	eventPublisher *services.EventPublisherService
	interval       time.Duration
	logger         *log.Logger
}

// NewCertificateExpiryScanJob creates the scan job. Interval is configurable via
// CERT_EXPIRY_SCAN_INTERVAL (default 12h).
func NewCertificateExpiryScanJob(db *database.DB, bypassDB *sql.DB, eventPublisher *services.EventPublisherService) *CertificateExpiryScanJob {
	interval := 12 * time.Hour
	if v := os.Getenv("CERT_EXPIRY_SCAN_INTERVAL"); v != "" {
		if p, err := time.ParseDuration(v); err == nil && p > 0 {
			interval = p
		}
	}
	return &CertificateExpiryScanJob{
		db:             db,
		bypassDB:       bypassDB,
		eventPublisher: eventPublisher,
		interval:       interval,
		logger:         log.New(log.Writer(), "[CertExpiryScan] ", log.LstdFlags),
	}
}

// Start runs the scan immediately, then on the configured interval until ctx is done.
func (j *CertificateExpiryScanJob) Start(ctx context.Context) {
	j.logger.Printf("Starting certificate expiry scan (interval: %v)", j.interval)
	j.scan(ctx)

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			j.logger.Printf("Stopping certificate expiry scan")
			return
		case <-ticker.C:
			j.scan(ctx)
		}
	}
}

// currentTier returns the tightest expiry tier the given days-remaining has crossed,
// and whether any tier applies (a cert more than 30 days out has no tier).
func currentTier(daysRemaining int) (tier int, applies bool) {
	for _, t := range expiryTiers {
		if daysRemaining <= t {
			tier, applies = t, true
		}
	}
	return tier, applies
}

type expiryCert struct {
	id            uuid.UUID
	tenantID      uuid.UUID
	commonName    sql.NullString
	notAfter      time.Time
	state         string
	alertTier     sql.NullInt64
	daysRemaining int
}

func (j *CertificateExpiryScanJob) scan(ctx context.Context) {
	// RLS: cross-tenant — runs on the bypass role. This sweep reads every
	// tenant's certificates to raise expiry alerts, so there is no single
	// app.tenant_id to set. On the RLS-scoped handle it returns zero rows and
	// logs nothing, so no expiry alert would ever fire again.
	const q = `
		SELECT id, tenant_id, common_name, not_after, certificate_state, expiry_alert_tier,
		       FLOOR(EXTRACT(EPOCH FROM (not_after - NOW())) / 86400.0)::int AS days_remaining
		FROM certificates
		WHERE not_after IS NOT NULL
		  AND is_ca_certificate = false
		  AND certificate_state NOT IN ('revoked', 'destroyed', 'deactivated')
	`
	rows, err := j.bypassDB.QueryContext(ctx, q)
	if err != nil {
		j.logger.Printf("scan query failed: %v", err)
		return
	}
	var certs []expiryCert
	for rows.Next() {
		var c expiryCert
		if err := rows.Scan(&c.id, &c.tenantID, &c.commonName, &c.notAfter, &c.state, &c.alertTier, &c.daysRemaining); err != nil {
			j.logger.Printf("scan row failed: %v", err)
			continue
		}
		certs = append(certs, c)
	}
	_ = rows.Close()

	var alerts, expired int
	for _, c := range certs {
		// Bridge: a certificate that has just crossed not_after flips to 'expired'
		// and emits certificate.changed so compliance re-evaluates it same-day. The
		// state guard makes this fire exactly once per certificate.
		if c.daysRemaining <= 0 && c.state != "expired" {
			// Scope each write to its cert's tenant so the UPDATE satisfies RLS WITH CHECK.
			if err := database.WithTenantTx(ctx, j.db, c.tenantID, func(tx *sqlx.Tx) error {
				_, e := tx.ExecContext(ctx,
					`UPDATE certificates SET certificate_state = 'expired',
					    certificate_state_reason = 'not_after elapsed (expiry scan)', updated_at = NOW()
					 WHERE id = $1`, c.id)
				return e
			}); err != nil {
				j.logger.Printf("mark expired failed cert=%s: %v", c.id, err)
			} else {
				if err := j.eventPublisher.PublishCertificateChanged(ctx, c.tenantID, c.id, sharedevents.ChangeTypeUpdated, "cert-expiry-scan"); err != nil {
					j.logger.Printf("bridge publish failed cert=%s: %v", c.id, err)
				}
				expired++
			}
		}

		tier, applies := currentTier(c.daysRemaining)
		if !applies {
			// Renewed / replaced (now >30 days out): clear the tier so a future
			// expiry alerts again from the top.
			if c.alertTier.Valid {
				// Scope each write to its cert's tenant so the UPDATE satisfies RLS WITH CHECK.
				if err := database.WithTenantTx(ctx, j.db, c.tenantID, func(tx *sqlx.Tx) error {
					_, e := tx.ExecContext(ctx, `UPDATE certificates SET expiry_alert_tier = NULL WHERE id = $1`, c.id)
					return e
				}); err != nil {
					j.logger.Printf("reset alert tier failed cert=%s: %v", c.id, err)
				}
			}
			continue
		}

		// Alert only on first entry or escalation to a tighter tier (lower number).
		if c.alertTier.Valid && tier >= int(c.alertTier.Int64) {
			continue
		}

		var cn *string
		if c.commonName.Valid {
			cn = &c.commonName.String
		}
		payload := &invevents.CertificateExpiringPayload{
			CertificateID: c.id,
			AssetID:       c.id, // certs may be unlinked (uploaded); cert id is the stable handle
			CommonName:    cn,
			NotAfter:      c.notAfter,
			DaysRemaining: c.daysRemaining,
		}
		if err := j.eventPublisher.PublishCertificateExpiring(ctx, c.tenantID, payload, "cert-expiry-scan"); err != nil {
			j.logger.Printf("expiring publish failed cert=%s: %v", c.id, err)
			continue
		}
		// Scope each write to its cert's tenant so the UPDATE satisfies RLS WITH CHECK.
		if err := database.WithTenantTx(ctx, j.db, c.tenantID, func(tx *sqlx.Tx) error {
			_, e := tx.ExecContext(ctx, `UPDATE certificates SET expiry_alert_tier = $2 WHERE id = $1`, c.id, tier)
			return e
		}); err != nil {
			j.logger.Printf("update alert tier failed cert=%s: %v", c.id, err)
		}
		alerts++
	}

	j.logger.Printf("scan complete: %d certs examined, %d expiry alerts, %d newly expired (bridge)", len(certs), alerts, expired)
}
