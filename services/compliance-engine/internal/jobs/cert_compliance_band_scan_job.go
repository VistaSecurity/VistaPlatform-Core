package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// CertComplianceBandScanJob re-materializes compliance findings for certificates
// whose verdict can change with nothing but the passage of time.
//
// WHY THIS EXISTS. Compliance materialization is event-driven and bounded by
// design: an asset or certificate changes, an event is raised, and a per-subject
// reconcile folds every published framework's controls over that subject.
// `cert_expiration_days` is the platform's ONLY purely time-dependent
// measurement — it decreases every day with no inventory change — so a
// certificate that crosses the 90-day threshold (cert-expiry-90-day / CE-90-001)
// or the 30-day one (cert-expiry-30-day / CE-30-001), with nothing else about it
// changing, raises no event and is never re-evaluated. Its stored `findings` row
// keeps whatever verdict the last reconcile computed and `tenant_framework_scores`
// keeps reporting it. Flagged in and left undecided there.
//
// The one bridge that did exist is inventory-service's certificate expiry scan,
// which publishes `certificate.changed` at exactly one boundary — the day a
// certificate crosses not_after. That covers the expired transition and nothing
// above it. It stays where it is (it also owns the certificate_state write); this
// job covers every other threshold.
//
// WHY HERE AND NOT IN INVENTORY-SERVICE. Widening that bridge would need
// inventory-service to read the platform-framework tables to know how wide the
// band is, plus per-certificate de-duplication so a 12-hourly scan does not
// republish forever — either a new marker column on `certificates` (the
// notification ladder's `expiry_alert_tier` cannot be reused; widening it to 90
// would add a user-visible 90-day notification nobody asked for) or an
// unconditional republish on every scan. Running the sweep in compliance-engine
// needs none of that: the framework tables and the reconcile primitive are both
// already local, the call is in-process rather than over NATS, and NO dedup marker
// is needed because the reconcile is convergent and the finding upsert already
// no-ops on an unchanged finding. CertLadderScanJob next door re-scans on the same
// interval with no marker for the same reason.
type CertComplianceBandScanJob struct {
	db *sqlx.DB
	// bypassDB is the BYPASSRLS handle. The tenant enumerator below spans every
	// tenant's certificates, so it has no app.tenant_id to set and must not run on
	// the RLS-scoped handle — there it returns zero rows and the sweep silently
	// does nothing.
	bypassDB *sqlx.DB
	findings *services.FindingsService
	interval time.Duration
	stop     chan struct{}
}

func NewCertComplianceBandScanJob(db, bypassDB *sqlx.DB, findings *services.FindingsService,
	interval time.Duration) *CertComplianceBandScanJob {
	return &CertComplianceBandScanJob{
		db: db, bypassDB: bypassDB, findings: findings,
		interval: interval, stop: make(chan struct{}),
	}
}

// CertComplianceBandScanEnabled reports whether the sweep is on (default true).
// Kill-switch for the same reason COMPLIANCE_RECONCILE_WORKER_ENABLED exists: this
// job writes findings on a timer, so an operator needs a way to stop it without
// stopping the service. Disabling it degrades to event-driven evaluation only —
// i.e. back to the staleness described above.
func CertComplianceBandScanEnabled() bool {
	return os.Getenv("COMPLIANCE_CERT_BAND_SCAN_ENABLED") != "false"
}

// Start runs an initial sweep shortly after boot, then on the interval. The initial
// delay is offset from CertLadderScanJob's so the two certificate sweeps do not
// contend on boot.
func (j *CertComplianceBandScanJob) Start() {
	if !CertComplianceBandScanEnabled() {
		log.Printf("[CertComplianceBandScan] Disabled by COMPLIANCE_CERT_BAND_SCAN_ENABLED=false")
		return
	}
	go func() {
		initial := time.NewTimer(3 * time.Minute)
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

func (j *CertComplianceBandScanJob) Stop() { close(j.stop) }

// bandMeasurement is one stored `cert_expiration_days` rule: the rule type and its
// raw predicate, exactly as a control carries it.
type bandMeasurement struct {
	RuleType  string `db:"rule_type"`
	Predicate []byte `db:"predicate"`
}

// widestBandDays returns the largest days-remaining value at which ANY of these
// rules can change its verdict — the width of the window a scan has to cover.
//
// Operator-agnostic on purpose. A threshold flips as the measured value crosses
// its `value` whichever way the comparison points, so ">= 90", "<= 90" and "== 90"
// all make 90 a day on which a verdict can move. (This is the one place where this
// job's query deliberately differs from AlertCatalogService.CertPolicyRungs, which
// keeps only ">="/">" because it is projecting ALERT rungs — "warn when remaining
// drops to N" is only meaningful for a lower bound.)
//
// Returns -1 when no usable rule is found, which is correct and self-limiting rather than a
// failure: with no cert_expiration_days control published there is nothing
// time-dependent to re-evaluate, and the caller scans nothing. Hardcoding a floor
// of 90 here would be the bug this function exists to avoid — a platform admin who
// authors a control at 180 days must widen the window, and one who removes them all
// must not leave a phantom window behind.
func widestBandDays(measurements []bandMeasurement) int {
	widest := -1
	consider := func(v float64) {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return
		}
		if d := max(0, int(math.Ceil(v))); d > widest {
			widest = d
		}
	}
	for _, m := range measurements {
		var predicate map[string]interface{}
		if err := json.Unmarshal(m.Predicate, &predicate); err != nil {
			continue
		}
		switch m.RuleType {
		case "threshold":
			if v, ok := toFloat(predicate["value"]); ok {
				consider(v)
			}
		case "range":
			// Both bounds matter: a verdict moves at either edge.
			if v, ok := toFloat(predicate["min"]); ok {
				consider(v)
			}
			if v, ok := toFloat(predicate["max"]); ok {
				consider(v)
			}
		}
	}
	return widest
}

// toFloat narrows the handful of numeric shapes encoding/json produces for a
// predicate literal.
func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

// bandDays reads every cert_expiration_days rule carried by a PUBLISHED platform
// framework's controls and returns the widest.
//
// Scoped to published platform frameworks because that is EXACTLY the set the
// reconcile folds (evaluateSubjects lists `platform_frameworks WHERE status =
// 'published'` and evaluates with the "platform" scenario). Deriving the window
// from a wider set would scan certificates nothing re-evaluates; deriving it from a
// narrower one — the tenant's ACTIVE licenses, say — would leave a published but
// unlicensed framework's control to go stale, because the reconcile evaluates it
// regardless of licensing. These tables are platform-global with no RLS, so this is
// one query per sweep rather than one per tenant.
func (j *CertComplianceBandScanJob) bandDays(ctx context.Context) (int, error) {
	var measurements []bandMeasurement
	err := j.db.SelectContext(ctx, &measurements, `
		SELECT cm.rule_type, cm.predicate
		FROM control_measurements cm
		JOIN measurement_types mt ON mt.id = cm.measurement_type_id
		JOIN platform_framework_controls pfc ON pfc.id = cm.control_id
		JOIN platform_frameworks pf ON pf.id = pfc.framework_id
		WHERE cm.framework_type = 'platform'
		  AND mt.code = 'cert_expiration_days'
		  AND pf.status = 'published'
	`)
	if err != nil {
		return 0, fmt.Errorf("read cert_expiration_days rules: %w", err)
	}
	return widestBandDays(measurements), nil
}

// ScanAll re-evaluates every tenant's in-band certificates. Errors are logged per
// tenant, never fatal.
func (j *CertComplianceBandScanJob) ScanAll() {
	ctx := context.Background()

	band, err := j.bandDays(ctx)
	if err != nil {
		log.Printf("[CertComplianceBandScan] Band derivation failed: %v", err)
		return
	}
	if band < 0 {
		log.Printf("[CertComplianceBandScan] No published cert_expiration_days control; nothing to re-evaluate")
		return
	}

	tenants, err := j.tenantsWithInBandCerts(ctx, band)
	if err != nil {
		log.Printf("[CertComplianceBandScan] Tenant listing failed: %v", err)
		return
	}

	var scanned, certsTotal int
	for _, tenantID := range tenants {
		n, err := j.scanTenant(ctx, tenantID, band)
		if err != nil {
			log.Printf("[CertComplianceBandScan] Tenant %s scan failed: %v", tenantID, err)
			continue
		}
		scanned++
		certsTotal += n
	}
	log.Printf("[CertComplianceBandScan] Sweep complete: band=%dd tenants=%d/%d certificates=%d",
		band, scanned, len(tenants), certsTotal)
}

// tenantsWithInBandCerts lists the tenants holding at least one certificate inside
// the band. Soft-deleted tenants are excluded (SEC-5): reconciling a tenant nobody
// can see the findings of is pure waste.
func (j *CertComplianceBandScanJob) tenantsWithInBandCerts(ctx context.Context, band int) ([]uuid.UUID, error) {
	// RLS: cross-tenant enumerator — bypass role. Each tenant's certificates are
	// then read and reconciled under that tenant's app.tenant_id.
	var ids []uuid.UUID
	err := j.bypassDB.SelectContext(ctx, &ids, `
		SELECT DISTINCT c.tenant_id
		FROM certificates c
		JOIN tenants t ON t.id = c.tenant_id AND t.deleted_at IS NULL
		WHERE c.not_after IS NOT NULL
		  AND c.is_ca_certificate = false
		  AND c.not_after <= NOW() + ($1 || ' days')::interval
	`, fmt.Sprint(band+1))
	return ids, err
}

// scanTenant reconciles one tenant's in-band certificates and reports how many.
func (j *CertComplianceBandScanJob) scanTenant(ctx context.Context, tenantID uuid.UUID, band int) (int, error) {
	var certIDs []uuid.UUID
	err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		// The filters mirror the `certificate` measurement SHAPE, not the
		// notification scan's: non-CA (a chain intermediate yields no measurement
		// value under any certificate control) and a known not_after. Deliberately
		// NO certificate_state filter — the shape has none, so a revoked or
		// deactivated certificate IS still evaluated, and skipping it here would
		// leave exactly the stale verdict this job exists to clear.
		//
		// band+1 is a scan-boundary margin: a certificate sitting a fraction of a
		// day outside the widest threshold at query time is about to cross it, and
		// including it costs one convergent no-op.
		rows, qErr := tx.QueryContext(ctx, `
			SELECT id FROM certificates
			WHERE tenant_id = $1
			  AND not_after IS NOT NULL
			  AND is_ca_certificate = false
			  AND not_after <= NOW() + ($2 || ' days')::interval
		`, tenantID, fmt.Sprint(band+1))
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			certIDs = append(certIDs, id)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, fmt.Errorf("list in-band certificates: %w", err)
	}
	if len(certIDs) == 0 {
		return 0, nil
	}

	summary, err := j.findings.ReconcileCertificates(ctx, tenantID, certIDs, "cert-band-scan")
	if err != nil {
		return 0, err
	}
	if summary.FindingsActivated > 0 || summary.FindingsInactivated > 0 {
		log.Printf("[CertComplianceBandScan] tenant=%s certificates=%d activated=+%d inactivated=%d",
			tenantID, len(certIDs), summary.FindingsActivated, summary.FindingsInactivated)
	}
	return len(certIDs), nil
}
