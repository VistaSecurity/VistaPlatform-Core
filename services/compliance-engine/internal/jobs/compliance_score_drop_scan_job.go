package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

const (
	scoreDropAlertType        = "compliance_score_drop"
	hygieneScoreDropAlertType = "hygiene_score_drop"
	// hygieneFrameworkCode is the Core Inventory Hygiene framework, whose drop
	// is reported as its own alert type.
	hygieneFrameworkCode   = "inventory-hygiene"
	scoreDropThreshold     = 10         // points lost in the lookback window
	scoreDropLookback      = "24 hours" // reference is the score ~24h ago
	scoreDropSnapshotPrune = "30 hours" // keep a little past the lookback
)

// scoreDropAlertTypes is every alert type this one job produces. The tenant and
// open-alert listings key on it, so adding a framework split below without
// adding it here would leave the new type's alerts unreachable for resolution.
var scoreDropAlertTypes = []string{scoreDropAlertType, hygieneScoreDropAlertType}

// alertTypeForFramework routes a framework's score drop onto an alert type.
//
// One detector, two types. Inventory Hygiene is measured by the same score
// rollup as every other framework and drops for the same reasons, so a second
// evaluator would be a copy of this one with a WHERE clause — and the copy is
// what drifts. What differs is only what the drop MEANS: hygiene is data
// quality, not security posture, and a tenant will want to route (and silence)
// the two separately. That is a type, not an evaluator.
func alertTypeForFramework(code string) string {
	if code == hygieneFrameworkCode {
		return hygieneScoreDropAlertType
	}
	return scoreDropAlertType
}

// scoreDropNoun names what kind of score dropped, for the alert a person reads.
// Capitalised at the head of a title, lowercase mid-sentence.
func scoreDropNoun(alertType string, titleCase bool) string {
	if alertType == hygieneScoreDropAlertType {
		if titleCase {
			return "Hygiene"
		}
		return "hygiene"
	}
	if titleCase {
		return "Compliance"
	}
	return "compliance"
}

// isSignificantDrop reports whether the score fell by more than the threshold.
func isSignificantDrop(reference, current, threshold int) bool {
	return reference-current > threshold
}

// ComplianceScoreDropScanJob watches each tenant's per-framework compliance
// score (tenant_framework_scores, which keeps only the current value) and
// raises a fixed medium alert when a framework's score fell by more than 10
// points versus ~24h ago, auto-resolving when it recovers. Because the
// platform persists no score history, the job keeps its own lightweight
// per-(tenant,framework) snapshot trail in alert_framework_score_snapshots.
//
// Consequence: drop detection is only meaningful once the job has been running
// for at least the lookback window (before then there is no 24h-old reference
// and the framework is skipped).
//
// The alert TYPE is per framework (see alertTypeForFramework): Inventory
// Hygiene's drop is `hygiene_score_drop`, every other framework's is
// `compliance_score_drop`. Each framework maps to exactly one type, so a single
// drop can never open two alerts.
type ComplianceScoreDropScanJob struct {
	db           *sqlx.DB
	bypassDB     *sqlx.DB
	catalog      *services.AlertCatalogService
	alertEngine  *services.AlertEngineService
	interval     time.Duration
	initialDelay time.Duration
	stop         chan struct{}
}

func NewComplianceScoreDropScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *ComplianceScoreDropScanJob {
	return &ComplianceScoreDropScanJob{
		db: db, bypassDB: bypassDB, catalog: catalog, alertEngine: alertEngine,
		interval: interval, initialDelay: 3 * time.Minute, stop: make(chan struct{}),
	}
}

func (j *ComplianceScoreDropScanJob) Start() {
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

func (j *ComplianceScoreDropScanJob) Stop() { close(j.stop) }

func (j *ComplianceScoreDropScanJob) ScanAll() {
	tenants, err := j.tenants()
	if err != nil {
		log.Printf("[ScoreDropScan] Tenant listing failed: %v", err)
		return
	}
	for _, tenantID := range tenants {
		if err := j.scanTenant(context.Background(), tenantID); err != nil {
			log.Printf("[ScoreDropScan] Tenant %s scan failed: %v", tenantID, err)
		}
	}
}

func (j *ComplianceScoreDropScanJob) tenants() ([]uuid.UUID, error) {
	rows, err := j.bypassDB.Query(`
		SELECT DISTINCT tenant_id FROM tenant_framework_scores
		UNION
		SELECT DISTINCT tenant_id FROM alerts WHERE alert_type = ANY($1) AND status <> 'resolved'
	`, pq.Array(scoreDropAlertTypes))
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

type frameworkScore struct {
	frameworkID uuid.UUID
	name        string
	code        string
	score       int
}

// alertType is the type this framework's drop is reported as.
func (f frameworkScore) alertType() string { return alertTypeForFramework(f.code) }

func (j *ComplianceScoreDropScanJob) scanTenant(ctx context.Context, tenantID uuid.UUID) error {
	// Both types are gated independently: a tenant who silences hygiene noise
	// must not thereby silence a PCI-DSS score collapse, and vice versa.
	enabled := map[string]bool{}
	for _, at := range scoreDropAlertTypes {
		enabled[at] = j.catalog.IsTypeEnabled(ctx, tenantID, at)
	}
	if !enabled[scoreDropAlertType] && !enabled[hygieneScoreDropAlertType] {
		return nil
	}

	// Current scores for activated frameworks (RLS-scoped read).
	var scores []frameworkScore
	openSubjects := map[uuid.UUID]string{}
	err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, `
			SELECT tfs.platform_framework_id, pf.name, pf.code, tfs.score
			FROM tenant_framework_scores tfs
			JOIN platform_frameworks pf ON pf.id = tfs.platform_framework_id
			JOIN tenant_framework_licenses tfl
			  ON tfl.platform_framework_id = tfs.platform_framework_id AND tfl.tenant_id = tfs.tenant_id
			WHERE tfs.tenant_id = $1
			  -- score is NULLable: a framework with no ASSESSED control
			  -- has no score, so it cannot have dropped. Scanning NULL into an
			  -- int would also fail outright.
			  AND tfs.score IS NOT NULL
			  AND tfl.subscription_status = 'active'
			  AND (tfl.subscription_expires_at IS NULL OR tfl.subscription_expires_at > NOW())
		`, tenantID)
		if qErr != nil {
			return qErr
		}
		for rows.Next() {
			var s frameworkScore
			if err := rows.Scan(&s.frameworkID, &s.name, &s.code, &s.score); err != nil {
				_ = rows.Close()
				return err
			}
			scores = append(scores, s)
		}
		_ = rows.Close()

		// The open alert's OWN type is carried through, not re-derived: a
		// framework that was renamed or re-coded must still be able to resolve
		// the alert it actually opened.
		aRows, aErr := tx.QueryContext(ctx, `
			SELECT subject_id, alert_type FROM alerts
			WHERE tenant_id = $1 AND alert_type = ANY($2) AND status <> 'resolved' AND subject_id IS NOT NULL
		`, tenantID, pq.Array(scoreDropAlertTypes))
		if aErr != nil {
			return aErr
		}
		defer func() { _ = aRows.Close() }()
		for aRows.Next() {
			var sid uuid.UUID
			var at string
			if err := aRows.Scan(&sid, &at); err == nil {
				openSubjects[sid] = at
			}
		}
		return aRows.Err()
	})
	if err != nil {
		return err
	}

	shouldBeOpen := map[uuid.UUID]bool{}
	for _, fs := range scores {
		if !enabled[fs.alertType()] {
			// The snapshot trail is still NOT written for a disabled type: it
			// is this detector's memory, and a tenant re-enabling the type
			// tomorrow should start judging from then rather than from a
			// reference it was not watching.
			continue
		}
		// Record the current score, then compare against the ~24h-old reference.
		if _, err := j.bypassDB.ExecContext(ctx, `
			INSERT INTO alert_framework_score_snapshots (tenant_id, platform_framework_id, score)
			VALUES ($1, $2, $3)
		`, tenantID, fs.frameworkID, fs.score); err != nil {
			log.Printf("[ScoreDropScan] snapshot insert failed (tenant=%s fw=%s): %v", tenantID, fs.frameworkID, err)
			continue
		}

		var reference sql.NullInt64
		if err := j.bypassDB.QueryRowContext(ctx, `
			SELECT score FROM alert_framework_score_snapshots
			WHERE tenant_id = $1 AND platform_framework_id = $2
			  AND captured_at <= NOW() - INTERVAL '`+scoreDropLookback+`'
			ORDER BY captured_at DESC LIMIT 1
		`, tenantID, fs.frameworkID).Scan(&reference); err != nil && err != sql.ErrNoRows {
			log.Printf("[ScoreDropScan] reference lookup failed (tenant=%s fw=%s): %v", tenantID, fs.frameworkID, err)
			continue
		}
		if !reference.Valid {
			continue // no 24h-old reference yet — can't judge a drop
		}

		ref := int(reference.Int64)
		if isSignificantDrop(ref, fs.score, scoreDropThreshold) {
			shouldBeOpen[fs.frameworkID] = true
			j.raise(ctx, tenantID, fs, ref)
		} else {
			j.resolve(ctx, tenantID, fs.alertType(), fs.frameworkID, map[string]interface{}{
				"observed":        scoreDropNoun(fs.alertType(), false) + " score recovered",
				"current_score":   fs.score,
				"reference_score": ref,
				"observed_at":     time.Now().Format(time.RFC3339),
			})
		}
	}

	// Open alerts for frameworks no longer active/scored → resolve.
	for sid, openType := range openSubjects {
		if shouldBeOpen[sid] {
			continue
		}
		// A DISABLED type is not evaluated at all, and that includes its sweep.
		//
		// Before this job served two types, a disabled type returned from
		// scanTenant before reaching here and its open alerts simply stayed
		// open. With two types the function no longer returns early, so without
		// this guard silencing ONE type auto-resolved every open alert of that
		// type — under the observation "framework no longer active or scored",
		// which is not what happened: the framework is still activated and still
		// scored, the tenant just stopped wanting to be told. The work item
		// vanished from Remediation → Alerts with a false reason in its
		// timeline, and re-enabling the type did not bring it back.
		if !enabled[openType] {
			continue
		}
		alreadyHandled := false
		for _, fs := range scores {
			if fs.frameworkID == sid && enabled[fs.alertType()] {
				alreadyHandled = true // resolved/raised in the loop above
				break
			}
		}
		if !alreadyHandled {
			j.resolve(ctx, tenantID, openType, sid, map[string]interface{}{
				"observed":    "framework no longer active or scored",
				"observed_at": time.Now().Format(time.RFC3339),
			})
		}
	}

	// Trim the snapshot trail past the lookback window.
	if _, err := j.bypassDB.ExecContext(ctx, `
		DELETE FROM alert_framework_score_snapshots
		WHERE tenant_id = $1 AND captured_at < NOW() - INTERVAL '`+scoreDropSnapshotPrune+`'
	`, tenantID); err != nil {
		log.Printf("[ScoreDropScan] snapshot prune failed (tenant=%s): %v", tenantID, err)
	}
	return nil
}

func (j *ComplianceScoreDropScanJob) raise(ctx context.Context, tenantID uuid.UUID, fs frameworkScore, reference int) {
	frameworkID := fs.frameworkID
	alertType := fs.alertType()
	drop := reference - fs.score
	title := fmt.Sprintf("%s score dropped: %s", scoreDropNoun(alertType, true), fs.name)
	message := fmt.Sprintf("%s %s score fell from %d to %d (−%d) in the last 24 hours.",
		fs.name, scoreDropNoun(alertType, false), reference, fs.score, drop)
	if _, err := j.alertEngine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenantID,
		AlertType:    alertType,
		Source:       "compliance-engine",
		SubjectType:  "framework",
		SubjectID:    &frameworkID,
		SubjectLabel: fs.name,
		Severity:     "medium",
		Title:        title,
		Message:      message,
		Metadata: map[string]interface{}{
			"framework":       fs.name,
			"framework_id":    fs.frameworkID.String(),
			"framework_code":  fs.code,
			"current_score":   fs.score,
			"reference_score": reference,
			"drop":            drop,
			"threshold":       scoreDropThreshold,
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[ScoreDropScan] Raise failed (fw=%s tenant=%s): %v", fs.frameworkID, tenantID, err)
	}
}

func (j *ComplianceScoreDropScanJob) resolve(ctx context.Context, tenantID uuid.UUID, alertType string, frameworkID uuid.UUID, observation map[string]interface{}) {
	sid := frameworkID
	if err := j.alertEngine.ResolveAuto(ctx, events.AlertResolveEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertType:   alertType,
		SubjectID:   &sid,
		Observation: observation,
		Timestamp:   time.Now(),
	}); err != nil {
		log.Printf("[ScoreDropScan] Auto-resolve failed (fw=%s tenant=%s): %v", frameworkID, tenantID, err)
	}
}
