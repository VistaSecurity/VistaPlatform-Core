package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/alertcatalog"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
)

// FindingsAlertScanJob turns OPEN findings into stateful alerts (ADR-0005 D7,
// workstream 3.9).
//
// Three alert types are driven from here — `known_vulnerability`,
// `end_of_life` and `drift_detected` — because all three answer the same shape
// of question: "which subjects currently have an open finding bad enough to
// tell somebody about, and how bad is the worst one?" The producers already did
// the judging; this job does the telling.
//
// # One alert per SUBJECT, not per finding
//
// The alert's dedupe key is (tenant, alert_type, subject_id), so an asset with
// an end-of-life operating system AND end-of-life hardware gets one alert, at
// the worse of the two rungs, naming both. That is the granularity a person
// acts on: "this machine is past support" is one piece of work, not two. The
// FINDINGS stay separate — they are what the risk rollup, the Findings tab and
// the ticket are keyed on.
//
// # What a rung grades
//
// The rungs here grade the ALERT — how urgently somebody should be told. That
// is a different question from the finding's severity, which grades how much
// risk the condition adds to the asset and is what feeds the risk rollup. The
// two can differ, deliberately: an end-of-life package and an end-of-life
// operating system are the same deadline but not the same blast radius, so the
// findings registry grades them differently while the deadline is the deadline.
//
// The severities and the threshold wording live in
// standards/alert-registry.yaml; the NUMBERS live in this file, for exactly the
// reason the eol producer's ladder gives — `threshold` is free text in the
// detector's own units, and parsing an integer back out of an English sentence
// would make a typo in the YAML a silent change of behaviour.
// TestFindingsAlertLaddersMatchRegistry asserts the two still describe the same
// ladder.
//
// # Raise-on-change
//
// A pass only writes when the alert is NEW or its rung has MOVED. The alert
// engine would dedupe a re-raise into a silent touch anyway, but a touch is
// still an UPDATE per subject per pass, and on a tenant with ten thousand
// vulnerable installs that is ten thousand pointless writes an hour that also
// keep moving `last_event_at` for an alert where nothing happened.
//
// A rung that moved DOWN is a write too. Raise only ever escalates — a
// same-or-lower raise is deduped into a touch — so a partial fix that drops the
// worst CVSS from 9.8 to 5.1, or the resolution of the worst of several
// findings, used to leave the alert displaying the worst grade it ever reached
// for as long as anything remained open. The downward move goes through
// AlertEngineService.Deescalate, which lowers the severity and appends the
// change to the alert's evidence chain without notifying anybody: a pager that
// fires to report good news is a pager that gets muted.
type FindingsAlertScanJob struct {
	db           *sqlx.DB
	bypassDB     *sqlx.DB
	catalog      *services.AlertCatalogService
	alertEngine  *services.AlertEngineService
	interval     time.Duration
	initialDelay time.Duration
	spec         findingsAlertSpec
	stop         chan struct{}
}

// findingsAlertSpec describes one findings-driven alert type. Every string
// field is a compile-time constant supplied by the constructors below.
type findingsAlertSpec struct {
	alertType string   // registry alert_type
	producer  string   // findings producer key
	kinds     []string // the finding kinds this alert type covers
	logTag    string

	// rungFor maps one open finding onto an index into the registry ladder for
	// this alert type, worst-last. ok=false means the finding crosses no rung —
	// it is a real finding, visible on the asset, that does not warrant telling
	// anybody about right now.
	rungFor func(f openFinding) (int, bool)

	// summarize builds the alert's title, message and metadata for one subject.
	summarize func(g subjectGroup, rung alertcatalog.LadderRung) (string, string, map[string]interface{})
}

// NewVulnerabilityAlertScanJob raises `known_vulnerability` from the
// vulnerability producer's findings.
func NewVulnerabilityAlertScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *FindingsAlertScanJob {
	return newFindingsAlertScanJob(db, bypassDB, catalog, alertEngine, interval, findingsAlertSpec{
		alertType: "known_vulnerability",
		producer:  sharedfindings.ProducerVulnerability,
		kinds:     []string{sharedfindings.KindKnownVulnerability},
		logTag:    "VulnerabilityAlertScan",
		rungFor:   vulnerabilityRungFor,
		summarize: summarizeVulnerability,
	})
}

// NewEndOfLifeAlertScanJob raises `end_of_life` from the eol producer's three
// finding kinds.
func NewEndOfLifeAlertScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *FindingsAlertScanJob {
	return newFindingsAlertScanJob(db, bypassDB, catalog, alertEngine, interval, findingsAlertSpec{
		alertType: "end_of_life",
		producer:  sharedfindings.ProducerEOL,
		kinds: []string{
			sharedfindings.KindOSEndOfLife,
			sharedfindings.KindSoftwareEndOfLife,
			sharedfindings.KindHardwareEndOfSupport,
		},
		logTag:    "EndOfLifeAlertScan",
		rungFor:   endOfLifeRungFor,
		summarize: summarizeEndOfLife,
	})
}

// NewDriftAlertScanJob raises `drift_detected` from the drift producer's four
// finding kinds.
func NewDriftAlertScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *FindingsAlertScanJob {
	return newFindingsAlertScanJob(db, bypassDB, catalog, alertEngine, interval, findingsAlertSpec{
		alertType: "drift_detected",
		producer:  sharedfindings.ProducerDrift,
		kinds: []string{
			sharedfindings.KindNewClassInSegment,
			sharedfindings.KindUnexpectedProtocol,
			sharedfindings.KindPortProfileChanged,
			sharedfindings.KindNewIssuer,
		},
		logTag:    "DriftAlertScan",
		rungFor:   driftRungFor,
		summarize: summarizeDrift,
	})
}

func newFindingsAlertScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration, spec findingsAlertSpec) *FindingsAlertScanJob {
	return &FindingsAlertScanJob{
		db: db, bypassDB: bypassDB, catalog: catalog, alertEngine: alertEngine,
		interval: interval, initialDelay: 4 * time.Minute, spec: spec, stop: make(chan struct{}),
	}
}

func (j *FindingsAlertScanJob) Start() {
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

func (j *FindingsAlertScanJob) Stop() { close(j.stop) }

// ScanAll evaluates every tenant. Errors are logged per tenant, never fatal.
func (j *FindingsAlertScanJob) ScanAll() {
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

// tenants lists tenants with an open finding of this type's kinds, OR an open
// alert of this type. The second half is what lets a tenant whose last finding
// just cleared still get its alert auto-resolved.
func (j *FindingsAlertScanJob) tenants() ([]uuid.UUID, error) {
	rows, err := j.bypassDB.Query(`
		SELECT DISTINCT tenant_id FROM findings f
		 WHERE f.producer = $1 AND f.kind = ANY($2) AND `+sharedfindings.OpenSQL("f")+`
		UNION
		SELECT DISTINCT tenant_id FROM alerts WHERE alert_type = $3 AND status <> 'resolved'
	`, j.spec.producer, pq.Array(j.spec.kinds), j.spec.alertType)
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

// openFinding is one row of the producer's currently-open findings.
type openFinding struct {
	id           uuid.UUID
	kind         string
	subjectType  string
	subjectID    uuid.UUID
	subjectLabel string
	severity     string
	score        int
	summary      string
	evidence     map[string]any
}

// subjectGroup is every open finding about one subject, plus the rung the
// worst of them reaches.
type subjectGroup struct {
	subjectType  string
	subjectID    uuid.UUID
	subjectLabel string
	findings     []openFinding

	// rungIndex is the worst rung any of the findings crosses; worst is the
	// finding that set it. Only meaningful when crosses is true.
	rungIndex int
	worst     openFinding
	crosses   bool
}

// openAlert is one currently-open alert of this type.
type openAlert struct {
	subjectID uuid.UUID
	severity  string
}

func (j *FindingsAlertScanJob) scanTenant(ctx context.Context, tenantID uuid.UUID) error {
	if !j.catalog.IsTypeEnabled(ctx, tenantID, j.spec.alertType) {
		return nil
	}

	var found []openFinding
	openAlerts := map[uuid.UUID]openAlert{}
	err := shareddatabase.WithTenantTx(ctx, j.db.DB, tenantID, func(tx *sql.Tx) error {
		// OpenSQL is the generated open-finding predicate spelled as SQL — the
		// SAME definition the query language's `finding:(…)` and the inventory
		// list's `has_findings` facet compile. Writing the two halves out by
		// hand here is exactly how the facet once came to count a different set
		// from the list it led to.
		rows, qErr := tx.QueryContext(ctx, `
			SELECT f.id, f.kind, f.subject_type, f.subject_id, COALESCE(f.subject_label, ''),
			       f.severity, f.score, f.summary, f.evidence
			FROM findings f
			WHERE f.tenant_id = $1 AND f.producer = $2 AND f.kind = ANY($3)
			  AND `+sharedfindings.OpenSQL("f"), tenantID, j.spec.producer, pq.Array(j.spec.kinds))
		if qErr != nil {
			return qErr
		}
		for rows.Next() {
			var f openFinding
			var evidence []byte
			if err := rows.Scan(&f.id, &f.kind, &f.subjectType, &f.subjectID, &f.subjectLabel,
				&f.severity, &f.score, &f.summary, &evidence); err != nil {
				_ = rows.Close()
				return err
			}
			if len(evidence) > 0 {
				// A finding whose evidence will not parse is still a finding.
				// Dropping it here would turn an unreadable detail into a
				// missing alert, which is the worse of the two failures.
				if err := json.Unmarshal(evidence, &f.evidence); err != nil {
					log.Printf("[%s] finding %s has unreadable evidence: %v", j.spec.logTag, f.id, err)
				}
			}
			found = append(found, f)
		}
		_ = rows.Close()

		aRows, aErr := tx.QueryContext(ctx, `
			SELECT subject_id, severity FROM alerts
			WHERE tenant_id = $1 AND alert_type = $2 AND status <> 'resolved' AND subject_id IS NOT NULL
		`, tenantID, j.spec.alertType)
		if aErr != nil {
			return aErr
		}
		defer func() { _ = aRows.Close() }()
		for aRows.Next() {
			var a openAlert
			if err := aRows.Scan(&a.subjectID, &a.severity); err == nil {
				openAlerts[a.subjectID] = a
			}
		}
		return aRows.Err()
	})
	if err != nil {
		return err
	}

	groups := j.group(found)

	// Raise (or escalate) every subject that crosses a rung.
	shouldBeOpen := map[uuid.UUID]bool{}
	for _, g := range groups {
		if !g.crosses {
			continue
		}
		// Marked BEFORE the rung lookup, deliberately: a registry error means
		// this pass cannot say how bad the subject is, which is not the same as
		// saying it is fine. Leaving it out of shouldBeOpen would let the sweep
		// below auto-resolve a live alert on the strength of a lookup failure.
		shouldBeOpen[g.subjectID] = true
		rung, rErr := alertcatalog.FixedRung(j.spec.alertType, g.rungIndex)
		if rErr != nil {
			log.Printf("[%s] rung lookup failed (subject=%s tenant=%s): %v",
				j.spec.logTag, g.subjectID, tenantID, rErr)
			continue
		}
		existing, isOpen := openAlerts[g.subjectID]
		switch {
		case isOpen && severityWorse(existing.severity, rung.Severity):
			// The condition got BETTER without going away — a partial fix
			// dropped the worst CVSS, or the worst of several findings was
			// resolved and a milder one is left. Raise would dedupe this into a
			// silent touch and the alert would keep the worst grade it ever
			// reached, so the downward move is its own call.
			j.deescalate(ctx, tenantID, g, rung, existing.severity)
		case isOpen && !severityWorse(rung.Severity, existing.severity):
			continue // nothing changed — see "Raise-on-change" on the type
		default:
			j.raise(ctx, tenantID, g, rung)
		}
	}

	// Open alerts whose subject no longer crosses a rung → auto-resolve.
	for subjectID := range openAlerts {
		if shouldBeOpen[subjectID] {
			continue
		}
		j.resolve(ctx, tenantID, subjectID, j.resolveObservation(groups, subjectID))
	}
	return nil
}

// group collapses findings onto their subjects and picks the worst rung each
// subject reaches.
//
// Sorted by subject id so a run's raises are in a stable order — which matters
// only for readable logs, but a nondeterministic order is the kind of thing
// that makes a flaky test look like a real bug.
func (j *FindingsAlertScanJob) group(found []openFinding) []subjectGroup {
	bySubject := map[uuid.UUID]*subjectGroup{}
	order := make([]uuid.UUID, 0, len(found))
	for _, f := range found {
		g, ok := bySubject[f.subjectID]
		if !ok {
			g = &subjectGroup{subjectType: f.subjectType, subjectID: f.subjectID, subjectLabel: f.subjectLabel}
			bySubject[f.subjectID] = g
			order = append(order, f.subjectID)
		}
		g.findings = append(g.findings, f)
		if g.subjectLabel == "" {
			g.subjectLabel = f.subjectLabel
		}
		idx, ok := j.spec.rungFor(f)
		if !ok {
			continue
		}
		if !g.crosses || idx > g.rungIndex {
			g.crosses = true
			g.rungIndex = idx
			g.worst = f
		}
	}
	sort.Slice(order, func(a, b int) bool { return order[a].String() < order[b].String() })
	out := make([]subjectGroup, 0, len(order))
	for _, id := range order {
		out = append(out, *bySubject[id])
	}
	return out
}

// resolveObservation says WHY an open alert is being resolved, distinguishing
// the two ways a subject stops crossing a rung. Both are real outcomes and they
// mean different things to the person reading the timeline: "we no longer see
// it" versus "we still see it, it is just no longer urgent".
func (j *FindingsAlertScanJob) resolveObservation(groups []subjectGroup, subjectID uuid.UUID) map[string]interface{} {
	observation := map[string]interface{}{"observed_at": time.Now().Format(time.RFC3339)}
	for _, g := range groups {
		if g.subjectID != subjectID {
			continue
		}
		observation["observed"] = "the condition is no longer severe enough to alert on"
		observation["open_findings"] = len(g.findings)
		return observation
	}
	observation["observed"] = "the condition is no longer detected"
	observation["open_findings"] = 0
	return observation
}

func (j *FindingsAlertScanJob) raise(ctx context.Context, tenantID uuid.UUID, g subjectGroup, rung alertcatalog.LadderRung) {
	subjectID := g.subjectID
	title, message, metadata := j.spec.summarize(g, rung)
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	metadata["rung"] = rung.Threshold
	metadata["finding_ids"] = findingIDs(g)
	metadata["subject_type"] = g.subjectType
	if _, err := j.alertEngine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenantID,
		AlertType:    j.spec.alertType,
		Source:       "compliance-engine",
		SubjectType:  g.subjectType,
		SubjectID:    &subjectID,
		SubjectLabel: g.subjectLabel,
		Severity:     rung.Severity,
		Title:        title,
		Message:      message,
		Metadata:     metadata,
		Timestamp:    time.Now(),
	}); err != nil {
		log.Printf("[%s] Raise failed (subject=%s tenant=%s): %v", j.spec.logTag, g.subjectID, tenantID, err)
	}
}

// deescalate lowers an open alert to a rung that has fallen. The event payload
// is the same shape the raise builds, so the alert's title, message and
// metadata describe the findings that are open NOW rather than the worse ones
// that opened it.
func (j *FindingsAlertScanJob) deescalate(ctx context.Context, tenantID uuid.UUID, g subjectGroup,
	rung alertcatalog.LadderRung, from string) {
	subjectID := g.subjectID
	title, message, metadata := j.spec.summarize(g, rung)
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	metadata["rung"] = rung.Threshold
	metadata["finding_ids"] = findingIDs(g)
	metadata["subject_type"] = g.subjectType
	if _, err := j.alertEngine.Deescalate(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenantID,
		AlertType:    j.spec.alertType,
		Source:       "compliance-engine",
		SubjectType:  g.subjectType,
		SubjectID:    &subjectID,
		SubjectLabel: g.subjectLabel,
		Severity:     rung.Severity,
		Title:        title,
		Message:      message,
		Metadata:     metadata,
		Timestamp:    time.Now(),
	}, map[string]interface{}{
		"observed":      "the worst open finding on this subject is now less severe",
		"from":          from,
		"to":            rung.Severity,
		"rung":          rung.Threshold,
		"open_findings": len(g.findings),
	}); err != nil {
		log.Printf("[%s] De-escalate failed (subject=%s tenant=%s): %v", j.spec.logTag, g.subjectID, tenantID, err)
	}
}

func (j *FindingsAlertScanJob) resolve(ctx context.Context, tenantID, subjectID uuid.UUID, observation map[string]interface{}) {
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

func findingIDs(g subjectGroup) []string {
	out := make([]string, 0, len(g.findings))
	for _, f := range g.findings {
		out = append(out, f.id.String())
	}
	sort.Strings(out)
	return out
}

// severityWorse reports whether a outranks b on the alert severity ladder.
func severityWorse(a, b string) bool {
	return alertcatalog.SeverityRank(a) > alertcatalog.SeverityRank(b)
}

// --- known_vulnerability ----------------------------------------------------

// The CVSS qualitative severity band boundaries, times ten.
//
// `findings.score` for a known_vulnerability finding IS the CVSS base score ×10
// (the findings registry says `score_source: cvss_x10`), so banding it at these
// numbers is the published CVSS v3.1/v4.0 mapping rather than a second opinion
// about it — the same anchor models.RiskBands uses.
const (
	vulnAlertMediumScore   = 40 // CVSS 4.0
	vulnAlertHighScore     = 70 // CVSS 7.0
	vulnAlertCriticalScore = 90 // CVSS 9.0
)

// Rung indices into the known_vulnerability ladder, worst-last.
const (
	vulnRungMedium   = 0
	vulnRungHigh     = 1
	vulnRungCritical = 2
)

// vulnerabilityRungFor picks the rung for one vulnerability finding.
//
// Below CVSS 4.0 — and for an advisory the feed never scored, which the
// producer records at score 0 with `worst_cvss_scored: false` — no rung is
// crossed and no alert opens. That is a decision about NOTIFICATION, not a
// judgement that the finding is harmless: the finding still exists, still shows
// on the asset's Findings tab, and still says "not scored" where it was never
// graded. Opening an alert would be claiming a severity nobody assigned.
func vulnerabilityRungFor(f openFinding) (int, bool) {
	switch {
	case f.score >= vulnAlertCriticalScore:
		return vulnRungCritical, true
	case f.score >= vulnAlertHighScore:
		return vulnRungHigh, true
	case f.score >= vulnAlertMediumScore:
		return vulnRungMedium, true
	}
	return 0, false
}

func summarizeVulnerability(g subjectGroup, rung alertcatalog.LadderRung) (string, string, map[string]interface{}) {
	label := g.subjectLabel
	if label == "" {
		label = "an installed package"
	}
	worstCVE, worstCVSS, cveCount := vulnEvidence(g.worst)

	title := fmt.Sprintf("Vulnerable software: %s", label)
	var message string
	switch {
	case cveCount > 1 && worstCVE != "":
		message = fmt.Sprintf("%s matches %d published advisories; the worst is %s (CVSS %s).",
			label, cveCount, worstCVE, worstCVSS)
	case worstCVE != "":
		message = fmt.Sprintf("%s matches published advisory %s (CVSS %s).", label, worstCVE, worstCVSS)
	default:
		message = fmt.Sprintf("%s matches a published advisory (CVSS %s).", label, worstCVSS)
	}

	meta := map[string]interface{}{
		"worst_cvss_score": float64(g.worst.score) / 10,
		"advisory_count":   cveCount,
	}
	if worstCVE != "" {
		meta["worst_cve"] = worstCVE
	}
	return title, message, meta
}

// vulnEvidence reads the worst CVE id, its score as a display string, and how
// many advisories matched, out of the producer's evidence.
//
// The producer sorts `cves` worst-first and stamps `cve_count`, so this reads
// rather than re-derives. Everything is optional: an evidence document that
// does not carry what is expected yields an alert that names no CVE rather than
// no alert at all.
func vulnEvidence(f openFinding) (cve string, cvss string, count int) {
	cvss = fmt.Sprintf("%.1f", float64(f.score)/10)
	if n, ok := evidenceInt(f.evidence, "cve_count"); ok {
		count = n
	}
	raw, ok := f.evidence["cves"].([]interface{})
	if !ok || len(raw) == 0 {
		return "", cvss, count
	}
	if count == 0 {
		count = len(raw)
	}
	first, ok := raw[0].(map[string]interface{})
	if !ok {
		return "", cvss, count
	}
	if id, ok := first["cve_id"].(string); ok {
		cve = id
	}
	return cve, cvss, count
}

// --- end_of_life ------------------------------------------------------------

// The end-of-life alert ladder, in days remaining (negative means past).
//
// eolAlertWarnDays is 180 rather than 90 so the ladder has somewhere to start
// for HARDWARE, whose finding opens 180 days out (replacing a chassis takes a
// purchase order and a rack visit). An operating system or a package has no
// finding until 90 days out, so for those the first rung a subject can actually
// reach is the 90-day one — which is the Lifecycle framework's planning window,
// and is stated in the registry description rather than left to be discovered.
const (
	eolAlertWarnDays     = 180
	eolAlertNearDays     = 90
	eolAlertLongPastDays = 365
)

// Rung indices into the end_of_life ladder, worst-last.
const (
	eolRungApproaching = 0
	eolRungNear        = 1
	eolRungPast        = 2
	eolRungLongPast    = 3
)

// endOfLifeRungFor picks the rung for one end-of-life finding from the days
// remaining the producer recorded in its evidence.
//
// The day the end-of-life date falls is still supported — a product goes out of
// support at the END of its end-of-life date — so `days >= 0` is "approaching"
// and only a negative count is "past". Same convention as the producer's own
// ladder, deliberately: an alert that said "past" a day before the finding did
// would be the two-opinions bug in miniature.
//
// When the evidence carries no day count the finding's OWN severity picks the
// rung. That is not a guess: the producer graded the same condition, and the
// alert ladder's four severities are exactly the four the eol finding kinds
// use, so the mapping is a lookup rather than an invention. A finding that
// yields neither opens no alert.
func endOfLifeRungFor(f openFinding) (int, bool) {
	days, ok := evidenceInt(f.evidence, "days_remaining")
	if !ok {
		return eolRungForSeverity(f.severity)
	}
	switch {
	case days < -eolAlertLongPastDays:
		return eolRungLongPast, true
	case days < 0:
		return eolRungPast, true
	case days <= eolAlertNearDays:
		return eolRungNear, true
	case days <= eolAlertWarnDays:
		return eolRungApproaching, true
	}
	return 0, false
}

// eolRungForSeverity finds the rung carrying a severity, for the fallback above.
func eolRungForSeverity(severity string) (int, bool) {
	entry, ok := alertcatalog.Get("end_of_life")
	if !ok {
		return 0, false
	}
	for i, r := range entry.Rungs {
		if r.Severity == severity {
			return i, true
		}
	}
	return 0, false
}

func summarizeEndOfLife(g subjectGroup, rung alertcatalog.LadderRung) (string, string, map[string]interface{}) {
	label := g.subjectLabel
	if label == "" {
		label = "an inventory subject"
	}
	days, hasDays := evidenceInt(g.worst.evidence, "days_remaining")

	title := fmt.Sprintf("Approaching end of life: %s", label)
	if hasDays && days < 0 {
		title = fmt.Sprintf("Past end of life: %s", label)
	}

	what := eolWhat(g)
	var message string
	switch {
	case hasDays && days < 0:
		message = fmt.Sprintf("%s: %s went out of support %s.", label, what, eolAlertDetail(days))
	case hasDays:
		message = fmt.Sprintf("%s: %s goes out of support %s.", label, what, eolAlertDetail(days))
	default:
		message = fmt.Sprintf("%s: %s is at or past its vendor end-of-life date.", label, what)
	}
	if len(g.findings) > 1 {
		message += fmt.Sprintf(" %d end-of-life findings are open on this subject.", len(g.findings))
	}

	meta := map[string]interface{}{
		"finding_kinds":  distinctKinds(g),
		"worst_kind":     g.worst.kind,
		"open_findings":  len(g.findings),
		"worst_severity": g.worst.severity,
	}
	if hasDays {
		meta["days_remaining"] = days
	}
	if date, ok := g.worst.evidence["eol_date"].(string); ok && date != "" {
		meta["eol_date"] = date
	}
	if product, ok := g.worst.evidence["catalogue_product"].(string); ok && product != "" {
		meta["catalogue_product"] = product
	}
	return title, message, meta
}

// eolWhat names what is going out of support, in a person's words.
func eolWhat(g subjectGroup) string {
	switch g.worst.kind {
	case sharedfindings.KindOSEndOfLife:
		return "its operating system"
	case sharedfindings.KindHardwareEndOfSupport:
		return "its hardware"
	case sharedfindings.KindSoftwareEndOfLife:
		return "this package"
	default:
		return "it"
	}
}

// distinctKinds lists the distinct finding kinds open on one subject, sorted.
func distinctKinds(g subjectGroup) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(g.findings))
	for _, f := range g.findings {
		if seen[f.kind] {
			continue
		}
		seen[f.kind] = true
		out = append(out, f.kind)
	}
	sort.Strings(out)
	return out
}

// eolAlertDetail phrases a day count as a date relationship, matching the
// producer's own wording so the alert and the finding read the same way.
func eolAlertDetail(days int) string {
	switch {
	case days > 1:
		return fmt.Sprintf("in %d days", days)
	case days == 1:
		return "tomorrow"
	case days == 0:
		return "today"
	case days == -1:
		return "1 day ago"
	default:
		return fmt.Sprintf("%d days ago", -days)
	}
}

// --- drift_detected ----------------------------------------------------------

// driftRungFor picks the rung for one drift finding from the finding's OWN
// severity.
//
// Drift has no second scale to grade on. A vulnerability has a CVSS and an
// end-of-life date has a countdown, so for those the alert ladder is a
// judgement the producer did not make. A drift finding has neither: the
// findings registry fixes a severity per kind (a changed listening-port profile
// is low, a new issuer is medium), and that judgement is the only one there is.
// Re-deriving it here would be the two-opinions bug — so the rung IS the
// severity, looked up in the registry ladder rather than mapped through a table
// written out a second time.
//
// A severity the ladder does not carry yields no rung, which means no alert and
// no de-escalation of one already open. That is a corrupt row (every drift kind
// has a fixed registry severity), and opening an alert at a rung nobody chose
// would be inventing the grade this function exists not to invent.
// TestDriftLadderCoversEveryDriftKind fails if a new drift kind is registered
// with a severity the ladder cannot express.
func driftRungFor(f openFinding) (int, bool) {
	entry, ok := alertcatalog.Get("drift_detected")
	if !ok {
		return 0, false
	}
	for i, r := range entry.Rungs {
		if r.Severity == f.severity {
			return i, true
		}
	}
	return 0, false
}

func summarizeDrift(g subjectGroup, _ alertcatalog.LadderRung) (string, string, map[string]interface{}) {
	label := g.subjectLabel
	if label == "" {
		label = "an inventory subject"
	}

	title := fmt.Sprintf("Changed since baseline: %s", label)
	// The producer already rendered the registry's title_template into the
	// finding's summary ("web-01 started speaking telnet"), so the alert says
	// what the finding says rather than paraphrasing it into a second wording
	// the user then has to reconcile with the Findings tab.
	message := g.worst.summary
	if message == "" {
		message = fmt.Sprintf("%s differs from its recent baseline.", label)
	}
	if len(g.findings) > 1 {
		message += fmt.Sprintf(" %d drift findings are open on this subject.", len(g.findings))
	}

	meta := map[string]interface{}{
		"finding_kinds":  distinctKinds(g),
		"worst_kind":     g.worst.kind,
		"open_findings":  len(g.findings),
		"worst_severity": g.worst.severity,
	}
	// The baseline window the judgement was made under. A drift finding read
	// three weeks later is unreadable without it, and the tenant may have
	// changed the window since — so it travels on the alert too.
	if days, ok := evidenceInt(g.worst.evidence, "window_days"); ok {
		meta["window_days"] = days
	}
	return title, message, meta
}

// --- evidence helpers -------------------------------------------------------

// evidenceInt reads an integer out of a decoded JSON evidence document.
//
// ok=false means the key is absent or is not a number. It is deliberately NOT
// "absent means zero": zero days remaining is a real and important answer (the
// end-of-life date is today), and collapsing the two would make a missing
// measurement look like a deadline that just arrived.
func evidenceInt(evidence map[string]any, key string) (int, bool) {
	if evidence == nil {
		return 0, false
	}
	switch v := evidence[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	case string:
		// Never produced by the current writers; tolerated because a number
		// that arrived as a string is still an answer, and refusing it would
		// lose an alert over a serialisation detail.
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
