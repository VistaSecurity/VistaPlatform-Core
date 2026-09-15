package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
)

var ErrFindingNotFound = errors.New("finding not found")

// sqlExecutor is satisfied by both *sql.Tx and *sqlx.DB, letting
// recordFindingHistory write to compliance_finding_history either inside a
// tenant-scoped transaction (passed the tx) or standalone (passed s.db).
type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// FindingsService handles finding assignments, ticket management, and event-driven finding generation.
//
// bypassDB is the BYPASSRLS handle (crypto_bypass) used only by the deliberately
// cross-tenant sweep AutoCloseInactiveFindings (Phase 4); every tenant-scoped path
// keeps using db (crypto_app, subject to RLS) via WithTenantTx.
type FindingsService struct {
	db                      *sqlx.DB
	bypassDB                *sqlx.DB
	ruleEvaluator           *RuleEvaluator
	frameworkLicenseService *FrameworkLicenseService
	evaluationService       *EvaluationService
	metricsService          *MetricsService

	// coalescer debounces whole-tenant reconciles (see tenantCoalescer). Nil is valid
	// and degrades to running every request inline.
	coalescer *tenantCoalescer
}

// NewFindingsService creates a new findings service
func NewFindingsService(db, bypassDB *sqlx.DB, ruleEvaluator *RuleEvaluator, frameworkLicenseService *FrameworkLicenseService, evaluationService *EvaluationService, metricsService *MetricsService) *FindingsService {
	return &FindingsService{
		db:                      db,
		bypassDB:                bypassDB,
		ruleEvaluator:           ruleEvaluator,
		frameworkLicenseService: frameworkLicenseService,
		evaluationService:       evaluationService,
		metricsService:          metricsService,
		coalescer:               newTenantCoalescer(),
	}
}

func licensedFindingExistsInTx(ctx context.Context, tx *sql.Tx, tenantID, findingID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM findings cf
			WHERE cf.id = $1 AND cf.tenant_id = $2
			  AND ` + complianceProducerScope("cf") + `
			  AND ` + licensedFindingScopeSQL("cf", "$2") + `
		)
	`
	if err := tx.QueryRowContext(ctx, query, findingID, tenantID).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// ReconcileTenantCoalesced runs a whole-tenant reconcile (or a framework-scoped one when
// frameworkID is non-nil) through the per-tenant coalescer, so a burst of requests for
// the same tenant collapses into one in-flight pass plus a follow-up. Returns
// coalesced=true (and a nil summary) when the request was absorbed by a run already in
// flight — that is a success, not a skip: the in-flight runner re-checks and covers it.
func (s *FindingsService) ReconcileTenantCoalesced(ctx context.Context, tenantID, frameworkID uuid.UUID) (*EvaluationSummary, bool, error) {
	key := tenantID.String()
	if frameworkID != uuid.Nil {
		key += "/" + frameworkID.String()
	}

	var summary *EvaluationSummary
	_, coalesced, err := s.coalescer.Run(key, func() error {
		var runErr error
		if frameworkID != uuid.Nil {
			summary, runErr = s.EvaluateTenantFrameworkScoped(ctx, tenantID, frameworkID)
		} else {
			summary, runErr = s.EvaluateTenantFrameworks(ctx, tenantID)
		}
		return runErr
	})
	if err != nil {
		return nil, false, err
	}
	if coalesced {
		return nil, true, nil
	}
	return summary, false, nil
}

// AssignFindingOwner assigns a user to a finding
func (s *FindingsService) AssignFindingOwner(tenantID, findingID, assignedTo, assignedBy uuid.UUID, notes *string) error {
	now := time.Now()
	query := `
		UPDATE findings
		SET assigned_to = $1, assigned_at = $2, assigned_by = $3, remediation_notes = $4, updated_at = $5
		WHERE id = $6 AND tenant_id = $7
		  AND ` + complianceProducerScope("findings") + `
	`
	ctx := context.Background()
	return shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		visible, err := licensedFindingExistsInTx(ctx, tx, tenantID, findingID)
		if err != nil {
			return fmt.Errorf("failed to check finding: %w", err)
		}
		if !visible {
			return ErrFindingNotFound
		}
		res, err := tx.ExecContext(ctx, query, assignedTo, now, assignedBy, notes, now, findingID, tenantID)
		if err != nil {
			return fmt.Errorf("failed to assign finding owner: %w", err)
		}
		if rows, err := res.RowsAffected(); err != nil {
			return err
		} else if rows == 0 {
			return ErrFindingNotFound
		}
		return nil
	})
}

// UnassignFindingOwner removes assignment from a finding
func (s *FindingsService) UnassignFindingOwner(tenantID, findingID uuid.UUID) error {
	query := `
		UPDATE findings
		SET assigned_to = NULL, assigned_at = NULL, assigned_by = NULL, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
		  AND ` + complianceProducerScope("findings") + `
	`
	ctx := context.Background()
	return shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		visible, err := licensedFindingExistsInTx(ctx, tx, tenantID, findingID)
		if err != nil {
			return fmt.Errorf("failed to check finding: %w", err)
		}
		if !visible {
			return ErrFindingNotFound
		}
		res, err := tx.ExecContext(ctx, query, findingID, tenantID)
		if err != nil {
			return fmt.Errorf("failed to unassign finding owner: %w", err)
		}
		if rows, err := res.RowsAffected(); err != nil {
			return err
		} else if rows == 0 {
			return ErrFindingNotFound
		}
		return nil
	})
}

// GetFinding retrieves a finding by ID
func (s *FindingsService) GetFinding(tenantID, findingID uuid.UUID) (*models.ComplianceFinding, error) {
	// Scan manually to handle the JSONB evidence field — sqlx's Get cannot
	// scan JSONB into map[string]interface{} (same reason GetFindingsByAsset
	// scans manually).
	query := `
		SELECT id, tenant_id, producer, kind, control_id, subject_id, subject_type,
		       subject_label, severity, score, summary, evidence,
		       first_seen, last_seen, assigned_to, assigned_at, assigned_by, remediation_notes,
		       detection_state, workflow_status, occurrence_count, resurfaced_at,
		       suppressed_until, suppression_reason, is_stale, last_evaluated_at,
		       evaluation_version, created_at, updated_at
		FROM findings cf
		WHERE cf.id = $1 AND cf.tenant_id = $2
		  AND ` + complianceProducerScope("cf") + `
		  AND ` + licensedFindingScopeSQL("cf", "$2") + `
	`
	var finding models.ComplianceFinding
	var evidenceJSONB []byte
	var assignedTo, assignedBy, remediationNotes, suppressionReason, subjectLabel sql.NullString
	var assignedAt, resurfacedAt, suppressedUntil, lastEvaluatedAt sql.NullTime
	// NullUUID, like every other finding reader. `control_id` is NULLable —
	// findings_control_id_compliance_only_check makes it compliance-ONLY, not
	// compliance-ALWAYS — so scanning straight into uuid.UUID turns a row this
	// producer could legitimately write into a scan error, which the handler
	// would report as a failed request rather than as the finding it is.
	var controlID uuid.NullUUID

	var notFound bool
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(context.Background(), query, findingID, tenantID).Scan(
			&finding.ID, &finding.TenantID, &finding.Producer, &finding.Kind,
			&controlID, &finding.SubjectID, &finding.SubjectType, &subjectLabel,
			&finding.Severity, &finding.Score, &finding.Summary, &evidenceJSONB,
			&finding.FirstSeen, &finding.LastSeen, &assignedTo, &assignedAt,
			&assignedBy, &remediationNotes, &finding.DetectionState,
			&finding.WorkflowStatus, &finding.OccurrenceCount, &resurfacedAt,
			&suppressedUntil, &suppressionReason, &finding.IsStale,
			&lastEvaluatedAt, &finding.EvaluationVersion,
			&finding.CreatedAt, &finding.UpdatedAt,
		)
		if scanErr == sql.ErrNoRows {
			notFound = true
			return nil
		}
		return scanErr
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get finding: %w", err)
	}
	if notFound {
		return nil, ErrFindingNotFound
	}

	finding.Evidence = make(map[string]interface{})
	if len(evidenceJSONB) > 0 {
		if err := json.Unmarshal(evidenceJSONB, &finding.Evidence); err != nil {
			finding.Evidence = make(map[string]interface{})
		}
	}
	if assignedTo.Valid {
		if parsedID, err := uuid.Parse(assignedTo.String); err == nil {
			finding.AssignedTo = &parsedID
		}
	}
	if assignedBy.Valid {
		if parsedID, err := uuid.Parse(assignedBy.String); err == nil {
			finding.AssignedBy = &parsedID
		}
	}
	if assignedAt.Valid {
		finding.AssignedAt = &assignedAt.Time
	}
	if resurfacedAt.Valid {
		finding.ResurfacedAt = &resurfacedAt.Time
	}
	if suppressedUntil.Valid {
		finding.SuppressedUntil = &suppressedUntil.Time
	}
	if suppressionReason.Valid {
		finding.SuppressionReason = &suppressionReason.String
	}
	if remediationNotes.Valid {
		finding.RemediationNotes = &remediationNotes.String
	}
	if lastEvaluatedAt.Valid {
		finding.LastEvaluatedAt = &lastEvaluatedAt.Time
	}
	if subjectLabel.Valid {
		finding.SubjectLabel = &subjectLabel.String
	}
	if controlID.Valid {
		finding.ControlID = controlID.UUID
	}

	// Get ticket count
	ticketCount, _ := s.GetTicketCountForFinding(tenantID, findingID)
	finding.TicketCount = ticketCount

	return &finding, nil
}

// GetTicketCountForFinding returns the number of tickets for a finding.
func (s *FindingsService) GetTicketCountForFinding(tenantID, findingID uuid.UUID) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM tickets WHERE finding_id = $1 AND tenant_id = $2`
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), query, findingID, tenantID).Scan(&count)
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetFindingsByAsset returns the OPEN findings on one asset, from EVERY
// producer — the read behind the asset page's Findings tab.
//
// Two things changed with workstream 3.1 and both are visible in the product.
//
// All producers, not just compliance. The tab used to say "showing
// cryptographic findings" because there was nothing else to show; the table it
// reads is now the one every producer writes, so the answer is no longer
// scoped by who happened to be asking. Only `compliance` writes today, and the
// tab says which producers have actually looked rather than implying the list
// is complete.
//
// The asset AND its descendants, resolved by findings.AssetSubjects — the same
// five paths the query language's `finding:(…)` walks. Most findings are on a
// certificate or a crypto configuration, so the asset-only reading (which is
// what `WHERE asset_id = $2` was) returned almost nothing.
//
// The licence gate applies to compliance rows only. It asks whether a finding's
// CONTROL belongs to a framework the tenant activated, and a finding with no
// control — every other producer's — has no such question to answer. Applying
// it unconditionally would have hidden every EOL and vulnerability finding the
// moment those producers ship, which is failure-by-omission in a security view.
func (s *FindingsService) GetFindingsByAsset(tenantID, assetID uuid.UUID) ([]models.ComplianceFinding, error) {
	subjects := sharedfindings.AssetSubjectClause("cf", "a", newAliasCounter(), quoteSubjectType)
	query := `
		SELECT cf.id, cf.tenant_id, cf.producer, cf.kind, cf.control_id,
		       cf.subject_id, cf.subject_type, cf.subject_label,
		       cf.severity, cf.score, cf.summary, cf.evidence,
		       cf.first_seen, cf.last_seen, cf.assigned_to, cf.assigned_at, cf.assigned_by,
		       cf.remediation_notes, cf.detection_state, cf.workflow_status,
		       cf.occurrence_count, cf.resurfaced_at, cf.suppressed_until, cf.suppression_reason,
		       cf.is_stale, cf.last_evaluated_at, cf.evaluation_version,
		       cf.created_at, cf.updated_at
		FROM findings cf
		-- A one-row inline relation, NOT a join to the assets table. The subject
		-- paths correlate to a.id and that is all they need; requiring the asset
		-- ROW to exist would make a finding vanish from the page the moment its
		-- asset was archived or hard-deleted, which is exactly when somebody is
		-- most likely to be looking for it.
		CROSS JOIN (SELECT $2::uuid AS id) a
		WHERE cf.tenant_id = $1
		  AND (` + subjects + `)
		  AND ` + sharedfindings.OpenSQL("cf") + `
		  AND (cf.producer <> '` + sharedfindings.ProducerCompliance + `' OR ` + licensedFindingScopeSQL("cf", "$1") + `)
		ORDER BY ` + severityRankSQL("cf.severity") + ` DESC, cf.last_seen DESC
	`
	// Scan manually to handle JSONB evidence field
	var results []models.ComplianceFinding
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(context.Background(), query, tenantID, assetID)
		if err != nil {
			return fmt.Errorf("failed to query findings by asset: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var finding models.ComplianceFinding
			var evidenceJSONB []byte
			var assignedTo, assignedBy, remediationNotes, suppressionReason, subjectLabel sql.NullString
			var assignedAt, resurfacedAt, suppressedUntil, lastEvaluatedAt sql.NullTime
			var controlID uuid.NullUUID

			err := rows.Scan(
				&finding.ID, &finding.TenantID, &finding.Producer, &finding.Kind, &controlID,
				&finding.SubjectID, &finding.SubjectType, &subjectLabel,
				&finding.Severity, &finding.Score, &finding.Summary, &evidenceJSONB,
				&finding.FirstSeen, &finding.LastSeen, &assignedTo, &assignedAt,
				&assignedBy, &remediationNotes, &finding.DetectionState,
				&finding.WorkflowStatus, &finding.OccurrenceCount, &resurfacedAt,
				&suppressedUntil, &suppressionReason, &finding.IsStale,
				&lastEvaluatedAt, &finding.EvaluationVersion,
				&finding.CreatedAt, &finding.UpdatedAt,
			)
			if err != nil {
				return fmt.Errorf("failed to scan finding: %w", err)
			}
			if controlID.Valid {
				finding.ControlID = controlID.UUID
			}
			if subjectLabel.Valid {
				finding.SubjectLabel = &subjectLabel.String
			}

			// Unmarshal evidence JSONB
			if len(evidenceJSONB) > 0 {
				finding.Evidence = make(map[string]interface{})
				if err := json.Unmarshal(evidenceJSONB, &finding.Evidence); err != nil {
					finding.Evidence = make(map[string]interface{})
				}
			} else {
				finding.Evidence = make(map[string]interface{})
			}

			// Handle nullable fields
			if assignedTo.Valid {
				parsedID, err := uuid.Parse(assignedTo.String)
				if err == nil {
					finding.AssignedTo = &parsedID
				}
			}
			if assignedBy.Valid {
				parsedID, err := uuid.Parse(assignedBy.String)
				if err == nil {
					finding.AssignedBy = &parsedID
				}
			}
			if assignedAt.Valid {
				finding.AssignedAt = &assignedAt.Time
			}
			if resurfacedAt.Valid {
				finding.ResurfacedAt = &resurfacedAt.Time
			}
			if suppressedUntil.Valid {
				finding.SuppressedUntil = &suppressedUntil.Time
			}
			if suppressionReason.Valid {
				finding.SuppressionReason = &suppressionReason.String
			}
			if remediationNotes.Valid {
				finding.RemediationNotes = &remediationNotes.String
			}
			if lastEvaluatedAt.Valid {
				finding.LastEvaluatedAt = &lastEvaluatedAt.Time
			}

			results = append(results, finding)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	// Get ticket counts for each finding
	for i := range results {
		ticketCount, _ := s.GetTicketCountForFinding(tenantID, results[i].ID)
		results[i].TicketCount = ticketCount
	}

	return results, nil
}

// FindingListFilters narrows ListFindings. Zero values mean "no filter".
type FindingListFilters struct {
	WorkflowStatus string     // NEW / NOTIFIED / RESOLVED / SUPPRESSED (case-insensitive)
	Severity       string     // info / low / medium / high / critical (any spelling; normalized)
	AssignedTo     *uuid.UUID // findings assigned to this user
	Unassigned     bool       // findings with no assignee (ignored when AssignedTo is set)
	// Producer is a registry producer key — `eol`, `vulnerability`,
	// `compliance`, … Empty means EVERY producer, which is this page's default.
	// The handler validates it against the generated registry, so a typo is a
	// 400 rather than an empty page that reads as "nothing wrong".
	Producer    string
	ControlID   *uuid.UUID
	FrameworkID *uuid.UUID // platform or tenant framework — matched through its controls
	// SubjectType / SubjectID narrow to findings about ONE thing — the software
	// install behind a "3 vulnerabilities" cell, the certificate behind an
	// expiry badge. Both or neither: a subject id with no type would match a
	// uuid that happens to collide across two subject vocabularies, and a type
	// with no id is the producer filter spelled worse.
	//
	// This is what makes a count in a table clickable. Without it the caller
	// has to page the whole findings stream and filter client-side, which is
	// capped — so a subject past the cap renders "3 vulnerabilities" linking to
	// an empty page, which is the "reads as applied and is not" failure the
	// producer filter is refused for.
	SubjectType string
	SubjectID   *uuid.UUID
	// Search is the free-text term the Findings page's search box sends.
	//
	// SERVER-side, and that is the whole point of it existing. The page pages
	// the stream to a cap (five pages of 200) and used to narrow it in the
	// browser, so searching for a product installed on the 1,200th finding
	// returned nothing and looked exactly like "no findings match" — the
	// page-capped equivalent of a filter that reads as applied and is not.
	//
	// Matched against what the row itself RENDERS: the summary, the subject
	// label, the kind with its underscores opened out (which is precisely what
	// the client's `kindLabel` prints, so typing what is on screen matches it),
	// and the host in the row's context line. Nothing more — searching a field
	// nobody can see makes an empty result unexplainable, and searching one the
	// row does not show makes a HIT unexplainable, which is worse.
	Search string
}

// findingSearchPattern turns a typed term into a LIKE pattern, or "" when
// there is nothing to search for.
//
// The wildcards are ESCAPED. Without that, a term containing `%` — which a
// person searching for "99% CPU" or pasting a URL-encoded string will type —
// matches every row while reading on screen as a narrowing search, and `_`
// quietly matches any single character. Postgres's default LIKE escape is the
// backslash, so the backslash itself has to be escaped first; doing it in one
// pass (rather than three chained replaces) is what keeps that true.
func findingSearchPattern(term string) string {
	trimmed := strings.TrimSpace(term)
	if trimmed == "" {
		return ""
	}
	var b strings.Builder
	b.WriteByte('%')
	for _, r := range trimmed {
		if r == '\\' || r == '%' || r == '_' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('%')
	return b.String()
}

// findingListWhere builds the WHERE shared by ListFindings and
// CountFindingsByProducer, so the page and the numbers above it cannot describe
// different sets. (The `has_findings` facet was withdrawn in Gate 1 for exactly
// that divergence — two hand-written expressions over two tables.)
//
// includeProducer is false for the per-producer tally: the counts have to show
// every producer's number, including the ones the active chip filters out, or
// each chip would report only the count of itself.
func findingListWhere(tenantID uuid.UUID, filters FindingListFilters, includeProducer bool) ([]string, []interface{}, int) {
	// The framework licence gate applies to COMPLIANCE rows only.
	//
	// It asks whether a finding's CONTROL belongs to a framework the tenant
	// activated, and a finding with no control — every other producer's — has
	// no such question to answer. Applied unconditionally (which is what it
	// was while this read was compliance-scoped) it would hide every
	// end-of-life and vulnerability finding behind a framework subscription:
	// failure-by-omission in a security view. GetFindingsByAsset has been
	// written this way since; this is the org-wide page catching up.
	where := []string{"cf.tenant_id = $1", "cf.detection_state = 'ACTIVE'",
		"(" + nonComplianceProducerScope("cf") + " OR " + licensedFindingScopeSQL("cf", "$1") + ")"}
	args := []interface{}{tenantID}
	idx := 2
	if includeProducer && filters.Producer != "" {
		where = append(where, fmt.Sprintf("cf.producer = $%d", idx))
		args = append(args, filters.Producer)
		idx++
	}
	if filters.WorkflowStatus != "" {
		where = append(where, fmt.Sprintf("UPPER(cf.workflow_status) = UPPER($%d)", idx))
		args = append(args, filters.WorkflowStatus)
		idx++
	}
	if filters.Severity != "" {
		// normalizeSeverity, not a LOWER() comparison: `medium`, `med` and
		// `Medium` all name one rung of the registry ladder, and a caller that
		// still says `Med` (the old compliance_findings spelling) must get the
		// rows rather than an empty page.
		where = append(where, fmt.Sprintf("cf.severity = $%d", idx))
		args = append(args, normalizeSeverity(filters.Severity))
		idx++
	}
	if filters.AssignedTo != nil {
		where = append(where, fmt.Sprintf("cf.assigned_to = $%d", idx))
		args = append(args, *filters.AssignedTo)
		idx++
	} else if filters.Unassigned {
		where = append(where, "cf.assigned_to IS NULL")
	}
	// control_id and framework_id are COMPLIANCE-shaped filters, and they narrow
	// to compliance rows by construction: every other producer leaves
	// `control_id` NULL (findings_control_id_compliance_only_check), so
	// `cf.control_id = $n` and the framework EXISTS match nothing else. Said
	// here rather than left to be rediscovered — on a page that now lists
	// end-of-life findings, picking a framework drops them, and that is the
	// filter meaning what it says rather than a bug.
	if filters.ControlID != nil {
		where = append(where, fmt.Sprintf("cf.control_id = $%d", idx))
		args = append(args, *filters.ControlID)
		idx++
	}
	// The subject pair. Indexed by findings_subject_idx
	// (tenant_id, subject_type, subject_id), so this is a lookup rather than a
	// scan however many findings the tenant has.
	if filters.SubjectType != "" && filters.SubjectID != nil {
		where = append(where, fmt.Sprintf("cf.subject_type = $%d AND cf.subject_id = $%d", idx, idx+1))
		args = append(args, filters.SubjectType, *filters.SubjectID)
		idx += 2
	}
	// Free text. One placeholder used four times rather than four copies of
	// the same argument — the pattern is identical and repeating it would leave
	// four places for a future edit to change three of.
	//
	// The last arm is the HOST, and it is an EXISTS rather than a column of the
	// page query's join. That is what lets it live here, in the WHERE all three
	// queries share: a predicate over `na.hostname` would only be legal in the
	// page query, and the COUNT that pages this list runs without the joins, so
	// the total and the rows would describe different sets. As an EXISTS it is
	// self-contained and cannot fan a row out, so COUNT(*) still counts
	// findings.
	//
	// It has to be searchable. made a software_install finding render its
	// PACKAGE as the title and the host as a context line underneath, on the
	// grounds that nine end-of-life packages on one machine must not be nine
	// identical rows — and a row whose host is on screen but unsearchable makes
	// an empty result unexplainable. The hostname is the most natural thing to
	// type on this page.
	if term := findingSearchPattern(filters.Search); term != "" {
		where = append(where, fmt.Sprintf(`(
			cf.summary ILIKE $%d
			OR cf.subject_label ILIKE $%d
			OR replace(cf.kind, '_', ' ') ILIKE $%d
			OR (cf.subject_type IN ('asset', 'software_install') AND EXISTS (
				SELECT 1 FROM assets ha
				 WHERE ha.tenant_id = cf.tenant_id
				   AND ha.id = coalesce(
				         (SELECT si.asset_id FROM software_installs si
				           WHERE si.tenant_id = cf.tenant_id AND si.id = cf.subject_id),
				         cf.subject_id)
				   AND ha.deleted_at IS NULL
				   AND ha.hostname ILIKE $%d))
		)`, idx, idx, idx, idx))
		args = append(args, term)
		idx++
	}
	if filters.FrameworkID != nil {
		where = append(where, fmt.Sprintf(`(
			EXISTS (SELECT 1 FROM platform_framework_controls pfc WHERE pfc.id = cf.control_id AND pfc.framework_id = $%d)
			OR EXISTS (SELECT 1 FROM tenant_framework_controls tfc WHERE tfc.id = cf.control_id AND tfc.framework_id = $%d)
		)`, idx, idx))
		args = append(args, *filters.FrameworkID)
		idx++
	}
	return where, args, idx
}

// ListFindings returns a page of the tenant's ACTIVE findings from EVERY
// producer, newest-seen first, with the subject's display object joined
// (). Suppressed findings are included (unlike GetFindingsByAsset) so
// a triage surface can show and un-suppress them; narrow with the
// WorkflowStatus filter when they aren't wanted.
//
// Every producer, not just `compliance`. This read carried
// complianceProducerScope until the `eol` and `vulnerability` producers
// shipped, at which point Risk & Compliance → Findings would have become the
// one surface in the product that silently omitted them — the asset page's
// Findings tab, the query language and the `has_findings` facet all show them.
// Narrow with the Producer filter; the per-producer tally is
// CountFindingsByProducer.
func (s *FindingsService) ListFindings(tenantID uuid.UUID, filters FindingListFilters, page, pageSize int) ([]models.ComplianceFinding, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}

	where, args, idx := findingListWhere(tenantID, filters, true)
	whereSQL := strings.Join(where, " AND ")

	var total int
	countQuery := "SELECT COUNT(*) FROM findings cf WHERE " + whereSQL
	// Snapshot the filter args before LIMIT/OFFSET are appended for the page query.
	countArgs := append([]interface{}(nil), args...)

	// Scan manually to handle the JSONB evidence field (same as the other
	// finding readers). The asset join is display-only: hostname/IP/port/
	// environment for rendering a row without an N+1 per-asset fetch.
	//
	// cf.subject_id is NOT always an `assets` id — this producer's subject_type
	// is asset or certificate, and about 3 in 4 findings on a live tenant are
	// the certificate kind (v0.5.7 live QA: 15 of 19). Without the certificate
	// join a certificate-scoped finding resolved to no asset at all and the UI
	// fell back to rendering the raw UUID (H-9b).
	//
	// `asset` here is the FINDING's subject kind, a value of findings.subject_type
	// in the registry's vocabulary. The joined object's own `asset_type` field, by
	// contrast, is the asset's class key (assets.class_key): the `asset_type` ENUM
	// is gone.
	//   - asset: join assets directly. This covers configuration measurements
	//     too — their subject IS the asset (see findings_sql.go), and the
	//     configurations they were taken over are in
	//     evidence.crypto_implementation_ids rather than in this join.
	//   - certificate: join certificates directly, display common_name (fallback
	//     subject_dn) as DisplayName. A certificate can be bound to zero, one, or
	//     several assets (see assetsForCertificate below) so it is not resolved to
	//     a single host here — the certificate's own identity IS the object.
	//
	// There is no crypto_implementations join. There used to be one, keyed
	// `ci.id = cf.subject_id AND cf.subject_type = 'crypto_configuration'`, and
	// it never matched a single row in any release: no writer has ever put a
	// crypto_implementations id in subject_id. It rendered nothing, cost a join
	// per page, and read as though the case were handled. When the configuration
	// producer ships (3.5) it will need a join written against what that producer
	// actually writes, not this one revived.
	query := `
		SELECT cf.id, cf.tenant_id, cf.producer, cf.kind, cf.control_id,
		       cf.subject_id, cf.subject_type, cf.subject_label,
		       cf.severity, cf.score, cf.summary,
		       cf.evidence, cf.first_seen, cf.last_seen, cf.assigned_to, cf.assigned_at,
		       cf.assigned_by, cf.remediation_notes, cf.detection_state, cf.workflow_status,
		       cf.occurrence_count, cf.resurfaced_at, cf.suppressed_until, cf.suppression_reason,
		       cf.is_stale, cf.last_evaluated_at, cf.evaluation_version,
		       cf.created_at, cf.updated_at,
		       na.id AS joined_asset_id,
		       na.hostname, host(na.primary_address) AS ip_address, na_e.port, na.class_key AS asset_type, na.environment,
		       cert.common_name, cert.subject_dn
		FROM findings cf
		-- A software_install subject resolves to the HOST it is installed on.
		-- The eol and vulnerability producers both write findings on the
		-- install (the identity index allows one open row per subject, so an
		-- asset-subject software finding would collapse forty end-of-life
		-- packages into one), and a row that named only the package would have
		-- no host to show, no asset link and no environment.
		LEFT JOIN software_installs si
		       ON si.tenant_id = cf.tenant_id AND si.id = cf.subject_id
		      AND cf.subject_type = 'software_install'
		-- Both key columns in every assets join: the table is hash-partitioned by
		-- tenant_id and keyed on (tenant_id, id), with no index on id alone, so
		-- naming only id scans all eight partitions for every finding on the page.
		-- coalesce rather than an OR so it stays ONE equality the index can use.
		LEFT JOIN assets na
		       ON na.tenant_id = cf.tenant_id AND na.id = coalesce(si.asset_id, cf.subject_id)
		      AND na.deleted_at IS NULL
		      AND cf.subject_type IN ('asset', 'software_install')
		-- A finding ON AN ASSET is about the thing, not one of its faces, so its
		-- port is only meaningful when the asset has exactly one endpoint. More
		-- than one and there is no single true answer, which NULL says honestly.
		LEFT JOIN LATERAL (
			SELECT CASE WHEN count(*) = 1 THEN min(x.port) END AS port
			  FROM asset_endpoints x
			 WHERE x.tenant_id = na.tenant_id AND x.asset_id = na.id
		) na_e ON true
		LEFT JOIN certificates cert ON cert.id = cf.subject_id AND cf.subject_type = 'certificate'
		WHERE ` + whereSQL + fmt.Sprintf(`
		ORDER BY cf.last_seen DESC, cf.id
		LIMIT $%d OFFSET $%d`, idx, idx+1)
	args = append(args, pageSize, (page-1)*pageSize)

	var findings []models.ComplianceFinding
	if err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(context.Background(), countQuery, countArgs...).Scan(&total); err != nil {
			return fmt.Errorf("failed to count findings: %w", err)
		}

		rows, err := tx.QueryContext(context.Background(), query, args...)
		if err != nil {
			return fmt.Errorf("failed to query findings: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var finding models.ComplianceFinding
			var evidenceJSONB []byte
			var assignedTo, assignedBy, remediationNotes, suppressionReason, subjectLabel sql.NullString
			var assignedAt, resurfacedAt, suppressedUntil, lastEvaluatedAt sql.NullTime
			var aHostname, aIP, aType, aEnv sql.NullString
			var aPort sql.NullInt64
			var certCommonName, certSubjectDN sql.NullString
			// The joined asset's own id, so a software_install finding's asset
			// link points at the HOST rather than at the package row.
			var assetID uuid.NullUUID
			// NullUUID, like every other finding reader. `control_id` is
			// NULLable — findings_control_id_compliance_only_check makes it
			// compliance-ONLY, not compliance-ALWAYS — and this read is no
			// longer scoped to compliance, so a straight uuid.UUID would turn
			// the first end-of-life finding on the page into a scan error the
			// handler reports as a 500.
			var controlID uuid.NullUUID

			err := rows.Scan(
				&finding.ID, &finding.TenantID, &finding.Producer, &finding.Kind,
				&controlID, &finding.SubjectID, &finding.SubjectType, &subjectLabel,
				&finding.Severity, &finding.Score, &finding.Summary, &evidenceJSONB,
				&finding.FirstSeen, &finding.LastSeen, &assignedTo, &assignedAt,
				&assignedBy, &remediationNotes, &finding.DetectionState,
				&finding.WorkflowStatus, &finding.OccurrenceCount, &resurfacedAt,
				&suppressedUntil, &suppressionReason, &finding.IsStale,
				&lastEvaluatedAt, &finding.EvaluationVersion,
				&finding.CreatedAt, &finding.UpdatedAt,
				&assetID,
				&aHostname, &aIP, &aPort, &aType, &aEnv,
				&certCommonName, &certSubjectDN,
			)
			if err != nil {
				return fmt.Errorf("failed to scan finding: %w", err)
			}

			finding.Evidence = make(map[string]interface{})
			if len(evidenceJSONB) > 0 {
				if err := json.Unmarshal(evidenceJSONB, &finding.Evidence); err != nil {
					finding.Evidence = make(map[string]interface{})
				}
			}
			if assignedTo.Valid {
				if parsedID, err := uuid.Parse(assignedTo.String); err == nil {
					finding.AssignedTo = &parsedID
				}
			}
			if assignedBy.Valid {
				if parsedID, err := uuid.Parse(assignedBy.String); err == nil {
					finding.AssignedBy = &parsedID
				}
			}
			if assignedAt.Valid {
				finding.AssignedAt = &assignedAt.Time
			}
			if resurfacedAt.Valid {
				finding.ResurfacedAt = &resurfacedAt.Time
			}
			if suppressedUntil.Valid {
				finding.SuppressedUntil = &suppressedUntil.Time
			}
			if suppressionReason.Valid {
				finding.SuppressionReason = &suppressionReason.String
			}
			if remediationNotes.Valid {
				finding.RemediationNotes = &remediationNotes.String
			}
			if lastEvaluatedAt.Valid {
				finding.LastEvaluatedAt = &lastEvaluatedAt.Time
			}
			if subjectLabel.Valid {
				finding.SubjectLabel = &subjectLabel.String
			}
			if controlID.Valid {
				finding.ControlID = controlID.UUID
			}
			assetRowID := finding.SubjectID
			if assetID.Valid {
				assetRowID = assetID.UUID
			}
			switch {
			case assetID.Valid || aHostname.Valid || aIP.Valid || aType.Valid || aEnv.Valid || aPort.Valid:
				// subject_type = asset, or software_install resolved to its
				// host. The joined object's id is the ASSET's, not the
				// subject's: it is what an "open asset" link has to carry, and
				// for a software_install the subject id names a package row no
				// asset page exists for.
				asset := &models.Asset{ID: assetRowID, TenantID: finding.TenantID}
				if aHostname.Valid {
					asset.Hostname = &aHostname.String
				}
				if aIP.Valid {
					asset.IPAddress = &aIP.String
				}
				if aPort.Valid {
					port := int(aPort.Int64)
					asset.Port = &port
				}
				if aType.Valid {
					asset.AssetType = aType.String
				}
				if aEnv.Valid {
					asset.Environment = &aEnv.String
				}
				finding.Asset = asset
			case certCommonName.Valid || certSubjectDN.Valid:
				// subject_type = certificate: the certificate itself is the named object.
				asset := &models.Asset{ID: finding.SubjectID, TenantID: finding.TenantID, AssetType: "certificate"}
				name := certCommonName.String
				if name == "" {
					name = certSubjectDN.String
				}
				if name != "" {
					asset.DisplayName = &name
				}
				finding.Asset = asset
			}

			findings = append(findings, finding)
		}
		return rows.Err()
	}); err != nil {
		return nil, 0, err
	}

	for i := range findings {
		ticketCount, _ := s.GetTicketCountForFinding(tenantID, findings[i].ID)
		findings[i].TicketCount = ticketCount
	}

	return findings, total, nil
}

// CountFindingsByProducer tallies the tenant's ACTIVE findings per producer,
// under the SAME filters as ListFindings except the producer one.
//
// It is what the Findings page's producer chips count. Sharing
// findingListWhere with the list is the point: a chip that said "End of life
// 12" over a list of 9 would be the `has_findings` divergence again, where a
// number and the rows it leads to were two hand-written expressions.
//
// Producers with no findings are NOT in the map. The caller renders a chip per
// REGISTERED producer and reads a missing key as 0, so a producer that has
// never written anything still appears — "we looked and found none" is a
// different answer from "nobody has looked", and only the registry knows which
// producers exist.
func (s *FindingsService) CountFindingsByProducer(tenantID uuid.UUID, filters FindingListFilters) (map[string]int, error) {
	where, args, _ := findingListWhere(tenantID, filters, false)
	query := "SELECT cf.producer, COUNT(*) FROM findings cf WHERE " +
		strings.Join(where, " AND ") + " GROUP BY cf.producer"

	out := map[string]int{}
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(context.Background(), query, args...)
		if err != nil {
			return fmt.Errorf("failed to count findings by producer: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var producerKey string
			var n int
			if err := rows.Scan(&producerKey, &n); err != nil {
				return fmt.Errorf("failed to scan producer count: %w", err)
			}
			out[producerKey] = n
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SeverityCounts is the per-severity finding tally within a control group.
//
// `Med` was renamed `Medium` with the registry ladder (workstream 3.1): the DB
// no longer has a rung spelled `Med`, and a JSON key that still said so would be
// the last place in the product using a vocabulary nothing else understands.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// FindingsByControlGroup is active findings aggregated for one framework control
// (ADR-0007 item 4) — backs the Posture "top exposures" ranking. Read off the
// materialized findings (ADR-0014), so it stays consistent with the Findings
// page rather than re-evaluating live.
type FindingsByControlGroup struct {
	ControlID      uuid.UUID      `json:"control_id"`
	ControlName    string         `json:"control_name"`
	FrameworkID    uuid.UUID      `json:"framework_id"`
	FrameworkName  string         `json:"framework_name"`
	WorstSeverity  string         `json:"worst_severity"` // critical | high | medium | low | info
	FindingCount   int            `json:"finding_count"`
	AffectedAssets int            `json:"affected_assets"`
	SeverityCounts SeverityCounts `json:"severity_counts"`
	// TargetKind names what AffectedAssets is actually counting: "asset" when
	// every finding in the group is about an asset, "certificate" /
	// "configuration" when every finding is about that other kind, "mixed"
	// otherwise (the compliance producer's subject_type is asset / certificate /
	// crypto_configuration). L-5: the UI used to always say "N assets" even when
	// the objects were certificates, which reads as wrong to anyone who knows
	// what they're looking at.
	TargetKind string `json:"target_kind"`
}

// targetKindFromSubjectTypes maps the set of subject_type values observed in a
// findings-by-control group to the display noun for AffectedAssets.
//
// `configuration` is reachable only once the configuration producer ships
// (workstream 3.5) — this producer's configuration measurements are about the
// ASSET and count as such, which is what AffectedAssets has always counted. It
// is spelled here rather than left out so the arm exists the day a
// crypto_configuration subject appears, instead of silently rendering "asset".
func targetKindFromSubjectTypes(subjectTypes []string) string {
	if len(subjectTypes) != 1 {
		return "mixed"
	}
	switch subjectTypes[0] {
	case SubjectCertificate:
		return "certificate"
	case sharedfindings.SubjectCryptoConfiguration:
		return "configuration"
	default:
		return "asset"
	}
}

// GetFindingsByControl returns active findings grouped by framework control,
// ranked worst-severity → finding-count → affected-assets, limited to `limit`
// groups (ADR-0007 item 4). Orphaned findings whose control no longer maps to a
// platform/tenant framework are excluded — an exposure needs a framework home.
func (s *FindingsService) GetFindingsByControl(tenantID uuid.UUID, limit int) ([]FindingsByControlGroup, error) {
	if limit < 1 {
		limit = 5
	}
	if limit > 50 {
		limit = 50
	}

	// A finding's control_id resolves to exactly one of platform/tenant controls
	// (UUIDs are globally unique), so the paired LEFT JOINs never double-count;
	// COALESCE picks whichever side matched. detection_state='ACTIVE' and the
	// licensed scope both mirror ListFindings so the ranking, the Findings page
	// and the Posture page's Top Exposures panel all agree.
	query := `
		SELECT
			cf.control_id AS control_id,
			COALESCE(pfc.title, tfc.title, 'Unknown control')      AS control_name,
			COALESCE(pf.id, tf.id)                                 AS framework_id,
			COALESCE(pf.name, tf.name, 'Unknown framework')        AS framework_name,
			COUNT(*)                                               AS finding_count,
			COUNT(DISTINCT cf.subject_id)                          AS asset_count,
			ARRAY_AGG(DISTINCT cf.subject_type)                    AS subject_types,
			COUNT(*) FILTER (WHERE cf.severity = '` + SeverityCritical + `') AS crit,
			COUNT(*) FILTER (WHERE cf.severity = '` + SeverityHigh + `')     AS high,
			COUNT(*) FILTER (WHERE cf.severity = '` + SeverityMedium + `')   AS med,
			COUNT(*) FILTER (WHERE cf.severity = '` + SeverityLow + `')      AS low,
			MAX(` + severityRankSQL("cf.severity") + `) AS worst_rank
		FROM findings cf
		LEFT JOIN platform_framework_controls pfc ON pfc.id = cf.control_id
		LEFT JOIN platform_frameworks pf          ON pf.id = pfc.framework_id
		LEFT JOIN tenant_framework_controls tfc   ON tfc.id = cf.control_id
		LEFT JOIN tenant_frameworks tf            ON tf.id = tfc.framework_id
		WHERE cf.tenant_id = $1
		  AND cf.detection_state = 'ACTIVE'
		  AND ` + complianceProducerScope("cf") + `
		  AND (pfc.id IS NOT NULL OR tfc.id IS NOT NULL)
		  AND ` + licensedFindingScopeSQL("cf", "$1") + `
		GROUP BY cf.control_id, pfc.title, tfc.title, pf.id, pf.name, tf.id, tf.name
		ORDER BY worst_rank DESC, finding_count DESC, asset_count DESC
		LIMIT $2`

	type byControlRow struct {
		ControlID     uuid.UUID      `db:"control_id"`
		ControlName   string         `db:"control_name"`
		FrameworkID   uuid.UUID      `db:"framework_id"`
		FrameworkName string         `db:"framework_name"`
		FindingCount  int            `db:"finding_count"`
		AssetCount    int            `db:"asset_count"`
		SubjectTypes  pq.StringArray `db:"subject_types"`
		Crit          int            `db:"crit"`
		High          int            `db:"high"`
		Med           int            `db:"med"`
		Low           int            `db:"low"`
		WorstRank     int            `db:"worst_rank"`
	}
	var rowsData []byControlRow
	if err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		dbRows, err := tx.QueryContext(context.Background(), query, tenantID, limit)
		if err != nil {
			return fmt.Errorf("failed to aggregate findings by control: %w", err)
		}
		defer func() { _ = dbRows.Close() }()
		for dbRows.Next() {
			var r byControlRow
			if err := dbRows.Scan(
				&r.ControlID, &r.ControlName, &r.FrameworkID, &r.FrameworkName,
				&r.FindingCount, &r.AssetCount, &r.SubjectTypes, &r.Crit, &r.High, &r.Med, &r.Low, &r.WorstRank,
			); err != nil {
				return fmt.Errorf("failed to scan findings-by-control row: %w", err)
			}
			rowsData = append(rowsData, r)
		}
		return dbRows.Err()
	}); err != nil {
		return nil, err
	}

	groups := make([]FindingsByControlGroup, 0, len(rowsData))
	for _, r := range rowsData {
		groups = append(groups, FindingsByControlGroup{
			ControlID:      r.ControlID,
			ControlName:    r.ControlName,
			FrameworkID:    r.FrameworkID,
			FrameworkName:  r.FrameworkName,
			WorstSeverity:  severityFromRank(r.WorstRank),
			FindingCount:   r.FindingCount,
			AffectedAssets: r.AssetCount,
			SeverityCounts: SeverityCounts{Critical: r.Crit, High: r.High, Medium: r.Med, Low: r.Low},
			TargetKind:     targetKindFromSubjectTypes([]string(r.SubjectTypes)),
		})
	}
	return groups, nil
}

// FindingStatistics represents aggregated finding counts
type FindingStatistics struct {
	TotalFindings      int `json:"total_findings"`
	ActiveFindings     int `json:"active_findings"`
	InactiveFindings   int `json:"inactive_findings"`
	ArchivedFindings   int `json:"archived_findings"`
	NewFindings        int `json:"new_findings"`
	NotifiedFindings   int `json:"notified_findings"`
	ResolvedFindings   int `json:"resolved_findings"`
	SuppressedFindings int `json:"suppressed_findings"`
	ResurfacedFindings int `json:"resurfaced_findings"`
	// SeverityCounts tallies ACTIVE findings by severity, tenant-wide, off the
	// same materialized findings the Findings page and
	// GetFindingsByControl read — so a dashboard tile built from this field
	// agrees with the Findings page instead of inventory-service's
	// crypto-implementation-risk-score-derived "critical findings" count
	// (H-2: the two used to read from unrelated tables and disagree).
	SeverityCounts SeverityCounts `json:"severity_counts"`
}

// GetFindingStatistics returns aggregated statistics for findings
func (s *FindingsService) GetFindingStatistics(tenantID uuid.UUID) (*FindingStatistics, error) {
	stats := &FindingStatistics{}

	// Get counts by detection state
	// All four rollups carry the licensed scope (see licensedFindingScopeSQL):
	// these counts drive the Dashboard's severity tiles, and an unactivated
	// framework's findings used to land there — a tenant whose single activated
	// framework had zero Criticals still read "5 Critical" on the Dashboard.
	query := `
		SELECT
			detection_state,
			COUNT(*) as count
		FROM findings cf
		WHERE tenant_id = $1
		  AND ` + complianceProducerScope("cf") + `
		  AND ` + licensedFindingScopeSQL("cf", "$1") + `
		GROUP BY detection_state
	`
	// Get counts by workflow status
	workflowQuery := `
		SELECT
			workflow_status,
			COUNT(*) as count
		FROM findings cf
		WHERE tenant_id = $1
		  AND detection_state = 'ACTIVE'
		  AND ` + complianceProducerScope("cf") + `
		  AND ` + licensedFindingScopeSQL("cf", "$1") + `
		GROUP BY workflow_status
	`
	// Get resurfaced findings count
	resurfacedQuery := `
		SELECT COUNT(*)
		FROM findings cf
		WHERE tenant_id = $1
		  AND detection_state = 'ACTIVE'
		  AND resurfaced_at IS NOT NULL
		  AND ` + complianceProducerScope("cf") + `
		  AND ` + licensedFindingScopeSQL("cf", "$1") + `
	`
	// Get counts by severity, ACTIVE findings only, tenant-wide (no control-join,
	// no LIMIT) — the same detection_state scope GetFindingsByControl uses, so
	// this is the true tenant-wide total rather than a sum over a capped list of
	// control groups.
	severityQuery := `
		SELECT
			severity,
			COUNT(*) as count
		FROM findings cf
		WHERE tenant_id = $1
		  AND detection_state = 'ACTIVE'
		  AND ` + complianceProducerScope("cf") + `
		  AND ` + licensedFindingScopeSQL("cf", "$1") + `
		GROUP BY severity
	`

	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		stateRows, err := tx.QueryContext(context.Background(), query, tenantID)
		if err != nil {
			return fmt.Errorf("failed to get detection state counts: %w", err)
		}
		defer func() { _ = stateRows.Close() }()
		for stateRows.Next() {
			var detectionState string
			var count int
			if err := stateRows.Scan(&detectionState, &count); err != nil {
				return fmt.Errorf("failed to scan detection state count: %w", err)
			}
			stats.TotalFindings += count
			switch detectionState {
			case "ACTIVE":
				stats.ActiveFindings = count
			case "INACTIVE":
				stats.InactiveFindings = count
			case "ARCHIVED":
				stats.ArchivedFindings = count
			}
		}
		if err := stateRows.Err(); err != nil {
			return fmt.Errorf("failed to get detection state counts: %w", err)
		}

		wfRows, err := tx.QueryContext(context.Background(), workflowQuery, tenantID)
		if err != nil {
			return fmt.Errorf("failed to get workflow status counts: %w", err)
		}
		defer func() { _ = wfRows.Close() }()
		for wfRows.Next() {
			var workflowStatus string
			var count int
			if err := wfRows.Scan(&workflowStatus, &count); err != nil {
				return fmt.Errorf("failed to scan workflow status count: %w", err)
			}
			switch workflowStatus {
			case "NEW":
				stats.NewFindings = count
			case "NOTIFIED":
				stats.NotifiedFindings = count
			case "RESOLVED":
				stats.ResolvedFindings = count
			case "SUPPRESSED":
				stats.SuppressedFindings = count
			}
		}
		if err := wfRows.Err(); err != nil {
			return fmt.Errorf("failed to get workflow status counts: %w", err)
		}

		sevRows, err := tx.QueryContext(context.Background(), severityQuery, tenantID)
		if err != nil {
			return fmt.Errorf("failed to get severity counts: %w", err)
		}
		defer func() { _ = sevRows.Close() }()
		for sevRows.Next() {
			var severity string
			var count int
			if err := sevRows.Scan(&severity, &count); err != nil {
				return fmt.Errorf("failed to scan severity count: %w", err)
			}
			switch severity {
			case SeverityCritical:
				stats.SeverityCounts.Critical = count
			case SeverityHigh:
				stats.SeverityCounts.High = count
			case SeverityMedium:
				stats.SeverityCounts.Medium = count
			case SeverityLow:
				stats.SeverityCounts.Low = count
			}
		}
		if err := sevRows.Err(); err != nil {
			return fmt.Errorf("failed to get severity counts: %w", err)
		}

		if err := tx.QueryRowContext(context.Background(), resurfacedQuery, tenantID).Scan(&stats.ResurfacedFindings); err != nil {
			return fmt.Errorf("failed to get resurfaced findings count: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// GetEvidenceID returns the evidence ID for a finding in both UUID and formatted format
func (s *FindingsService) GetEvidenceID(tenantID, findingID uuid.UUID) (string, string, error) {
	// Verify finding exists, belongs to tenant, and is in an activated/custom framework.
	var exists bool
	ctx := context.Background()
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		var err error
		exists, err = licensedFindingExistsInTx(ctx, tx, tenantID, findingID)
		return err
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to check finding: %w", err)
	}
	if !exists {
		return "", "", ErrFindingNotFound
	}

	// Return UUID and formatted evidence ID
	evidenceID := findingID.String()
	evidenceRef := fmt.Sprintf("CF-%s", findingID.String())
	return evidenceID, evidenceRef, nil
}

// Legacy CreateTicket, UpdateTicket, ListTickets methods removed.
// All ticket operations now go through TicketService → tickets table.

// OnAssetChanged handles asset changed events. Per ADR-0015 it reconciles ONLY the
// changed asset against every published framework's controls (extract-once for that
// asset, fold all controls, reconcile that asset's findings), then refreshes the
// rollups of the frameworks it touched. This replaces the ADR-0014 whole-tenant
// reconcile-on-change, which was O(assets²) under bulk discovery and OOM-killed the
// service in v3.1.0. Tenant-wide reconcile still exists for framework-change and
// manual triggers (EvaluateTenantFrameworks via the reconcile worker).
func (s *FindingsService) OnAssetChanged(ctx context.Context, event events.AssetChangedEvent) error {
	log.Printf("[FindingsService] Processing asset changed event: tenant=%s, asset=%s, change=%s",
		event.TenantID, event.AssetID, event.ChangeType)

	summary, err := s.EvaluateAsset(ctx, event.TenantID, event.AssetID)
	if err != nil {
		return fmt.Errorf("per-asset evaluation failed: %w", err)
	}

	log.Printf("[FindingsService] INFO: Completed asset change reconcile: event_id=%s, asset_id=%s, controls=%d, activated=+%d, inactivated=%d",
		event.EventID, event.AssetID, summary.ControlsEvaluated, summary.FindingsActivated, summary.FindingsInactivated)
	return nil
}

// OnAssetDeleted handles asset deleted events
func (s *FindingsService) OnAssetDeleted(ctx context.Context, event events.AssetDeletedEvent) error {
	tenantID := event.TenantID
	assetID := event.AssetID

	log.Printf("[FindingsService] INFO: Processing asset deleted event: event_id=%s, tenant_id=%s, asset_id=%s, source=%s",
		event.EventID, tenantID, assetID, event.Source)

	// Mark this producer's findings ON THIS ASSET as INACTIVE.
	//
	// Subject-scoped, not asset-scoped-with-descendants: a deleted asset's
	// certificates and configurations are deleted by their own events, and
	// inactivating a certificate's finding here would be this service deciding
	// the certificate is gone on the strength of one of its hosts going away.
	query := `
		UPDATE findings
		SET detection_state = 'INACTIVE',
		    updated_at = NOW()
		WHERE tenant_id = $1 AND subject_id = $2 AND detection_state = 'ACTIVE'
		  AND ` + complianceProducerScope("findings") + `
	`
	var updatedCount int64
	if err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, query, tenantID, assetID)
		if err != nil {
			return fmt.Errorf("failed to mark findings inactive: %w", err)
		}
		updatedCount, _ = result.RowsAffected()
		return nil
	}); err != nil {
		return err
	}

	log.Printf("[FindingsService] INFO: Marked findings as inactive for deleted asset: event_id=%s, asset_id=%s, findings_marked=%d",
		event.EventID, assetID, updatedCount)
	return nil
}

// certFanOutLimit caps how many linked assets a single certificate change will reconcile
// one-by-one before falling back to a single (coalesced) whole-tenant pass. Per-asset
// passes re-extract measurements per asset, so past a few dozen assets one shared-
// extraction tenant pass is the cheaper shape. Well above the common case: a certificate
// is normally bound to a handful of endpoints.
const certFanOutLimit = 32

// OnCertificateChanged handles certificate changed events.
//
// Scoped per ADR-0015, like OnAssetChanged. A certificate change moves exactly two kinds
// of measurement:
//
//   - certificate-scoped ones (cert_pqc_status, cert signature, validity, …), whose
//     MeasurementValue.AssetID *is* the certificate id — so the certificate reconciles as
//     its own "asset";
//   - crypto-configuration-scoped ones on the assets the certificate is bound to.
//
// Both are reachable with the bounded per-asset primitive, so this no longer fires a
// FULL-TENANT reconcile per certificate event. That was the W2-13 finding: a cert-heavy
// ingest batch fired one whole-tenant pass (every published control × every asset) per
// event, and at 10k assets the passes were both redundant and enormous.
//
// Tenant-wide remains the fallback for the two cases the scoped path cannot bound: the
// link lookup failing, and a certificate bound to more assets than certFanOutLimit. That
// fallback goes through the per-tenant coalescer so a burst still costs one pass.
func (s *FindingsService) OnCertificateChanged(ctx context.Context, event events.CertificateChangedEvent) error {
	tenantID := event.TenantID
	certificateID := event.CertificateID

	log.Printf("[FindingsService] INFO: Processing certificate changed event: event_id=%s, tenant_id=%s, certificate_id=%s, change_type=%s, source=%s",
		event.EventID, tenantID, certificateID, event.ChangeType, event.Source)

	assetIDs, err := s.assetsForCertificate(ctx, tenantID, certificateID)
	if err != nil {
		// Linkage unknown — fall back to a tenant-wide (coalesced) reconcile rather than
		// silently leaving the certificate's findings stale.
		log.Printf("[FindingsService] WARN: certificate→asset lookup failed (cert=%s): %v; falling back to tenant reconcile", certificateID, err)
		return s.reconcileTenantAfterCertChange(ctx, event, "link_lookup_failed", 0)
	}

	targets, tenantWide := certReconcileTargets(certificateID, assetIDs)
	if tenantWide {
		return s.reconcileTenantAfterCertChange(ctx, event, "fan_out_over_limit", len(assetIDs))
	}

	var activated, inactivated, failures int
	for _, target := range targets {
		summary, err := s.EvaluateAsset(ctx, tenantID, target)
		if err != nil {
			log.Printf("[FindingsService] ERROR: per-asset reconcile after cert change failed (cert=%s target=%s): %v", certificateID, target, err)
			failures++
			continue
		}
		activated += summary.FindingsActivated
		inactivated += summary.FindingsInactivated
	}
	if failures > 0 {
		return fmt.Errorf("certificate change reconcile failed for %d/%d targets (cert=%s)", failures, len(targets), certificateID)
	}

	log.Printf("[FindingsService] INFO: Completed certificate change reconcile (scoped): event_id=%s, certificate_id=%s, linked_assets=%d, targets=%d, activated=+%d, inactivated=%d, failures=%d",
		event.EventID, certificateID, len(assetIDs), len(targets), activated, inactivated, failures)
	return nil
}

// certReconcileTargets decides what a certificate change reconciles. Pure (no DB) so the
// scoping decision is unit-testable.
//
// The certificate itself is ALWAYS a target: certificate-scoped measurements key their
// findings on the certificate id, so a certificate with no asset binding at all still has
// findings to converge — the pre-W2-13 code returned early on zero links and left them
// stale. Duplicates are dropped (a certificate can be reachable through several
// implementations of the same asset). tenantWide is true only past certFanOutLimit.
func certReconcileTargets(certificateID uuid.UUID, assetIDs []uuid.UUID) (targets []uuid.UUID, tenantWide bool) {
	if len(assetIDs) > certFanOutLimit {
		return nil, true
	}
	seen := map[uuid.UUID]bool{certificateID: true}
	targets = append(targets, certificateID)
	for _, id := range assetIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		targets = append(targets, id)
	}
	return targets, false
}

// assetsForCertificate returns the infrastructure assets a certificate is bound to.
//
// There are TWO link paths and both matter: crypto_implementations.certificate_id is the
// primary/leaf binding, while crypto_implementation_certificates carries the chain
// (intermediate/root/additional) certificates. The pre-W2-13 query consulted only the
// junction, so a leaf certificate — the common case — resolved to zero assets.
func (s *FindingsService) assetsForCertificate(ctx context.Context, tenantID, certificateID uuid.UUID) ([]uuid.UUID, error) {
	const query = `
		SELECT DISTINCT ci.asset_id
		FROM crypto_implementations ci
		WHERE ci.tenant_id = $1
		  AND (ci.certificate_id = $2
		       OR EXISTS (SELECT 1 FROM crypto_implementation_certificates cic
		                   WHERE cic.crypto_implementation_id = ci.id
		                     AND cic.certificate_id = $2))
	`
	var assetIDs []uuid.UUID
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, tenantID, certificateID)
		if err != nil {
			return fmt.Errorf("failed to get assets for certificate: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			if err := rows.Scan(&assetID); err != nil {
				continue
			}
			assetIDs = append(assetIDs, assetID)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return assetIDs, nil
}

// reconcileTenantAfterCertChange runs the whole-tenant fallback through the coalescer.
func (s *FindingsService) reconcileTenantAfterCertChange(ctx context.Context, event events.CertificateChangedEvent, reason string, linkedAssets int) error {
	summary, coalesced, err := s.ReconcileTenantCoalesced(ctx, event.TenantID, uuid.Nil)
	if err != nil {
		return fmt.Errorf("tenant evaluation failed after certificate change: %w", err)
	}
	if coalesced {
		log.Printf("[FindingsService] INFO: Certificate change reconcile coalesced into an in-flight tenant pass: event_id=%s, certificate_id=%s, reason=%s",
			event.EventID, event.CertificateID, reason)
		return nil
	}
	log.Printf("[FindingsService] INFO: Completed certificate change reconcile (tenant-wide, reason=%s): event_id=%s, certificate_id=%s, linked_assets=%d, activated=+%d, inactivated=%d",
		reason, event.EventID, event.CertificateID, linkedAssets, summary.FindingsActivated, summary.FindingsInactivated)
	return nil
}

// findingLastSeenRefreshInterval is how stale a finding's last_seen is allowed to get
// before an otherwise-unchanged reconcile pass rewrites the row just to refresh it.
//
// Tradeoff, deliberately taken: before W2-13, EVERY reconcile pass rewrote EVERY active
// finding (last_seen = now(), occurrence_count + 1) even when the finding was byte-for-
// byte identical to what was already stored. At 10k assets × dozens of controls that is
// hundreds of thousands of pointless row versions per pass — WAL, bloat, and autovacuum
// churn produced purely by the act of looking. last_seen is a freshness indicator on a
// UI, not an audit field (the finding-history table is the audit trail), so an hour of
// granularity is invisible to a user and removes essentially all of the churn. Anything
// MATERIAL — detection_state, severity, summary, evidence — still writes immediately.
//
// Consequence to know: occurrence_count now counts times the finding was seen to CHANGE
// (or was refreshed hourly), not times a reconcile pass ran. The old number tracked how
// often the engine happened to be triggered, which was never a property of the finding.
const findingLastSeenRefreshInterval = time.Hour

// findingUpsertChunkSize bounds how many findings share one transaction. Big enough that
// per-transaction overhead disappears, small enough that a chunk that has to be retried
// row-by-row (see upsertFindings) is cheap and that a pass does not hold row locks on a
// tenant's whole finding set at once.
const findingUpsertChunkSize = 500

// findingUpsert is one (control, subject) pair to materialize in a batched
// reconcile write. The subject is whatever the measurement was taken on — an
// asset, a certificate or a crypto configuration — which is why it is not
// called AssetID.
type findingUpsert struct {
	ControlID      uuid.UUID
	SubjectID      uuid.UUID
	Finding        *models.ComplianceFinding
	DetectionState string
}

// findingWriteStats reports what a batch of upserts actually did.
type findingWriteStats struct {
	Created int // rows inserted
	Updated int // rows rewritten (something material changed, or last_seen went stale)
	Skipped int // no-ops — identical to what was already stored
	Failed  int
}

// Processed is the number of pairs successfully reconciled (written or confirmed
// already-correct). Callers use it for EvaluationSummary.FindingsActivated: a pair that
// needed no write is still an active finding.
func (w findingWriteStats) Processed() int { return w.Created + w.Updated + w.Skipped }

// normalizeFindingEvidence renders a finding's evidence for storage. nil becomes `{}`
// rather than JSON `null` so the created and updated paths agree — they did not before,
// which made an unchanged finding look changed on the pass after its creation.
func normalizeFindingEvidence(finding *models.ComplianceFinding) []byte {
	if finding == nil || finding.Evidence == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(finding.Evidence)
	if err != nil || len(b) == 0 || string(b) == "null" {
		return []byte("{}")
	}
	return b
}

// upsertFinding upserts a single finding based on stable identity
// (tenant_id, producer, kind, subject_type, subject_id, control_id). Thin wrapper
// over the batch path so there is exactly one implementation of the write
// semantics.
func (s *FindingsService) upsertFinding(ctx context.Context, tenantID, controlID, subjectID uuid.UUID, finding *models.ComplianceFinding, detectionState string) error {
	return s.upsertFindingChunk(ctx, tenantID, []findingUpsert{{
		ControlID:      controlID,
		SubjectID:      subjectID,
		Finding:        finding,
		DetectionState: detectionState,
	}})
}

// upsertFindings materializes a whole reconcile pass's findings, ONE TRANSACTION PER
// CHUNK instead of one per finding. Before W2-13 each (control, subject) pair paid its own
// BEGIN / SET app.tenant_id / SELECT / write / COMMIT round-trip, so a tenant pass at
// scale was hundreds of thousands of single-row transactions.
//
// Robustness: a transaction is all-or-nothing, so one poison row could otherwise sink a
// whole chunk. If a chunk fails, it is retried row-by-row (the pre-W2-13 shape), which
// isolates the bad row and preserves the old "log it and keep going" behaviour.
func (s *FindingsService) upsertFindings(ctx context.Context, tenantID uuid.UUID, items []findingUpsert) findingWriteStats {
	var total findingWriteStats
	for start := 0; start < len(items); start += findingUpsertChunkSize {
		end := min(start+findingUpsertChunkSize, len(items))
		chunk := s.writeChunk(ctx, tenantID, items[start:end])
		total.Created += chunk.Created
		total.Updated += chunk.Updated
		total.Skipped += chunk.Skipped
		total.Failed += chunk.Failed
	}
	return total
}

// writeChunk writes one chunk, falling back to row-at-a-time on transaction failure.
func (s *FindingsService) writeChunk(ctx context.Context, tenantID uuid.UUID, chunk []findingUpsert) findingWriteStats {
	var stats findingWriteStats
	err := s.upsertFindingChunkStats(ctx, tenantID, chunk, &stats)
	if err == nil {
		return stats
	}
	if len(chunk) > 1 {
		log.Printf("[FindingsService] WARN: batched finding upsert of %d rows failed (%v); retrying row-by-row", len(chunk), err)
	}

	stats = findingWriteStats{}
	for i := range chunk {
		var one findingWriteStats
		if err := s.upsertFindingChunkStats(ctx, tenantID, chunk[i:i+1], &one); err != nil {
			log.Printf("[FindingsService] upsert finding failed (control=%s subject=%s): %v", chunk[i].ControlID, chunk[i].SubjectID, err)
			stats.Failed++
			continue
		}
		stats.Created += one.Created
		stats.Updated += one.Updated
		stats.Skipped += one.Skipped
	}
	return stats
}

// upsertFindingChunk writes one chunk in a single tenant-scoped transaction.
func (s *FindingsService) upsertFindingChunk(ctx context.Context, tenantID uuid.UUID, items []findingUpsert) error {
	var stats findingWriteStats
	return s.upsertFindingChunkStats(ctx, tenantID, items, &stats)
}

func (s *FindingsService) upsertFindingChunkStats(ctx context.Context, tenantID uuid.UUID, items []findingUpsert, stats *findingWriteStats) error {
	if len(items) == 0 {
		return nil
	}
	now := time.Now()
	lastSeenFloor := now.Add(-findingLastSeenRefreshInterval)

	return shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		existing, err := loadExistingFindings(ctx, tx, tenantID, items)
		if err != nil {
			return err
		}

		for _, item := range items {
			key := controlSubject{ControlID: item.ControlID, SubjectID: item.SubjectID}
			prior, found := existing[key]
			if !found {
				if err := s.insertFinding(ctx, tx, tenantID, item, now, stats); err != nil {
					return err
				}
				continue
			}
			if err := s.updateFinding(ctx, tx, item, prior, now, lastSeenFloor, stats); err != nil {
				return err
			}
		}
		return nil
	})
}

// priorFinding is the stored state a reconcile pass needs in order to decide what (if
// anything) to write. Everything else the decision depends on — severity, summary,
// evidence, last_seen — is compared IN SQL by the guarded UPDATE below, because jsonb
// equality is semantic (key order and whitespace are normalized) and a Go-side byte
// comparison of marshalled evidence would report a difference on every pass.
type priorFinding struct {
	ID             uuid.UUID
	DetectionState string
}

func loadExistingFindings(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, items []findingUpsert) (map[controlSubject]priorFinding, error) {
	controlIDs := make([]string, len(items))
	subjectIDs := make([]string, len(items))
	for i, it := range items {
		controlIDs[i] = it.ControlID.String()
		subjectIDs[i] = it.SubjectID.String()
	}

	query := `
		SELECT control_id, subject_id, id, detection_state
		FROM findings
		WHERE tenant_id = $1
		  AND detection_state <> 'ARCHIVED'
		  AND ` + complianceProducerScope("findings") + `
		  AND (control_id, subject_id) IN (
		      SELECT p.c, p.a FROM unnest($2::uuid[], $3::uuid[]) AS p(c, a)
		  )
	`
	rows, err := tx.QueryContext(ctx, query, tenantID, pq.Array(controlIDs), pq.Array(subjectIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to load existing findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[controlSubject]priorFinding, len(items))
	for rows.Next() {
		var key controlSubject
		var prior priorFinding
		if err := rows.Scan(&key.ControlID, &key.SubjectID, &prior.ID, &prior.DetectionState); err != nil {
			return nil, fmt.Errorf("failed to scan existing finding: %w", err)
		}
		out[key] = prior
	}
	return out, rows.Err()
}

// insertFinding creates a finding that the prefetch did not see.
//
// ON CONFLICT against findings_open_subject_uniq (the partial unique index on
// tenant_id, producer, kind, subject_type, subject_id, control_id WHERE
// detection_state <> 'ARCHIVED') keeps the duplicate-row race backstopped WITHOUT
// raising a unique violation — which matters more now than it did per-row, because
// an error here would abort the whole chunk's transaction rather than just this
// pair. `xmax = 0` distinguishes a true insert from a conflict-update so history is
// only written for a genuine creation.
//
// `score` is written as the literal 0 rather than carried from the finding: the
// registry declares control_noncompliant's feeds_risk false, so a compliance
// finding contributes nothing to the per-asset risk rollup. A nonzero score here
// would be counted by workstream 3.2's recompute and would swamp it.
func (s *FindingsService) insertFinding(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, item findingUpsert, now time.Time, stats *findingWriteStats) error {
	finding := item.Finding
	findingID := uuid.New()
	severity := SeverityLow
	summary := "Compliance violation detected"
	subjectType := SubjectAsset
	var subjectLabel *string
	firstSeen, lastSeen := now, now
	evidenceJSON := normalizeFindingEvidence(finding)

	if finding != nil {
		findingID = finding.ID
		severity = normalizeSeverity(finding.Severity)
		summary = finding.Summary
		subjectType = normalizeSubjectType(finding.SubjectType)
		subjectLabel = finding.SubjectLabel
		if !finding.FirstSeen.IsZero() {
			firstSeen = finding.FirstSeen
		}
		if !finding.LastSeen.IsZero() {
			lastSeen = finding.LastSeen
		}
	}

	insertQuery := `
		INSERT INTO findings (
			id, tenant_id, producer, kind, control_id, subject_id, subject_type, subject_label,
			severity, score, summary, evidence,
			first_seen, last_seen, detection_state, workflow_status, occurrence_count,
			created_at, updated_at
		) VALUES ($1, $2, '` + sharedfindings.ProducerCompliance + `', '` + sharedfindings.KindControlNoncompliant + `',
			$3, $4, $5, $6, $7, 0, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (tenant_id, producer, kind, subject_type, subject_id, control_id)
			WHERE detection_state <> 'ARCHIVED'
		DO UPDATE SET
			last_seen = EXCLUDED.last_seen,
			occurrence_count = findings.occurrence_count + 1,
			detection_state = EXCLUDED.detection_state,
			severity = EXCLUDED.severity,
			summary = EXCLUDED.summary,
			evidence = EXCLUDED.evidence,
			updated_at = EXCLUDED.updated_at
		RETURNING id, (xmax = 0) AS inserted
	`

	var storedID uuid.UUID
	var inserted bool
	if err := tx.QueryRowContext(ctx, insertQuery,
		findingID, tenantID, item.ControlID, item.SubjectID, subjectType, subjectLabel,
		severity, summary, evidenceJSON,
		firstSeen, lastSeen, item.DetectionState, "NEW", 1,
		now, now,
	).Scan(&storedID, &inserted); err != nil {
		return fmt.Errorf("failed to create finding: %w", err)
	}

	if !inserted {
		// Lost the race to a concurrent writer; the row is now correct but this pass did
		// not create it, so no creation-history row is owed.
		stats.Updated++
		if s.metricsService != nil {
			s.metricsService.RecordFindingUpserted(false)
		}
		return nil
	}

	s.recordFindingHistory(ctx, tx, storedID, nil, "detection_state", "", item.DetectionState, "Initial finding creation")
	log.Printf("[FindingsService] INFO: Created new finding: finding_id=%s, control_id=%s, subject_id=%s, subject_type=%s, severity=%s, detection_state=%s",
		storedID, item.ControlID, item.SubjectID, subjectType, severity, item.DetectionState)
	stats.Created++
	if s.metricsService != nil {
		s.metricsService.RecordFindingUpserted(true)
	}
	return nil
}

// updateFinding rewrites an existing finding ONLY when something material changed or its
// last_seen has gone stale. The guard lives in the UPDATE's WHERE clause (not in Go) so
// evidence is compared with jsonb semantics; RETURNING tells us whether the write
// happened, which is also how a no-op is counted.
func (s *FindingsService) updateFinding(ctx context.Context, tx *sql.Tx, item findingUpsert, prior priorFinding, now, lastSeenFloor time.Time, stats *findingWriteStats) error {
	resurfaced := prior.DetectionState == "INACTIVE" && item.DetectionState == "ACTIVE"

	// nil finding => keep the stored severity/summary/evidence (COALESCE below).
	var severity, summary any
	var evidence any
	if item.Finding != nil {
		severity = normalizeSeverity(item.Finding.Severity)
		summary = item.Finding.Summary
		evidence = normalizeFindingEvidence(item.Finding)
	}

	const updateQuery = `
		UPDATE findings
		SET last_seen = $1,
		    occurrence_count = occurrence_count + 1,
		    detection_state = $2,
		    workflow_status = CASE
		        WHEN $3::boolean AND workflow_status <> 'SUPPRESSED' THEN 'NEW'
		        ELSE workflow_status
		    END,
		    resurfaced_at = CASE WHEN $3::boolean THEN $1 ELSE resurfaced_at END,
		    severity = COALESCE($5::text, severity),
		    summary = COALESCE($6::text, summary),
		    evidence = COALESCE($7::jsonb, evidence),
		    updated_at = $1
		WHERE id = $4
		  AND (
		        detection_state IS DISTINCT FROM $2
		     OR severity IS DISTINCT FROM COALESCE($5::text, severity)
		     OR summary IS DISTINCT FROM COALESCE($6::text, summary)
		     OR evidence IS DISTINCT FROM COALESCE($7::jsonb, evidence)
		     OR last_seen IS NULL
		     OR last_seen < $8
		  )
		RETURNING id
	`

	var writtenID uuid.UUID
	err := tx.QueryRowContext(ctx, updateQuery,
		now, item.DetectionState, resurfaced, prior.ID,
		severity, summary, evidence, lastSeenFloor,
	).Scan(&writtenID)
	if err == sql.ErrNoRows {
		// Nothing material changed and last_seen is still fresh — the reconcile converged
		// without touching the row. This is the W2-13 no-op skip.
		stats.Skipped++
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to update finding: %w", err)
	}

	// History rows record genuine transitions only, exactly as before.
	if prior.DetectionState != item.DetectionState {
		s.recordFindingHistory(ctx, tx, prior.ID, nil, "detection_state", prior.DetectionState, item.DetectionState, "State changed by event")
	}
	if resurfaced {
		s.recordFindingHistory(ctx, tx, prior.ID, nil, "resurfaced_at", "", now.Format(time.RFC3339), "Finding resurfaced")
	}

	stats.Updated++
	if s.metricsService != nil {
		s.metricsService.RecordFindingUpserted(false)
		if prior.DetectionState != item.DetectionState {
			s.metricsService.RecordStateTransition(prior.DetectionState, item.DetectionState)
		}
	}
	return nil
}

// markFindingInactive marks a finding as inactive if it exists and is active
func (s *FindingsService) markFindingInactive(ctx context.Context, tenantID, controlID, subjectID uuid.UUID) error {
	query := `
		UPDATE findings
		SET detection_state = 'INACTIVE',
		    updated_at = NOW()
		WHERE tenant_id = $1 AND control_id = $2 AND subject_id = $3
		  AND detection_state = 'ACTIVE'
		  AND ` + complianceProducerScope("findings") + `
		RETURNING id
	`

	return shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		var findingID uuid.UUID
		err := tx.QueryRowContext(ctx, query, tenantID, controlID, subjectID).Scan(&findingID)
		if err == sql.ErrNoRows {
			// No active finding to mark inactive
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to mark finding inactive: %w", err)
		}

		// The WHERE clause guarantees the prior state was ACTIVE, so this is always an
		// ACTIVE->INACTIVE transition. (RETURNING detection_state yields the NEW value,
		// 'INACTIVE'; recording that as the history old_value corrupted the audit trail —
		// caught by TestIntegration_FindingFlip_WritesOneHistoryRowPerTransition.)
		const oldState = "ACTIVE"

		// Record metrics
		if s.metricsService != nil {
			s.metricsService.RecordFindingMarkedInactive()
			s.metricsService.RecordStateTransition(oldState, "INACTIVE")
		}

		// Record history
		s.recordFindingHistory(ctx, tx, findingID, nil, "detection_state", oldState, "INACTIVE", "Violation no longer detected")

		return nil
	})
}

// recordFindingHistory records a change to finding history. It writes to
// compliance_finding_history, which has no tenant_id and no RLS policy, so it
// execs on whatever executor it is given: pass the enclosing *sql.Tx to keep the
// history write inside the same tenant-scoped transaction as the finding write,
// or pass s.db for standalone (no-tx) callers.
func (s *FindingsService) recordFindingHistory(ctx context.Context, q sqlExecutor, findingID uuid.UUID, changedBy *uuid.UUID, fieldName, oldValue, newValue, reason string) {
	query := `
		INSERT INTO compliance_finding_history (
			finding_id, changed_by, changed_at, field_name, old_value, new_value, change_reason
		) VALUES ($1, $2, NOW(), $3, $4, $5, $6)
	`
	_, err := q.ExecContext(ctx, query, findingID, changedBy, fieldName, oldValue, newValue, reason)
	if err != nil {
		log.Printf("[FindingsService] Warning: Failed to record finding history: %v", err)
	}
}

// AutoCloseInactiveFindings auto-resolves workflow status for findings that have been INACTIVE for a grace period
// This implements the auto-close logic: findings that pass N consecutive evaluations get their workflow status resolved
func (s *FindingsService) AutoCloseInactiveFindings(ctx context.Context, gracePeriodDays int) error {
	if gracePeriodDays <= 0 {
		gracePeriodDays = 7 // Default 7 days
	}

	cutoffDate := time.Now().AddDate(0, 0, -gracePeriodDays)

	// Find findings that are INACTIVE, not suppressed, and not already resolved
	// RLS: cross-tenant sweep — runs on the bypass role (Phase 4). Uses bypassDB
	// (crypto_bypass) so the no-tenant_id sweep isn't fail-closed by RLS.
	query := `
		UPDATE findings
		SET workflow_status = 'RESOLVED',
		    updated_at = NOW()
		WHERE detection_state = 'INACTIVE'
		  AND workflow_status NOT IN ('RESOLVED', 'SUPPRESSED')
		  AND last_seen < $1
		  AND ` + complianceProducerScope("findings") + `
		  AND id IN (
		      SELECT id FROM findings
		      WHERE detection_state = 'INACTIVE'
		        AND workflow_status NOT IN ('RESOLVED', 'SUPPRESSED')
		        AND last_seen < $1
		        AND ` + complianceProducerScope("findings") + `
		      LIMIT 1000
		  )
		RETURNING id, workflow_status
	`

	var updatedIDs []uuid.UUID
	var oldStatuses []string
	rows, err := s.bypassDB.QueryContext(ctx, query, cutoffDate)
	if err != nil {
		return fmt.Errorf("failed to auto-close findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var findingID uuid.UUID
		var oldStatus string
		if err := rows.Scan(&findingID, &oldStatus); err != nil {
			continue
		}
		updatedIDs = append(updatedIDs, findingID)
		oldStatuses = append(oldStatuses, oldStatus)
	}

	// Record history for each updated finding. compliance_finding_history has no
	// tenant_id / RLS policy, but these rows were resolved cross-tenant on the
	// bypass pool, so keep the paired history writes on bypassDB too.
	for i, findingID := range updatedIDs {
		s.recordFindingHistory(ctx, s.bypassDB, findingID, nil, "workflow_status", oldStatuses[i], "RESOLVED",
			fmt.Sprintf("Auto-resolved after being INACTIVE for %d days", gracePeriodDays))
	}

	if len(updatedIDs) > 0 {
		log.Printf("[FindingsService] Auto-closed %d findings (INACTIVE for %d+ days)", len(updatedIDs), gracePeriodDays)
	}

	return nil
}

// UpdateWorkflowStatus updates the workflow status of a finding
func (s *FindingsService) UpdateWorkflowStatus(tenantID, findingID, changedBy uuid.UUID, workflowStatus string, suppressionReason *string, suppressedUntil *time.Time) error {
	// Validate workflow status
	validStatuses := map[string]bool{
		"NEW":        true,
		"NOTIFIED":   true,
		"RESOLVED":   true,
		"SUPPRESSED": true,
	}
	if !validStatuses[workflowStatus] {
		return fmt.Errorf("invalid workflow status: %s", workflowStatus)
	}

	// Get current finding to record history
	var oldWorkflowStatus string
	var oldSuppressedUntil *time.Time
	var oldSuppressionReason *string
	query := `
		SELECT workflow_status, suppressed_until, suppression_reason
		FROM findings cf
		WHERE cf.id = $1 AND cf.tenant_id = $2
		  AND ` + complianceProducerScope("cf") + `
		  AND ` + licensedFindingScopeSQL("cf", "$2") + `
	`
	// Update finding
	updateQuery := `
		UPDATE findings
		SET workflow_status = $1,
		    suppressed_until = $2,
		    suppression_reason = $3,
		    updated_at = NOW()
		WHERE id = $4 AND tenant_id = $5
		  AND ` + complianceProducerScope("findings") + `
	`
	ctx := context.Background()
	if err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, query, findingID, tenantID).Scan(&oldWorkflowStatus, &oldSuppressedUntil, &oldSuppressionReason); err != nil {
			if err == sql.ErrNoRows {
				return ErrFindingNotFound
			}
			return fmt.Errorf("failed to get finding: %w", err)
		}
		res, err := tx.ExecContext(ctx, updateQuery, workflowStatus, suppressedUntil, suppressionReason, findingID, tenantID)
		if err != nil {
			return fmt.Errorf("failed to update workflow status: %w", err)
		}
		if rows, err := res.RowsAffected(); err != nil {
			return err
		} else if rows == 0 {
			return ErrFindingNotFound
		}
		return nil
	}); err != nil {
		return err
	}

	// Record history
	oldValue := ""
	if oldWorkflowStatus != "" {
		oldValue = oldWorkflowStatus
	}
	newValue := workflowStatus
	reason := "Workflow status updated by user"
	if workflowStatus == "SUPPRESSED" && suppressionReason != nil {
		reason = fmt.Sprintf("Suppressed: %s", *suppressionReason)
	}
	s.recordFindingHistory(context.Background(), s.db, findingID, &changedBy, "workflow_status", oldValue, newValue, reason)

	return nil
}

// GetFindingHistory retrieves the history of a finding
func (s *FindingsService) GetFindingHistory(tenantID, findingID uuid.UUID) ([]models.ComplianceFindingHistory, error) {
	// Verify finding belongs to tenant and is in an activated/custom framework.
	var exists bool
	ctx := context.Background()
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		var err error
		exists, err = licensedFindingExistsInTx(ctx, tx, tenantID, findingID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to check finding: %w", err)
	}
	if !exists {
		return nil, ErrFindingNotFound
	}

	// Get history
	query := `
		SELECT id, finding_id, changed_by, changed_at, field_name, old_value, new_value, change_reason
		FROM compliance_finding_history
		WHERE finding_id = $1
		ORDER BY changed_at DESC
	`
	var history []models.ComplianceFindingHistory
	err = s.db.Select(&history, query, findingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding history: %w", err)
	}

	return history, nil
}
