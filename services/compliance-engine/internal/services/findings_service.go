package services

import (
	"context"
	"database/sql"
	"encoding/json"
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
)

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
		UPDATE compliance_findings
		SET assigned_to = $1, assigned_at = $2, assigned_by = $3, remediation_notes = $4, updated_at = $5
		WHERE id = $6 AND tenant_id = $7
	`
	return shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(context.Background(), query, assignedTo, now, assignedBy, notes, now, findingID, tenantID); err != nil {
			return fmt.Errorf("failed to assign finding owner: %w", err)
		}
		return nil
	})
}

// UnassignFindingOwner removes assignment from a finding
func (s *FindingsService) UnassignFindingOwner(tenantID, findingID uuid.UUID) error {
	query := `
		UPDATE compliance_findings
		SET assigned_to = NULL, assigned_at = NULL, assigned_by = NULL, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
	`
	return shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(context.Background(), query, findingID, tenantID); err != nil {
			return fmt.Errorf("failed to unassign finding owner: %w", err)
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
		SELECT id, tenant_id, control_id, asset_id, severity, summary, evidence,
		       first_seen, last_seen, assigned_to, assigned_at, assigned_by, remediation_notes,
		       detection_state, workflow_status, occurrence_count, resurfaced_at,
		       suppressed_until, suppression_reason, is_stale, last_evaluated_at,
		       evaluation_version, created_at, updated_at
		FROM compliance_findings
		WHERE id = $1 AND tenant_id = $2
	`
	var finding models.ComplianceFinding
	var evidenceJSONB []byte
	var assignedTo, assignedBy, remediationNotes, suppressionReason sql.NullString
	var assignedAt, resurfacedAt, suppressedUntil, lastEvaluatedAt sql.NullTime

	var notFound bool
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(context.Background(), query, findingID, tenantID).Scan(
			&finding.ID, &finding.TenantID, &finding.ControlID, &finding.AssetID,
			&finding.Severity, &finding.Summary, &evidenceJSONB,
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
		return nil, fmt.Errorf("finding not found")
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

// GetFindingsByAsset retrieves all findings for a specific asset
func (s *FindingsService) GetFindingsByAsset(tenantID, assetID uuid.UUID) ([]models.ComplianceFinding, error) {
	query := `
		SELECT id, tenant_id, control_id, asset_id, severity, summary, evidence,
		       first_seen, last_seen, assigned_to, assigned_at, assigned_by, remediation_notes,
		       detection_state, workflow_status, occurrence_count, resurfaced_at,
		       suppressed_until, suppression_reason, is_stale, last_evaluated_at,
		       evaluation_version, created_at, updated_at
		FROM compliance_findings
		WHERE tenant_id = $1 AND asset_id = $2
		  AND detection_state = 'ACTIVE'
		  AND (workflow_status != 'SUPPRESSED' OR workflow_status IS NULL)
		ORDER BY last_seen DESC
	`
	// Scan manually to handle JSONB evidence field
	var findings []models.ComplianceFinding
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(context.Background(), query, tenantID, assetID)
		if err != nil {
			return fmt.Errorf("failed to query findings by asset: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var finding models.ComplianceFinding
			var evidenceJSONB []byte
			var assignedTo, assignedBy, remediationNotes, suppressionReason sql.NullString
			var assignedAt, resurfacedAt, suppressedUntil, lastEvaluatedAt sql.NullTime

			err := rows.Scan(
				&finding.ID, &finding.TenantID, &finding.ControlID, &finding.AssetID,
				&finding.Severity, &finding.Summary, &evidenceJSONB,
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

			findings = append(findings, finding)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	// Get ticket counts for each finding
	for i := range findings {
		ticketCount, _ := s.GetTicketCountForFinding(tenantID, findings[i].ID)
		findings[i].TicketCount = ticketCount
	}

	return findings, nil
}

// FindingListFilters narrows ListFindings. Zero values mean "no filter".
type FindingListFilters struct {
	WorkflowStatus string     // NEW / NOTIFIED / RESOLVED / SUPPRESSED (case-insensitive)
	Severity       string     // Low / Med / High / Critical ("medium" is normalized to Med)
	AssignedTo     *uuid.UUID // findings assigned to this user
	Unassigned     bool       // findings with no assignee (ignored when AssignedTo is set)
	ControlID      *uuid.UUID
	FrameworkID    *uuid.UUID // platform or tenant framework — matched through its controls
}

// ListFindings returns a page of the tenant's ACTIVE compliance findings,
// newest-seen first, with the owning asset joined for display ().
// Suppressed findings are included (unlike GetFindingsByAsset) so a triage
// surface can show and un-suppress them; narrow with the WorkflowStatus
// filter when they aren't wanted.
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

	where := []string{"cf.tenant_id = $1", "cf.detection_state = 'ACTIVE'"}
	args := []interface{}{tenantID}
	idx := 2
	if filters.WorkflowStatus != "" {
		where = append(where, fmt.Sprintf("UPPER(cf.workflow_status) = UPPER($%d)", idx))
		args = append(args, filters.WorkflowStatus)
		idx++
	}
	if filters.Severity != "" {
		severity := filters.Severity
		if strings.EqualFold(severity, "medium") {
			severity = "Med" // DB stores Low / Med / High / Critical
		}
		where = append(where, fmt.Sprintf("LOWER(cf.severity) = LOWER($%d)", idx))
		args = append(args, severity)
		idx++
	}
	if filters.AssignedTo != nil {
		where = append(where, fmt.Sprintf("cf.assigned_to = $%d", idx))
		args = append(args, *filters.AssignedTo)
		idx++
	} else if filters.Unassigned {
		where = append(where, "cf.assigned_to IS NULL")
	}
	if filters.ControlID != nil {
		where = append(where, fmt.Sprintf("cf.control_id = $%d", idx))
		args = append(args, *filters.ControlID)
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
	whereSQL := strings.Join(where, " AND ")

	var total int
	countQuery := "SELECT COUNT(*) FROM compliance_findings cf WHERE " + whereSQL
	// Snapshot the filter args before LIMIT/OFFSET are appended for the page query.
	countArgs := append([]interface{}(nil), args...)

	// Scan manually to handle the JSONB evidence field (same as the other
	// finding readers). The asset join is display-only: hostname/IP/port/
	// environment for rendering a row without an N+1 per-asset fetch.
	//
	// cf.asset_id is NOT always a network_assets id — compliance_findings.asset_type
	// (compliance_findings_asset_type_check) is network_asset / certificate /
	// crypto_implementation, and only ~1 in 4 findings on a live tenant are the
	// network_asset kind (v0.5.7 live QA: 15 of 19). Without these two extra
	// joins, a certificate- or crypto-config-scoped finding resolved to no asset at
	// all and the UI fell back to rendering the raw asset_id UUID (H-9b).
	//   - certificate: join certificates directly, display common_name (fallback
	//     subject_dn) as DisplayName. A certificate can be bound to zero, one, or
	//     several assets (see assetsForCertificate below) so it is not resolved to
	//     a single host here — the certificate's own identity IS the object.
	//   - crypto_implementation: the config row carries its OWN asset_id pointing at
	//     the network asset it was observed on, so that asset's hostname/ip/port/
	//     environment/type resolve directly — this is the "asset it's deployed on"
	//     case. DisplayName additionally carries the protocol/cipher label so two
	//     configs on the same host are distinguishable.
	query := `
		SELECT cf.id, cf.tenant_id, cf.control_id, cf.asset_id, cf.severity, cf.summary,
		       cf.evidence, cf.first_seen, cf.last_seen, cf.assigned_to, cf.assigned_at,
		       cf.assigned_by, cf.remediation_notes, cf.detection_state, cf.workflow_status,
		       cf.occurrence_count, cf.resurfaced_at, cf.suppressed_until, cf.suppression_reason,
		       cf.is_stale, cf.last_evaluated_at, cf.evaluation_version,
		       cf.created_at, cf.updated_at,
		       na.hostname, na.ip_address, na.port, na.asset_type, na.environment,
		       cert.common_name, cert.subject_dn,
		       ci_na.hostname, ci_na.ip_address, ci_na.port, ci_na.asset_type, ci_na.environment,
		       ci.protocol, ci.protocol_version
		FROM compliance_findings cf
		LEFT JOIN network_assets na ON na.id = cf.asset_id AND na.deleted_at IS NULL AND cf.asset_type = 'network_asset'
		LEFT JOIN certificates cert ON cert.id = cf.asset_id AND cf.asset_type = 'certificate'
		LEFT JOIN crypto_implementations ci ON ci.id = cf.asset_id AND cf.asset_type = 'crypto_implementation'
		LEFT JOIN network_assets ci_na ON ci_na.id = ci.asset_id AND ci_na.deleted_at IS NULL
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
			var assignedTo, assignedBy, remediationNotes, suppressionReason sql.NullString
			var assignedAt, resurfacedAt, suppressedUntil, lastEvaluatedAt sql.NullTime
			var aHostname, aIP, aType, aEnv sql.NullString
			var aPort sql.NullInt64
			var certCommonName, certSubjectDN sql.NullString
			var ciHostname, ciIP, ciType, ciEnv sql.NullString
			var ciPort sql.NullInt64
			var ciProtocol, ciProtocolVersion sql.NullString

			err := rows.Scan(
				&finding.ID, &finding.TenantID, &finding.ControlID, &finding.AssetID,
				&finding.Severity, &finding.Summary, &evidenceJSONB,
				&finding.FirstSeen, &finding.LastSeen, &assignedTo, &assignedAt,
				&assignedBy, &remediationNotes, &finding.DetectionState,
				&finding.WorkflowStatus, &finding.OccurrenceCount, &resurfacedAt,
				&suppressedUntil, &suppressionReason, &finding.IsStale,
				&lastEvaluatedAt, &finding.EvaluationVersion,
				&finding.CreatedAt, &finding.UpdatedAt,
				&aHostname, &aIP, &aPort, &aType, &aEnv,
				&certCommonName, &certSubjectDN,
				&ciHostname, &ciIP, &ciPort, &ciType, &ciEnv,
				&ciProtocol, &ciProtocolVersion,
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
			switch {
			case aHostname.Valid || aIP.Valid || aType.Valid || aEnv.Valid || aPort.Valid:
				// asset_type = network_asset: resolved directly.
				asset := &models.Asset{ID: finding.AssetID, TenantID: finding.TenantID}
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
				// asset_type = certificate: the certificate itself is the named object.
				asset := &models.Asset{ID: finding.AssetID, TenantID: finding.TenantID, AssetType: "certificate"}
				name := certCommonName.String
				if name == "" {
					name = certSubjectDN.String
				}
				if name != "" {
					asset.DisplayName = &name
				}
				finding.Asset = asset
			case ciHostname.Valid || ciIP.Valid || ciProtocol.Valid:
				// asset_type = crypto_implementation: resolve to the network asset the
				// configuration was observed on (ci.asset_id), plus a protocol/version
				// label so multiple configs on one host stay distinguishable.
				asset := &models.Asset{ID: finding.AssetID, TenantID: finding.TenantID}
				if ciHostname.Valid {
					asset.Hostname = &ciHostname.String
				}
				if ciIP.Valid {
					asset.IPAddress = &ciIP.String
				}
				if ciPort.Valid {
					port := int(ciPort.Int64)
					asset.Port = &port
				}
				if ciType.Valid {
					asset.AssetType = ciType.String
				}
				if ciEnv.Valid {
					asset.Environment = &ciEnv.String
				}
				if ciProtocol.Valid {
					label := ciProtocol.String
					if ciProtocolVersion.Valid && ciProtocolVersion.String != "" {
						label = label + " " + ciProtocolVersion.String
					}
					asset.DisplayName = &label
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

// SeverityCounts is the per-severity finding tally within a control group.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Med      int `json:"med"`
	Low      int `json:"low"`
}

// FindingsByControlGroup is active findings aggregated for one framework control
// (ADR-0007 item 4) — backs the Posture "top exposures" ranking. Read off the
// materialized compliance_findings table (ADR-0014), so it stays consistent with
// the Findings page rather than re-evaluating live.
type FindingsByControlGroup struct {
	ControlID      uuid.UUID      `json:"control_id"`
	ControlName    string         `json:"control_name"`
	FrameworkID    uuid.UUID      `json:"framework_id"`
	FrameworkName  string         `json:"framework_name"`
	WorstSeverity  string         `json:"worst_severity"` // Critical | High | Med | Low
	FindingCount   int            `json:"finding_count"`
	AffectedAssets int            `json:"affected_assets"`
	SeverityCounts SeverityCounts `json:"severity_counts"`
	// TargetKind names what AffectedAssets is actually counting: "asset" when
	// every finding in the group targets a network asset, "certificate" /
	// "configuration" when every finding targets that other kind, "mixed"
	// otherwise (compliance_findings.asset_type is network_asset / certificate /
	// crypto_implementation — see compliance_findings_asset_type_check). L-5:
	// the UI used to always say "N assets" even when the objects were
	// certificates, which reads as wrong to anyone who knows what they're
	// looking at.
	TargetKind string `json:"target_kind"`
}

// targetKindFromAssetTypes maps the set of asset_type values observed in a
// findings-by-control group to the display noun for AffectedAssets.
func targetKindFromAssetTypes(assetTypes []string) string {
	if len(assetTypes) != 1 {
		return "mixed"
	}
	switch assetTypes[0] {
	case "certificate":
		return "certificate"
	case "crypto_implementation":
		return "configuration"
	default:
		return "asset"
	}
}

// severityFromRank maps the SQL CASE rank back to the stored severity label.
func severityFromRank(rank int) string {
	switch rank {
	case 4:
		return "Critical"
	case 3:
		return "High"
	case 2:
		return "Med"
	case 1:
		return "Low"
	default:
		return "Low"
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
	// COALESCE picks whichever side matched. detection_state='ACTIVE' mirrors
	// ListFindings so the ranking agrees with the Findings page.
	const query = `
		SELECT
			cf.control_id AS control_id,
			COALESCE(pfc.title, tfc.title, 'Unknown control')      AS control_name,
			COALESCE(pf.id, tf.id)                                 AS framework_id,
			COALESCE(pf.name, tf.name, 'Unknown framework')        AS framework_name,
			COUNT(*)                                               AS finding_count,
			COUNT(DISTINCT cf.asset_id)                            AS asset_count,
			ARRAY_AGG(DISTINCT cf.asset_type)                      AS asset_types,
			COUNT(*) FILTER (WHERE cf.severity = 'Critical')       AS crit,
			COUNT(*) FILTER (WHERE cf.severity = 'High')           AS high,
			COUNT(*) FILTER (WHERE cf.severity = 'Med')            AS med,
			COUNT(*) FILTER (WHERE cf.severity = 'Low')            AS low,
			MAX(CASE cf.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
			                     WHEN 'Med' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END) AS worst_rank
		FROM compliance_findings cf
		LEFT JOIN platform_framework_controls pfc ON pfc.id = cf.control_id
		LEFT JOIN platform_frameworks pf          ON pf.id = pfc.framework_id
		LEFT JOIN tenant_framework_controls tfc   ON tfc.id = cf.control_id
		LEFT JOIN tenant_frameworks tf            ON tf.id = tfc.framework_id
		WHERE cf.tenant_id = $1
		  AND cf.detection_state = 'ACTIVE'
		  AND (pfc.id IS NOT NULL OR tfc.id IS NOT NULL)
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
		AssetTypes    pq.StringArray `db:"asset_types"`
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
				&r.FindingCount, &r.AssetCount, &r.AssetTypes, &r.Crit, &r.High, &r.Med, &r.Low, &r.WorstRank,
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
			SeverityCounts: SeverityCounts{Critical: r.Crit, High: r.High, Med: r.Med, Low: r.Low},
			TargetKind:     targetKindFromAssetTypes([]string(r.AssetTypes)),
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
	// same materialized compliance_findings table the Findings page and
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
	query := `
		SELECT
			detection_state,
			COUNT(*) as count
		FROM compliance_findings
		WHERE tenant_id = $1
		GROUP BY detection_state
	`
	// Get counts by workflow status
	workflowQuery := `
		SELECT
			workflow_status,
			COUNT(*) as count
		FROM compliance_findings
		WHERE tenant_id = $1
		  AND detection_state = 'ACTIVE'
		GROUP BY workflow_status
	`
	// Get resurfaced findings count
	resurfacedQuery := `
		SELECT COUNT(*)
		FROM compliance_findings
		WHERE tenant_id = $1
		  AND detection_state = 'ACTIVE'
		  AND resurfaced_at IS NOT NULL
	`
	// Get counts by severity, ACTIVE findings only, tenant-wide (no control-join,
	// no LIMIT) — the same detection_state scope GetFindingsByControl uses, so
	// this is the true tenant-wide total rather than a sum over a capped list of
	// control groups.
	severityQuery := `
		SELECT
			severity,
			COUNT(*) as count
		FROM compliance_findings
		WHERE tenant_id = $1
		  AND detection_state = 'ACTIVE'
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
			case "Critical":
				stats.SeverityCounts.Critical = count
			case "High":
				stats.SeverityCounts.High = count
			case "Med":
				stats.SeverityCounts.Med = count
			case "Low":
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
	// Verify finding exists and belongs to tenant
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM compliance_findings WHERE id = $1 AND tenant_id = $2)`
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), query, findingID, tenantID).Scan(&exists)
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to check finding: %w", err)
	}
	if !exists {
		return "", "", fmt.Errorf("finding not found")
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

	// Mark all findings for this asset as INACTIVE
	query := `
		UPDATE compliance_findings
		SET detection_state = 'INACTIVE',
		    updated_at = NOW()
		WHERE tenant_id = $1 AND asset_id = $2 AND detection_state = 'ACTIVE'
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
// UI, not an audit field (compliance_finding_history is the audit trail), so an hour of
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

// findingUpsert is one (control, asset) pair to materialize in a batched reconcile write.
type findingUpsert struct {
	ControlID      uuid.UUID
	AssetID        uuid.UUID
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
// (tenant_id, control_id, asset_id). Thin wrapper over the batch path so there is exactly
// one implementation of the write semantics.
func (s *FindingsService) upsertFinding(ctx context.Context, tenantID, controlID, assetID uuid.UUID, finding *models.ComplianceFinding, detectionState string) error {
	return s.upsertFindingChunk(ctx, tenantID, []findingUpsert{{
		ControlID:      controlID,
		AssetID:        assetID,
		Finding:        finding,
		DetectionState: detectionState,
	}})
}

// upsertFindings materializes a whole reconcile pass's findings, ONE TRANSACTION PER
// CHUNK instead of one per finding. Before W2-13 each (control, asset) pair paid its own
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
			log.Printf("[FindingsService] upsert finding failed (control=%s asset=%s): %v", chunk[i].ControlID, chunk[i].AssetID, err)
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
			key := controlAsset{ControlID: item.ControlID, AssetID: item.AssetID}
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

func loadExistingFindings(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, items []findingUpsert) (map[controlAsset]priorFinding, error) {
	controlIDs := make([]string, len(items))
	assetIDs := make([]string, len(items))
	for i, it := range items {
		controlIDs[i] = it.ControlID.String()
		assetIDs[i] = it.AssetID.String()
	}

	const query = `
		SELECT control_id, asset_id, id, detection_state
		FROM compliance_findings
		WHERE tenant_id = $1
		  AND detection_state <> 'ARCHIVED'
		  AND (control_id, asset_id) IN (
		      SELECT p.c, p.a FROM unnest($2::uuid[], $3::uuid[]) AS p(c, a)
		  )
	`
	rows, err := tx.QueryContext(ctx, query, tenantID, pq.Array(controlIDs), pq.Array(assetIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to load existing findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[controlAsset]priorFinding, len(items))
	for rows.Next() {
		var key controlAsset
		var prior priorFinding
		if err := rows.Scan(&key.ControlID, &key.AssetID, &prior.ID, &prior.DetectionState); err != nil {
			return nil, fmt.Errorf("failed to scan existing finding: %w", err)
		}
		out[key] = prior
	}
	return out, rows.Err()
}

// insertFinding creates a finding that the prefetch did not see.
//
// ON CONFLICT against idx_findings_identity (the partial unique index on
// tenant_id, control_id, asset_id WHERE detection_state <> 'ARCHIVED') keeps the
// duplicate-row race backstopped WITHOUT raising a unique violation — which matters more
// now than it did per-row, because an error here would abort the whole chunk's
// transaction rather than just this pair. `xmax = 0` distinguishes a true insert from a
// conflict-update so history is only written for a genuine creation.
func (s *FindingsService) insertFinding(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, item findingUpsert, now time.Time, stats *findingWriteStats) error {
	finding := item.Finding
	findingID := uuid.New()
	severity := "Low"
	summary := "Compliance violation detected"
	assetType := "network_asset"
	firstSeen, lastSeen := now, now
	evidenceJSON := normalizeFindingEvidence(finding)

	if finding != nil {
		findingID = finding.ID
		severity = finding.Severity
		summary = finding.Summary
		if finding.AssetType != "" {
			assetType = finding.AssetType
		}
		if !finding.FirstSeen.IsZero() {
			firstSeen = finding.FirstSeen
		}
		if !finding.LastSeen.IsZero() {
			lastSeen = finding.LastSeen
		}
	}

	const insertQuery = `
		INSERT INTO compliance_findings (
			id, tenant_id, control_id, asset_id, asset_type, severity, summary, evidence,
			first_seen, last_seen, detection_state, workflow_status, occurrence_count,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (tenant_id, control_id, asset_id) WHERE detection_state <> 'ARCHIVED'
		DO UPDATE SET
			last_seen = EXCLUDED.last_seen,
			occurrence_count = compliance_findings.occurrence_count + 1,
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
		findingID, tenantID, item.ControlID, item.AssetID, assetType, severity, summary, evidenceJSON,
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
	log.Printf("[FindingsService] INFO: Created new finding: finding_id=%s, control_id=%s, asset_id=%s, severity=%s, detection_state=%s",
		storedID, item.ControlID, item.AssetID, severity, item.DetectionState)
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
		severity = item.Finding.Severity
		summary = item.Finding.Summary
		evidence = normalizeFindingEvidence(item.Finding)
	}

	const updateQuery = `
		UPDATE compliance_findings
		SET last_seen = $1,
		    occurrence_count = occurrence_count + 1,
		    detection_state = $2,
		    workflow_status = CASE
		        WHEN $3::boolean AND workflow_status <> 'SUPPRESSED' THEN 'NEW'
		        ELSE workflow_status
		    END,
		    resurfaced_at = CASE WHEN $3::boolean THEN $1 ELSE resurfaced_at END,
		    severity = COALESCE($5::varchar, severity),
		    summary = COALESCE($6::text, summary),
		    evidence = COALESCE($7::jsonb, evidence),
		    updated_at = $1
		WHERE id = $4
		  AND (
		        detection_state IS DISTINCT FROM $2
		     OR severity IS DISTINCT FROM COALESCE($5::varchar, severity)
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
func (s *FindingsService) markFindingInactive(ctx context.Context, tenantID, controlID, assetID uuid.UUID) error {
	query := `
		UPDATE compliance_findings
		SET detection_state = 'INACTIVE',
		    updated_at = NOW()
		WHERE tenant_id = $1 AND control_id = $2 AND asset_id = $3
		  AND detection_state = 'ACTIVE'
		RETURNING id
	`

	return shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		var findingID uuid.UUID
		err := tx.QueryRowContext(ctx, query, tenantID, controlID, assetID).Scan(&findingID)
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
		UPDATE compliance_findings
		SET workflow_status = 'RESOLVED',
		    updated_at = NOW()
		WHERE detection_state = 'INACTIVE'
		  AND workflow_status NOT IN ('RESOLVED', 'SUPPRESSED')
		  AND last_seen < $1
		  AND id IN (
		      SELECT id FROM compliance_findings
		      WHERE detection_state = 'INACTIVE'
		        AND workflow_status NOT IN ('RESOLVED', 'SUPPRESSED')
		        AND last_seen < $1
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
		FROM compliance_findings
		WHERE id = $1 AND tenant_id = $2
	`
	// Update finding
	updateQuery := `
		UPDATE compliance_findings
		SET workflow_status = $1,
		    suppressed_until = $2,
		    suppression_reason = $3,
		    updated_at = NOW()
		WHERE id = $4 AND tenant_id = $5
	`
	if err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(context.Background(), query, findingID, tenantID).Scan(&oldWorkflowStatus, &oldSuppressedUntil, &oldSuppressionReason); err != nil {
			return fmt.Errorf("failed to get finding: %w", err)
		}
		if _, err := tx.ExecContext(context.Background(), updateQuery, workflowStatus, suppressedUntil, suppressionReason, findingID, tenantID); err != nil {
			return fmt.Errorf("failed to update workflow status: %w", err)
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
	// Verify finding belongs to tenant
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM compliance_findings WHERE id = $1 AND tenant_id = $2)`
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), checkQuery, findingID, tenantID).Scan(&exists)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to check finding: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("finding not found")
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
