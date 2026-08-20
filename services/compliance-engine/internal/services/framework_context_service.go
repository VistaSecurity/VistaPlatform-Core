package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
)

// FrameworkContextService provides a consolidated view of framework data for a tenant
// This service aggregates multiple API calls into a single response to reduce frontend overhead
type FrameworkContextService struct {
	db                      *sqlx.DB
	frameworkLicenseService *FrameworkLicenseService
	evaluationService       *EvaluationService
}

// NewFrameworkContextService creates a new framework context service
func NewFrameworkContextService(
	db *sqlx.DB,
	frameworkLicenseService *FrameworkLicenseService,
	evaluationService *EvaluationService,
) *FrameworkContextService {
	return &FrameworkContextService{
		db:                      db,
		frameworkLicenseService: frameworkLicenseService,
		evaluationService:       evaluationService,
	}
}

// FrameworkContextResponse is the consolidated response containing all framework data
type FrameworkContextResponse struct {
	Licensed           []models.LicensedFrameworkResponse `json:"licensed"`
	DefaultFrameworkID *string                            `json:"default_framework_id"`
	Status             *FrameworkContextStatus            `json:"status"`
	Subscription       *FrameworkSubscriptionInfo         `json:"subscription"`
	UserPreference     *string                            `json:"user_preference,omitempty"`
	LastUpdated        string                             `json:"last_updated"`
}

// FrameworkContextStatus contains compliance status for all licensed frameworks
type FrameworkContextStatus struct {
	Frameworks []FrameworkStatusItem `json:"frameworks"`
	// OverallScore averages only the frameworks that HAVE a score; nil when none do.
	OverallScore *float64 `json:"overall_score"`
}

// FrameworkStatusItem represents the compliance status for a single framework.
//
// ControlsPassing + ControlsFailing + ControlsNotAssessed == ControlsTotal, and
// CompliancePercent is scored over the ASSESSED subset only. It is nil —
// rendered "—" — when nothing was assessed; it is never 100 for "we didn't look".
//
// ControlsFailing counts every control with an ACTIVE, non-suppressed finding of
// ANY severity, so it now agrees with OpenFindingsControls by construction. The
// two used to disagree because status was derived from severity: a control whose
// worst finding was Low reported PASS.
type FrameworkStatusItem struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Code                 string `json:"code"`
	Version              string `json:"version"`
	CompliancePercent    *int   `json:"compliance_percent"`
	ControlsTotal        int    `json:"controls_total"`
	ControlsPassing      int    `json:"controls_passing"`
	ControlsFailing      int    `json:"controls_failing"`
	ControlsNotAssessed  int    `json:"controls_not_assessed"`
	OpenFindingsControls int    `json:"open_findings_controls"`
	IsDefault            bool   `json:"is_default"`
}

// FrameworkSubscriptionInfo contains tenant subscription information related to frameworks
type FrameworkSubscriptionInfo struct {
	Tier           string `json:"tier"`
	FrameworkLimit int    `json:"framework_limit"`
	FrameworksUsed int    `json:"frameworks_used"`
	CanAddMore     bool   `json:"can_add_more"`
}

// GetFrameworkContext returns all framework-related data for a tenant in a single call
func (s *FrameworkContextService) GetFrameworkContext(tenantID, userID uuid.UUID) (*FrameworkContextResponse, error) {
	response := &FrameworkContextResponse{
		LastUpdated: time.Now().Format(time.RFC3339),
	}

	// 1. Get licensed frameworks
	licensed, err := s.frameworkLicenseService.ListLicensedFrameworks(tenantID)
	if err != nil {
		log.Printf("WARN: Failed to get licensed frameworks for tenant %s: %v", tenantID, err)
		licensed = []models.LicensedFrameworkResponse{}
	}
	response.Licensed = licensed

	// 2. Find default framework ID
	// First, try to find one marked as default in licensed frameworks
	for _, lic := range licensed {
		if lic.IsDefault {
			response.DefaultFrameworkID = &lic.PlatformFrameworkID
			break
		}
	}

	// Fallback: If no default found but licensed frameworks exist, use Best Practices or first one
	if response.DefaultFrameworkID == nil && len(licensed) > 0 {
		// Prefer Best Practices if available
		for _, lic := range licensed {
			if lic.PlatformFramework != nil && lic.PlatformFramework.IsPlatformDefault {
				response.DefaultFrameworkID = &lic.PlatformFrameworkID
				break
			}
		}
		// If still no default, use the first licensed framework
		if response.DefaultFrameworkID == nil {
			response.DefaultFrameworkID = &licensed[0].PlatformFrameworkID
		}
	}

	// Final fallback: If no licensed frameworks at all, get platform default directly
	// This should never happen in normal operation (Best Practices is auto-licensed),
	// but provides defensive programming
	if response.DefaultFrameworkID == nil {
		var platformDefaultID uuid.UUID
		err := s.db.Get(&platformDefaultID, `
			SELECT id FROM platform_frameworks
			WHERE is_platform_default = true AND status = 'published'
			LIMIT 1
		`)
		if err == nil {
			defaultIDStr := platformDefaultID.String()
			response.DefaultFrameworkID = &defaultIDStr
			log.Printf("WARN: No licensed frameworks found for tenant %s, using platform default %s", tenantID, defaultIDStr)
		} else {
			log.Printf("ERROR: No licensed frameworks and platform default not found for tenant %s: %v", tenantID, err)
		}
	}

	// 3. Get user preference if userID is provided
	if userID != uuid.Nil {
		userPref, err := s.frameworkLicenseService.GetUserFrameworkPreference(userID, tenantID)
		if err != nil {
			log.Printf("WARN: Failed to get user framework preference: %v", err)
		} else if userPref != nil {
			prefStr := userPref.String()
			response.UserPreference = &prefStr
		}
	}

	// 4. Calculate compliance status for all licensed frameworks
	statusItems := make([]FrameworkStatusItem, 0, len(licensed))
	var totalScore float64
	var totalWeight int

	for _, lic := range licensed {
		// Skip if PlatformFramework is not populated (shouldn't happen, but defensive)
		if lic.PlatformFramework == nil {
			log.Printf("WARN: Licensed framework %s has nil PlatformFramework for tenant %s", lic.PlatformFrameworkID, tenantID)
			continue
		}

		frameworkID, err := uuid.Parse(lic.PlatformFrameworkID)
		if err != nil {
			log.Printf("WARN: Invalid framework ID %s for tenant %s: %v", lic.PlatformFrameworkID, tenantID, err)
			continue
		}

		// Calculate compliance score for this framework
		stats := s.calculateFrameworkStats(tenantID, frameworkID)
		openFindingsControls := s.countControlsWithOpenFindings(tenantID, frameworkID)

		statusItems = append(statusItems, FrameworkStatusItem{
			ID:                   lic.PlatformFrameworkID,
			Name:                 lic.PlatformFramework.Name,
			Code:                 lic.PlatformFramework.Code,
			Version:              lic.PlatformFramework.Version,
			CompliancePercent:    stats.Score,
			ControlsTotal:        stats.Total,
			ControlsPassing:      stats.Passing,
			ControlsFailing:      stats.Failing,
			ControlsNotAssessed:  stats.NotAssessed,
			OpenFindingsControls: openFindingsControls,
			IsDefault:            lic.IsDefault,
		})

		if stats.Score != nil {
			totalScore += float64(*stats.Score)
			totalWeight++
		}
	}

	var overallScore *float64
	if totalWeight > 0 {
		avg := totalScore / float64(totalWeight)
		overallScore = &avg
	}

	response.Status = &FrameworkContextStatus{
		Frameworks:   statusItems,
		OverallScore: overallScore,
	}

	// 5. Get subscription info
	response.Subscription = s.getSubscriptionInfo(tenantID, len(licensed))

	return response, nil
}

// countControlsWithOpenFindings returns how many of a framework's controls
// carry at least one ACTIVE, non-suppressed finding, regardless of severity —
// the same "has an open exposure" definition FindingsService.GetFindingsByControl
// uses. calculateFrameworkStats's ControlsFailing is severity-weighted (a
// control whose worst finding is Low scores as passing), so it can read lower
// than this raw count. Exposed separately rather than folded into
// ControlsFailing so the scoring model stays the single documented one
// (framework_score.go) while the UI still gets a truthful "has findings" signal.
func (s *FrameworkContextService) countControlsWithOpenFindings(tenantID, frameworkID uuid.UUID) int {
	var count int
	// RLS: compliance_findings — must run inside a tenant tx with app.tenant_id
	// set, or the plain pool returns zero rows silently (no error).
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRow(`
			SELECT COUNT(DISTINCT cf.control_id)
			FROM compliance_findings cf
			JOIN platform_framework_controls pfc ON pfc.id = cf.control_id
			WHERE cf.tenant_id = $1
			  AND pfc.framework_id = $2
			  AND cf.detection_state = 'ACTIVE'
			  AND (cf.workflow_status <> 'SUPPRESSED' OR cf.workflow_status IS NULL)
		`, tenantID, frameworkID).Scan(&count)
	})
	if err != nil {
		log.Printf("WARN: Failed to count controls with open findings for framework %s: %v", frameworkID, err)
		return 0
	}
	return count
}

// calculateFrameworkStats calculates compliance statistics for a framework.
//
// Scores through frameworkScore — the same severity-weighted model the live
// evaluation and the materialized rollup use. It used to count controls flat,
// which meant the Posture scorecard and the framework summary page could show
// different percentages for the same framework.
//
// Every failure path returns NO score rather than 100. A read error is
// exactly the state where the honest answer is "we do not know"; returning 100
// made a broken query look like a perfect posture.
func (s *FrameworkContextService) calculateFrameworkStats(tenantID, frameworkID uuid.UUID) scoreBreakdown {
	type controlRow struct {
		ID               uuid.UUID `db:"id"`
		BaselineSeverity string    `db:"baseline_severity"`
	}
	var controls []controlRow
	err := s.db.Select(&controls, `
		SELECT id, baseline_severity
		FROM platform_framework_controls
		WHERE framework_id = $1
	`, frameworkID)
	if err != nil {
		log.Printf("WARN: Failed to get controls for framework %s: %v", frameworkID, err)
		return scoreBreakdown{}
	}
	if len(controls) == 0 {
		return scoreBreakdown{}
	}

	controlIDs := make([]uuid.UUID, len(controls))
	for i, c := range controls {
		controlIDs[i] = c.ID
	}
	assessments, err := loadControlAssessments(context.Background(), s.db.DB, tenantID, controlIDs, "platform")
	if err != nil {
		log.Printf("WARN: Failed to load control assessments for framework %s: %v", frameworkID, err)
		return scoreBreakdown{Total: len(controls), NotAssessed: len(controls)}
	}

	outcomes := outcomesFromAssessments(controls,
		func(c controlRow) uuid.UUID { return c.ID },
		func(c controlRow) string { return c.BaselineSeverity },
		assessments)
	return frameworkScore(outcomes)
}

// unlimitedFrameworkLimit is how an unlimited cap is reported on the wire.
// FrameworkSubscriptionInfo.FrameworkLimit is a non-pointer int in a pinned
// contract, and -1 is the platform's existing "unlimited" encoding for numeric
// caps (see UsageLimits in auth-service).
const unlimitedFrameworkLimit = -1

// getSubscriptionInfo retrieves subscription information for a tenant.
//
// It reads through shared/services.LimitEnforcementService — the same path that
// ENFORCES the framework cap.
//
// The previous implementation selected `st.tier` and
// `st.compliance_framework_limit`, and NEITHER COLUMN EXISTS on
// subscription_tiers. Postgres therefore errored on every call, the error was
// swallowed by the "default to free tier" branch, and every tenant on every
// plan was reported as tier "free" with a framework limit of 1 — including
// Enterprise tenants with an unlimited cap. currentCount was also adjusted by a
// hardcoded -1 for Best Practices, duplicating a free-framework carve-out that
// countActiveFrameworkSubscriptions already applies properly.
func (s *FrameworkContextService) getSubscriptionInfo(tenantID uuid.UUID, currentCount int) *FrameworkSubscriptionInfo {
	info := &FrameworkSubscriptionInfo{}

	// Tier NAME (the real column) for display.
	var tierName sql.NullString
	if err := s.db.QueryRow(`
		SELECT st.name
		FROM tenants t
		JOIN subscription_tiers st ON t.subscription_tier_id = st.id
		WHERE t.id = $1
	`, tenantID).Scan(&tierName); err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("WARN: framework subscription tier lookup failed for tenant %s: %v", tenantID, err)
	}
	if tierName.Valid {
		info.Tier = tierName.String
	}

	// Cap + usage from the enforcement path. Asking whether ONE more framework
	// fits is exactly the question CanAddMore answers, so this can no longer
	// disagree with the 402 the tenant would actually get.
	enforcement := sharedservices.NewLimitEnforcementService(s.db.DB)
	check, err := enforcement.CheckComplianceFrameworkCountLimit(tenantID, 1)
	if err != nil {
		log.Printf("WARN: framework cap resolve failed for tenant %s: %v", tenantID, err)
		// Report what we know rather than a fabricated cap: usage as counted by
		// the caller, and "cannot add more" — the conservative answer, matching
		// how the resolver itself defaults.
		info.FrameworksUsed = currentCount
		return info
	}

	info.FrameworksUsed = check.CurrentUsage
	info.CanAddMore = check.Allowed
	if check.Limit == nil {
		info.FrameworkLimit = unlimitedFrameworkLimit
	} else {
		info.FrameworkLimit = *check.Limit
	}
	return info
}

// BatchEvaluateRequest represents a request to evaluate multiple frameworks
type BatchEvaluateRequest struct {
	FrameworkIDs []string               `json:"framework_ids" binding:"required"`
	Filters      models.ScenarioFilters `json:"filters,omitempty"`
}

// BatchEvaluateResponse represents the response from batch evaluation
type BatchEvaluateResponse struct {
	Results     []BatchEvaluateResult `json:"results"`
	LastUpdated string                `json:"last_updated"`
}

// BatchEvaluateResult represents evaluation results for a single framework
type BatchEvaluateResult struct {
	FrameworkID         string                `json:"framework_id"`
	FrameworkName       string                `json:"framework_name"`
	FrameworkCode       string                `json:"framework_code"`
	FrameworkVersion    string                `json:"framework_version"`
	Score               *int                  `json:"score"` // nil when nothing was assessed (#1369)
	ControlsTotal       int                   `json:"controls_total"`
	ControlsPassing     int                   `json:"controls_passing"`
	ControlsFailing     int                   `json:"controls_failing"`
	ControlsNotAssessed int                   `json:"controls_not_assessed"`
	AffectedAssets      int                   `json:"affected_assets"`
	Findings            []BatchFindingSummary `json:"findings,omitempty"`
	ControlBreakdown    []BatchControlStatus  `json:"control_breakdown,omitempty"`
}

// BatchFindingSummary represents a summarized finding
type BatchFindingSummary struct {
	ID        string `json:"id"`
	ControlID string `json:"control_id"`
	AssetID   string `json:"asset_id"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
}

// BatchControlStatus represents control status in batch evaluation
type BatchControlStatus struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"` // PASS | FAIL | NOT_ASSESSED
	Severity string `json:"severity"`
	// NotAssessedReason is machine-readable and empty unless Status is
	// NOT_ASSESSED: no_measurements / nothing_in_scope / check_error.
	NotAssessedReason string `json:"not_assessed_reason,omitempty"`
	Findings          int    `json:"findings"`
}

// BatchEvaluateFrameworks evaluates multiple frameworks in a single call
func (s *FrameworkContextService) BatchEvaluateFrameworks(tenantID uuid.UUID, request *BatchEvaluateRequest, includeDetails bool) (*BatchEvaluateResponse, error) {
	response := &BatchEvaluateResponse{
		Results:     make([]BatchEvaluateResult, 0, len(request.FrameworkIDs)),
		LastUpdated: time.Now().Format(time.RFC3339),
	}

	for _, frameworkIDStr := range request.FrameworkIDs {
		frameworkID, err := uuid.Parse(frameworkIDStr)
		if err != nil {
			log.Printf("WARN: Invalid framework ID: %s", frameworkIDStr)
			continue
		}

		// Validate that framework is licensed for this tenant (RLS: tenant_framework_licenses)
		var isLicensed bool
		err = shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(context.Background(), `
				SELECT EXISTS(
					SELECT 1 FROM tenant_framework_licenses
					WHERE tenant_id = $1 AND platform_framework_id = $2
					  AND `+sqlActiveSubscription+`
				)
			`, tenantID, frameworkID).Scan(&isLicensed)
		})
		if err != nil || !isLicensed {
			log.Printf("WARN: Framework %s not licensed for tenant %s", frameworkID, tenantID)
			continue
		}

		result, err := s.evaluateSingleFramework(tenantID, frameworkID, request.Filters, includeDetails)
		if err != nil {
			log.Printf("WARN: Failed to evaluate framework %s: %v", frameworkID, err)
			continue
		}

		response.Results = append(response.Results, *result)
	}

	return response, nil
}

// evaluateSingleFramework evaluates a single framework and returns the result
func (s *FrameworkContextService) evaluateSingleFramework(tenantID, frameworkID uuid.UUID, filters models.ScenarioFilters, includeDetails bool) (*BatchEvaluateResult, error) {
	// Get framework info
	var framework models.PlatformFramework
	err := s.db.Get(&framework, `
		SELECT id, code, name, version, description, organization, status,
		       is_platform_default, published_at, published_by, created_by, created_at, updated_at
		FROM platform_frameworks
		WHERE id = $1 AND status = 'published'
	`, frameworkID)
	if err != nil {
		return nil, fmt.Errorf("framework not found: %w", err)
	}

	// Get all controls for the framework
	var controls []struct {
		ID               uuid.UUID `db:"id"`
		ControlID        string    `db:"control_id"`
		Title            string    `db:"title"`
		BaselineSeverity string    `db:"baseline_severity"`
	}
	err = s.db.Select(&controls, `
		SELECT id, control_id, title, baseline_severity
		FROM platform_framework_controls
		WHERE framework_id = $1
		ORDER BY control_id
	`, frameworkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get controls: %w", err)
	}

	result := &BatchEvaluateResult{
		FrameworkID:      frameworkID.String(),
		FrameworkName:    framework.Name,
		FrameworkCode:    framework.Code,
		FrameworkVersion: framework.Version,
		ControlsTotal:    len(controls),
	}

	affectedAssetSet := make(map[uuid.UUID]bool)
	var controlBreakdown []BatchControlStatus
	var findings []BatchFindingSummary

	type controlFinding struct {
		ID       uuid.UUID
		AssetID  uuid.UUID
		Severity string
		Summary  string
	}

	// Load every ACTIVE, non-suppressed finding for ALL of the framework's
	// controls in ONE query, keyed by control, instead of one query per control.
	// A published framework routinely carries 50–150 controls, and this ran a
	// separate round-trip for each of them on every batch evaluate.
	//
	// The read hits the RLS-policied compliance_findings table, so it runs
	// inside a tenant tx that has set app.tenant_id.
	findingsByControl := make(map[uuid.UUID][]controlFinding, len(controls))
	controlIDs := make([]string, 0, len(controls))
	for _, control := range controls {
		controlIDs = append(controlIDs, control.ID.String())
	}

	ctx := context.Background()
	if len(controlIDs) > 0 {
		_ = shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
			query := `
				SELECT control_id, id, asset_id, severity, summary
				FROM compliance_findings
				WHERE tenant_id = $1 AND control_id = ANY($2::uuid[])
				  AND detection_state = 'ACTIVE'
				  AND (workflow_status != 'SUPPRESSED' OR workflow_status IS NULL)
				ORDER BY control_id
			`
			rows, qErr := tx.QueryContext(ctx, query, tenantID, pq.Array(controlIDs))
			if qErr != nil {
				if qErr != sql.ErrNoRows {
					log.Printf("WARN: Failed to get findings for framework %s: %v", frameworkID, qErr)
				}
				return nil
			}
			defer func() { _ = rows.Close() }()

			for rows.Next() {
				var controlID uuid.UUID
				var f controlFinding
				if scanErr := rows.Scan(&controlID, &f.ID, &f.AssetID, &f.Severity, &f.Summary); scanErr != nil {
					log.Printf("WARN: Failed to scan finding for framework %s: %v", frameworkID, scanErr)
					continue
				}
				findingsByControl[controlID] = append(findingsByControl[controlID], f)
			}
			if rowsErr := rows.Err(); rowsErr != nil {
				log.Printf("WARN: Failed to read findings for framework %s: %v", frameworkID, rowsErr)
			}
			return nil
		})
	}

	// Assessment state for every control, from the shared loader — so this
	// endpoint cannot disagree with the posture scorecard or the rollup.
	controlUUIDs := make([]uuid.UUID, 0, len(controls))
	for _, c := range controls {
		controlUUIDs = append(controlUUIDs, c.ID)
	}
	assessments, aErr := loadControlAssessments(ctx, s.db.DB, tenantID, controlUUIDs, "platform")
	if aErr != nil {
		return nil, fmt.Errorf("failed to load control assessments: %w", aErr)
	}

	// Roll the findings up per control, in control_id order (unchanged from the
	// per-control-query version — `controls` is already ORDER BY control_id).
	outcomes := make([]controlOutcome, 0, len(controls))
	for _, control := range controls {
		controlFindings := findingsByControl[control.ID]

		findingCount := len(controlFindings)
		assessment := assessments[control.ID]
		status := assessment.Status
		if status == "" {
			status = statusNotAssessed
			assessment.Reason = reasonNoMeasurements
		}
		severity := "Low"

		if findingCount > 0 {
			// Any violation fails the control; severity is the badge/weight, not
			// the verdict.
			status = statusFail
			for _, f := range controlFindings {
				affectedAssetSet[f.AssetID] = true
				switch f.Severity {
				case "Critical":
					severity = "Critical"
				case "High":
					if severity != "Critical" {
						severity = "High"
					}
				case "Med":
					if severity == "Low" {
						severity = "Med"
					}
				}

				// Add to findings list if details requested
				if includeDetails {
					findings = append(findings, BatchFindingSummary{
						ID:        f.ID.String(),
						ControlID: control.ID.String(),
						AssetID:   f.AssetID.String(),
						Severity:  f.Severity,
						Summary:   f.Summary,
					})
				}
			}
		}

		switch status {
		case statusFail:
			result.ControlsFailing++
		case statusNotAssessed:
			result.ControlsNotAssessed++
		default:
			result.ControlsPassing++
		}
		outcomes = append(outcomes, controlOutcome{BaselineSeverity: control.BaselineSeverity, Status: status})

		if includeDetails {
			reason := ""
			if status == statusNotAssessed {
				reason = assessment.Reason
			}
			controlBreakdown = append(controlBreakdown, BatchControlStatus{
				ID:                control.ID.String(),
				Name:              control.Title,
				Status:            status,
				Severity:          severity,
				NotAssessedReason: reason,
				Findings:          findingCount,
			})
		}
	}

	// Score through the ONE model — severity-weighted, over the assessed subset.
	// This used to be a local flat control count, which is precisely the
	// divergence framework_score.go exists to prevent.
	result.Score = frameworkScore(outcomes).Score

	result.AffectedAssets = len(affectedAssetSet)

	if includeDetails {
		result.ControlBreakdown = controlBreakdown
		result.Findings = findings
	}

	return result, nil
}
