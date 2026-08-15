package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// ErrFrameworkNotFound is returned by EvaluateFramework when the requested
// framework_id resolves to neither a published platform framework nor a
// tenant custom policy. Callers (e.g. the /summary HTTP handler) should map
// this to a 404 rather than a 500 — it typically means a stale client-side
// framework reference (for example, an ID cached in the browser from a prior
// seed run), not a server fault.
var ErrFrameworkNotFound = errors.New("framework not found")

// EvaluationService handles compliance evaluation and scoring
type EvaluationService struct {
	db            *sqlx.DB
	ruleEvaluator *RuleEvaluator
}

// NewEvaluationService creates a new evaluation service
func NewEvaluationService(db *sqlx.DB, ruleEvaluator ...*RuleEvaluator) *EvaluationService {
	svc := &EvaluationService{db: db}
	if len(ruleEvaluator) > 0 {
		svc.ruleEvaluator = ruleEvaluator[0]
	}
	return svc
}

// SummaryResponse represents the compliance summary for a framework
type SummaryResponse struct {
	Framework   FrameworkSummary `json:"framework"`
	LastUpdated string           `json:"last_updated"`
	KPIs        KPISummary       `json:"kpis"`
	Families    []FamilySummary  `json:"families"`
	Controls    []ControlSummary `json:"controls"`
}

// FrameworkSummary represents framework information
type FrameworkSummary struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// KPISummary represents key performance indicators.
//
// Score is a POINTER: a framework with no ASSESSED controls has no score, and
// any sentinel integer would be read as a posture claim. The UI renders
// nil as "—". ControlsAssessed / ControlsTotal is the coverage figure that
// accompanies it ("8 of 11 controls assessed").
//
// The old Warn KPI is gone with the WARN status: it was only ever reachable from
// a Med baseline severity and earned no score weight.
type KPISummary struct {
	Score               *int `json:"score"`
	FailingControls     int  `json:"failing_controls"`
	NotAssessedControls int  `json:"not_assessed_controls"`
	ControlsTotal       int  `json:"controls_total"`
	ControlsAssessed    int  `json:"controls_assessed"`
	AffectedAssets      int  `json:"affected_assets"`
	OverridesActive     int  `json:"overrides_active"`
}

// FamilySummary represents family-level summary
type FamilySummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pass        int    `json:"pass"`
	Fail        int    `json:"fail"`
	NotAssessed int    `json:"not_assessed"`
}

// ControlSummary represents control-level summary
type ControlSummary struct {
	ID                string `json:"id"`
	ControlID         string `json:"control_id"`
	Name              string `json:"name"`
	Family            string `json:"family"`
	StatusEffective   string `json:"status_effective"`
	StatusBaseline    string `json:"status_baseline"`
	SeverityEffective string `json:"severity_effective"`
	SeverityBaseline  string `json:"severity_baseline"`
	// NotAssessedReason is machine-readable and empty unless the status is
	// NOT_ASSESSED: no_measurements / nothing_in_scope / check_error. The UI
	// shows one bucket ("Not assessed") with a different sentence per reason.
	NotAssessedReason string `json:"not_assessed_reason,omitempty"`
	Findings          int    `json:"findings"`
	LastSeen          string `json:"last_seen"`
	HasOverride       bool   `json:"has_override"`
}

// ControlDetailsResponse represents detailed control information
type ControlDetailsResponse struct {
	Control         ControlDetailsControl `json:"control"`
	Rationale       string                `json:"rationale"`
	EvidenceSummary EvidenceSummary       `json:"evidence_summary"`
	Findings        []FindingSummary      `json:"findings"`
	Overrides       OverrideSummary       `json:"overrides"`
}

// ControlDetailsControl represents control details
type ControlDetailsControl struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Score  *int   `json:"score,omitempty"`
}

// EvidenceSummary represents evidence summary
type EvidenceSummary struct {
	FailingFindingsCount int    `json:"failing_findings_count"`
	AffectedAssetsCount  int    `json:"affected_assets_count"`
	LastSeen             string `json:"last_seen"`
}

// FindingSummary represents a finding summary
type FindingSummary struct {
	ID               string  `json:"id"`
	Severity         string  `json:"severity"`
	Asset            string  `json:"asset"`
	Summary          string  `json:"summary"`
	FirstSeen        string  `json:"first_seen"`
	LastSeen         string  `json:"last_seen"`
	AssignedTo       *string `json:"assigned_to,omitempty"`
	AssignedAt       *string `json:"assigned_at,omitempty"`
	AssignedBy       *string `json:"assigned_by,omitempty"`
	RemediationNotes *string `json:"remediation_notes,omitempty"`
	TicketCount      int     `json:"ticket_count,omitempty"`
}

// OverrideSummary represents override information
type OverrideSummary struct {
	Disregard        bool                    `json:"disregard"`
	SeverityOverride *SeverityOverrideDetail `json:"severity_override,omitempty"`
}

// SeverityOverrideDetail represents severity override details
type SeverityOverrideDetail struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Rationale string `json:"rationale"`
	By        string `json:"by"`
	At        string `json:"at"`
}

// EvaluateFramework evaluates compliance for a framework with filters and overrides.
// For platform frameworks, validates that the tenant has an active subscription.
func (s *EvaluationService) EvaluateFramework(tenantID, frameworkID uuid.UUID, version string, filters models.ScenarioFilters, scenarioID *uuid.UUID) (*SummaryResponse, error) {
	// Resolve framework: platform first, then tenant (custom policy).
	var framework models.Framework
	var frameworkSource string // "platform" or "tenant"

	err := s.db.Get(&framework, `
		SELECT id, code, name, version, description,
		       (status = 'published') as active, created_at, updated_at
		FROM platform_frameworks
		WHERE id = $1 AND status = 'published'
	`, frameworkID)
	if err == nil {
		frameworkSource = "platform"

		// License enforcement: verify tenant has active subscription for platform frameworks.
		// tenant_framework_licenses is RLS-policied: scope the read with app.tenant_id.
		ctx := context.Background()
		var isLicensed bool
		var licErr error
		if tx, txErr := s.db.BeginTxx(ctx, nil); txErr != nil {
			licErr = fmt.Errorf("begin tx: %w", txErr)
		} else {
			func() {
				defer func() { _ = tx.Rollback() }()
				if err := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); err != nil {
					licErr = err
					return
				}
				if err := tx.Get(&isLicensed, `
					SELECT EXISTS(
						SELECT 1 FROM tenant_framework_licenses
						WHERE tenant_id = $1 AND platform_framework_id = $2
						  AND `+sqlActiveSubscription+`
					)
				`, tenantID, frameworkID); err != nil {
					licErr = err
					return
				}
				licErr = tx.Commit()
			}()
		}
		if licErr != nil {
			log.Printf("WARN: License check failed for tenant %s framework %s: %v (allowing evaluation)", tenantID, frameworkID, licErr)
		} else if !isLicensed {
			return nil, fmt.Errorf("framework not licensed: tenant does not have an active subscription for this framework")
		}
	} else {
		// Try tenant_frameworks (custom policies)
		var tenantFramework struct {
			ID          uuid.UUID `db:"id"`
			Name        string    `db:"name"`
			Version     string    `db:"version"`
			Description string    `db:"description"`
		}
		// tenant_frameworks is RLS-policied: scope the read with app.tenant_id.
		ctx := context.Background()
		if tx, txErr := s.db.BeginTxx(ctx, nil); txErr != nil {
			err = fmt.Errorf("begin tx: %w", txErr)
		} else {
			func() {
				defer func() { _ = tx.Rollback() }()
				if scErr := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); scErr != nil {
					err = scErr
					return
				}
				if gErr := tx.Get(&tenantFramework, `
					SELECT id, name, version, description
					FROM tenant_frameworks
					WHERE id = $1 AND tenant_id = $2
				`, frameworkID, tenantID); gErr != nil {
					err = gErr
					return
				}
				err = tx.Commit()
			}()
		}
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w: %s", ErrFrameworkNotFound, frameworkID)
			}
			return nil, fmt.Errorf("failed to get framework: %w", err)
		}
		frameworkSource = "tenant"
		framework = models.Framework{
			ID:          tenantFramework.ID,
			Code:        "",
			Name:        tenantFramework.Name,
			Version:     tenantFramework.Version,
			Description: tenantFramework.Description,
			Active:      true,
		}
	}

	// Get all controls for the framework (use frameworkSource to avoid redundant table probing)
	controls, err := s.getControlsForFramework(frameworkID, filters, frameworkSource)
	if err != nil {
		return nil, fmt.Errorf("failed to get controls: %w", err)
	}

	// Get overrides (global + scenario-specific)
	overrides, err := s.getOverrides(tenantID, scenarioID)
	if err != nil {
		return nil, fmt.Errorf("failed to get overrides: %w", err)
	}

	// Evaluate each control
	controlSummaries := make([]ControlSummary, 0, len(controls))
	familyCounts := make(map[string]map[string]int) // family_id -> {pass, fail, not_assessed}

	var totalControls, passControls, failingControls, notAssessedControls int
	outcomes := make([]controlOutcome, 0, len(controls)) // folded by frameworkScore
	affectedAssetSet := make(map[uuid.UUID]bool)

	// Use the framework source determined above for live evaluation
	frameworkType := frameworkSource

	// Materialized assessment for every control, from the SAME loader the rollup
	// and the posture scorecard use. Without it this path defaulted an
	// unviolated control to PASS, which is how a framework with no measurements
	// configured — or a tenant with no inventory at all — scored 100.
	controlIDs := make([]uuid.UUID, 0, len(controls))
	for _, c := range controls {
		controlIDs = append(controlIDs, c.ID)
	}
	assessments, err := loadControlAssessments(context.Background(), s.db.DB, tenantID, controlIDs, frameworkType)
	if err != nil {
		return nil, fmt.Errorf("failed to load control assessments: %w", err)
	}

	for _, control := range controls {
		// Get stored findings for this control
		findings, err := s.getFindingsForControl(tenantID, control.ID, filters)
		if err != nil {
			return nil, fmt.Errorf("failed to get findings for control %s: %w", control.ControlID, err)
		}

		// If no stored findings and live evaluator is available, evaluate on-demand.
		// This handles new tenants and cases where NATS events haven't been processed yet.
		var baselineStatus, baselineSeverity, notAssessedReason string
		findingCount := len(findings)

		if findingCount == 0 && s.ruleEvaluator != nil {
			result, evalErr := s.ruleEvaluator.EvaluateControl(tenantID, control.ID, frameworkType)
			if evalErr == nil && result != nil {
				// The live evaluator is the only path that can tell
				// nothing-in-scope and check-error apart, because it is the only
				// one that actually runs extraction.
				baselineStatus = strings.ToUpper(result.Status)
				baselineSeverity = result.Severity
				notAssessedReason = result.NotAssessedReason
				findingCount = len(result.Findings)
				for _, f := range result.Findings {
					affectedAssetSet[f.AssetID] = true
				}
			} else {
				baselineStatus, baselineSeverity, notAssessedReason = s.controlStatusFromAssessment(findings, assessments[control.ID])
			}
		} else {
			baselineStatus, baselineSeverity, notAssessedReason = s.controlStatusFromAssessment(findings, assessments[control.ID])
			for _, finding := range findings {
				affectedAssetSet[finding.AssetID] = true
			}
		}

		// Apply overrides
		effectiveStatus, effectiveSeverity, hasOverride := s.applyOverrides(control.ID, baselineStatus, baselineSeverity, overrides)

		// Get family name, handling nil Family (for tenant frameworks)
		familyName := ""
		if control.Family != nil {
			familyName = control.Family.Name
		}

		// Create control summary
		if effectiveStatus != statusNotAssessed {
			notAssessedReason = ""
		}
		controlSummary := ControlSummary{
			ID:                control.ID.String(),
			ControlID:         control.ControlID,
			Name:              control.Title,
			Family:            familyName,
			StatusEffective:   effectiveStatus,
			StatusBaseline:    baselineStatus,
			SeverityEffective: effectiveSeverity,
			SeverityBaseline:  baselineSeverity,
			NotAssessedReason: notAssessedReason,
			Findings:          findingCount,
			LastSeen:          s.getLastSeen(findings),
			HasOverride:       hasOverride,
		}
		controlSummaries = append(controlSummaries, controlSummary)

		// Update counters
		totalControls++
		outcomes = append(outcomes, controlOutcome{
			BaselineSeverity: control.BaselineSeverity,
			Status:           effectiveStatus,
		})

		switch effectiveStatus {
		case statusPass:
			passControls++
		case statusFail:
			failingControls++
		case statusNotAssessed:
			notAssessedControls++
		}

		// Update family counts (handle nil FamilyID for tenant frameworks)
		familyIDStr := "default"
		if control.FamilyID != (uuid.Nil) {
			familyIDStr = control.FamilyID.String()
		}
		if familyCounts[familyIDStr] == nil {
			familyCounts[familyIDStr] = map[string]int{"pass": 0, "fail": 0, "not_assessed": 0}
		}
		familyCounts[familyIDStr][strings.ToLower(effectiveStatus)]++
	}

	// Build family summaries. Platform/tenant framework controls do not
	// currently populate family_id (the column is dormant; legacy compliance
	// families were removed). Everything buckets as "Default" until the
	// modern frameworks add their own family taxonomy.
	familySummaries := make([]FamilySummary, 0, len(familyCounts))
	for familyID, counts := range familyCounts {
		name := familyID
		if familyID == "default" {
			name = "Default"
		}
		familySummaries = append(familySummaries, FamilySummary{
			ID:          familyID,
			Name:        name,
			Pass:        counts["pass"],
			Fail:        counts["fail"],
			NotAssessed: counts["not_assessed"],
		})
	}

	// Canonical severity-weighted score over the ASSESSED controls only
	// (Critical 4x, High 3x, Med 2x, Low 1x). Score is nil — "—", never 100 —
	// when nothing was assessed.
	breakdown := frameworkScore(outcomes)

	overridesActive := len(overrides)

	return &SummaryResponse{
		Framework: FrameworkSummary{
			ID:      framework.ID.String(),
			Version: framework.Version,
		},
		LastUpdated: time.Now().Format(time.RFC3339),
		KPIs: KPISummary{
			Score:               breakdown.Score,
			FailingControls:     failingControls,
			NotAssessedControls: notAssessedControls,
			ControlsTotal:       totalControls,
			ControlsAssessed:    passControls + failingControls,
			AffectedAssets:      len(affectedAssetSet),
			OverridesActive:     overridesActive,
		},
		Families: familySummaries,
		Controls: controlSummaries,
	}, nil
}

// getControlsForFramework gets controls for a framework with optional filtering.
// The frameworkSource hint ("platform" or "tenant") avoids redundant table
// probing. If empty, tries platform first, then tenant.
func (s *EvaluationService) getControlsForFramework(frameworkID uuid.UUID, filters models.ScenarioFilters, frameworkSource ...string) ([]models.Control, error) {
	source := ""
	if len(frameworkSource) > 0 {
		source = frameworkSource[0]
	}

	args := []interface{}{frameworkID}
	var controls []models.Control

	// Platform framework controls
	if source == "" || source == "platform" {
		query := `
			SELECT c.id, c.framework_id, COALESCE(c.family_id, '00000000-0000-0000-0000-000000000000'::uuid) as family_id, c.control_id, c.title, c.description,
			       c.baseline_severity, c.crypto_relevant, c.created_at, c.updated_at
			FROM platform_framework_controls c
			WHERE c.framework_id = $1
		`
		if filters.EncryptionOnly {
			query += " AND c.crypto_relevant = true"
		}
		query += " ORDER BY c.control_id"

		err := s.db.Select(&controls, query, args...)
		if err == nil && len(controls) > 0 {
			return controls, nil
		}
		if source == "platform" {
			if err != nil {
				return nil, fmt.Errorf("failed to get platform framework controls: %w", err)
			}
			return controls, nil // 0 controls is valid
		}
	}

	// Tenant framework controls (custom policies)
	if source == "" || source == "tenant" {
		query := `
			SELECT c.id, c.framework_id, COALESCE(c.family_id, '00000000-0000-0000-0000-000000000000'::uuid) as family_id, c.control_id, c.title, c.description,
			       c.baseline_severity, c.crypto_relevant, c.created_at, c.updated_at
			FROM tenant_framework_controls c
			WHERE c.framework_id = $1
		`
		if filters.EncryptionOnly {
			query += " AND c.crypto_relevant = true"
		}
		query += " ORDER BY c.control_id"

		err := s.db.Select(&controls, query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to get tenant framework controls: %w", err)
		}
		for i := range controls {
			controls[i].Family = nil
		}
		return controls, nil
	}

	return nil, fmt.Errorf("no controls found for framework %s (source: %s)", frameworkID, source)
}

// ComplianceScoreResponse represents the overall compliance score across all frameworks.
// Score is nil when no framework contributed an assessed score — "—", never 0.
type ComplianceScoreResponse struct {
	Score          *float64               `json:"score"`
	FrameworkCount int                    `json:"framework_count"`
	Frameworks     []FrameworkScoreDetail `json:"frameworks"`
}

// FrameworkScoreDetail represents score details for a single framework
type FrameworkScoreDetail struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Code    string `json:"code"`
	Version string `json:"version"`
	Score   *int   `json:"score"` // nil when no control was assessed (#1369)
	Type    string `json:"type"`  // "platform" or "tenant"
}

// MultiFrameworkEvaluationResult represents evaluation result for a single framework
type MultiFrameworkEvaluationResult struct {
	FrameworkID      string              `json:"framework_id"`
	FrameworkName    string              `json:"framework_name"`
	FrameworkCode    string              `json:"framework_code,omitempty"`
	FrameworkVersion string              `json:"framework_version"`
	FrameworkType    string              `json:"framework_type"` // "platform" or "tenant"
	Score            *int                `json:"score"`          // nil when nothing was assessed (#1369)
	Summary          *SummaryResponse    `json:"summary"`
	AffectedEntities map[string][]string `json:"affected_entities"` // entity_type -> []entity_id
	Controls         struct {
		Total       int `json:"total"`
		Passing     int `json:"passing"`
		Failing     int `json:"failing"`
		NotAssessed int `json:"not_assessed"`
	} `json:"controls"`
	LastEvaluated string `json:"last_evaluated"`
}

// EvaluateMultipleFrameworks evaluates multiple frameworks in parallel
func (s *EvaluationService) EvaluateMultipleFrameworks(
	tenantID uuid.UUID,
	frameworkIDs []uuid.UUID,
	frameworkVersions map[string]string,
	filters models.ScenarioFilters,
	entityType string,
) ([]MultiFrameworkEvaluationResult, error) {
	ctx := context.Background()
	_ = ctx // Context for future cancellation support
	results := make([]MultiFrameworkEvaluationResult, 0, len(frameworkIDs))
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Evaluate each framework in parallel
	for _, frameworkID := range frameworkIDs {
		wg.Add(1)
		go func(fwID uuid.UUID) {
			defer wg.Done()

			// Get version for this framework
			version := frameworkVersions[fwID.String()]
			if version == "" {
				version = "1.0" // Default version
			}

			// Evaluate framework
			summary, err := s.EvaluateFramework(tenantID, fwID, version, filters, nil)
			if err != nil {
				// Log error but continue with other frameworks
				fmt.Printf("ERROR: Failed to evaluate framework %s: %v\n", fwID, err)
				return
			}

			// Get framework info for name/code
			var frameworkName, frameworkCode, frameworkType string
			var framework models.Framework
			err = s.db.Get(&framework, `
				SELECT id, code, name, version, description,
				       (status = 'published') as active, created_at, updated_at
				FROM platform_frameworks
				WHERE id = $1 AND status = 'published'
			`, fwID)
			if err == nil {
				frameworkName = framework.Name
				frameworkCode = framework.Code
				frameworkType = "platform"
			} else {
				// Try tenant framework (RLS-policied: scope with app.tenant_id).
				var tenantFramework struct {
					Name string `db:"name"`
				}
				gctx := context.Background()
				if tx, txErr := s.db.BeginTxx(gctx, nil); txErr != nil {
					err = fmt.Errorf("begin tx: %w", txErr)
				} else {
					func() {
						defer func() { _ = tx.Rollback() }()
						if scErr := shareddatabase.SetTenantContext(gctx, tx.Tx, tenantID); scErr != nil {
							err = scErr
							return
						}
						if gErr := tx.Get(&tenantFramework, `
							SELECT name
							FROM tenant_frameworks
							WHERE id = $1 AND tenant_id = $2
						`, fwID, tenantID); gErr != nil {
							err = gErr
							return
						}
						err = tx.Commit()
					}()
				}
				if err == nil {
					frameworkName = tenantFramework.Name
					frameworkType = "tenant"
				} else {
					frameworkName = "Unknown Framework"
					frameworkType = "unknown"
				}
			}

			// Extract affected entities from findings
			affectedEntities := make(map[string][]string)
			entityIDSet := make(map[string]map[string]bool) // entity_type -> entity_id -> true

			for _, control := range summary.Controls {
				// Get detailed findings for this control to extract entity references
				controlID, err := uuid.Parse(control.ID)
				if err != nil {
					continue
				}
				findings, err := s.getFindingsForControl(tenantID, controlID, filters)
				if err == nil {
					for _, finding := range findings {
						// Determine entity type from finding
						// For now, we'll use asset_id as the primary entity reference
						if finding.Asset != nil && finding.Asset.ID != uuid.Nil {
							entityTypeKey := "systems" // Assets are systems
							if entityIDSet[entityTypeKey] == nil {
								entityIDSet[entityTypeKey] = make(map[string]bool)
							}
							entityIDSet[entityTypeKey][finding.Asset.ID.String()] = true
						}
					}
				}
			}

			// Convert sets to slices
			for et, idSet := range entityIDSet {
				ids := make([]string, 0, len(idSet))
				for id := range idSet {
					ids = append(ids, id)
				}
				affectedEntities[et] = ids
			}

			// Count controls. StatusEffective is UPPERCASE (calculateControlStatus /
			// applyOverrides); comparing it against lowercase literals here matched
			// nothing, so this endpoint reported 0 passing / 0 failing forever
			// regardless of real posture. Compare against the shared constants.
			passingControls := 0
			failingControls := 0
			notAssessedControls := 0
			for _, control := range summary.Controls {
				switch control.StatusEffective {
				case statusPass:
					passingControls++
				case statusFail:
					failingControls++
				case statusNotAssessed:
					notAssessedControls++
				}
			}

			result := MultiFrameworkEvaluationResult{
				FrameworkID:      fwID.String(),
				FrameworkName:    frameworkName,
				FrameworkCode:    frameworkCode,
				FrameworkVersion: version,
				FrameworkType:    frameworkType,
				Score:            summary.KPIs.Score,
				Summary:          summary,
				AffectedEntities: affectedEntities,
				Controls: struct {
					Total       int `json:"total"`
					Passing     int `json:"passing"`
					Failing     int `json:"failing"`
					NotAssessed int `json:"not_assessed"`
				}{
					Total:       len(summary.Controls),
					Passing:     passingControls,
					Failing:     failingControls,
					NotAssessed: notAssessedControls,
				},
				LastEvaluated: time.Now().Format(time.RFC3339),
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(frameworkID)
	}

	wg.Wait()

	return results, nil
}

// GetComplianceScore calculates the overall compliance score across all active frameworks for a tenant
// If frameworkID is provided, only calculates score for that specific framework
// Otherwise, uses tenant's default framework (from tenant_framework_licenses)
// All tenants automatically have Best Practices licensed via database trigger
func (s *EvaluationService) GetComplianceScore(tenantID uuid.UUID, frameworkID *uuid.UUID) (*ComplianceScoreResponse, error) {
	var targetFrameworkID uuid.UUID
	var frameworkScores []FrameworkScoreDetail
	var totalScore float64
	var totalWeight int

	// tenant_framework_licenses is RLS-policied: scope these reads with app.tenant_id.
	ctx := context.Background()

	// If specific framework ID provided, use it (after validation)
	if frameworkID != nil {
		// Validate that framework is licensed for this tenant
		var isLicensed bool
		tx, err := s.db.BeginTxx(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("begin tx: %w", err)
		}
		func() {
			defer func() { _ = tx.Rollback() }()
			if scErr := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); scErr != nil {
				err = scErr
				return
			}
			if gErr := tx.Get(&isLicensed, `
				SELECT EXISTS(
					SELECT 1 FROM tenant_framework_licenses
					WHERE tenant_id = $1 AND platform_framework_id = $2
					  AND `+sqlActiveSubscription+`
				)
			`, tenantID, *frameworkID); gErr != nil {
				err = gErr
				return
			}
			err = tx.Commit()
		}()
		if err != nil || !isLicensed {
			return nil, fmt.Errorf("framework not licensed for tenant or not found")
		}
		targetFrameworkID = *frameworkID
	} else {
		// Get tenant's default framework from licenses
		var defaultLicense struct {
			PlatformFrameworkID uuid.UUID `db:"platform_framework_id"`
		}
		tx, err := s.db.BeginTxx(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("begin tx: %w", err)
		}
		func() {
			defer func() { _ = tx.Rollback() }()
			if scErr := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); scErr != nil {
				err = scErr
				return
			}
			if gErr := tx.Get(&defaultLicense, `
				SELECT platform_framework_id
				FROM tenant_framework_licenses
				WHERE tenant_id = $1 AND is_default = true AND `+sqlActiveSubscription+`
				LIMIT 1
			`, tenantID); gErr != nil {
				err = gErr
				return
			}
			err = tx.Commit()
		}()

		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("no default framework found - all tenants should have Best Practices licensed")
			}
			return nil, fmt.Errorf("failed to get default framework: %w", err)
		}
		targetFrameworkID = defaultLicense.PlatformFrameworkID
	}

	// Get framework details
	var framework models.PlatformFramework
	err := s.db.Get(&framework, `
		SELECT id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at
		FROM platform_frameworks
		WHERE id = $1 AND status = 'published'
	`, targetFrameworkID)
	if err != nil {
		return nil, fmt.Errorf("framework not found: %w", err)
	}

	// Evaluate the framework using EvaluateFramework
	summary, err := s.EvaluateFramework(tenantID, targetFrameworkID, framework.Version, models.ScenarioFilters{}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate framework: %w", err)
	}

	// Extract score from summary. A framework with nothing assessed carries no
	// score forward — averaging a sentinel in would invent posture.
	score := summary.KPIs.Score
	frameworkScores = append(frameworkScores, FrameworkScoreDetail{
		ID:      framework.ID.String(),
		Name:    framework.Name,
		Code:    framework.Code,
		Version: framework.Version,
		Score:   score,
		Type:    "platform",
	})

	var overallScore *float64
	if score != nil {
		totalScore = float64(*score)
		totalWeight = 1
		avg := totalScore / float64(totalWeight)
		overallScore = &avg
	}

	return &ComplianceScoreResponse{
		Score:          overallScore,
		FrameworkCount: len(frameworkScores),
		Frameworks:     frameworkScores,
	}, nil
}

// calculatePlatformFrameworkScore calculates the severity-weighted compliance score for a platform framework
func (s *EvaluationService) calculatePlatformFrameworkScore(tenantID, frameworkID uuid.UUID) (*int, error) {
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
		return nil, err
	}

	if len(controls) == 0 {
		// A framework with no controls has nothing to assess. It used to return
		// 100, which claims a clean bill of health for an empty policy.
		return nil, nil
	}

	controlIDs := make([]uuid.UUID, 0, len(controls))
	for _, ctrl := range controls {
		controlIDs = append(controlIDs, ctrl.ID)
	}
	assessments, err := loadControlAssessments(context.Background(), s.db.DB, tenantID, controlIDs, "platform")
	if err != nil {
		return nil, err
	}

	outcomes := make([]controlOutcome, 0, len(controls))
	for _, ctrl := range controls {
		findings, ferr := s.getFindingsForControl(tenantID, ctrl.ID, models.ScenarioFilters{})
		if ferr != nil {
			continue
		}
		status, _, _ := s.controlStatusFromAssessment(findings, assessments[ctrl.ID])
		outcomes = append(outcomes, controlOutcome{BaselineSeverity: ctrl.BaselineSeverity, Status: status})
	}

	return frameworkScore(outcomes).Score, nil
}

// FrameworkStatusResponse represents framework status information
type FrameworkStatusResponse struct {
	Frameworks        []FrameworkStatusDetail `json:"frameworks"`
	OverallScore      *float64                `json:"overall_score"` // nil when nothing was assessed (#1369)
	SelectedFramework *FrameworkStatusDetail  `json:"selected_framework,omitempty"`
}

// FrameworkStatusDetail represents status for a single framework
type FrameworkStatusDetail struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Code              string `json:"code"`
	Version           string `json:"version"`
	CompliancePercent *int   `json:"compliance_percent"` // nil when nothing was assessed (#1369)
	Type              string `json:"type"`               // "platform" or "tenant"
	IsSelected        bool   `json:"is_selected"`
}

// GetFrameworkStatus returns compliance status for all active frameworks with selection logic
// Now uses tenant_framework_licenses instead of tenant_admin_settings
// All tenants automatically have Best Practices licensed via database trigger
func (s *EvaluationService) GetFrameworkStatus(tenantID uuid.UUID) (*FrameworkStatusResponse, error) {
	// tenant_framework_licenses is RLS-policied: scope its reads/writes with app.tenant_id.
	ctx := context.Background()

	// Get licensed frameworks for this tenant
	type LicensedFrameworkRow struct {
		PlatformFrameworkID uuid.UUID `db:"platform_framework_id"`
		IsDefault           bool      `db:"is_default"`
	}
	var licensedFrameworks []LicensedFrameworkRow
	err := func() error {
		tx, txErr := s.db.BeginTxx(ctx, nil)
		if txErr != nil {
			return fmt.Errorf("begin tx: %w", txErr)
		}
		defer func() { _ = tx.Rollback() }()
		if scErr := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); scErr != nil {
			return scErr
		}
		if sErr := tx.Select(&licensedFrameworks, `
			SELECT platform_framework_id, is_default
			FROM tenant_framework_licenses
			WHERE tenant_id = $1 AND `+sqlActiveSubscription+`
		`, tenantID); sErr != nil {
			return sErr
		}
		return tx.Commit()
	}()
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get licensed frameworks: %w", err)
	}

	// Build map of licensed framework IDs and find default
	licensedMap := make(map[uuid.UUID]bool)
	var defaultFrameworkID *uuid.UUID
	for _, lf := range licensedFrameworks {
		licensedMap[lf.PlatformFrameworkID] = true
		if lf.IsDefault {
			defaultFrameworkID = &lf.PlatformFrameworkID
		}
	}

	// Determine active/default framework
	// All tenants have at least Best Practices licensed, so defaultFrameworkID should always exist
	var activeFrameworkID uuid.UUID
	if defaultFrameworkID != nil {
		activeFrameworkID = *defaultFrameworkID
	} else {
		// Auto-create Best Practices license if missing (defensive programming)
		log.Printf("⚠️ No default framework found for tenant %s, auto-creating Best Practices license", tenantID)
		var bestPracticesID uuid.UUID
		err = s.db.Get(&bestPracticesID, `
			SELECT id FROM platform_frameworks
			WHERE is_platform_default = true AND status = 'published'
			LIMIT 1
		`)
		if err != nil {
			return nil, fmt.Errorf("failed to find Best Practices framework: %w", err)
		}

		// Check if tenant exists
		var tenantExists bool
		err = s.db.Get(&tenantExists, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)`, tenantID)
		if err != nil || !tenantExists {
			return nil, fmt.Errorf("tenant not found: %s", tenantID)
		}

		// Create Best Practices license as default (RLS-policied write).
		err = func() error {
			tx, txErr := s.db.BeginTxx(ctx, nil)
			if txErr != nil {
				return fmt.Errorf("begin tx: %w", txErr)
			}
			defer func() { _ = tx.Rollback() }()
			if scErr := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); scErr != nil {
				return scErr
			}
			if _, eErr := tx.Exec(`
				INSERT INTO tenant_framework_licenses (
					id, tenant_id, platform_framework_id, is_locked, locked_at, locked_by,
					is_default, purchased_at, created_at, updated_at
				) VALUES (
					gen_random_uuid(), $1, $2, false, NULL, NULL, true, NOW(), NOW(), NOW()
				)
				ON CONFLICT (tenant_id, platform_framework_id) DO NOTHING
			`, tenantID, bestPracticesID); eErr != nil {
				return eErr
			}
			return tx.Commit()
		}()
		if err != nil {
			return nil, fmt.Errorf("failed to auto-create Best Practices license: %w", err)
		}

		activeFrameworkID = bestPracticesID
		log.Printf("✅ Auto-created Best Practices license for tenant %s", tenantID)

		// Re-fetch licensed frameworks after auto-creation (RLS-policied read).
		err = func() error {
			tx, txErr := s.db.BeginTxx(ctx, nil)
			if txErr != nil {
				return fmt.Errorf("begin tx: %w", txErr)
			}
			defer func() { _ = tx.Rollback() }()
			if scErr := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); scErr != nil {
				return scErr
			}
			if sErr := tx.Select(&licensedFrameworks, `
				SELECT platform_framework_id, is_default
				FROM tenant_framework_licenses
				WHERE tenant_id = $1 AND `+sqlActiveSubscription+`
			`, tenantID); sErr != nil {
				return sErr
			}
			return tx.Commit()
		}()
		if err != nil {
			return nil, fmt.Errorf("failed to get licensed frameworks after auto-creation: %w", err)
		}

		// Rebuild licensed map
		licensedMap = make(map[uuid.UUID]bool)
		for _, lf := range licensedFrameworks {
			licensedMap[lf.PlatformFrameworkID] = true
		}
	}

	// Calculate status for all frameworks
	var frameworkStatuses []FrameworkStatusDetail
	var totalScore float64
	var totalWeight int

	// Get licensed platform frameworks with details
	type LicensedFrameworkDetail struct {
		PlatformFramework models.PlatformFramework `db:"pf"`
		IsDefault         bool                     `db:"is_default"`
	}
	var licensedDetails []LicensedFrameworkDetail

	if len(licensedFrameworks) > 0 {
		// Query platform frameworks for licensed ones
		query := `
			SELECT
				pf.id, pf.code, pf.name, pf.version, pf.description, pf.organization, pf.status,
				pf.is_platform_default, pf.published_at, pf.published_by, pf.created_by, pf.created_at, pf.updated_at,
				tfl.is_default
			FROM platform_frameworks pf
			JOIN tenant_framework_licenses tfl ON pf.id = tfl.platform_framework_id
			WHERE tfl.tenant_id = $1 AND ` + sqlActiveSubscriptionTfl + `
			ORDER BY tfl.is_default DESC, pf.name
		`
		// Joined on tenant_framework_licenses (RLS-policied): run inside a
		// tenant-scoped transaction so app.tenant_id is set on the query connection.
		txErr := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
			rows, qErr := tx.QueryContext(ctx, query, tenantID)
			if qErr != nil {
				if qErr == sql.ErrNoRows {
					return nil
				}
				return qErr
			}
			defer func() { _ = rows.Close() }()

			for rows.Next() {
				var detail LicensedFrameworkDetail
				sErr := rows.Scan(
					&detail.PlatformFramework.ID,
					&detail.PlatformFramework.Code,
					&detail.PlatformFramework.Name,
					&detail.PlatformFramework.Version,
					&detail.PlatformFramework.Description,
					&detail.PlatformFramework.Organization,
					&detail.PlatformFramework.Status,
					&detail.PlatformFramework.IsPlatformDefault,
					&detail.PlatformFramework.PublishedAt,
					&detail.PlatformFramework.PublishedBy,
					&detail.PlatformFramework.CreatedBy,
					&detail.PlatformFramework.CreatedAt,
					&detail.PlatformFramework.UpdatedAt,
					&detail.IsDefault,
				)
				if sErr == nil {
					licensedDetails = append(licensedDetails, detail)
				}
			}
			return rows.Err()
		})
		if txErr != nil {
			return nil, fmt.Errorf("failed to get licensed framework details: %w", txErr)
		}
	}

	// Add licensed frameworks to status list
	for _, detail := range licensedDetails {
		// Calculate score directly for the platform framework using its controls and findings
		score, err := s.calculatePlatformFrameworkScore(tenantID, detail.PlatformFramework.ID)
		if err != nil {
			log.Printf("⚠️ Failed to calculate score for framework %s: %v", detail.PlatformFramework.ID, err)
			score = nil
		}

		isSelected := activeFrameworkID == detail.PlatformFramework.ID

		frameworkStatuses = append(frameworkStatuses, FrameworkStatusDetail{
			ID:                detail.PlatformFramework.ID.String(),
			Name:              detail.PlatformFramework.Name,
			Code:              detail.PlatformFramework.Code,
			Version:           detail.PlatformFramework.Version,
			CompliancePercent: score,
			Type:              "platform",
			IsSelected:        isSelected,
		})
		if score != nil {
			totalScore += float64(*score)
			totalWeight++
		}
	}

	// Note: All tenants automatically have Best Practices licensed via database trigger,
	// so the platform default fallback below should never execute. Keeping as no-op for safety.
	// If no licensed frameworks exist (shouldn't happen), the function will have already
	// returned an error at line 789.

	// Calculate overall score across the frameworks that HAVE one.
	var overallScore *float64
	if totalWeight > 0 {
		avg := totalScore / float64(totalWeight)
		overallScore = &avg
	}

	// Find selected framework detail
	var selectedFramework *FrameworkStatusDetail
	for i := range frameworkStatuses {
		if frameworkStatuses[i].IsSelected {
			selectedFramework = &frameworkStatuses[i]
			break
		}
	}

	// If no frameworks exist at all, return empty response (not an error)
	if len(frameworkStatuses) == 0 {
		return &FrameworkStatusResponse{
			Frameworks:        []FrameworkStatusDetail{},
			OverallScore:      nil,
			SelectedFramework: nil,
		}, nil
	}

	return &FrameworkStatusResponse{
		Frameworks:        frameworkStatuses,
		OverallScore:      overallScore,
		SelectedFramework: selectedFramework,
	}, nil
}

// getFindingsForControl gets findings for a specific control with filters
func (s *EvaluationService) getFindingsForControl(tenantID, controlID uuid.UUID, filters models.ScenarioFilters) ([]models.ComplianceFinding, error) {
	return s.getFindingsForControlScoped(tenantID, controlID, filters, false)
}

func (s *EvaluationService) getVisibleFindingsForControl(tenantID, controlID uuid.UUID, filters models.ScenarioFilters) ([]models.ComplianceFinding, error) {
	return s.getFindingsForControlScoped(tenantID, controlID, filters, true)
}

func (s *EvaluationService) getFindingsForControlScoped(tenantID, controlID uuid.UUID, filters models.ScenarioFilters, licensedOnly bool) ([]models.ComplianceFinding, error) {
	// Note: We join network_assets only for filtering, not for selecting fields
	// Asset fields are in the joined Asset struct with db:"-" tag, so sqlx can't scan them
	query := `
		SELECT cf.id, cf.tenant_id, cf.control_id, cf.asset_id, cf.severity, cf.summary,
		       cf.evidence, cf.first_seen, cf.last_seen, cf.assigned_to, cf.assigned_at,
		       cf.assigned_by, cf.remediation_notes, cf.detection_state, cf.workflow_status,
		       cf.occurrence_count, cf.resurfaced_at, cf.suppressed_until, cf.suppression_reason,
		       cf.is_stale, cf.last_evaluated_at, cf.evaluation_version,
		       cf.created_at, cf.updated_at
		FROM compliance_findings cf
		LEFT JOIN network_assets na ON cf.asset_id = na.id AND na.deleted_at IS NULL
		WHERE cf.tenant_id = $1 AND cf.control_id = $2
		  AND cf.detection_state = 'ACTIVE'
		  AND (cf.workflow_status != 'SUPPRESSED' OR cf.workflow_status IS NULL)
	`
	args := []interface{}{tenantID, controlID}
	argIndex := 3
	if licensedOnly {
		query += " AND " + licensedFindingScopeSQL("cf", "$1")
	}

	// Apply environment filter (only if asset exists and is not deleted)
	// Ignore "undefined" string values (from frontend URLSearchParams)
	if filters.Environment != "" && strings.ToLower(filters.Environment) != "undefined" {
		query += fmt.Sprintf(" AND (na.environment = $%d OR na.id IS NULL)", argIndex)
		args = append(args, filters.Environment)
		argIndex++
	}

	// Apply severity filter (normalize to match database format: Low, Med, High, Critical)
	// Ignore "undefined" string values (from frontend URLSearchParams)
	if filters.Severity != "" && strings.ToLower(filters.Severity) != "undefined" {
		severity := filters.Severity
		// Normalize severity to match database format
		switch strings.ToLower(severity) {
		case "low":
			severity = "Low"
		case "med", "medium":
			severity = "Med"
		case "high":
			severity = "High"
		case "critical":
			severity = "Critical"
		}
		query += fmt.Sprintf(" AND cf.severity = $%d", argIndex)
		args = append(args, severity)
	}

	query += " ORDER BY cf.last_seen DESC"

	// compliance_findings and network_assets are RLS-policied: run the read inside
	// a tenant-scoped transaction so app.tenant_id is set on the query connection.
	ctx := context.Background()
	var findings []models.ComplianceFinding
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		// Scan manually to handle JSONB evidence field
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("failed to query findings: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var finding models.ComplianceFinding
			var evidenceJSONB []byte

			err := rows.Scan(
				&finding.ID, &finding.TenantID, &finding.ControlID, &finding.AssetID,
				&finding.Severity, &finding.Summary, &evidenceJSONB,
				&finding.FirstSeen, &finding.LastSeen, &finding.AssignedTo, &finding.AssignedAt,
				&finding.AssignedBy, &finding.RemediationNotes, &finding.DetectionState,
				&finding.WorkflowStatus, &finding.OccurrenceCount, &finding.ResurfacedAt,
				&finding.SuppressedUntil, &finding.SuppressionReason, &finding.IsStale,
				&finding.LastEvaluatedAt, &finding.EvaluationVersion,
				&finding.CreatedAt, &finding.UpdatedAt,
			)
			if err != nil {
				return fmt.Errorf("failed to scan finding: %w", err)
			}

			// Unmarshal evidence JSONB
			if len(evidenceJSONB) > 0 {
				finding.Evidence = make(map[string]interface{})
				if err := json.Unmarshal(evidenceJSONB, &finding.Evidence); err != nil {
					// If unmarshal fails, initialize as empty map
					finding.Evidence = make(map[string]interface{})
				}
			} else {
				finding.Evidence = make(map[string]interface{})
			}

			findings = append(findings, finding)
		}

		if err = rows.Err(); err != nil {
			return fmt.Errorf("error iterating findings: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return findings, nil
}

// getOverrides gets overrides for a tenant (global + scenario-specific)
// Works with platform, tenant, and legacy framework controls via the framework_type column.
func (s *EvaluationService) getOverrides(tenantID uuid.UUID, scenarioID *uuid.UUID) (map[uuid.UUID]models.Override, error) {
	query := `
		SELECT id, tenant_id, scenario_id, control_id, override_type, severity_from,
		       severity_to, rationale, framework_type, created_by, created_at, updated_at
		FROM compliance_overrides
		WHERE tenant_id = $1
	`
	args := []interface{}{tenantID}

	if scenarioID != nil {
		query += " AND (scenario_id = $2 OR scenario_id IS NULL)"
		args = append(args, *scenarioID)
	} else {
		query += " AND scenario_id IS NULL"
	}

	// compliance_overrides is RLS-policied: scope the read with app.tenant_id.
	ctx := context.Background()
	var overrides []models.Override
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); err != nil {
		return nil, err
	}
	if err := tx.Select(&overrides, query, args...); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Convert to map for easy lookup
	overrideMap := make(map[uuid.UUID]models.Override)
	for _, override := range overrides {
		overrideMap[override.ControlID] = override
	}

	return overrideMap, nil
}

// severityToWeight converts a baseline severity to a numeric weight for scoring.
// Critical=4, High=3, Med=2, Low=1. This ensures critical control failures
// have 4x the impact on compliance score compared to low-severity ones.
func severityToWeight(severity string) int {
	switch severity {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Med":
		return 2
	default:
		return 1
	}
}

// controlStatusFromAssessment is calculateControlStatus plus the materialized
// assessment for the same control: a control with findings FAILS (and the worst
// severity is its weight/badge), while a control with none is PASS only if it was
// actually assessed. The old code returned PASS unconditionally, which is how a
// control with no measurements — or a tenant with nothing in inventory — reported
// a clean pass at 100.
func (s *EvaluationService) controlStatusFromAssessment(findings []models.ComplianceFinding, a controlAssessment) (status, severity, notAssessedReason string) {
	if len(findings) > 0 {
		status, severity = s.calculateControlStatus(findings)
		return status, severity, ""
	}
	if a.Status == statusNotAssessed {
		return statusNotAssessed, "Low", a.Reason
	}
	return statusPass, "Low", ""
}

// calculateControlStatus calculates the baseline status and severity for a control
// from its stored findings. Status is decided by whether the control was violated;
// severity is the worst finding's rating, which is the scoring WEIGHT and the
// badge, never the pass/fail input.
func (s *EvaluationService) calculateControlStatus(findings []models.ComplianceFinding) (status, severity string) {
	if len(findings) == 0 {
		return statusPass, "Low"
	}

	// Find highest severity finding
	highestSeverity := "Low"
	for _, finding := range findings {
		switch finding.Severity {
		case "Critical":
			highestSeverity = "Critical"
		case "High":
			if highestSeverity != "Critical" {
				highestSeverity = "High"
			}
		case "Med":
			if highestSeverity == "Low" {
				highestSeverity = "Med"
			}
		}
	}

	// Violated → FAIL, whatever the severity. Shared with the materialized path
	// so the in-memory fold and the SQL fold cannot disagree.
	return statusForFindings(true), highestSeverity
}

// applyOverrides applies overrides to control status and severity
func (s *EvaluationService) applyOverrides(controlID uuid.UUID, baselineStatus, baselineSeverity string, overrides map[uuid.UUID]models.Override) (effectiveStatus, effectiveSeverity string, hasOverride bool) {
	override, exists := overrides[controlID]
	if !exists {
		return baselineStatus, baselineSeverity, false
	}

	hasOverride = true
	effectiveSeverity = baselineSeverity

	switch override.OverrideType {
	case models.OverrideTypeDisregard:
		if baselineStatus == statusNotAssessed {
			// "Accept this risk" cannot manufacture evidence of a check that was
			// never run. A disregard on a not-assessed control leaves it not
			// assessed rather than laundering it into a pass.
			return baselineStatus, baselineSeverity, hasOverride
		}
		return statusPass, baselineSeverity, hasOverride
	case models.OverrideTypeSeverity:
		if override.SeverityTo != nil {
			effectiveSeverity = *override.SeverityTo
		}
		// A re-rating changes the control's WEIGHT, not whether it was violated
		//. It used to also flip the status, so re-rating a failing
		// control to Low made it report PASS.
		return baselineStatus, effectiveSeverity, hasOverride
	}

	return baselineStatus, baselineSeverity, hasOverride
}

// getLastSeen gets the most recent last_seen time from findings
func (s *EvaluationService) getLastSeen(findings []models.ComplianceFinding) string {
	if len(findings) == 0 {
		return "—"
	}

	var latest time.Time
	for _, finding := range findings {
		if finding.LastSeen.After(latest) {
			latest = finding.LastSeen
		}
	}

	if latest.IsZero() {
		return "—"
	}

	// Return relative time
	now := time.Now()
	diff := now.Sub(latest)

	if diff < time.Minute {
		return "just now"
	} else if diff < time.Hour {
		return fmt.Sprintf("%.0fm ago", diff.Minutes())
	} else if diff < 24*time.Hour {
		return fmt.Sprintf("%.0fh ago", diff.Hours())
	} else {
		return fmt.Sprintf("%.0fd ago", diff.Hours()/24)
	}
}

// GetControlDetails returns detailed information for a specific control
func (s *EvaluationService) GetControlDetails(tenantID, controlID uuid.UUID, scenarioID *uuid.UUID, filters models.ScenarioFilters, page, pageSize int) (*ControlDetailsResponse, error) {
	// Get control information - check platform_framework_controls first
	var control models.Control
	err := s.db.Get(&control, `
		SELECT c.id, c.framework_id, COALESCE(c.family_id, '00000000-0000-0000-0000-000000000000'::uuid) as family_id,
		       c.control_id, c.title, c.description,
		       c.baseline_severity, c.crypto_relevant, c.created_at, c.updated_at
		FROM platform_framework_controls c
		WHERE c.id = $1
	`, controlID)

	// If not found in platform_framework_controls, try tenant_framework_controls
	if err != nil {
		err = s.db.Get(&control, `
			SELECT c.id, c.framework_id, COALESCE(c.family_id, '00000000-0000-0000-0000-000000000000'::uuid) as family_id,
			       c.control_id, c.title, c.description,
			       c.baseline_severity, c.crypto_relevant, c.created_at, c.updated_at
			FROM tenant_framework_controls c
			WHERE c.id = $1
		`, controlID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get control: %w", err)
	}

	// Get findings for this control
	allFindings, err := s.getVisibleFindingsForControl(tenantID, controlID, filters)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}

	// Calculate baseline status
	baselineStatus, baselineSeverity := s.calculateControlStatus(allFindings)

	// Get overrides
	overrides, err := s.getOverrides(tenantID, scenarioID)
	if err != nil {
		return nil, fmt.Errorf("failed to get overrides: %w", err)
	}

	// Apply overrides
	effectiveStatus, _, hasOverride := s.applyOverrides(controlID, baselineStatus, baselineSeverity, overrides)

	// Count failing findings and affected assets
	failingFindingsCount := 0
	affectedAssetSet := make(map[uuid.UUID]bool)
	for _, finding := range allFindings {
		if finding.Severity == "Critical" || finding.Severity == "High" || finding.Severity == "Med" {
			failingFindingsCount++
		}
		affectedAssetSet[finding.AssetID] = true
	}

	// Paginate findings
	offset := (page - 1) * pageSize
	var paginatedFindings []models.ComplianceFinding
	if offset < len(allFindings) {
		end := offset + pageSize
		if end > len(allFindings) {
			end = len(allFindings)
		}
		paginatedFindings = allFindings[offset:end]
	}

	// Convert findings to summaries
	findingSummaries := make([]FindingSummary, 0, len(paginatedFindings))
	for _, finding := range paginatedFindings {
		// Get asset name from database. network_assets is RLS-policied: scope the
		// lookup with app.tenant_id.
		ctx := context.Background()
		assetName := "Unknown Asset"
		var hostname, ipAddress sql.NullString
		_ = shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `
				SELECT hostname, ip_address
				FROM network_assets
				WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
			`, finding.AssetID, tenantID).Scan(&hostname, &ipAddress)
		})
		if hostname.Valid && hostname.String != "" {
			assetName = hostname.String
		} else if ipAddress.Valid && ipAddress.String != "" {
			assetName = ipAddress.String
		}

		// Get assigned user email if assigned
		var assignedToEmail *string
		if finding.AssignedTo != nil {
			var email string
			err := s.db.Get(&email, "SELECT email FROM users WHERE id = $1", finding.AssignedTo)
			if err == nil && email != "" {
				assignedToEmail = &email
			}
		}

		// Get assigned_by user email if present
		var assignedByEmail *string
		if finding.AssignedBy != nil {
			var email string
			err := s.db.Get(&email, "SELECT email FROM users WHERE id = $1", finding.AssignedBy)
			if err == nil && email != "" {
				assignedByEmail = &email
			}
		}

		// Format assigned_at if present
		var assignedAtStr *string
		if finding.AssignedAt != nil {
			formatted := finding.AssignedAt.Format(time.RFC3339)
			assignedAtStr = &formatted
		}

		// Get ticket count. tickets is RLS-policied: scope with app.tenant_id.
		var ticketCount int
		_ = shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tickets WHERE finding_id = $1 AND tenant_id = $2", finding.ID, tenantID).Scan(&ticketCount)
		})

		findingSummaries = append(findingSummaries, FindingSummary{
			ID:               finding.ID.String(),
			Severity:         finding.Severity,
			Asset:            assetName,
			Summary:          finding.Summary,
			FirstSeen:        finding.FirstSeen.Format(time.RFC3339),
			LastSeen:         finding.LastSeen.Format(time.RFC3339),
			AssignedTo:       assignedToEmail,
			AssignedAt:       assignedAtStr,
			AssignedBy:       assignedByEmail,
			RemediationNotes: finding.RemediationNotes,
			TicketCount:      ticketCount,
		})
	}

	// Build override summary
	overrideSummary := OverrideSummary{
		Disregard: false,
	}
	if hasOverride {
		override, exists := overrides[controlID]
		if exists {
			overrideSummary.Disregard = override.OverrideType == models.OverrideTypeDisregard
			if override.OverrideType == models.OverrideTypeSeverity && override.SeverityFrom != nil && override.SeverityTo != nil {
				// Get user info for override creator
				var userName string
				_ = s.db.Get(&userName, "SELECT email FROM users WHERE id = $1", override.CreatedBy)
				if userName == "" {
					userName = "Unknown"
				}

				overrideSummary.SeverityOverride = &SeverityOverrideDetail{
					From:      *override.SeverityFrom,
					To:        *override.SeverityTo,
					Rationale: override.Rationale,
					By:        userName,
					At:        override.CreatedAt.Format(time.RFC3339),
				}
			}
		}
	}

	// Build rationale
	rationale := control.Description
	if rationale == "" {
		rationale = fmt.Sprintf("Control %s: %s", control.ControlID, control.Title)
	}
	if hasOverride {
		override, exists := overrides[controlID]
		if exists && override.Rationale != "" {
			rationale += fmt.Sprintf(" (Override: %s)", override.Rationale)
		}
	}

	// Calculate score (percentage of passing findings)
	score := 100
	if len(allFindings) > 0 {
		passingCount := len(allFindings) - failingFindingsCount
		score = (passingCount * 100) / len(allFindings)
	}

	return &ControlDetailsResponse{
		Control: ControlDetailsControl{
			ID:     control.ID.String(),
			Name:   control.Title,
			Status: effectiveStatus,
			Score:  &score,
		},
		Rationale: rationale,
		EvidenceSummary: EvidenceSummary{
			FailingFindingsCount: failingFindingsCount,
			AffectedAssetsCount:  len(affectedAssetSet),
			LastSeen:             s.getLastSeen(allFindings),
		},
		Findings:  findingSummaries,
		Overrides: overrideSummary,
	}, nil
}

// GetControlDetailsTotalCount returns the total count of findings for a control (for pagination)
func (s *EvaluationService) GetControlDetailsTotalCount(tenantID, controlID uuid.UUID, filters models.ScenarioFilters) (int, error) {
	allFindings, err := s.getVisibleFindingsForControl(tenantID, controlID, filters)
	if err != nil {
		return 0, err
	}
	return len(allFindings), nil
}

// ResolveControlID resolves a string control_id (e.g., "BP-002") to its UUID primary key.
// It searches platform_framework_controls and tenant_framework_controls. If
// frameworkIDStr is provided, it narrows the search to that framework first.
func (s *EvaluationService) ResolveControlID(controlIDStr, frameworkIDStr string) (uuid.UUID, error) {
	var id uuid.UUID
	var frameworkID *uuid.UUID
	if frameworkIDStr != "" {
		if fid, err := uuid.Parse(frameworkIDStr); err == nil {
			frameworkID = &fid
		}
	}

	// Try platform_framework_controls
	if frameworkID != nil {
		err := s.db.Get(&id, `SELECT id FROM platform_framework_controls WHERE control_id = $1 AND framework_id = $2 LIMIT 1`, controlIDStr, *frameworkID)
		if err == nil {
			return id, nil
		}
		// Try tenant_framework_controls
		err = s.db.Get(&id, `SELECT id FROM tenant_framework_controls WHERE control_id = $1 AND framework_id = $2 LIMIT 1`, controlIDStr, *frameworkID)
		if err == nil {
			return id, nil
		}
	}

	// Fallback: search without framework filter
	err := s.db.Get(&id, `SELECT id FROM platform_framework_controls WHERE control_id = $1 LIMIT 1`, controlIDStr)
	if err == nil {
		return id, nil
	}
	err = s.db.Get(&id, `SELECT id FROM tenant_framework_controls WHERE control_id = $1 LIMIT 1`, controlIDStr)
	if err == nil {
		return id, nil
	}

	return uuid.Nil, fmt.Errorf("control not found: %s", controlIDStr)
}
