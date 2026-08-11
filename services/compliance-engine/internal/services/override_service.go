package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// OverrideService handles compliance override CRUD operations
type OverrideService struct {
	db *sqlx.DB
}

// NewOverrideService creates a new override service
func NewOverrideService(db *sqlx.DB) *OverrideService {
	return &OverrideService{db: db}
}

// CreateOverride creates a new compliance override.
// frameworkType must be "platform" or "tenant" to indicate which control table
// the controlID references.
func (s *OverrideService) CreateOverride(tenantID, userID uuid.UUID, scenarioID *uuid.UUID, controlID uuid.UUID, overrideType models.OverrideType, severityFrom, severityTo *string, rationale, frameworkType string) (*models.Override, error) {
	// Validate override type
	if !overrideType.IsValid() {
		return nil, fmt.Errorf("invalid override type: %s", overrideType)
	}

	// Validate framework type
	if frameworkType == "" {
		frameworkType = "platform" // Default to platform for new overrides
	}
	if frameworkType != "platform" && frameworkType != "tenant" {
		return nil, fmt.Errorf("invalid framework_type: %s (must be platform or tenant)", frameworkType)
	}

	// Validate severity override parameters
	if overrideType == models.OverrideTypeSeverity {
		if severityFrom == nil || severityTo == nil {
			return nil, fmt.Errorf("severity_from and severity_to are required for severity overrides")
		}
		if !isValidSeverity(*severityFrom) || !isValidSeverity(*severityTo) {
			return nil, fmt.Errorf("invalid severity value")
		}
	}

	override := &models.Override{
		ID:            uuid.New(),
		TenantID:      tenantID,
		ScenarioID:    scenarioID,
		ControlID:     controlID,
		OverrideType:  overrideType,
		SeverityFrom:  severityFrom,
		SeverityTo:    severityTo,
		Rationale:     rationale,
		FrameworkType: frameworkType,
		CreatedBy:     userID,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	query := `
		INSERT INTO compliance_overrides (id, tenant_id, scenario_id, control_id, override_type, severity_from, severity_to, rationale, framework_type, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	_, err = tx.Exec(query,
		override.ID,
		override.TenantID,
		override.ScenarioID,
		override.ControlID,
		override.OverrideType,
		override.SeverityFrom,
		override.SeverityTo,
		override.Rationale,
		override.FrameworkType,
		override.CreatedBy,
		override.CreatedAt,
		override.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create override: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return override, nil
}

// GetOverride retrieves a specific override by ID.
// Control join is attempted across all three control tables via COALESCE.
func (s *OverrideService) GetOverride(overrideID uuid.UUID) (*models.Override, error) {
	override := &models.Override{}

	// RLS: looked up by primary key without a tenant in scope; relies on the WHERE on caller-supplied id. See Phase 4 follow-up.
	query := `
		SELECT o.id, o.tenant_id, o.scenario_id, o.control_id, o.override_type, o.severity_from,
		       o.severity_to, o.rationale, o.framework_type, o.created_by, o.created_at, o.updated_at
		FROM compliance_overrides o
		WHERE o.id = $1
	`

	err := s.db.Get(override, query, overrideID)
	if err != nil {
		return nil, fmt.Errorf("failed to get override: %w", err)
	}

	return override, nil
}

// ListOverrides retrieves overrides for a tenant with optional scenario filter
func (s *OverrideService) ListOverrides(tenantID uuid.UUID, scenarioID *uuid.UUID) ([]models.Override, error) {
	var overrides []models.Override

	query := `
		SELECT id, tenant_id, scenario_id, control_id, override_type, severity_from,
		       severity_to, rationale, framework_type, created_by, created_at, updated_at
		FROM compliance_overrides
		WHERE tenant_id = $1
	`
	args := []interface{}{tenantID}

	if scenarioID != nil {
		query += ` AND (scenario_id = $2 OR scenario_id IS NULL)`
		args = append(args, *scenarioID)
	} else {
		query += ` AND scenario_id IS NULL`
	}

	query += ` ORDER BY created_at DESC`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	if err := tx.Select(&overrides, query, args...); err != nil {
		return nil, fmt.Errorf("failed to list overrides: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return overrides, nil
}

// GetOverridesByControl retrieves overrides for a specific control
func (s *OverrideService) GetOverridesByControl(tenantID, controlID uuid.UUID, scenarioID *uuid.UUID) ([]models.Override, error) {
	var overrides []models.Override

	query := `
		SELECT o.id, o.tenant_id, o.scenario_id, o.control_id, o.override_type, o.severity_from,
		       o.severity_to, o.rationale, o.framework_type, o.created_by, o.created_at, o.updated_at
		FROM compliance_overrides o
		WHERE o.tenant_id = $1 AND o.control_id = $2
	`
	args := []interface{}{tenantID, controlID}

	if scenarioID != nil {
		query += ` AND (o.scenario_id = $3 OR o.scenario_id IS NULL)`
		args = append(args, *scenarioID)
	} else {
		query += ` AND o.scenario_id IS NULL`
	}

	query += ` ORDER BY o.created_at DESC`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	if err := tx.Select(&overrides, query, args...); err != nil {
		return nil, fmt.Errorf("failed to get overrides by control: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return overrides, nil
}

// DeleteOverride deletes an override
func (s *OverrideService) DeleteOverride(tenantID, overrideID uuid.UUID) error {
	query := `DELETE FROM compliance_overrides WHERE id = $1 AND tenant_id = $2`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	result, err := tx.Exec(query, overrideID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete override: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("override not found")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

// DeleteOverridesByScenario deletes all overrides for a specific scenario
func (s *OverrideService) DeleteOverridesByScenario(scenarioID uuid.UUID) error {
	// RLS: deletes by scenario_id without a tenant in scope (cascade cleanup); bypass-deferred (Phase 4).
	query := `DELETE FROM compliance_overrides WHERE scenario_id = $1`

	_, err := s.db.Exec(query, scenarioID)
	if err != nil {
		return fmt.Errorf("failed to delete overrides by scenario: %w", err)
	}

	return nil
}

// GetActiveOverrideForControl gets the active override for a control (scenario-specific takes precedence over global)
func (s *OverrideService) GetActiveOverrideForControl(tenantID, controlID uuid.UUID, scenarioID *uuid.UUID) (*models.Override, error) {
	query := `
		SELECT o.id, o.tenant_id, o.scenario_id, o.control_id, o.override_type, o.severity_from,
		       o.severity_to, o.rationale, o.framework_type, o.created_by, o.created_at, o.updated_at
		FROM compliance_overrides o
		WHERE o.tenant_id = $1 AND o.control_id = $2
	`
	args := []interface{}{tenantID, controlID}

	if scenarioID != nil {
		// Prioritize scenario-specific overrides, then global ones
		query += ` AND (o.scenario_id = $3 OR o.scenario_id IS NULL)`
		args = append(args, *scenarioID)
		query += ` ORDER BY CASE WHEN o.scenario_id IS NOT NULL THEN 0 ELSE 1 END, o.created_at DESC`
	} else {
		query += ` AND o.scenario_id IS NULL`
		query += ` ORDER BY o.created_at DESC`
	}

	query += ` LIMIT 1`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	override := &models.Override{}
	err = tx.Get(override, query, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No override found
		}
		return nil, fmt.Errorf("failed to get active override: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return override, nil
}

// isValidSeverity checks if a severity value is valid
func isValidSeverity(severity string) bool {
	validSeverities := []string{"Low", "Med", "High", "Critical"}
	for _, valid := range validSeverities {
		if severity == valid {
			return true
		}
	}
	return false
}
