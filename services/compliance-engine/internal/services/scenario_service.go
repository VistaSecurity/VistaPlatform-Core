package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// ScenarioService handles compliance scenario CRUD operations
type ScenarioService struct {
	db *sqlx.DB
}

// NewScenarioService creates a new scenario service
func NewScenarioService(db *sqlx.DB) *ScenarioService {
	return &ScenarioService{db: db}
}

// CreateScenario creates a new compliance scenario
func (s *ScenarioService) CreateScenario(tenantID, userID uuid.UUID, name string, frameworkID uuid.UUID, frameworkVersion string, filters models.ScenarioFilters) (*models.Scenario, error) {
	scenario := &models.Scenario{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Name:             name,
		FrameworkID:      frameworkID,
		FrameworkVersion: frameworkVersion,
		Filters:          filters,
		CreatedBy:        userID,
		UpdatedBy:        userID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	query := `
		INSERT INTO compliance_scenarios (id, tenant_id, name, framework_id, framework_version, filters, created_by, updated_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
		scenario.ID,
		scenario.TenantID,
		scenario.Name,
		scenario.FrameworkID,
		scenario.FrameworkVersion,
		scenario.Filters,
		scenario.CreatedBy,
		scenario.UpdatedBy,
		scenario.CreatedAt,
		scenario.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create scenario: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return scenario, nil
}

// UpdateScenario updates an existing compliance scenario
func (s *ScenarioService) UpdateScenario(tenantID, scenarioID, userID uuid.UUID, name string, filters models.ScenarioFilters) (*models.Scenario, error) {
	scenario := &models.Scenario{
		ID:        scenarioID,
		UpdatedBy: userID,
		UpdatedAt: time.Now(),
	}

	query := `
		UPDATE compliance_scenarios 
		SET name = $1, filters = $2, updated_by = $3, updated_at = $4
		WHERE id = $5 AND tenant_id = $6
		RETURNING id, tenant_id, name, framework_id, framework_version, filters, created_by, updated_by, created_at, updated_at
	`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	err = tx.Get(scenario, query, name, filters, userID, time.Now(), scenarioID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to update scenario: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return scenario, nil
}

// GetScenario retrieves a specific scenario by ID. Framework metadata is
// populated separately by callers that need it (via platform_frameworks or
// tenant_frameworks depending on framework_type) — scenarios no longer hard-
// join to the retired compliance_frameworks table.
func (s *ScenarioService) GetScenario(tenantID, scenarioID uuid.UUID) (*models.Scenario, error) {
	scenario := &models.Scenario{}

	query := `
		SELECT id, tenant_id, name, framework_id, framework_version, filters,
		       created_by, updated_by, created_at, updated_at
		FROM compliance_scenarios
		WHERE id = $1 AND tenant_id = $2
	`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	err = tx.Get(scenario, query, scenarioID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scenario: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return scenario, nil
}

// ListScenarios retrieves all scenarios for a tenant
func (s *ScenarioService) ListScenarios(tenantID uuid.UUID) ([]models.Scenario, error) {
	var scenarios []models.Scenario

	// Query scenarios without joining frameworks (Framework is populated separately if needed)
	query := `
		SELECT id, tenant_id, name, framework_id, framework_version, filters,
		       created_by, updated_by, created_at, updated_at
		FROM compliance_scenarios
		WHERE tenant_id = $1
		ORDER BY updated_at DESC
	`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	if err := tx.Select(&scenarios, query, tenantID); err != nil {
		return nil, fmt.Errorf("failed to list scenarios: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return scenarios, nil
}

// DeleteScenario deletes a scenario
func (s *ScenarioService) DeleteScenario(tenantID, scenarioID uuid.UUID) error {
	query := `DELETE FROM compliance_scenarios WHERE id = $1 AND tenant_id = $2`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	result, err := tx.Exec(query, scenarioID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete scenario: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scenario not found")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

// GetScenariosByFramework retrieves scenarios for a specific framework
func (s *ScenarioService) GetScenariosByFramework(tenantID, frameworkID uuid.UUID) ([]models.Scenario, error) {
	var scenarios []models.Scenario

	query := `
		SELECT id, tenant_id, name, framework_id, framework_version, filters,
		       created_by, updated_by, created_at, updated_at
		FROM compliance_scenarios
		WHERE tenant_id = $1 AND framework_id = $2
		ORDER BY updated_at DESC
	`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	if err := tx.Select(&scenarios, query, tenantID, frameworkID); err != nil {
		return nil, fmt.Errorf("failed to get scenarios by framework: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return scenarios, nil
}

// CheckScenarioNameExists checks if a scenario name already exists for a tenant
func (s *ScenarioService) CheckScenarioNameExists(tenantID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error) {
	query := `SELECT COUNT(*) FROM compliance_scenarios WHERE tenant_id = $1 AND name = $2`
	args := []interface{}{tenantID, name}

	if excludeID != nil {
		query += ` AND id != $3`
		args = append(args, *excludeID)
	}

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return false, err
	}

	var count int
	if err := tx.Get(&count, query, args...); err != nil {
		return false, fmt.Errorf("failed to check scenario name: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit tx: %w", err)
	}

	return count > 0, nil
}
