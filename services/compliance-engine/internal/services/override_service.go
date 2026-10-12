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
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedseverity "github.com/vistasecurity/vistaplatform/shared/severity"
)

// ErrDuplicateOverride is returned by CreateOverride when the tenant already has
// an override for the same control and scenario (or the same control globally).
// The handler maps it to 409. compliance_overrides has no unique index, so this
// check is the only thing keeping a control from having two competing overrides.
var ErrDuplicateOverride = errors.New("an override already exists for this control and scenario")

// OverrideService handles compliance override CRUD operations
type OverrideService struct {
	db       *sqlx.DB
	enqueuer *ReconcileEnqueuer
}

// SetReconcileEnqueuer wires the reconcile queue. Creating or deleting a global
// override changes the stored framework-score rollup, so it enqueues a scoped
// reconcile for the framework. Nil (NATS down) degrades to the next reconcile.
func (s *OverrideService) SetReconcileEnqueuer(e *ReconcileEnqueuer) { s.enqueuer = e }

// enqueueScoreRefresh enqueues a reconcile of the platform framework owning
// controlID so tenant_framework_scores picks up an override change. Scenario
// overrides do not enter the stored rollup (it has no scenario) and tenant
// custom policies have no rollup row, so both are skipped.
func (s *OverrideService) enqueueScoreRefresh(tenantID, controlID uuid.UUID, scenarioID *uuid.UUID, frameworkType string) {
	if s.enqueuer == nil || scenarioID != nil || frameworkType != "platform" {
		return
	}
	var frameworkID uuid.UUID
	if err := s.db.Get(&frameworkID, `SELECT framework_id FROM platform_framework_controls WHERE id = $1`, controlID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("[Override] framework lookup for control %s failed: %v", controlID, err)
		}
		return
	}
	s.enqueuer.EnqueueTenantScoped(tenantID, frameworkID, "override_changed")
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
	}
	for _, value := range []*string{severityFrom, severityTo} {
		if value != nil && !isValidSeverity(*value) {
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

	// Serialize concurrent creates for the same (tenant, control, scenario) so
	// the existence check below cannot race another insert past it.
	scenarioKey := ""
	if scenarioID != nil {
		scenarioKey = scenarioID.String()
	}
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		tenantID.String()+"|"+controlID.String()+"|"+scenarioKey); err != nil {
		return nil, fmt.Errorf("lock override key: %w", err)
	}
	var exists bool
	if err := tx.Get(&exists, `
		SELECT EXISTS (
			SELECT 1 FROM compliance_overrides
			WHERE tenant_id = $1 AND control_id = $2 AND framework_type = $3
			  AND scenario_id IS NOT DISTINCT FROM $4::uuid
		)`, tenantID, controlID, frameworkType, scenarioID); err != nil {
		return nil, fmt.Errorf("check existing override: %w", err)
	}
	if exists {
		return nil, ErrDuplicateOverride
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

	s.enqueueScoreRefresh(tenantID, controlID, scenarioID, frameworkType)
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
	query := `DELETE FROM compliance_overrides WHERE id = $1 AND tenant_id = $2
		RETURNING control_id, scenario_id, framework_type`

	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return err
	}

	var deleted struct {
		ControlID     uuid.UUID  `db:"control_id"`
		ScenarioID    *uuid.UUID `db:"scenario_id"`
		FrameworkType string     `db:"framework_type"`
	}
	if err := tx.Get(&deleted, query, overrideID, tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("override not found")
		}
		return fmt.Errorf("failed to delete override: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	s.enqueueScoreRefresh(tenantID, deleted.ControlID, deleted.ScenarioID, deleted.FrameworkType)

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
		// Scenario-specific overrides take precedence over global ones
		query += ` AND (o.scenario_id = $3 OR o.scenario_id IS NULL)`
		args = append(args, *scenarioID)
	} else {
		query += ` AND o.scenario_id IS NULL`
	}
	// The same precedence loadOverrides uses (scenario first, then earliest).
	query += ` ORDER BY (o.scenario_id IS NULL), o.created_at, o.id`

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
func isValidSeverity(value string) bool {
	_, err := sharedseverity.ControlWeight(sharedseverity.Severity(value))
	return err == nil
}
