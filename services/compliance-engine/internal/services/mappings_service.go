package services

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// MappingsService provides access to rule→finding mappings
type MappingsService struct {
	db *sqlx.DB
}

func NewMappingsService(db *sqlx.DB) *MappingsService {
	return &MappingsService{db: db}
}

// ListMappings retrieves all rule→finding mappings, optionally filtered by rule_id or framework_id
func (s *MappingsService) ListMappings(ruleID *uuid.UUID, frameworkID *string) ([]models.RuleVulnerabilityMapping, error) {
	query := `
		SELECT id, rule_id, finding_type, predicate, weight, framework_id, framework_version, created_at, updated_at
		FROM rule_vulnerability_mappings
		WHERE 1=1`
	args := []interface{}{}
	argPos := 1

	if ruleID != nil {
		query += fmt.Sprintf(" AND rule_id = $%d", argPos)
		args = append(args, *ruleID)
		argPos++
	}

	if frameworkID != nil {
		query += fmt.Sprintf(" AND framework_id = $%d", argPos)
		args = append(args, *frameworkID)
	}

	query += " ORDER BY created_at DESC"

	var mappings []models.RuleVulnerabilityMapping
	err := s.db.Select(&mappings, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query rule vulnerability mappings: %w", err)
	}

	return mappings, nil
}

// GetMapping retrieves a specific mapping by ID
func (s *MappingsService) GetMapping(id uuid.UUID) (*models.RuleVulnerabilityMapping, error) {
	query := `
		SELECT id, rule_id, finding_type, predicate, weight, framework_id, framework_version, created_at, updated_at
		FROM rule_vulnerability_mappings
		WHERE id = $1`

	var mapping models.RuleVulnerabilityMapping
	err := s.db.QueryRow(query, id).Scan(
		&mapping.ID, &mapping.RuleID, &mapping.FindingType, &mapping.Predicate,
		&mapping.Weight, &mapping.FrameworkID, &mapping.FrameworkVersion,
		&mapping.CreatedAt, &mapping.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("mapping not found")
		}
		return nil, fmt.Errorf("failed to get mapping: %w", err)
	}

	return &mapping, nil
}

// CreateMapping creates a new rule→finding mapping
func (s *MappingsService) CreateMapping(m models.RuleVulnerabilityMapping) (*models.RuleVulnerabilityMapping, error) {
	// Validate rule exists
	var ruleExists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM compliance_rules WHERE id = $1)", m.RuleID).Scan(&ruleExists)
	if err != nil {
		return nil, fmt.Errorf("failed to validate rule: %w", err)
	}
	if !ruleExists {
		return nil, fmt.Errorf("compliance rule not found")
	}

	// Set defaults
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	now := time.Now()
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = now
	}
	if m.Weight == 0 {
		m.Weight = 1
	}
	if m.Predicate == nil {
		m.Predicate = make(map[string]interface{})
	}

	query := `
		INSERT INTO rule_vulnerability_mappings (id, rule_id, finding_type, predicate, weight, framework_id, framework_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, rule_id, finding_type, predicate, weight, framework_id, framework_version, created_at, updated_at`

	err = s.db.QueryRow(query,
		m.ID, m.RuleID, m.FindingType, m.Predicate, m.Weight,
		m.FrameworkID, m.FrameworkVersion, m.CreatedAt, m.UpdatedAt,
	).Scan(
		&m.ID, &m.RuleID, &m.FindingType, &m.Predicate,
		&m.Weight, &m.FrameworkID, &m.FrameworkVersion,
		&m.CreatedAt, &m.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create mapping: %w", err)
	}

	return &m, nil
}

// UpdateMapping updates an existing mapping
func (s *MappingsService) UpdateMapping(id uuid.UUID, m models.RuleVulnerabilityMapping) (*models.RuleVulnerabilityMapping, error) {
	// Validate rule exists if provided
	if m.RuleID != uuid.Nil {
		var ruleExists bool
		err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM compliance_rules WHERE id = $1)", m.RuleID).Scan(&ruleExists)
		if err != nil {
			return nil, fmt.Errorf("failed to validate rule: %w", err)
		}
		if !ruleExists {
			return nil, fmt.Errorf("compliance rule not found")
		}
	}

	m.UpdatedAt = time.Now()

	query := `
		UPDATE rule_vulnerability_mappings
		SET rule_id = COALESCE($2, rule_id),
		    finding_type = COALESCE($3, finding_type),
		    predicate = COALESCE($4, predicate),
		    weight = COALESCE($5, weight),
		    framework_id = COALESCE($6, framework_id),
		    framework_version = COALESCE($7, framework_version),
		    updated_at = $8
		WHERE id = $1
		RETURNING id, rule_id, finding_type, predicate, weight, framework_id, framework_version, created_at, updated_at`

	var result models.RuleVulnerabilityMapping
	err := s.db.QueryRow(query,
		id,
		m.RuleID, m.FindingType, m.Predicate, m.Weight,
		m.FrameworkID, m.FrameworkVersion, m.UpdatedAt,
	).Scan(
		&result.ID, &result.RuleID, &result.FindingType, &result.Predicate,
		&result.Weight, &result.FrameworkID, &result.FrameworkVersion,
		&result.CreatedAt, &result.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("mapping not found")
		}
		return nil, fmt.Errorf("failed to update mapping: %w", err)
	}

	return &result, nil
}

// DeleteMapping deletes a mapping by ID
func (s *MappingsService) DeleteMapping(id uuid.UUID) error {
	result, err := s.db.Exec("DELETE FROM rule_vulnerability_mappings WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete mapping: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("mapping not found")
	}

	return nil
}
