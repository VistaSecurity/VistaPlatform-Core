package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// TemplateService handles measurement template operations
type TemplateService struct {
	db *sqlx.DB

	// tenantAuthor is the Enterprise custom-policies authoring backend, used
	// only by ApplyTemplateToTenant. Nil in a Core build (see edition.go).
	tenantAuthor TenantMeasurementAuthor
}

// NewTemplateService creates a new template service
func NewTemplateService(db *sqlx.DB) *TemplateService {
	return &TemplateService{db: db}
}

// SetTenantAuthor wires the Enterprise custom-policies authoring backend so
// templates can be applied to a tenant-authored framework control. Called only
// from the Enterprise edition wiring in cmd/edition_ee.go; a Core build leaves
// it unset and ApplyTemplateToTenant returns ErrCustomPoliciesUnavailable.
//
// Callers must not pass a nil *concrete value here: a nil pointer stored in an
// interface makes the field non-nil and the guard below would wrongly pass.
func (s *TemplateService) SetTenantAuthor(a TenantMeasurementAuthor) {
	s.tenantAuthor = a
}

// ListTemplates lists templates with optional filtering
func (s *TemplateService) ListTemplates(filters map[string]interface{}) ([]models.MeasurementTemplate, error) {
	baseQuery := `
		SELECT id, code, name, description, measurement_type_id, rule_type, predicate,
		       category, framework_tags, version, is_active, created_by, created_at, updated_at
		FROM measurement_templates
	`
	wb := shareddatabase.NewWhereBuilder()

	if category, ok := filters["category"].(string); ok && category != "" {
		wb.Add("category = %s", category)
	}
	if frameworkTag, ok := filters["framework_tag"].(string); ok && frameworkTag != "" {
		wb.Add("%s = ANY(framework_tags)", frameworkTag)
	}
	if isActive, ok := filters["is_active"].(bool); ok {
		wb.Add("is_active = %s", isActive)
	} else {
		wb.Add("is_active = %s", true)
	}

	whereClause, args := wb.Build()
	query := baseQuery + whereClause + " ORDER BY category, name"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query templates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var templates []models.MeasurementTemplate
	for rows.Next() {
		var template models.MeasurementTemplate
		var predicateJSONB []byte
		var createdBy sql.NullString

		err := rows.Scan(
			&template.ID, &template.Code, &template.Name, &template.Description,
			&template.MeasurementTypeID, &template.RuleType, &predicateJSONB,
			&template.Category, pq.Array(&template.FrameworkTags), &template.Version,
			&template.IsActive, &createdBy, &template.CreatedAt, &template.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan template: %w", err)
		}

		// Unmarshal predicate
		if len(predicateJSONB) > 0 {
			template.Predicate = make(map[string]interface{})
			if err := json.Unmarshal(predicateJSONB, &template.Predicate); err != nil {
				return nil, fmt.Errorf("failed to unmarshal predicate: %w", err)
			}
		}

		// Parse created_by
		if createdBy.Valid {
			if id, err := uuid.Parse(createdBy.String); err == nil {
				template.CreatedBy = &id
			}
		}

		templates = append(templates, template)
	}

	return templates, nil
}

// GetTemplate gets a template by ID
func (s *TemplateService) GetTemplate(id uuid.UUID) (*models.MeasurementTemplate, error) {
	query := `
		SELECT id, code, name, description, measurement_type_id, rule_type, predicate,
		       category, framework_tags, version, is_active, created_by, created_at, updated_at
		FROM measurement_templates
		WHERE id = $1
	`

	var template models.MeasurementTemplate
	var predicateJSONB []byte
	var createdBy sql.NullString

	err := s.db.QueryRow(query, id).Scan(
		&template.ID, &template.Code, &template.Name, &template.Description,
		&template.MeasurementTypeID, &template.RuleType, &predicateJSONB,
		&template.Category, pq.Array(&template.FrameworkTags), &template.Version,
		&template.IsActive, &createdBy, &template.CreatedAt, &template.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("template not found")
		}
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Unmarshal predicate
	if len(predicateJSONB) > 0 {
		template.Predicate = make(map[string]interface{})
		if err := json.Unmarshal(predicateJSONB, &template.Predicate); err != nil {
			return nil, fmt.Errorf("failed to unmarshal predicate: %w", err)
		}
	}

	// Parse created_by
	if createdBy.Valid {
		if id, err := uuid.Parse(createdBy.String); err == nil {
			template.CreatedBy = &id
		}
	}

	return &template, nil
}

// CreateTemplate creates a new template
func (s *TemplateService) CreateTemplate(input *models.MeasurementTemplateInput, createdBy uuid.UUID) (*models.MeasurementTemplate, error) {
	// Validate that measurement type exists
	var measurementTypeID uuid.UUID
	err := s.db.Get(&measurementTypeID, "SELECT id FROM measurement_types WHERE id = $1", input.MeasurementTypeID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("measurement type not found")
		}
		return nil, fmt.Errorf("failed to verify measurement type: %w", err)
	}

	// Serialize predicate
	predicateJSON, err := json.Marshal(input.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal predicate: %w", err)
	}

	template := &models.MeasurementTemplate{
		ID:                uuid.New(),
		Code:              input.Code,
		Name:              input.Name,
		Description:       input.Description,
		MeasurementTypeID: input.MeasurementTypeID,
		RuleType:          input.RuleType,
		Predicate:         input.Predicate,
		Category:          input.Category,
		FrameworkTags:     input.FrameworkTags,
		Version:           1,
		IsActive:          input.IsActive,
		CreatedBy:         &createdBy,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	query := `
		INSERT INTO measurement_templates (id, code, name, description, measurement_type_id, rule_type, predicate,
		                                  category, framework_tags, version, is_active, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, code, name, description, measurement_type_id, rule_type, predicate,
		          category, framework_tags, version, is_active, created_by, created_at, updated_at
	`

	var predicateJSONB []byte
	var createdByStr sql.NullString

	err = s.db.QueryRow(
		query,
		template.ID, template.Code, template.Name, template.Description,
		template.MeasurementTypeID, template.RuleType, predicateJSON,
		template.Category, pq.Array(template.FrameworkTags), template.Version,
		template.IsActive, createdBy, template.CreatedAt, template.UpdatedAt,
	).Scan(
		&template.ID, &template.Code, &template.Name, &template.Description,
		&template.MeasurementTypeID, &template.RuleType, &predicateJSONB,
		&template.Category, pq.Array(&template.FrameworkTags), &template.Version,
		&template.IsActive, &createdByStr, &template.CreatedAt, &template.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create template: %w", err)
	}

	if len(predicateJSONB) > 0 {
		if err := json.Unmarshal(predicateJSONB, &template.Predicate); err != nil {
			return nil, fmt.Errorf("failed to unmarshal predicate: %w", err)
		}
	}

	return template, nil
}

// UpdateTemplate updates a template
func (s *TemplateService) UpdateTemplate(id uuid.UUID, input *models.MeasurementTemplateInput) (*models.MeasurementTemplate, error) {
	// Check if template exists
	var currentVersion int
	err := s.db.Get(&currentVersion, "SELECT version FROM measurement_templates WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("template not found")
		}
		return nil, fmt.Errorf("failed to check template: %w", err)
	}

	// Serialize predicate
	predicateJSON, err := json.Marshal(input.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal predicate: %w", err)
	}

	// Increment version
	newVersion := currentVersion + 1

	query := `
		UPDATE measurement_templates
		SET code = $1, name = $2, description = $3, measurement_type_id = $4, rule_type = $5,
		    predicate = $6, category = $7, framework_tags = $8, version = $9, is_active = $10,
		    updated_at = NOW()
		WHERE id = $11
		RETURNING id, code, name, description, measurement_type_id, rule_type, predicate,
		          category, framework_tags, version, is_active, created_by, created_at, updated_at
	`

	template := &models.MeasurementTemplate{}
	var predicateJSONB []byte
	var createdByStr sql.NullString

	err = s.db.QueryRow(
		query,
		input.Code, input.Name, input.Description, input.MeasurementTypeID, input.RuleType,
		predicateJSON, input.Category, pq.Array(input.FrameworkTags), newVersion, input.IsActive, id,
	).Scan(
		&template.ID, &template.Code, &template.Name, &template.Description,
		&template.MeasurementTypeID, &template.RuleType, &predicateJSONB,
		&template.Category, pq.Array(&template.FrameworkTags), &template.Version,
		&template.IsActive, &createdByStr, &template.CreatedAt, &template.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update template: %w", err)
	}

	if len(predicateJSONB) > 0 {
		if err := json.Unmarshal(predicateJSONB, &template.Predicate); err != nil {
			return nil, fmt.Errorf("failed to unmarshal predicate: %w", err)
		}
	}
	if createdByStr.Valid {
		if id, err := uuid.Parse(createdByStr.String); err == nil {
			template.CreatedBy = &id
		}
	}

	return template, nil
}

// DeleteTemplate soft deletes a template (sets is_active = false)
func (s *TemplateService) DeleteTemplate(id uuid.UUID) error {
	_, err := s.db.Exec("UPDATE measurement_templates SET is_active = false, updated_at = NOW() WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}
	return nil
}

// ApplyTemplate applies a template to a control, creating a measurement
func (s *TemplateService) ApplyTemplate(templateID uuid.UUID, controlID uuid.UUID, frameworkType string) (*models.ControlMeasurement, error) {
	// Get template
	template, err := s.GetTemplate(templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	if !template.IsActive {
		return nil, fmt.Errorf("template is not active")
	}

	// Create measurement input from template
	measurementInput := &models.ControlMeasurementInput{
		MeasurementTypeID: template.MeasurementTypeID,
		RuleType:          template.RuleType,
		Predicate:         template.Predicate,
		Weight:            1, // Default weight
	}

	// Use appropriate service based on framework type
	switch frameworkType {
	case "platform":
		platformService := NewPlatformFrameworkService(s.db)
		return platformService.AddControlMeasurement(controlID, measurementInput)
	case "tenant":
		// For tenant, we need tenantID - this would need to be passed in
		// For now, return error indicating tenantID is required
		return nil, fmt.Errorf("tenant framework requires tenantID - use tenant service directly")
	}

	return nil, fmt.Errorf("invalid framework type: %s", frameworkType)
}

// ApplyTemplateToTenant applies a template to a tenant framework control
func (s *TemplateService) ApplyTemplateToTenant(templateID uuid.UUID, controlID uuid.UUID, tenantID uuid.UUID) (*models.ControlMeasurement, error) {
	// Get template
	template, err := s.GetTemplate(templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	if !template.IsActive {
		return nil, fmt.Errorf("template is not active")
	}

	// Create measurement input from template
	measurementInput := &models.ControlMeasurementInput{
		MeasurementTypeID: template.MeasurementTypeID,
		RuleType:          template.RuleType,
		Predicate:         template.Predicate,
		Weight:            1, // Default weight
	}

	// Writing a measurement onto a tenant-authored framework control IS
	// custom-policy authoring, so it goes through the Enterprise backend.
	// Core has none — say so plainly instead of failing obscurely.
	if s.tenantAuthor == nil {
		return nil, ErrCustomPoliciesUnavailable
	}
	// (note: tenantID comes first in the signature)
	return s.tenantAuthor.AddControlMeasurement(tenantID, controlID, measurementInput)
}

// GetTemplatesByCategory gets templates by category
func (s *TemplateService) GetTemplatesByCategory(category string) ([]models.MeasurementTemplate, error) {
	return s.ListTemplates(map[string]interface{}{
		"category":  category,
		"is_active": true,
	})
}

// GetTemplatesByFramework gets templates by framework tag
func (s *TemplateService) GetTemplatesByFramework(frameworkTag string) ([]models.MeasurementTemplate, error) {
	return s.ListTemplates(map[string]interface{}{
		"framework_tag": frameworkTag,
		"is_active":     true,
	})
}
