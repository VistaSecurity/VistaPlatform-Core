package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// PlatformFrameworkService handles platform framework operations
type PlatformFrameworkService struct {
	db        *sqlx.DB
	reconcile *ReconcileEnqueuer
}

// NewPlatformFrameworkService creates a new platform framework service
func NewPlatformFrameworkService(db *sqlx.DB) *PlatformFrameworkService {
	return &PlatformFrameworkService{db: db}
}

// SetReconcileEnqueuer wires the ADR-0014 reconcile enqueuer (optional; nil is a no-op).
func (s *PlatformFrameworkService) SetReconcileEnqueuer(e *ReconcileEnqueuer) {
	s.reconcile = e
}

// CreateFramework creates a new platform framework (draft status)
func (s *PlatformFrameworkService) CreateFramework(input *models.PlatformFrameworkInput, createdBy uuid.UUID) (*models.PlatformFramework, error) {
	// If trying to create a platform default, check if one already exists
	if input.IsPlatformDefault {
		existing, err := s.GetPlatformDefaultFramework()
		if err == nil && existing != nil {
			return nil, fmt.Errorf("a platform default framework already exists: %s (version %s)", existing.Name, existing.Version)
		}
	}

	framework := &models.PlatformFramework{
		ID:                uuid.New(),
		Code:              input.Code,
		Name:              input.Name,
		Version:           input.Version,
		Description:       input.Description,
		Organization:      input.Organization,
		Status:            "draft",
		IsPlatformDefault: input.IsPlatformDefault,
		CreatedBy:         createdBy,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	query := `
		INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, is_platform_default, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at
	`

	err := s.db.QueryRow(
		query,
		framework.ID, framework.Code, framework.Name, framework.Version,
		framework.Description, framework.Organization, framework.Status,
		framework.IsPlatformDefault, framework.CreatedBy, framework.CreatedAt, framework.UpdatedAt,
	).Scan(
		&framework.ID, &framework.Code, &framework.Name, &framework.Version,
		&framework.Description, &framework.Organization, &framework.Status,
		&framework.IsPlatformDefault, &framework.PublishedAt, &framework.PublishedBy,
		&framework.CreatedBy, &framework.CreatedAt, &framework.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create platform framework: %w", err)
	}

	return framework, nil
}

// UpdateFramework updates an existing platform framework (only if draft)
func (s *PlatformFrameworkService) UpdateFramework(id uuid.UUID, input *models.PlatformFrameworkInput) (*models.PlatformFramework, error) {
	// Check if framework exists and is in draft status
	var currentStatus string
	err := s.db.Get(&currentStatus, "SELECT status FROM platform_frameworks WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("framework not found")
		}
		return nil, fmt.Errorf("failed to check framework status: %w", err)
	}

	if currentStatus != "draft" {
		return nil, fmt.Errorf("can only update frameworks in draft status")
	}

	query := `
		UPDATE platform_frameworks
		SET code = $1, name = $2, version = $3, description = $4, organization = $5, updated_at = NOW()
		WHERE id = $6
		RETURNING id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at
	`

	framework := &models.PlatformFramework{}
	err = s.db.QueryRow(
		query,
		input.Code, input.Name, input.Version, input.Description, input.Organization, id,
	).Scan(
		&framework.ID, &framework.Code, &framework.Name, &framework.Version,
		&framework.Description, &framework.Organization, &framework.Status,
		&framework.IsPlatformDefault, &framework.PublishedAt, &framework.PublishedBy,
		&framework.CreatedBy, &framework.CreatedAt, &framework.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to update platform framework: %w", err)
	}

	return framework, nil
}

// PublishFramework publishes or archives a framework
func (s *PlatformFrameworkService) PublishFramework(id uuid.UUID, input *models.PublishFrameworkInput, publishedBy uuid.UUID) (*models.PlatformFramework, error) {
	var publishedAt *time.Time
	if input.Status == "published" {
		now := time.Now()
		publishedAt = &now
	}

	query := `
		UPDATE platform_frameworks
		SET status = $1, published_at = $2, published_by = $3, updated_at = NOW()
		WHERE id = $4
		RETURNING id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at
	`

	framework := &models.PlatformFramework{}
	err := s.db.QueryRow(query, input.Status, publishedAt, publishedBy, id).Scan(
		&framework.ID, &framework.Code, &framework.Name, &framework.Version,
		&framework.Description, &framework.Organization, &framework.Status,
		&framework.IsPlatformDefault, &framework.PublishedAt, &framework.PublishedBy,
		&framework.CreatedBy, &framework.CreatedAt, &framework.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to publish platform framework: %w", err)
	}

	// Auto-create version snapshot when publishing
	if input.Status == "published" {
		// Load controls for the snapshot
		controls, err := s.getFrameworkControls(framework.ID)
		if err != nil {
			fmt.Printf("Warning: Failed to load controls for version snapshot of framework %s: %v\n", framework.ID, err)
		} else {
			framework.Controls = controls
		}

		// Build snapshot with framework + controls
		snapshotData := map[string]interface{}{
			"id":                  framework.ID,
			"code":                framework.Code,
			"name":                framework.Name,
			"version":             framework.Version,
			"description":         framework.Description,
			"organization":        framework.Organization,
			"status":              framework.Status,
			"is_platform_default": framework.IsPlatformDefault,
			"published_at":        framework.PublishedAt,
			"published_by":        framework.PublishedBy,
			"created_by":          framework.CreatedBy,
			"created_at":          framework.CreatedAt,
			"updated_at":          framework.UpdatedAt,
			"controls":            framework.Controls,
		}

		snapshotJSON, err := json.Marshal(snapshotData)
		if err != nil {
			fmt.Printf("Warning: Failed to marshal version snapshot for framework %s: %v\n", framework.ID, err)
		} else {
			changeSummary := fmt.Sprintf("Published version %s", framework.Version)
			if err := s.CreateFrameworkVersionSnapshot(framework.ID, framework.Version, snapshotJSON, changeSummary, publishedBy); err != nil {
				fmt.Printf("Warning: Failed to create version snapshot for framework %s: %v\n", framework.ID, err)
			}
		}
	}

	// ADR-0014: publishing a framework changes every tenant's posture (it becomes
	// evaluable, and its rollup score appears even for non-activated tenants). Fan a
	// reconcile out to all tenants, scoped to THIS framework's controls so we
	// don't re-evaluate every other published framework × every asset. No-op if the
	// worker is off.
	s.reconcile.EnqueueAllTenantsScoped(framework.ID, "framework_published")

	return framework, nil
}

// ListFrameworks lists all platform frameworks with optional status filter
// Best Practices framework (platform default) is returned first
// Controls are loaded for each framework
func (s *PlatformFrameworkService) ListFrameworks(statusFilter string) ([]models.PlatformFramework, error) {
	query := `
		SELECT id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at
		FROM platform_frameworks
	`
	args := []interface{}{}

	if statusFilter != "" {
		query += " WHERE status = $1"
		args = append(args, statusFilter)
	}

	query += " ORDER BY is_platform_default DESC, created_at DESC"

	var frameworks []models.PlatformFramework
	err := s.db.Select(&frameworks, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list platform frameworks: %w", err)
	}

	// Load controls for each framework
	for i := range frameworks {
		controls, err := s.getFrameworkControls(frameworks[i].ID)
		if err != nil {
			// Log error but don't fail - framework list should still work
			fmt.Printf("Warning: Failed to load controls for framework %s: %v\n", frameworks[i].ID, err)
			frameworks[i].Controls = []models.PlatformFrameworkControl{}
		} else {
			frameworks[i].Controls = controls
		}
	}

	return frameworks, nil
}

// GetFramework gets a platform framework by ID with controls loaded
func (s *PlatformFrameworkService) GetFramework(id uuid.UUID) (*models.PlatformFramework, error) {
	query := `
		SELECT id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at
		FROM platform_frameworks
		WHERE id = $1
	`

	framework := &models.PlatformFramework{}
	err := s.db.Get(framework, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("framework not found")
		}
		return nil, fmt.Errorf("failed to get platform framework: %w", err)
	}

	// Load controls for the framework
	controls, err := s.getFrameworkControls(framework.ID)
	if err != nil {
		// Log error but don't fail - framework should still be returned
		fmt.Printf("Warning: Failed to load controls for framework %s: %v\n", framework.ID, err)
		framework.Controls = []models.PlatformFrameworkControl{}
	} else {
		framework.Controls = controls
	}

	return framework, nil
}

// getFrameworkControls loads all controls for a platform framework
func (s *PlatformFrameworkService) getFrameworkControls(frameworkID uuid.UUID) ([]models.PlatformFrameworkControl, error) {
	query := `
		SELECT id, framework_id, family_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
		FROM platform_framework_controls
		WHERE framework_id = $1
		ORDER BY control_id
	`

	var controls []models.PlatformFrameworkControl
	err := s.db.Select(&controls, query, frameworkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get framework controls: %w", err)
	}

	return controls, nil
}

// GetPlatformDefaultFramework returns the framework marked as platform default (Best Practices)
func (s *PlatformFrameworkService) GetPlatformDefaultFramework() (*models.PlatformFramework, error) {
	query := `
		SELECT id, code, name, version, description, organization, status, is_platform_default, published_at, published_by, created_by, created_at, updated_at
		FROM platform_frameworks
		WHERE is_platform_default = true
		LIMIT 1
	`

	framework := &models.PlatformFramework{}
	err := s.db.Get(framework, query)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("platform default framework not found")
		}
		return nil, fmt.Errorf("failed to get platform default framework: %w", err)
	}

	return framework, nil
}

// IsPlatformDefault checks if a framework is the platform default
func (s *PlatformFrameworkService) IsPlatformDefault(frameworkID uuid.UUID) (bool, error) {
	var isDefault bool
	err := s.db.Get(&isDefault, `
		SELECT is_platform_default
		FROM platform_frameworks
		WHERE id = $1
	`, frameworkID)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("framework not found")
		}
		return false, fmt.Errorf("failed to check platform default status: %w", err)
	}

	return isDefault, nil
}

// DeleteFramework deletes a platform framework (only if draft)
func (s *PlatformFrameworkService) DeleteFramework(id uuid.UUID) error {
	// Check if framework exists and is in draft status
	var status string
	err := s.db.Get(&status, "SELECT status FROM platform_frameworks WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("framework not found")
		}
		return fmt.Errorf("failed to check framework status: %w", err)
	}

	if status != "draft" {
		return fmt.Errorf("can only delete frameworks in draft status")
	}

	_, err = s.db.Exec("DELETE FROM platform_frameworks WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete platform framework: %w", err)
	}

	return nil
}

// CreateControl creates a control for a platform framework
func (s *PlatformFrameworkService) CreateControl(frameworkID uuid.UUID, input *models.PlatformFrameworkControlInput) (*models.PlatformFrameworkControl, error) {
	control := &models.PlatformFrameworkControl{
		ID:               uuid.New(),
		FrameworkID:      frameworkID,
		FamilyID:         input.FamilyID,
		ControlID:        input.ControlID,
		Title:            input.Title,
		Description:      input.Description,
		BaselineSeverity: input.BaselineSeverity,
		CryptoRelevant:   input.CryptoRelevant,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	query := `
		INSERT INTO platform_framework_controls (id, framework_id, family_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, framework_id, family_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
	`

	err := s.db.QueryRow(
		query,
		control.ID, control.FrameworkID, control.FamilyID, control.ControlID,
		control.Title, control.Description, control.BaselineSeverity, control.CryptoRelevant,
		control.CreatedAt, control.UpdatedAt,
	).Scan(
		&control.ID, &control.FrameworkID, &control.FamilyID, &control.ControlID,
		&control.Title, &control.Description, &control.BaselineSeverity, &control.CryptoRelevant,
		&control.CreatedAt, &control.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create platform framework control: %w", err)
	}

	return control, nil
}

// UpdateControl updates a platform framework control
func (s *PlatformFrameworkService) UpdateControl(controlID uuid.UUID, input *models.PlatformFrameworkControlInput) (*models.PlatformFrameworkControl, error) {
	query := `
		UPDATE platform_framework_controls
		SET family_id = $1, control_id = $2, title = $3, description = $4, baseline_severity = $5, crypto_relevant = $6, updated_at = NOW()
		WHERE id = $7
		RETURNING id, framework_id, family_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
	`

	control := &models.PlatformFrameworkControl{}
	err := s.db.QueryRow(
		query,
		input.FamilyID, input.ControlID, input.Title, input.Description,
		input.BaselineSeverity, input.CryptoRelevant, controlID,
	).Scan(
		&control.ID, &control.FrameworkID, &control.FamilyID, &control.ControlID,
		&control.Title, &control.Description, &control.BaselineSeverity, &control.CryptoRelevant,
		&control.CreatedAt, &control.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("control not found")
		}
		return nil, fmt.Errorf("failed to update platform framework control: %w", err)
	}

	return control, nil
}

// DeleteControl deletes a platform framework control
func (s *PlatformFrameworkService) DeleteControl(controlID uuid.UUID) error {
	_, err := s.db.Exec("DELETE FROM platform_framework_controls WHERE id = $1", controlID)
	if err != nil {
		return fmt.Errorf("failed to delete platform framework control: %w", err)
	}

	return nil
}

// AddControlMeasurement adds a measurement mapping to a control
func (s *PlatformFrameworkService) AddControlMeasurement(controlID uuid.UUID, input *models.ControlMeasurementInput) (*models.ControlMeasurement, error) {
	// Get measurement type for validation
	var measurementType models.MeasurementType
	err := s.db.Get(&measurementType, `
		SELECT id, code, name, description, data_type, extraction_query, units, valid_range,
		       allowed_rule_types, enum_values, valid_operators, predicate_schema, category,
		       created_at, updated_at
		FROM measurement_types
		WHERE id = $1
	`, input.MeasurementTypeID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("measurement type not found")
		}
		return nil, fmt.Errorf("failed to get measurement type: %w", err)
	}

	// Parse JSONB fields
	validator := NewMeasurementValidator()
	measurementType.AllowedRuleTypes = validator.ParseAllowedRuleTypes(measurementType.AllowedRuleTypes)
	measurementType.ValidOperators = validator.ParseValidOperators(measurementType.ValidOperators)
	measurementType.EnumValues = validator.ParseEnumValues(measurementType.EnumValues)

	// Validate measurement input
	if err := validator.ValidateMeasurementInput(input, &measurementType); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Serialize predicate to JSONB
	predicateJSON, err := json.Marshal(input.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal predicate: %w", err)
	}

	measurement := &models.ControlMeasurement{
		ID:                uuid.New(),
		ControlID:         controlID,
		FrameworkType:     "platform",
		MeasurementTypeID: input.MeasurementTypeID,
		RuleType:          input.RuleType,
		Predicate:         input.Predicate,
		SeverityOverride:  input.SeverityOverride,
		Weight:            input.Weight,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if measurement.Weight == 0 {
		measurement.Weight = 1
	}

	query := `
		INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
	`

	var predicateJSONB []byte
	err = s.db.QueryRow(
		query,
		measurement.ID, measurement.ControlID, measurement.FrameworkType,
		measurement.MeasurementTypeID, measurement.RuleType, predicateJSON,
		measurement.SeverityOverride, measurement.Weight, measurement.CreatedAt, measurement.UpdatedAt,
	).Scan(
		&measurement.ID, &measurement.ControlID, &measurement.FrameworkType,
		&measurement.MeasurementTypeID, &measurement.RuleType, &predicateJSONB,
		&measurement.SeverityOverride, &measurement.Weight, &measurement.CreatedAt, &measurement.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to add control measurement: %w", err)
	}

	// Unmarshal predicate back
	err = json.Unmarshal(predicateJSONB, &measurement.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal predicate: %w", err)
	}

	return measurement, nil
}

// UpdateControlMeasurement updates a control measurement mapping
func (s *PlatformFrameworkService) UpdateControlMeasurement(measurementID uuid.UUID, input *models.ControlMeasurementInput) (*models.ControlMeasurement, error) {
	// Get measurement type for validation
	var measurementType models.MeasurementType
	err := s.db.Get(&measurementType, `
		SELECT id, code, name, description, data_type, extraction_query, units, valid_range,
		       allowed_rule_types, enum_values, valid_operators, predicate_schema, category,
		       created_at, updated_at
		FROM measurement_types
		WHERE id = $1
	`, input.MeasurementTypeID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("measurement type not found")
		}
		return nil, fmt.Errorf("failed to get measurement type: %w", err)
	}

	// Parse JSONB fields
	validator := NewMeasurementValidator()
	measurementType.AllowedRuleTypes = validator.ParseAllowedRuleTypes(measurementType.AllowedRuleTypes)
	measurementType.ValidOperators = validator.ParseValidOperators(measurementType.ValidOperators)
	measurementType.EnumValues = validator.ParseEnumValues(measurementType.EnumValues)

	// Validate measurement input
	if err := validator.ValidateMeasurementInput(input, &measurementType); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Serialize predicate to JSONB
	predicateJSON, err := json.Marshal(input.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal predicate: %w", err)
	}

	weight := input.Weight
	if weight == 0 {
		weight = 1
	}

	query := `
		UPDATE control_measurements
		SET measurement_type_id = $1, rule_type = $2, predicate = $3, severity_override = $4, weight = $5, updated_at = NOW()
		WHERE id = $6 AND framework_type = 'platform'
		RETURNING id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
	`

	measurement := &models.ControlMeasurement{}
	var predicateJSONB []byte
	err = s.db.QueryRow(
		query,
		input.MeasurementTypeID, input.RuleType, predicateJSON,
		input.SeverityOverride, weight, measurementID,
	).Scan(
		&measurement.ID, &measurement.ControlID, &measurement.FrameworkType,
		&measurement.MeasurementTypeID, &measurement.RuleType, &predicateJSONB,
		&measurement.SeverityOverride, &measurement.Weight, &measurement.CreatedAt, &measurement.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("measurement not found")
		}
		return nil, fmt.Errorf("failed to update control measurement: %w", err)
	}

	// Unmarshal predicate back
	err = json.Unmarshal(predicateJSONB, &measurement.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal predicate: %w", err)
	}

	return measurement, nil
}

// DeleteControlMeasurement deletes a control measurement mapping
func (s *PlatformFrameworkService) DeleteControlMeasurement(measurementID uuid.UUID) error {
	_, err := s.db.Exec("DELETE FROM control_measurements WHERE id = $1 AND framework_type = 'platform'", measurementID)
	if err != nil {
		return fmt.Errorf("failed to delete control measurement: %w", err)
	}

	return nil
}

// ListControlMeasurements returns the platform measurement rules mapped to a control.
// The predicate JSONB is unmarshalled; the measurement_type is left for the caller to
// join (the authoring UI already holds the measurement-types catalog).
func (s *PlatformFrameworkService) ListControlMeasurements(controlID uuid.UUID) ([]models.ControlMeasurement, error) {
	rows, err := s.db.Query(`
		SELECT id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at
		FROM control_measurements
		WHERE control_id = $1 AND framework_type = 'platform'
		ORDER BY created_at ASC
	`, controlID)
	if err != nil {
		return nil, fmt.Errorf("failed to list control measurements: %w", err)
	}
	defer func() { _ = rows.Close() }()

	measurements := []models.ControlMeasurement{}
	for rows.Next() {
		var m models.ControlMeasurement
		var predicateBytes []byte
		var severityOverride sql.NullString
		if err := rows.Scan(&m.ID, &m.ControlID, &m.FrameworkType, &m.MeasurementTypeID, &m.RuleType, &predicateBytes, &severityOverride, &m.Weight, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan control measurement: %w", err)
		}
		if len(predicateBytes) > 0 {
			_ = json.Unmarshal(predicateBytes, &m.Predicate)
		}
		if severityOverride.Valid {
			m.SeverityOverride = severityOverride.String
		}
		measurements = append(measurements, m)
	}
	return measurements, rows.Err()
}

// CreateFrameworkVersionSnapshot creates a version snapshot for a framework
func (s *PlatformFrameworkService) CreateFrameworkVersionSnapshot(frameworkID uuid.UUID, version string, snapshot json.RawMessage, changeSummary string, changedBy uuid.UUID) error {
	query := `
		INSERT INTO platform_framework_versions (framework_id, version, snapshot, change_summary, changed_by)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := s.db.Exec(query, frameworkID, version, snapshot, changeSummary, changedBy)
	if err != nil {
		return fmt.Errorf("failed to create framework version snapshot: %w", err)
	}

	return nil
}

// ListFrameworkVersions lists version snapshots for a framework ordered by created_at DESC
func (s *PlatformFrameworkService) ListFrameworkVersions(frameworkID uuid.UUID) ([]models.PlatformFrameworkVersionSummary, error) {
	query := `
		SELECT id, version, change_summary, changed_by, created_at
		FROM platform_framework_versions
		WHERE framework_id = $1
		ORDER BY created_at DESC
	`

	var versions []models.PlatformFrameworkVersionSummary
	err := s.db.Select(&versions, query, frameworkID)
	if err != nil {
		return nil, fmt.Errorf("failed to list framework versions: %w", err)
	}

	return versions, nil
}

// GetFrameworkVersion gets a specific version snapshot by ID
func (s *PlatformFrameworkService) GetFrameworkVersion(versionID uuid.UUID) (*models.PlatformFrameworkVersion, error) {
	query := `
		SELECT id, framework_id, version, snapshot, change_summary, changed_by, created_at
		FROM platform_framework_versions
		WHERE id = $1
	`

	version := &models.PlatformFrameworkVersion{}
	err := s.db.Get(version, query, versionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("version not found")
		}
		return nil, fmt.Errorf("failed to get framework version: %w", err)
	}

	return version, nil
}
