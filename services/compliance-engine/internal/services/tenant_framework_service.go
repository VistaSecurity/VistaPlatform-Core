package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// TenantFrameworkService handles tenant framework operations
type TenantFrameworkService struct {
	db *sqlx.DB
}

// NewTenantFrameworkService creates a new tenant framework service
func NewTenantFrameworkService(db *sqlx.DB) *TenantFrameworkService {
	return &TenantFrameworkService{db: db}
}

// ListPublishedFrameworks lists all published platform frameworks (read-only for tenants)
// Best Practices framework (platform default) is returned first
// If tenantID is provided, includes license status for that tenant
func (s *TenantFrameworkService) ListPublishedFrameworks(tenantID *uuid.UUID) ([]models.PlatformFramework, error) {
	query := `
		SELECT f.id, f.code, f.name, f.version, f.description, f.organization, f.status,
		       f.is_platform_default, f.published_at, f.published_by, f.created_by, f.created_at, f.updated_at,
		       COALESCE(c.controls_count, 0) as controls_count
		FROM platform_frameworks f
		LEFT JOIN (
			SELECT framework_id, COUNT(*) as controls_count
			FROM platform_framework_controls
			GROUP BY framework_id
		) c ON c.framework_id = f.id
		WHERE f.status = 'published'
		ORDER BY f.is_platform_default DESC, f.published_at DESC, f.name
	`

	var frameworks []models.PlatformFramework
	err := s.db.Select(&frameworks, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list published frameworks: %w", err)
	}

	// If tenantID is provided, check license status for each framework
	if tenantID != nil {
		licensedQuery := `
			SELECT platform_framework_id
			FROM tenant_framework_licenses
			WHERE tenant_id = $1
		`
		// RLS: tenant_framework_licenses — set app.tenant_id on the same tx as the read.
		var licensedIDs []uuid.UUID
		ltx, terr := s.db.BeginTxx(context.Background(), nil)
		if terr != nil {
			return nil, fmt.Errorf("begin tx: %w", terr)
		}
		defer func() { _ = ltx.Rollback() }()
		if terr := shareddatabase.SetTenantContext(context.Background(), ltx.Tx, *tenantID); terr != nil {
			return nil, terr
		}
		err = ltx.Select(&licensedIDs, licensedQuery, *tenantID)
		if err == nil {
			err = ltx.Commit()
		}
		if err != nil && err != sql.ErrNoRows {
			// If table doesn't exist, just continue without license info
			if !strings.Contains(err.Error(), "does not exist") && !strings.Contains(err.Error(), "relation") {
				return nil, fmt.Errorf("failed to get licensed frameworks: %w", err)
			}
		}

		// Build map of licensed IDs
		licensedMap := make(map[uuid.UUID]bool)
		for _, id := range licensedIDs {
			licensedMap[id] = true
		}

		// Add license status to each framework (we'll use a custom response type)
		// For now, we'll add it as a JSON tag extension
		// Actually, we need to return a different type that includes is_licensed
		// Let's create a response type
	}

	return frameworks, nil
}

// ListPublishedFrameworksWithLicense lists all published frameworks with license status for a tenant
func (s *TenantFrameworkService) ListPublishedFrameworksWithLicense(tenantID uuid.UUID) ([]models.PublishedFrameworkWithLicense, error) {
	query := `
		SELECT f.id, f.code, f.name, f.version, f.description, f.organization, f.status,
		       f.is_platform_default, f.published_at, f.published_by, f.created_by, f.created_at, f.updated_at,
		       COALESCE(c.controls_count, 0) as controls_count,
		       CASE WHEN tfl.platform_framework_id IS NOT NULL THEN true ELSE false END as is_licensed
		FROM platform_frameworks f
		LEFT JOIN (
			SELECT framework_id, COUNT(*) as controls_count
			FROM platform_framework_controls
			GROUP BY framework_id
		) c ON c.framework_id = f.id
		LEFT JOIN tenant_framework_licenses tfl ON tfl.platform_framework_id = f.id AND tfl.tenant_id = $1 AND ` + sqlActiveSubscriptionTfl + `
		WHERE f.status = 'published'
		ORDER BY f.is_platform_default DESC, f.published_at DESC, f.name
	`

	// RLS: tenant_framework_licenses (via tfl join) — set app.tenant_id on the same tx as the read.
	var frameworks []models.PublishedFrameworkWithLicense
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}
	err = tx.Select(&frameworks, query, tenantID)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		// If table doesn't exist, return frameworks without license info
		if strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "relation") {
			// Fallback to basic query
			return s.listPublishedFrameworksBasic()
		}
		return nil, fmt.Errorf("failed to list published frameworks: %w", err)
	}

	// Debug: Log how many frameworks have licenses
	licensedCount := 0
	for _, fw := range frameworks {
		if fw.IsLicensed {
			licensedCount++
		}
	}
	log.Printf("📋 ListPublishedFrameworksWithLicense: Returning %d frameworks, %d are licensed for tenant %s", len(frameworks), licensedCount, tenantID)

	return frameworks, nil
}

// listPublishedFrameworksBasic lists published frameworks without license info (fallback)
func (s *TenantFrameworkService) listPublishedFrameworksBasic() ([]models.PublishedFrameworkWithLicense, error) {
	query := `
		SELECT f.id, f.code, f.name, f.version, f.description, f.organization, f.status,
		       f.is_platform_default, f.published_at, f.published_by, f.created_by, f.created_at, f.updated_at,
		       COALESCE(c.controls_count, 0) as controls_count,
		       false as is_licensed
		FROM platform_frameworks f
		LEFT JOIN (
			SELECT framework_id, COUNT(*) as controls_count
			FROM platform_framework_controls
			GROUP BY framework_id
		) c ON c.framework_id = f.id
		WHERE f.status = 'published'
		ORDER BY f.is_platform_default DESC, f.published_at DESC, f.name
	`

	var frameworks []models.PublishedFrameworkWithLicense
	err := s.db.Select(&frameworks, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list published frameworks: %w", err)
	}

	return frameworks, nil
}

// ViewFramework gets a published platform framework (read-only) with its controls
func (s *TenantFrameworkService) ViewFramework(id uuid.UUID) (*models.PlatformFramework, error) {
	query := `
		SELECT f.id, f.code, f.name, f.version, f.description, f.organization, f.status,
		       f.is_platform_default, f.published_at, f.published_by, f.created_by, f.created_at, f.updated_at,
		       COALESCE(c.controls_count, 0) as controls_count
		FROM platform_frameworks f
		LEFT JOIN (
			SELECT framework_id, COUNT(*) as controls_count
			FROM platform_framework_controls
			GROUP BY framework_id
		) c ON c.framework_id = f.id
		WHERE f.id = $1 AND f.status = 'published'
	`

	framework := &models.PlatformFramework{}
	err := s.db.Get(framework, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("published framework not found")
		}
		return nil, fmt.Errorf("failed to get published framework: %w", err)
	}

	// Load controls for the framework
	controlsQuery := `
		SELECT id, framework_id, family_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
		FROM platform_framework_controls
		WHERE framework_id = $1
		ORDER BY control_id
	`
	err = s.db.Select(&framework.Controls, controlsQuery, id)
	if err != nil {
		return nil, fmt.Errorf("failed to load framework controls: %w", err)
	}

	// Load each control's measurement rules (with their measurement type) so the
	// tenant-facing Framework Transparency browser can render what every control
	// actually checks — one query for the whole framework, grouped by control.
	byControl, err := s.loadPlatformMeasurementsByControl(id)
	if err != nil {
		return nil, fmt.Errorf("failed to load framework measurements: %w", err)
	}
	for i := range framework.Controls {
		framework.Controls[i].Measurements = byControl[framework.Controls[i].ID]
	}

	return framework, nil
}

// loadPlatformMeasurementsByControl loads every platform-framework control
// measurement for a framework in one query, joined to its measurement type, and
// groups the rows by control ID. Predicate JSONB is unmarshaled per row (mirrors
// ListControlMeasurements). Used by ViewFramework so the Framework Transparency
// browser can render each control's rules in plain language.
func (s *TenantFrameworkService) loadPlatformMeasurementsByControl(frameworkID uuid.UUID) (map[uuid.UUID][]models.ControlMeasurement, error) {
	rows, err := s.db.Query(`
		SELECT cm.id, cm.control_id, cm.framework_type, cm.measurement_type_id, cm.rule_type, cm.predicate, cm.severity_override, cm.weight, cm.created_at, cm.updated_at,
		       mt.code, mt.name, mt.description, mt.data_type, COALESCE(mt.units, '')
		FROM control_measurements cm
		JOIN platform_framework_controls pfc ON pfc.id = cm.control_id
		LEFT JOIN measurement_types mt ON mt.id = cm.measurement_type_id
		WHERE pfc.framework_id = $1 AND cm.framework_type = 'platform'
		ORDER BY cm.control_id, cm.created_at ASC
	`, frameworkID)
	if err != nil {
		return nil, fmt.Errorf("failed to query control measurements: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[uuid.UUID][]models.ControlMeasurement{}
	for rows.Next() {
		var m models.ControlMeasurement
		var predicateBytes []byte
		var severityOverride sql.NullString
		var mtCode, mtName, mtDesc, mtDataType, mtUnits sql.NullString
		if err := rows.Scan(
			&m.ID, &m.ControlID, &m.FrameworkType, &m.MeasurementTypeID, &m.RuleType, &predicateBytes, &severityOverride, &m.Weight, &m.CreatedAt, &m.UpdatedAt,
			&mtCode, &mtName, &mtDesc, &mtDataType, &mtUnits,
		); err != nil {
			return nil, fmt.Errorf("failed to scan control measurement: %w", err)
		}
		if len(predicateBytes) > 0 {
			_ = json.Unmarshal(predicateBytes, &m.Predicate)
		}
		if severityOverride.Valid {
			m.SeverityOverride = severityOverride.String
		}
		if mtName.Valid || mtCode.Valid {
			m.MeasurementType = &models.MeasurementType{
				ID:          m.MeasurementTypeID,
				Code:        mtCode.String,
				Name:        mtName.String,
				Description: mtDesc.String,
				DataType:    mtDataType.String,
				Units:       mtUnits.String,
			}
		}
		out[m.ControlID] = append(out[m.ControlID], m)
	}
	return out, rows.Err()
}

// ListTenantFrameworks lists all frameworks for a tenant
func (s *TenantFrameworkService) ListTenantFrameworks(tenantID uuid.UUID) ([]models.TenantFramework, error) {
	query := `
		SELECT f.id, f.tenant_id, f.name, f.version, f.description, f.source_framework_id, f.created_by, f.created_at, f.updated_at,
		       COALESCE(c.controls_count, 0) as controls_count
		FROM tenant_frameworks f
		LEFT JOIN (
			SELECT framework_id, COUNT(*) as controls_count
			FROM tenant_framework_controls
			GROUP BY framework_id
		) c ON c.framework_id = f.id
		WHERE f.tenant_id = $1
		ORDER BY f.created_at DESC
	`

	// RLS: tenant_frameworks — set app.tenant_id on the same tx as the read.
	var frameworks []models.TenantFramework
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}
	if err := tx.Select(&frameworks, query, tenantID); err != nil {
		return nil, fmt.Errorf("failed to list tenant frameworks: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return frameworks, nil
}

// GetTenantFramework gets a tenant framework by ID with its controls
func (s *TenantFrameworkService) GetTenantFramework(tenantID, frameworkID uuid.UUID) (*models.TenantFramework, error) {
	query := `
		SELECT id, tenant_id, name, version, description, source_framework_id, created_by, created_at, updated_at
		FROM tenant_frameworks
		WHERE id = $1 AND tenant_id = $2
	`

	// RLS: tenant_frameworks (ownership-scoped read) — run the whole body in one
	// tenant tx that has set app.tenant_id.
	tx, err := s.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := shareddatabase.SetTenantContext(context.Background(), tx.Tx, tenantID); err != nil {
		return nil, err
	}

	framework := &models.TenantFramework{}
	err = tx.Get(framework, query, frameworkID, tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("framework not found")
		}
		return nil, fmt.Errorf("failed to get tenant framework: %w", err)
	}

	// Load controls for the framework
	controlsQuery := `
		SELECT id, framework_id, family_id, control_id, title, description, baseline_severity, crypto_relevant, created_at, updated_at
		FROM tenant_framework_controls
		WHERE framework_id = $1
		ORDER BY control_id
	`
	err = tx.Select(&framework.Controls, controlsQuery, frameworkID)
	if err != nil {
		return nil, fmt.Errorf("failed to load framework controls: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return framework, nil
}

// ListControlMeasurements returns the measurement rules on a tenant control,
// scoped to the tenant via the framework→control join. The predicate JSONB is
// unmarshalled; the measurement_type is left for the caller to join.
func (s *TenantFrameworkService) ListControlMeasurements(tenantID, controlID uuid.UUID) ([]models.ControlMeasurement, error) {
	// RLS: tenant_frameworks (ownership scope via join) — set app.tenant_id on the
	// same tx as the read.
	ctx := context.Background()
	measurements := []models.ControlMeasurement{}
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, `
			SELECT cm.id, cm.control_id, cm.framework_type, cm.measurement_type_id, cm.rule_type, cm.predicate, cm.severity_override, cm.weight, cm.created_at, cm.updated_at
			FROM control_measurements cm
			JOIN tenant_framework_controls tfc ON cm.control_id = tfc.id
			JOIN tenant_frameworks tf ON tfc.framework_id = tf.id
			WHERE cm.control_id = $1 AND cm.framework_type = 'tenant' AND tf.tenant_id = $2
			ORDER BY cm.created_at ASC
		`, controlID, tenantID)
		if qErr != nil {
			return fmt.Errorf("failed to list control measurements: %w", qErr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var m models.ControlMeasurement
			var predicateBytes []byte
			var severityOverride sql.NullString
			if scanErr := rows.Scan(&m.ID, &m.ControlID, &m.FrameworkType, &m.MeasurementTypeID, &m.RuleType, &predicateBytes, &severityOverride, &m.Weight, &m.CreatedAt, &m.UpdatedAt); scanErr != nil {
				return fmt.Errorf("failed to scan control measurement: %w", scanErr)
			}
			if len(predicateBytes) > 0 {
				_ = json.Unmarshal(predicateBytes, &m.Predicate)
			}
			if severityOverride.Valid {
				m.SeverityOverride = severityOverride.String
			}
			measurements = append(measurements, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}
