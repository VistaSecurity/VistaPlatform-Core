package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

type LocationService struct {
	db *database.DB
}

func NewLocationService(db *database.DB) *LocationService {
	return &LocationService{db: db}
}

// ComputeFullPath builds the full path from root to this location (e.g. "North America / DC-West").
// RLS-scoped: reads the locations table, so it runs inside WithTenantTx (sets
// app.tenant_id). tenantID is threaded in for the context; the per-row lookups
// still match on id (locations.id is globally unique) under the tenant policy.
func (s *LocationService) ComputeFullPath(tenantID uuid.UUID, loc *models.Location) (string, error) {
	if loc == nil {
		return "", nil
	}
	parts := []string{loc.Name}
	parentID := loc.ParentID
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		for parentID != nil {
			var parent models.Location
			e := tx.Get(&parent, `SELECT id, name, parent_id FROM locations WHERE id = $1`, parentID)
			if e != nil {
				if e == sql.ErrNoRows {
					return nil
				}
				return fmt.Errorf("loading parent location: %w", e)
			}
			parts = append([]string{parent.Name}, parts...)
			parentID = parent.ParentID
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return strings.Join(parts, " / "), nil
}

// updateFullPath updates the full_path column for a location.
// RLS-scoped write over locations — wrapped in WithTenantTx.
func (s *LocationService) updateFullPath(tenantID, id uuid.UUID) error {
	var loc models.Location
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&loc, `SELECT id, name, parent_id FROM locations WHERE id = $1`, id)
	})
	if err != nil {
		return err
	}
	fullPath, err := s.ComputeFullPath(tenantID, &loc)
	if err != nil {
		return err
	}
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`UPDATE locations SET full_path = $1, updated_at = NOW() WHERE id = $2`, fullPath, id)
		return e
	})
}

// Create creates a new location and sets full_path.
func (s *LocationService) Create(tenantID uuid.UUID, input models.LocationInput) (*models.Location, error) {
	fullPath := input.Name
	if input.ParentID != nil {
		var parent models.Location
		// RLS-scoped read over locations.
		err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			return tx.Get(&parent, `SELECT id, name, parent_id, full_path FROM locations WHERE id = $1 AND tenant_id = $2`, *input.ParentID, tenantID)
		})
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("parent location not found")
			}
			return nil, err
		}
		if parent.FullPath != "" {
			fullPath = parent.FullPath + " / " + input.Name
		} else {
			fullPath = parent.Name + " / " + input.Name
		}
	}

	var id uuid.UUID
	query := `INSERT INTO locations (tenant_id, name, parent_id, location_type, description, address, city, state_province, country, latitude, longitude, timezone, cloud_provider, cloud_region, metadata, full_path, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW())
		RETURNING id`
	metadata := toJSONB(input.Metadata)
	// RLS-scoped write over locations — WithTenantTx sets app.tenant_id so the
	// INSERT's tenant_id satisfies the policy WITH CHECK.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query,
			tenantID, input.Name, input.ParentID, input.LocationType, input.Description, input.Address, input.City, input.StateProvince, input.Country,
			input.Latitude, input.Longitude, input.Timezone, input.CloudProvider, input.CloudRegion, metadata, fullPath,
		).Scan(&id)
	}); err != nil {
		return nil, fmt.Errorf("insert location: %w", err)
	}
	return s.GetByID(tenantID, id)
}

func toJSONB(m map[string]interface{}) interface{} {
	if m == nil {
		return nil
	}
	return models.JSONB(m)
}

// GetByID returns a location by ID (must belong to tenant).
func (s *LocationService) GetByID(tenantID, id uuid.UUID) (*models.Location, error) {
	var loc models.Location
	// RLS-scoped read over locations.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&loc, `SELECT * FROM locations WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if loc.FullPath == "" {
		loc.FullPath, _ = s.ComputeFullPath(tenantID, &loc)
	}
	return &loc, nil
}

// GetByIDWithChildren returns a location and its direct children.
func (s *LocationService) GetByIDWithChildren(tenantID, id uuid.UUID) (*models.Location, error) {
	loc, err := s.GetByID(tenantID, id)
	if err != nil || loc == nil {
		return loc, err
	}
	var children []models.Location
	// RLS-scoped read over locations.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&children, `SELECT * FROM locations WHERE parent_id = $1 AND tenant_id = $2 ORDER BY name`, id, tenantID)
	})
	if err != nil {
		return nil, err
	}
	for i := range children {
		if children[i].FullPath == "" {
			children[i].FullPath, _ = s.ComputeFullPath(tenantID, &children[i])
		}
	}
	loc.Children = children
	return loc, nil
}

// List returns locations for a tenant, optionally filtered by parent_id or flattened.
func (s *LocationService) List(tenantID uuid.UUID, filters models.LocationFilters) ([]models.Location, int, error) {
	baseQuery := `FROM locations WHERE tenant_id = $1 AND 1=1`
	args := []interface{}{tenantID}
	argIdx := 2
	if filters.ParentID != nil {
		baseQuery += fmt.Sprintf(` AND parent_id = $%d`, argIdx)
		args = append(args, *filters.ParentID)
		argIdx++
	}
	if filters.LocationType != "" {
		baseQuery += fmt.Sprintf(` AND location_type = $%d`, argIdx)
		args = append(args, filters.LocationType)
		argIdx++
	}

	page, pageSize := filters.Page, filters.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	countArgs := append([]interface{}{}, args...)
	args = append(args, pageSize, (page-1)*pageSize)
	query := `SELECT * ` + baseQuery + fmt.Sprintf(` ORDER BY name LIMIT $%d OFFSET $%d`, argIdx, argIdx+1)

	var total int
	var list []models.Location
	// RLS-scoped reads over locations — count + page run in one tenant tx.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow(`SELECT COUNT(*) `+baseQuery, countArgs...).Scan(&total); e != nil {
			return e
		}
		return tx.Select(&list, query, args...)
	})
	if err != nil {
		return nil, 0, err
	}
	for i := range list {
		if list[i].FullPath == "" {
			list[i].FullPath, _ = s.ComputeFullPath(tenantID, &list[i])
		}
	}
	return list, total, nil
}

// GetTree returns the full hierarchy of locations for a tenant (root-level locations with Children populated).
func (s *LocationService) GetTree(tenantID uuid.UUID) ([]models.Location, error) {
	var roots []models.Location
	// RLS-scoped read over locations.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&roots, `SELECT * FROM locations WHERE tenant_id = $1 AND parent_id IS NULL ORDER BY name`, tenantID)
	})
	if err != nil {
		return nil, err
	}
	for i := range roots {
		roots[i].FullPath, _ = s.ComputeFullPath(tenantID, &roots[i])
		roots[i].Children, _ = s.loadChildrenRecursive(tenantID, roots[i].ID)
	}
	return roots, nil
}

func (s *LocationService) loadChildrenRecursive(tenantID, parentID uuid.UUID) ([]models.Location, error) {
	var children []models.Location
	// RLS-scoped read over locations.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&children, `SELECT * FROM locations WHERE tenant_id = $1 AND parent_id = $2 ORDER BY name`, tenantID, parentID)
	})
	if err != nil {
		return nil, err
	}
	for i := range children {
		children[i].FullPath, _ = s.ComputeFullPath(tenantID, &children[i])
		children[i].Children, _ = s.loadChildrenRecursive(tenantID, children[i].ID)
	}
	return children, nil
}

// Update updates a location.
func (s *LocationService) Update(tenantID, id uuid.UUID, input models.LocationInput) (*models.Location, error) {
	loc, err := s.GetByID(tenantID, id)
	if err != nil || loc == nil {
		return nil, err
	}
	metadata := toJSONB(input.Metadata)
	// RLS-scoped write over locations.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`UPDATE locations SET name = $1, parent_id = $2, location_type = $3, description = $4, address = $5, city = $6, state_province = $7, country = $8, latitude = $9, longitude = $10, timezone = $11, cloud_provider = $12, cloud_region = $13, metadata = $14, updated_at = NOW() WHERE id = $15 AND tenant_id = $16`,
			input.Name, input.ParentID, input.LocationType, input.Description, input.Address, input.City, input.StateProvince, input.Country,
			input.Latitude, input.Longitude, input.Timezone, input.CloudProvider, input.CloudRegion, metadata, id, tenantID)
		return e
	})
	if err != nil {
		return nil, err
	}
	if err := s.updateFullPath(tenantID, id); err != nil {
		return nil, err
	}
	return s.GetByID(tenantID, id)
}

// Delete removes a location. Fails if any network_segments or network_assets reference it.
func (s *LocationService) Delete(tenantID, id uuid.UUID) error {
	var segCount, assetCount int
	// RLS-scoped reads + delete over network_segments / network_assets / locations.
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_ = tx.QueryRow(`SELECT COUNT(*) FROM network_segments WHERE location_id = $1`, id).Scan(&segCount)
		_ = tx.QueryRow(`SELECT COUNT(*) FROM network_assets WHERE location_id = $1 AND deleted_at IS NULL`, id).Scan(&assetCount)
		if segCount > 0 || assetCount > 0 {
			return fmt.Errorf("cannot delete location: referenced by %d network segment(s) and %d asset(s)", segCount, assetCount)
		}
		_, err := tx.Exec(`DELETE FROM locations WHERE id = $1 AND tenant_id = $2`, id, tenantID)
		return err
	})
}

// GetLocationAssets returns assets for a location (for summary). Uses explicit columns and tags/metadata as text so JSONB scans correctly.
func (s *LocationService) GetLocationAssets(tenantID, locationID uuid.UUID) ([]models.Asset, int, error) {
	query := `
		SELECT a.id, a.tenant_id, a.hostname, a.ip_address, a.port, a.asset_type,
			a.operating_system, a.environment, a.business_unit, a.owner_email,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.first_discovered_at, a.last_seen_at, a.created_at, a.updated_at, a.deleted_at,
			a.location_id, a.network_segment_id, ns.name AS network_segment_name,
			a.service_name, a.service_version, a.service_confidence, a.service_identification_method,
			a.risk_score, ` + models.RiskLevelCaseSQL("COALESCE(a.risk_score, 0)") + ` AS risk_level
		FROM network_assets a
		LEFT JOIN network_segments ns ON ns.id = a.network_segment_id
		WHERE a.tenant_id = $1 AND a.location_id = $2 AND a.deleted_at IS NULL
		ORDER BY a.last_seen_at DESC LIMIT 100
	`
	var total int
	var assets []models.Asset
	// RLS-scoped reads over network_assets / network_segments — count + page in one tenant tx.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow(`SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND location_id = $2 AND deleted_at IS NULL`, tenantID, locationID).Scan(&total); e != nil {
			return e
		}
		rows, e := tx.Queryx(query, tenantID, locationID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var asset models.Asset
			var tagsText, metadataText string
			if e := rows.Scan(
				&asset.ID, &asset.TenantID, &asset.Hostname, &asset.IPAddress, &asset.Port,
				&asset.AssetType, &asset.OperatingSystem, &asset.Environment, &asset.BusinessUnit,
				&asset.OwnerEmail, &asset.Description, &tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
				&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
				&asset.DeletedAt, &asset.LocationID, &asset.NetworkSegmentID, &asset.NetworkSegmentName, &asset.ServiceName, &asset.ServiceVersion,
				&asset.ServiceConfidence, &asset.ServiceIdentificationMethod,
				&asset.RiskScore, &asset.RiskLevel,
			); e != nil {
				return e
			}
			if tagsText != "" {
				_ = json.Unmarshal([]byte(tagsText), &asset.Tags)
			}
			if asset.Tags == nil {
				asset.Tags = make(map[string]interface{})
			}
			if metadataText != "" {
				_ = json.Unmarshal([]byte(metadataText), &asset.Metadata)
			}
			if asset.Metadata == nil {
				asset.Metadata = make(map[string]interface{})
			}
			assets = append(assets, asset)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return assets, total, nil
}

// GetLocationSummary returns summary with finding counts for a location.
func (s *LocationService) GetLocationSummary(tenantID, locationID uuid.UUID) (*models.LocationSummary, error) {
	loc, err := s.GetByID(tenantID, locationID)
	if err != nil || loc == nil {
		return nil, err
	}
	sum := &models.LocationSummary{Location: *loc}
	// RLS-scoped reads over network_assets / crypto_implementations / certificates — all in one tenant tx.
	_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_ = tx.QueryRow(`SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND location_id = $2 AND deleted_at IS NULL`, tenantID, locationID).Scan(&sum.AssetCount)
		_ = tx.QueryRow(`SELECT COUNT(*) FROM crypto_implementations ci JOIN network_assets na ON ci.asset_id = na.id WHERE na.tenant_id = $1 AND na.location_id = $2 AND na.deleted_at IS NULL AND ci.deleted_at IS NULL`, tenantID, locationID).Scan(&sum.CryptoConfigCount)
		_ = tx.QueryRow(`SELECT COUNT(DISTINCT c.id) FROM certificates c JOIN crypto_implementation_certificates cic ON cic.certificate_id = c.id JOIN crypto_implementations ci ON ci.id = cic.crypto_implementation_id JOIN network_assets na ON na.id = ci.asset_id WHERE na.tenant_id = $1 AND na.location_id = $2 AND na.deleted_at IS NULL`, tenantID, locationID).Scan(&sum.CertificateCount)
		// Band the stored risk_score rather than reading the risk_level column:
		// nothing has ever written that column, so it sits at its schema DEFAULT
		// 'Informational' on every row and these three counters were structurally
		// always 0. models.RiskBands is the single banding source (CLAUDE.md).
		// network_assets.risk_score is already the per-asset roll-up (GREATEST
		// over its implementations), so banding it here bands once, per asset.
		countByBand := func(band string, dest *int) {
			_ = tx.QueryRow(`SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND location_id = $2 AND deleted_at IS NULL AND `+
				models.MustRiskBandSQL("COALESCE(risk_score, 0)", band), tenantID, locationID).Scan(dest)
		}
		countByBand("Critical", &sum.CriticalFindings)
		countByBand("High", &sum.HighFindings)
		countByBand("Medium", &sum.MediumFindings)
		_ = tx.QueryRow(`SELECT COUNT(*) FROM certificates c JOIN crypto_implementation_certificates cic ON cic.certificate_id = c.id JOIN crypto_implementations ci ON ci.id = cic.crypto_implementation_id JOIN network_assets na ON na.id = ci.asset_id WHERE na.tenant_id = $1 AND na.location_id = $2 AND na.deleted_at IS NULL AND c.not_after > NOW() AND c.not_after <= NOW() + INTERVAL '30 days'`, tenantID, locationID).Scan(&sum.ExpiringCerts30D)
		_ = tx.QueryRow(`SELECT COUNT(*) FROM certificates c JOIN crypto_implementation_certificates cic ON cic.certificate_id = c.id JOIN crypto_implementations ci ON ci.id = cic.crypto_implementation_id JOIN network_assets na ON na.id = ci.asset_id WHERE na.tenant_id = $1 AND na.location_id = $2 AND na.deleted_at IS NULL AND c.not_after < NOW()`, tenantID, locationID).Scan(&sum.ExpiredCerts)
		return nil
	})
	return sum, nil
}

// FindOrCreateCloudLocation returns a location for the given cloud provider/region, creating it if it does not exist.
func (s *LocationService) FindOrCreateCloudLocation(tenantID uuid.UUID, cloudProvider, cloudRegion string) (*models.Location, error) {
	var loc models.Location
	// RLS-scoped read over locations.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&loc, `SELECT * FROM locations WHERE tenant_id = $1 AND cloud_provider = $2 AND cloud_region = $3`, tenantID, cloudProvider, cloudRegion)
	})
	if err == nil {
		if loc.FullPath == "" {
			loc.FullPath = cloudProvider + " / " + cloudRegion
		}
		return &loc, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	name := cloudProvider + " " + cloudRegion
	input := models.LocationInput{
		Name:          name,
		LocationType:  "cloud_region",
		CloudProvider: &cloudProvider,
		CloudRegion:   &cloudRegion,
	}
	return s.Create(tenantID, input)
}
