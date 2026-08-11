package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/network"
)

type NetworkSegmentService struct {
	db              *database.DB
	locationService *LocationService
}

func NewNetworkSegmentService(db *database.DB, locationService *LocationService) *NetworkSegmentService {
	return &NetworkSegmentService{db: db, locationService: locationService}
}

// GetSegmentForIP returns the first matching active network segment for the given IP/hostname, or nil.
// CIDR segments are matched first (most specific prefix first), then IP range, then domain.
func (s *NetworkSegmentService) GetSegmentForIP(tenantID uuid.UUID, ipAddress *string, hostname *string) (*models.NetworkSegment, error) {
	var segments []models.NetworkSegment
	// LEFT JOIN: a segment's location is optional, so an INNER JOIN would silently
	// drop location-less (WAN/VPN/multi-region) segments from matching entirely.
	// RLS-scoped read over network_segments (JOIN locations).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&segments, `SELECT ns.*, l.name as location_name, l.full_path as location_full_path
		FROM network_segments ns
		LEFT JOIN locations l ON l.id = ns.location_id
		WHERE ns.tenant_id = $1 AND ns.is_active = true
		ORDER BY ns.segment_type, ns.created_at`, tenantID)
	})
	if err != nil {
		return nil, err
	}
	if len(segments) == 0 {
		return nil, nil
	}

	// Sort so CIDR (by prefix length desc), then ip_range, then domain. Same type keep order.
	sort.Slice(segments, func(i, j int) bool {
		if segments[i].SegmentType != segments[j].SegmentType {
			order := map[string]int{"cidr": 0, "ip_range": 1, "domain": 2, "cloud_vpc": 3}
			return order[segments[i].SegmentType] < order[segments[j].SegmentType]
		}
		if segments[i].SegmentType == "cidr" {
			_, n1, e1 := net.ParseCIDR(segments[i].Value)
			_, n2, e2 := net.ParseCIDR(segments[j].Value)
			if e1 != nil || e2 != nil {
				return false
			}
			m1, _ := n1.Mask.Size()
			m2, _ := n2.Mask.Size()
			return m1 > m2 // larger mask = more specific first
		}
		return false
	})

	// Match IP first
	if ipAddress != nil && *ipAddress != "" {
		for i := range segments {
			seg := &segments[i]
			switch seg.SegmentType {
			case "cidr":
				if network.IsIPInCIDR(*ipAddress, seg.Value) {
					return seg, nil
				}
			case "ip_range":
				start, end, err := network.ParseIPRange(seg.Value)
				if err == nil && network.IsIPInRange(*ipAddress, start, end) {
					return seg, nil
				}
			}
		}
	}

	// Match hostname/domain
	if hostname != nil && *hostname != "" {
		for i := range segments {
			if segments[i].SegmentType == "domain" && network.MatchesDomainPattern(*hostname, segments[i].Value) {
				return &segments[i], nil
			}
		}
	}

	return nil, nil
}

// EnrichAssetFromSegment applies segment context to an asset (environment, location_id, etc.).
func (s *NetworkSegmentService) EnrichAssetFromSegment(asset *models.Asset, segment *models.NetworkSegment, locationName string) {
	if segment == nil {
		return
	}
	env := segment.Environment
	asset.Environment = &env
	// Location is an optional default: only stamp it when the segment carries one,
	// so a location-less (WAN/VPN/multi-region) segment doesn't clobber an asset's
	// own discovered location.
	if segment.LocationID != nil {
		asset.LocationID = segment.LocationID
	}
	asset.NetworkSegmentID = &segment.ID
	if segment.BusinessUnit != nil && (asset.BusinessUnit == nil || *asset.BusinessUnit == "") {
		asset.BusinessUnit = segment.BusinessUnit
	}
	if locationName != "" {
		asset.Site = &locationName
	}
	if len(segment.Tags) > 0 {
		asset.Tags = mergeSegmentTags(asset.Tags, segment.Tags)
	}
}

// mergeSegmentTags merges segment tags into existing asset tags; new keys override.
func mergeSegmentTags(existing, newTags map[string]interface{}) map[string]interface{} {
	if existing == nil {
		existing = make(map[string]interface{})
	}
	for k, v := range newTags {
		existing[k] = v
	}
	return existing
}

// EnrichAssetByID looks up segment by IP/hostname and updates the asset row with segment context (environment, location_id, etc.).
func (s *NetworkSegmentService) EnrichAssetByID(tenantID, assetID uuid.UUID, ipAddress, hostname *string) error {
	seg, err := s.GetSegmentForIP(tenantID, ipAddress, hostname)
	if err != nil || seg == nil {
		return err
	}
	// location_id and site are optional defaults: when the segment has no location,
	// pass NULL and COALESCE so the asset keeps whatever location it already had.
	var locName *string
	if seg.LocationName != nil && *seg.LocationName != "" {
		locName = seg.LocationName
	}
	bu := seg.BusinessUnit
	// RLS-scoped read of current tags + write over network_assets, in one tenant tx.
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		var currentTags models.JSONB
		_ = tx.QueryRow(`SELECT tags FROM network_assets WHERE id = $1 AND tenant_id = $2`, assetID, tenantID).Scan(&currentTags)
		merged := mergeSegmentTags(currentTags, seg.Tags)
		tagsVal := toJSONB(merged)
		_, e := tx.Exec(`
		UPDATE network_assets SET
			environment = $1, location_id = COALESCE($2, location_id), network_segment_id = $3,
			business_unit = COALESCE($4, business_unit), site = COALESCE($5, site), tags = $6, updated_at = NOW()
		WHERE id = $7 AND tenant_id = $8`,
			seg.Environment, seg.LocationID, seg.ID, bu, locName, tagsVal, assetID, tenantID)
		return e
	})
}

// List returns network segments for a tenant with optional filters.
func (s *NetworkSegmentService) List(tenantID uuid.UUID, filters models.NetworkSegmentFilters) ([]models.NetworkSegment, int, error) {
	baseQuery := `FROM network_segments ns LEFT JOIN locations l ON l.id = ns.location_id WHERE ns.tenant_id = $1`
	args := []interface{}{tenantID}
	argIdx := 2
	if filters.IsActive != nil {
		baseQuery += fmt.Sprintf(` AND ns.is_active = $%d`, argIdx)
		args = append(args, *filters.IsActive)
		argIdx++
	}
	if filters.Environment != "" {
		baseQuery += fmt.Sprintf(` AND ns.environment = $%d`, argIdx)
		args = append(args, filters.Environment)
		argIdx++
	}
	if filters.LocationID != nil {
		baseQuery += fmt.Sprintf(` AND ns.location_id = $%d`, argIdx)
		args = append(args, *filters.LocationID)
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
	sel := `SELECT ns.*, l.name as location_name, l.full_path as location_full_path `
	query := sel + baseQuery + fmt.Sprintf(` ORDER BY ns.name LIMIT $%d OFFSET $%d`, argIdx, argIdx+1)

	var total int
	var list []models.NetworkSegment
	// RLS-scoped reads over network_segments (JOIN locations) — count + page in one tenant tx.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow(`SELECT COUNT(*) `+baseQuery, countArgs...).Scan(&total); e != nil {
			return e
		}
		return tx.Select(&list, query, args...)
	})
	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// GetByID returns a network segment by ID.
func (s *NetworkSegmentService) GetByID(tenantID, id uuid.UUID) (*models.NetworkSegment, error) {
	var seg models.NetworkSegment
	// RLS-scoped read over network_segments (JOIN locations).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&seg, `SELECT ns.*, l.name as location_name, l.full_path as location_full_path
		FROM network_segments ns LEFT JOIN locations l ON l.id = ns.location_id
		WHERE ns.id = $1 AND ns.tenant_id = $2`, id, tenantID)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &seg, nil
}

// Create creates a new network segment.
func (s *NetworkSegmentService) Create(tenantID uuid.UUID, input models.NetworkSegmentInput) (*models.NetworkSegment, error) {
	// Location is optional. When provided, verify it belongs to the tenant.
	if input.LocationID != nil {
		var locID uuid.UUID
		// RLS-scoped read over locations.
		err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			return tx.QueryRow(`SELECT id FROM locations WHERE id = $1 AND tenant_id = $2`, *input.LocationID, tenantID).Scan(&locID)
		})
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("location not found")
			}
			return nil, err
		}
	}
	tags := toJSONB(input.Tags)
	meta := toJSONB(input.Metadata)
	isActive := input.IsActive
	if isActive == nil {
		defaultActive := true
		isActive = &defaultActive
	}
	var id uuid.UUID
	q := `INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, location_id, business_unit, owner_email, description, is_active, auto_approve_discoveries, tags, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW()) RETURNING id`
	// RLS-scoped write over network_segments.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(q,
			tenantID, input.Name, input.SegmentType, input.Value, input.NetworkType, input.Environment, input.LocationID,
			input.BusinessUnit, input.OwnerEmail, input.Description, isActive, input.AutoApproveDiscoveries, tags, meta,
		).Scan(&id)
	})
	if err != nil {
		return nil, err
	}
	return s.GetByID(tenantID, id)
}

// segmentExists reports whether a segment with the same value already exists for
// the tenant. Value is the natural identity of a segment (a CIDR/range/domain),
// so it's the dedupe key for bulk import.
func (s *NetworkSegmentService) segmentExists(tenantID uuid.UUID, value string) (bool, error) {
	var exists bool
	// RLS-scoped read over network_segments.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM network_segments WHERE tenant_id = $1 AND value = $2)`,
			tenantID, value).Scan(&exists)
	})
	return exists, err
}

// validateSegmentValue checks that a segment's value is well-formed for its
// type, so a malformed CIDR/range produces a clear per-row error on import
// instead of a silently broken segment that never matches a scan.
func validateSegmentValue(segmentType, value string) error {
	switch segmentType {
	case "cidr":
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("invalid CIDR %q", value)
		}
	case "ip_range":
		if _, _, err := network.ParseIPRange(value); err != nil {
			return fmt.Errorf("invalid IP range %q (expected start-end)", value)
		}
	case "domain", "cloud_vpc":
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("value is required")
		}
	default:
		return fmt.Errorf("unsupported segment_type %q", segmentType)
	}
	return nil
}

// BulkCreate creates many network segments in one request, reusing Create for
// each row so behavior matches single creation. Rows are validated for value
// format and deduped within the batch and against existing segments. Partial
// success is the norm — a bad row is recorded and the rest of the batch proceeds.
func (s *NetworkSegmentService) BulkCreate(tenantID uuid.UUID, inputs []models.NetworkSegmentInput) *models.BulkImportResult {
	res := models.NewBulkImportResult(len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for i, in := range inputs {
		if err := validateSegmentValue(in.SegmentType, in.Value); err != nil {
			res.Add(i, models.BulkRowError, nil, err.Error())
			continue
		}
		key := strings.ToLower(strings.TrimSpace(in.Value))
		if _, dup := seen[key]; dup {
			res.Add(i, models.BulkRowSkippedDuplicate, nil, "duplicate of an earlier row in this file")
			continue
		}
		seen[key] = struct{}{}
		exists, err := s.segmentExists(tenantID, in.Value)
		if err != nil {
			res.Add(i, models.BulkRowError, nil, "failed to check for an existing segment")
			continue
		}
		if exists {
			res.Add(i, models.BulkRowSkippedDuplicate, nil, "a segment with this value already exists")
			continue
		}
		seg, err := s.Create(tenantID, in)
		if err != nil {
			res.Add(i, models.BulkRowError, nil, err.Error())
			continue
		}
		res.Add(i, models.BulkRowCreated, &seg.ID, "")
	}
	return res
}

// Update updates a network segment.
func (s *NetworkSegmentService) Update(tenantID, id uuid.UUID, input models.NetworkSegmentInput) (*models.NetworkSegment, error) {
	seg, err := s.GetByID(tenantID, id)
	if err != nil {
		return nil, err
	}
	if seg == nil {
		return nil, fmt.Errorf("network segment not found")
	}

	// Location is optional. When provided, verify it belongs to the tenant.
	if input.LocationID != nil {
		var locID uuid.UUID
		// RLS-scoped read over locations.
		err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			return tx.QueryRow(`SELECT id FROM locations WHERE id = $1 AND tenant_id = $2`, *input.LocationID, tenantID).Scan(&locID)
		})
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("location not found")
			}
			return nil, err
		}
	}

	tags := toJSONB(input.Tags)
	meta := toJSONB(input.Metadata)
	isActive := input.IsActive
	if isActive == nil {
		// Keep the persisted value when omitted so updates never write NULL to is_active.
		currentIsActive := seg.IsActive
		isActive = &currentIsActive
	}
	// RLS-scoped write over network_segments.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`UPDATE network_segments SET name = $1, segment_type = $2, value = $3, network_type = $4, environment = $5, location_id = $6, business_unit = $7, owner_email = $8, description = $9, is_active = $10, auto_approve_discoveries = $11, tags = $12, metadata = $13, updated_at = NOW() WHERE id = $14 AND tenant_id = $15`,
			input.Name, input.SegmentType, input.Value, input.NetworkType, input.Environment, input.LocationID,
			input.BusinessUnit, input.OwnerEmail, input.Description, isActive, input.AutoApproveDiscoveries, tags, meta, id, tenantID)
		return e
	})
	if err != nil {
		return nil, err
	}
	return s.GetByID(tenantID, id)
}

// Delete deletes a network segment.
func (s *NetworkSegmentService) Delete(tenantID, id uuid.UUID) error {
	var n int64
	// RLS-scoped write over network_segments.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		result, e := tx.Exec(`DELETE FROM network_segments WHERE id = $1 AND tenant_id = $2`, id, tenantID)
		if e != nil {
			return e
		}
		n, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ClassifyAsset returns ownership classification (internal, third_party, unknown) based on segment match.
func (s *NetworkSegmentService) ClassifyAsset(tenantID uuid.UUID, ipAddress *string, hostname *string, fqdns []string) (string, error) {
	seg, err := s.GetSegmentForIP(tenantID, ipAddress, hostname)
	if err != nil {
		return "unknown", err
	}
	if seg != nil {
		return "internal", nil
	}
	if ipAddress != nil && *ipAddress != "" {
		if network.IsIPInCIDR(*ipAddress, "10.0.0.0/8") ||
			network.IsIPInCIDR(*ipAddress, "172.16.0.0/12") ||
			network.IsIPInCIDR(*ipAddress, "192.168.0.0/16") {
			return "unknown", nil
		}
	}
	return "third_party", nil
}

// GetTagsForAsset returns merged tags from the matching segment, if any.
func (s *NetworkSegmentService) GetTagsForAsset(tenantID uuid.UUID, ipAddress *string, hostname *string, fqdns []string) (map[string]interface{}, error) {
	seg, err := s.GetSegmentForIP(tenantID, ipAddress, hostname)
	if err != nil || seg == nil {
		return make(map[string]interface{}), err
	}
	if seg.Tags == nil {
		return make(map[string]interface{}), nil
	}
	out := make(map[string]interface{})
	for k, v := range seg.Tags {
		out[k] = v
	}
	return out, nil
}

// ReclassifyAllAssets re-enriches all assets for a tenant using current network segments.
func (s *NetworkSegmentService) ReclassifyAllAssets(tenantID uuid.UUID) (int, error) {
	var assets []struct {
		ID       uuid.UUID
		IP       sql.NullString
		Hostname sql.NullString
	}
	// RLS-scoped read over network_assets. Materialized up front so the per-asset
	// loop below — which opens its own tenant txs via GetSegmentForIP / GetByID — does
	// not run inside an open cursor on the pool.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&assets, `SELECT id, ip_address as ip, hostname FROM network_assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID)
	})
	if err != nil {
		return 0, err
	}
	updated := 0
	for _, a := range assets {
		var ip, host *string
		if a.IP.Valid {
			ip = &a.IP.String
		}
		if a.Hostname.Valid {
			host = &a.Hostname.String
		}
		seg, err := s.GetSegmentForIP(tenantID, ip, host)
		if err != nil {
			continue
		}
		if seg != nil {
			// Location/site are optional segment defaults: when the matched segment
			// has no location, COALESCE leaves the asset's existing location intact
			// rather than wiping it on every reclassify.
			var locName *string
			if seg.LocationID != nil {
				if loc, _ := s.locationService.GetByID(tenantID, *seg.LocationID); loc != nil {
					locName = &loc.Name
				}
			}
			// RLS-scoped write over network_assets.
			err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
				_, e := tx.Exec(`UPDATE network_assets SET environment = $1, location_id = COALESCE($2, location_id), network_segment_id = $3, business_unit = COALESCE($4, business_unit), site = COALESCE($5, site), updated_at = NOW() WHERE id = $6 AND tenant_id = $7`,
					seg.Environment, seg.LocationID, seg.ID, seg.BusinessUnit, locName, a.ID, tenantID)
				return e
			})
		} else {
			// RLS-scoped write over network_assets.
			err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
				_, e := tx.Exec(`UPDATE network_assets SET environment = NULL, location_id = NULL, network_segment_id = NULL, site = NULL, updated_at = NOW() WHERE id = $1 AND tenant_id = $2`, a.ID, tenantID)
				return e
			})
		}
		if err == nil {
			updated++
		}
	}
	return updated, nil
}

// ManageAutoApprovalRules creates or updates discovery_auto_approval_rules for segments with auto_approve_discoveries = true,
// and disables rules for segments with auto_approve_discoveries = false. Uses network_segment_id in conditions.
// userID is used as created_by for new rules; use uuid.Nil to only update/disable (e.g. from reclassify-all without user context).
func (s *NetworkSegmentService) ManageAutoApprovalRules(tenantID, userID uuid.UUID) error {
	// RLS-scoped reads + writes over discovery_auto_approval_rules and network_segments —
	// the existing-rules scan, segment list, and per-segment upsert/disable form one unit.
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// Get existing rules linked to network segments
		query := `SELECT id, conditions FROM discovery_auto_approval_rules
			WHERE tenant_id = $1 AND conditions->>'network_segment_id' IS NOT NULL`
		rows, err := tx.Query(query, tenantID)
		if err != nil {
			return fmt.Errorf("failed to query existing rules: %w", err)
		}
		defer func() { _ = rows.Close() }()

		existingRules := make(map[string]uuid.UUID) // segment_id -> rule_id
		for rows.Next() {
			var ruleID uuid.UUID
			var conditionsJSON []byte
			if err := rows.Scan(&ruleID, &conditionsJSON); err != nil {
				continue
			}
			var conditions map[string]interface{}
			if err := json.Unmarshal(conditionsJSON, &conditions); err != nil {
				continue
			}
			if segID, ok := conditions["network_segment_id"].(string); ok {
				existingRules[segID] = ruleID
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}

		// All segments for tenant (to know auto_approve and to disable rules when off)
		var segments []models.NetworkSegment
		err = tx.Select(&segments, `SELECT id, name, value, network_type, auto_approve_discoveries, is_active FROM network_segments WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return fmt.Errorf("failed to list segments: %w", err)
		}

		for _, seg := range segments {
			segIDStr := seg.ID.String()
			ruleID, exists := existingRules[segIDStr]

			if seg.AutoApproveDiscoveries {
				conditions := map[string]interface{}{
					"source":                        "sensor_discoveries",
					"network_ownership":             "internal",
					"network_type":                  seg.NetworkType,
					"require_network_segment_match": true,
					"network_segment_id":            segIDStr,
				}
				conditionsJSON, err := json.Marshal(conditions)
				if err != nil {
					continue
				}
				ruleName := fmt.Sprintf("Auto-approve sensor discoveries: %s", seg.Value)
				ruleDescription := fmt.Sprintf("Auto-approve sensor discoveries matching network segment: %s", seg.Name)

				if exists {
					_, err = tx.Exec(`UPDATE discovery_auto_approval_rules
						SET name = $1, description = $2, conditions = $3, is_active = $4, updated_at = NOW()
						WHERE id = $5`, ruleName, ruleDescription, conditionsJSON, seg.IsActive, ruleID)
					if err != nil {
						fmt.Printf("Warning: failed to update auto-approval rule for segment %s: %v\n", seg.ID, err)
					}
				} else if userID != uuid.Nil {
					_, err = tx.Exec(`INSERT INTO discovery_auto_approval_rules
						(tenant_id, name, description, conditions, is_active, created_by, created_at, updated_at)
						VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
						tenantID, ruleName, ruleDescription, conditionsJSON, seg.IsActive, userID)
					if err != nil {
						fmt.Printf("Warning: failed to create auto-approval rule for segment %s: %v\n", seg.ID, err)
					}
				}
			} else if exists {
				_, err = tx.Exec(`UPDATE discovery_auto_approval_rules SET is_active = false, updated_at = NOW() WHERE id = $1`, ruleID)
				if err != nil {
					fmt.Printf("Warning: failed to disable auto-approval rule for segment %s: %v\n", seg.ID, err)
				}
			}
		}
		return nil
	})
}

// MigrateAutoApprovalRulesToSegments updates discovery_auto_approval_rules that reference network_space_id
// to use network_segment_id by matching the segment's value (CIDR/range) from tenant_admin_settings.config.
func (s *NetworkSegmentService) MigrateAutoApprovalRulesToSegments(tenantID uuid.UUID) (int, error) {
	var configJSON []byte
	// RLS-scoped read over tenant_admin_settings.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT config FROM tenant_admin_settings WHERE tenant_id = $1`, tenantID).Scan(&configJSON)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	var config map[string]interface{}
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return 0, err
	}
	spacesRaw, ok := config["network_spaces"]
	if !ok {
		return 0, nil
	}
	spacesJSON, _ := json.Marshal(spacesRaw)
	var spaces []struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(spacesJSON, &spaces); err != nil {
		return 0, err
	}
	spaceIDToValue := make(map[string]string)
	for _, sp := range spaces {
		spaceIDToValue[sp.ID] = sp.Value
	}

	updated := 0
	// RLS-scoped reads + writes over discovery_auto_approval_rules and network_segments —
	// the rule scan, per-rule segment lookup, and rule update form one unit in one tenant tx.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(`SELECT id, conditions FROM discovery_auto_approval_rules
		WHERE tenant_id = $1 AND conditions->>'network_space_id' IS NOT NULL`, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		type pendingUpdate struct {
			ruleID  uuid.UUID
			newJSON []byte
		}
		var pending []pendingUpdate
		for rows.Next() {
			var ruleID uuid.UUID
			var conditionsJSON []byte
			if err := rows.Scan(&ruleID, &conditionsJSON); err != nil {
				continue
			}
			var conditions map[string]interface{}
			if err := json.Unmarshal(conditionsJSON, &conditions); err != nil {
				continue
			}
			spaceIDVal, ok := conditions["network_space_id"]
			if !ok {
				continue
			}
			var spaceID string
			switch v := spaceIDVal.(type) {
			case string:
				spaceID = v
			default:
				continue
			}
			value, ok := spaceIDToValue[spaceID]
			if !ok {
				continue
			}
			var seg models.NetworkSegment
			if err := tx.Get(&seg, `SELECT id FROM network_segments WHERE tenant_id = $1 AND value = $2`, tenantID, value); err != nil || seg.ID == uuid.Nil {
				continue
			}
			delete(conditions, "network_space_id")
			delete(conditions, "require_network_space_match")
			conditions["network_segment_id"] = seg.ID.String()
			conditions["require_network_segment_match"] = true
			newJSON, err := json.Marshal(conditions)
			if err != nil {
				continue
			}
			pending = append(pending, pendingUpdate{ruleID: ruleID, newJSON: newJSON})
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, p := range pending {
			if _, err := tx.Exec(`UPDATE discovery_auto_approval_rules SET conditions = $1, updated_at = NOW() WHERE id = $2`, p.newJSON, p.ruleID); err != nil {
				continue
			}
			updated++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return updated, nil
}

// MigrateFromNetworkSpaces reads tenant_admin_settings.config.network_spaces, find-or-creates a default location,
// inserts segments (ON CONFLICT tenant_id, value DO NOTHING), migrates auto-approval rules, and returns the count of segments migrated.
func (s *NetworkSegmentService) MigrateFromNetworkSpaces(tenantID uuid.UUID) (int, error) {
	var configJSON []byte
	// RLS-scoped read over tenant_admin_settings.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT config FROM tenant_admin_settings WHERE tenant_id = $1`, tenantID).Scan(&configJSON)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	var config map[string]interface{}
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return 0, err
	}
	spacesRaw, ok := config["network_spaces"]
	if !ok {
		return 0, nil
	}
	spacesJSON, _ := json.Marshal(spacesRaw)
	var spaces []struct {
		ID                     string `json:"id"`
		Type                   string `json:"type"`
		Value                  string `json:"value"`
		NetworkType            string `json:"network_type"`
		Description            string `json:"description"`
		IsActive               bool   `json:"is_active"`
		AutoApproveDiscoveries *bool  `json:"auto_approve_discoveries"`
	}
	if err := json.Unmarshal(spacesJSON, &spaces); err != nil {
		return 0, err
	}
	if len(spaces) == 0 {
		return 0, nil
	}

	// Find or create default location "Unclassified" for migrated segments
	var locationID uuid.UUID
	// RLS-scoped read over locations.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT id FROM locations WHERE tenant_id = $1 AND name = $2 AND location_type = $3`,
			tenantID, "Unclassified", "site").Scan(&locationID)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			loc, createErr := s.locationService.Create(tenantID, models.LocationInput{
				Name:         "Unclassified",
				LocationType: "site",
				Description:  ptrString("Default location for migrated network spaces"),
			})
			if createErr != nil {
				return 0, fmt.Errorf("create default location: %w", createErr)
			}
			locationID = loc.ID
		} else {
			return 0, err
		}
	}

	tags := toJSONB(nil)
	meta := toJSONB(nil)
	migrated := 0
	// RLS-scoped writes over network_segments — the whole insert batch runs in one tenant tx.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		for _, sp := range spaces {
			autoApprove := false
			if sp.AutoApproveDiscoveries != nil {
				autoApprove = *sp.AutoApproveDiscoveries
			}
			segmentType := sp.Type
			if segmentType == "" {
				segmentType = "cidr"
			}
			networkType := sp.NetworkType
			if networkType == "" {
				networkType = "private"
			}
			result, e := tx.Exec(`
			INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, location_id, description, is_active, auto_approve_discoveries, tags, metadata, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'production', $6, $7, $8, $9, $10, $11, NOW(), NOW())
			ON CONFLICT (tenant_id, value) DO NOTHING`,
				tenantID, sp.Value, segmentType, sp.Value, networkType, locationID, ptrString(sp.Description), sp.IsActive, autoApprove, tags, meta)
			if e != nil {
				continue
			}
			n, _ := result.RowsAffected()
			migrated += int(n)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	_, _ = s.MigrateAutoApprovalRulesToSegments(tenantID)
	return migrated, nil
}

// FindOrCreateCloudSegment returns a network segment for the given cloud provider/region/VPC, creating location and segment if needed.
func (s *NetworkSegmentService) FindOrCreateCloudSegment(tenantID uuid.UUID, cloudProvider, cloudRegion, vpcID, environment string) (*models.NetworkSegment, error) {
	loc, err := s.locationService.FindOrCreateCloudLocation(tenantID, cloudProvider, cloudRegion)
	if err != nil {
		return nil, err
	}
	value := vpcID
	if value == "" {
		value = "cloud://" + cloudProvider + "/" + cloudRegion
	}
	seg, err := s.GetByValue(tenantID, value)
	if err != nil {
		return nil, err
	}
	if seg != nil {
		return seg, nil
	}
	name := cloudProvider + " " + cloudRegion
	if vpcID != "" {
		name = name + " " + vpcID
	}
	isActive := true
	input := models.NetworkSegmentInput{
		Name:        name,
		SegmentType: "cloud_vpc",
		Value:       value,
		NetworkType: "cloud",
		Environment: environment,
		LocationID:  &loc.ID,
		IsActive:    &isActive,
	}
	return s.Create(tenantID, input)
}

// GetByValue returns a segment by tenant_id and value (for FindOrCreateCloudSegment).
func (s *NetworkSegmentService) GetByValue(tenantID uuid.UUID, value string) (*models.NetworkSegment, error) {
	var seg models.NetworkSegment
	// RLS-scoped read over network_segments (JOIN locations).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&seg, `SELECT ns.*, l.name as location_name, l.full_path as location_full_path
		FROM network_segments ns LEFT JOIN locations l ON l.id = ns.location_id
		WHERE ns.tenant_id = $1 AND ns.value = $2`, tenantID, value)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &seg, nil
}
