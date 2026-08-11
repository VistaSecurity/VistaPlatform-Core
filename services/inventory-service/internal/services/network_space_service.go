package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/network"

	"github.com/google/uuid"
)

type NetworkSpaceService struct {
	db *database.DB
}

func NewNetworkSpaceService(db *database.DB) *NetworkSpaceService {
	return &NetworkSpaceService{db: db}
}

// GetNetworkSpaces retrieves network spaces for a tenant from tenant_admin_settings
func (s *NetworkSpaceService) GetNetworkSpaces(tenantID uuid.UUID) ([]models.NetworkSpace, error) {
	var configJSON []byte
	var config map[string]interface{}

	// RLS-scoped read over tenant_admin_settings.
	query := `SELECT config FROM tenant_admin_settings WHERE tenant_id = $1`
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID).Scan(&configJSON)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			// No settings exist yet, return empty list
			return []models.NetworkSpace{}, nil
		}
		return nil, fmt.Errorf("failed to get network spaces: %w", err)
	}

	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, fmt.Errorf("failed to parse settings config: %w", err)
	}

	// Extract network_spaces from config
	networkSpacesRaw, exists := config["network_spaces"]
	if !exists {
		return []models.NetworkSpace{}, nil
	}

	// Convert to JSON and back to properly unmarshal
	networkSpacesJSON, err := json.Marshal(networkSpacesRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal network spaces: %w", err)
	}

	var networkSpaces []models.NetworkSpace
	if err := json.Unmarshal(networkSpacesJSON, &networkSpaces); err != nil {
		return nil, fmt.Errorf("failed to unmarshal network spaces: %w", err)
	}

	// Filter to only active spaces
	var activeSpaces []models.NetworkSpace
	for _, space := range networkSpaces {
		if space.IsActive {
			activeSpaces = append(activeSpaces, space)
		}
	}

	return activeSpaces, nil
}

// SaveNetworkSpaces saves network spaces to tenant_admin_settings
// Note: This requires the user ID for the updated_by field
func (s *NetworkSpaceService) SaveNetworkSpaces(tenantID, userID uuid.UUID, spaces []models.NetworkSpace) error {
	// RLS-scoped read + write over tenant_admin_settings — the version read and the
	// conditional insert/update form one optimistic-locking unit, so they run in one tenant tx.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// Get current config
		var configJSON []byte
		var config map[string]interface{}

		query := `SELECT config, version FROM tenant_admin_settings WHERE tenant_id = $1`
		var version int
		err := tx.QueryRow(query, tenantID).Scan(&configJSON, &version)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to get current settings: %w", err)
		}

		if err == sql.ErrNoRows {
			// Create new settings
			config = make(map[string]interface{})
			version = 0
		} else {
			if err := json.Unmarshal(configJSON, &config); err != nil {
				return fmt.Errorf("failed to parse current config: %w", err)
			}
		}

		// Update network_spaces in config
		config["network_spaces"] = spaces

		// Marshal updated config
		updatedConfigJSON, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		// Save to database
		if version == 0 {
			// Insert new record
			insertQuery := `INSERT INTO tenant_admin_settings (tenant_id, config, version, updated_by, created_at, updated_at)
				VALUES ($1, $2, 1, $3, NOW(), NOW())`
			_, err = tx.Exec(insertQuery, tenantID, updatedConfigJSON, userID)
			if err != nil {
				return fmt.Errorf("failed to insert settings: %w", err)
			}
		} else {
			// Update existing record with optimistic locking
			updateQuery := `UPDATE tenant_admin_settings
				SET config = $1, version = version + 1, updated_by = $2, updated_at = NOW()
				WHERE tenant_id = $3 AND version = $4`
			result, err := tx.Exec(updateQuery, updatedConfigJSON, userID, tenantID, version)
			if err != nil {
				return fmt.Errorf("failed to update settings: %w", err)
			}
			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				return fmt.Errorf("settings were modified by another process, please retry")
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// Manage auto-approval rules for network spaces
	if err := s.manageAutoApprovalRules(tenantID, userID, spaces); err != nil {
		// Log error but don't fail the save operation
		fmt.Printf("Warning: failed to manage auto-approval rules: %v\n", err)
	}

	return nil
}

// manageAutoApprovalRules creates or updates auto-approval rules for network spaces with auto_approve_discoveries enabled
func (s *NetworkSpaceService) manageAutoApprovalRules(tenantID, userID uuid.UUID, spaces []models.NetworkSpace) error {
	// RLS-scoped reads + writes over discovery_auto_approval_rules — the existing-rules
	// scan and the per-space upsert/disable form one unit, so they run in one tenant tx.
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// Get existing rules linked to network spaces
		query := `SELECT id, conditions FROM discovery_auto_approval_rules
			WHERE tenant_id = $1 AND conditions->>'network_space_id' IS NOT NULL`
		rows, err := tx.Query(query, tenantID)
		if err != nil {
			return fmt.Errorf("failed to query existing rules: %w", err)
		}
		defer func() { _ = rows.Close() }()

		existingRules := make(map[string]uuid.UUID) // network_space_id -> rule_id
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
			if spaceID, ok := conditions["network_space_id"].(string); ok {
				existingRules[spaceID] = ruleID
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}

		// Process each network space
		for _, space := range spaces {
			shouldAutoApprove := space.AutoApproveDiscoveries != nil && *space.AutoApproveDiscoveries
			ruleID, exists := existingRules[space.ID]

			if shouldAutoApprove {
				// Create or update rule
				conditions := map[string]interface{}{
					"source":                      "sensor_discoveries",
					"network_ownership":           "internal",
					"network_type":                space.NetworkType,
					"require_network_space_match": true,
					"network_space_id":            space.ID,
				}

				conditionsJSON, err := json.Marshal(conditions)
				if err != nil {
					continue
				}

				ruleName := fmt.Sprintf("Auto-approve sensor discoveries: %s", space.Value)
				ruleDescription := fmt.Sprintf("Auto-approve sensor discoveries matching network space: %s", space.Description)
				if ruleDescription == "" {
					ruleDescription = fmt.Sprintf("Auto-approve sensor discoveries matching network space: %s", space.Value)
				}

				if exists {
					// Update existing rule
					updateQuery := `UPDATE discovery_auto_approval_rules
						SET name = $1, description = $2, conditions = $3, is_active = $4, updated_at = NOW()
						WHERE id = $5`
					_, err = tx.Exec(updateQuery, ruleName, ruleDescription, conditionsJSON, space.IsActive, ruleID)
					if err != nil {
						fmt.Printf("Warning: failed to update auto-approval rule for space %s: %v\n", space.ID, err)
					}
				} else {
					// Create new rule
					insertQuery := `INSERT INTO discovery_auto_approval_rules
						(tenant_id, name, description, conditions, is_active, created_by, created_at, updated_at)
						VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
						RETURNING id`
					err = tx.QueryRow(insertQuery, tenantID, ruleName, ruleDescription, conditionsJSON, space.IsActive, userID).Scan(&ruleID)
					if err != nil {
						fmt.Printf("Warning: failed to create auto-approval rule for space %s: %v\n", space.ID, err)
					}
				}
			} else if exists {
				// Disable rule if auto-approve is turned off
				updateQuery := `UPDATE discovery_auto_approval_rules
					SET is_active = false, updated_at = NOW()
					WHERE id = $1`
				_, err = tx.Exec(updateQuery, ruleID)
				if err != nil {
					fmt.Printf("Warning: failed to disable auto-approval rule for space %s: %v\n", space.ID, err)
				}
			}
		}

		return nil
	})
}

// ClassifyAsset determines if an asset belongs to internal network space
// Returns: 'internal', 'third_party', or 'unknown'
func (s *NetworkSpaceService) ClassifyAsset(tenantID uuid.UUID, ipAddress *string, hostname *string, fqdns []string) (string, error) {
	// Get active network spaces
	spaces, err := s.GetNetworkSpaces(tenantID)
	if err != nil {
		return "unknown", fmt.Errorf("failed to get network spaces: %w", err)
	}

	// If no network spaces defined, default to unknown
	if len(spaces) == 0 {
		return "unknown", nil
	}

	// Check IP address against CIDR blocks and IP ranges
	if ipAddress != nil && *ipAddress != "" {
		for _, space := range spaces {
			if !space.IsActive {
				continue
			}

			switch space.Type {
			case "cidr":
				if network.IsIPInCIDR(*ipAddress, space.Value) {
					return "internal", nil
				}
			case "ip_range":
				startIP, endIP, err := network.ParseIPRange(space.Value)
				if err == nil {
					if network.IsIPInRange(*ipAddress, startIP, endIP) {
						return "internal", nil
					}
				}
			}
		}
	}

	// Check hostname and FQDNs against domain patterns
	domainsToCheck := []string{}
	if hostname != nil && *hostname != "" {
		domainsToCheck = append(domainsToCheck, *hostname)
	}
	domainsToCheck = append(domainsToCheck, fqdns...)

	for _, domain := range domainsToCheck {
		if domain == "" {
			continue
		}
		for _, space := range spaces {
			if !space.IsActive {
				continue
			}
			if space.Type == "domain" {
				if network.MatchesDomainPattern(domain, space.Value) {
					return "internal", nil
				}
			}
		}
	}

	// If no match found, check if IP is in private ranges (RFC 1918)
	// If it's a private IP and no explicit rules, we might want to classify as customer
	// But for now, we'll return 'unknown' to be safe
	if ipAddress != nil && *ipAddress != "" {
		// Check for private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
		if network.IsIPInCIDR(*ipAddress, "10.0.0.0/8") ||
			network.IsIPInCIDR(*ipAddress, "172.16.0.0/12") ||
			network.IsIPInCIDR(*ipAddress, "192.168.0.0/16") {
			// Private IP but no explicit rule - return unknown for manual review
			return "unknown", nil
		}
	}

	// No match found - classify as third_party
	return "third_party", nil
}

// GetTagsForAsset returns tags from all matching network spaces for an asset
// Tags from multiple matching spaces are merged (additive, last match wins for duplicate keys)
func (s *NetworkSpaceService) GetTagsForAsset(tenantID uuid.UUID, ipAddress *string, hostname *string, fqdns []string) (map[string]interface{}, error) {
	// Get active network spaces
	spaces, err := s.GetNetworkSpaces(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network spaces: %w", err)
	}

	// If no network spaces defined, return empty tags
	if len(spaces) == 0 {
		return make(map[string]interface{}), nil
	}

	// Collect tags from all matching spaces
	collectedTags := make(map[string]interface{})

	// Check IP address against CIDR blocks and IP ranges
	if ipAddress != nil && *ipAddress != "" {
		for _, space := range spaces {
			if !space.IsActive {
				continue
			}

			var matches bool
			switch space.Type {
			case "cidr":
				matches = network.IsIPInCIDR(*ipAddress, space.Value)
			case "ip_range":
				startIP, endIP, err := network.ParseIPRange(space.Value)
				if err == nil {
					matches = network.IsIPInRange(*ipAddress, startIP, endIP)
				}
			default:
				matches = false
			}

			if matches && space.Tags != nil && len(space.Tags) > 0 {
				// Merge tags from this space (later spaces override earlier ones)
				for k, v := range space.Tags {
					collectedTags[k] = v
				}
			}
		}
	}

	// Check hostname and FQDNs against domain patterns
	domainsToCheck := []string{}
	if hostname != nil && *hostname != "" {
		domainsToCheck = append(domainsToCheck, *hostname)
	}
	domainsToCheck = append(domainsToCheck, fqdns...)

	for _, domain := range domainsToCheck {
		if domain == "" {
			continue
		}
		for _, space := range spaces {
			if !space.IsActive {
				continue
			}
			if space.Type == "domain" {
				if network.MatchesDomainPattern(domain, space.Value) {
					if len(space.Tags) > 0 {
						// Merge tags from this space
						for k, v := range space.Tags {
							collectedTags[k] = v
						}
					}
				}
			}
		}
	}

	return collectedTags, nil
}

// mergeTags merges tags from network spaces into existing asset tags
// Network space tags override existing tags for same keys
func mergeTags(existingTags, newTags map[string]interface{}) map[string]interface{} {
	// Start with a copy of existing tags
	merged := make(map[string]interface{})
	for k, v := range existingTags {
		merged[k] = v
	}

	// Override/add tags from network spaces
	for k, v := range newTags {
		merged[k] = v
	}

	return merged
}

// ReclassifyAllAssets reclassifies all assets for a tenant based on current network spaces
func (s *NetworkSpaceService) ReclassifyAllAssets(tenantID uuid.UUID) (int, error) {
	// Materialize all tenant assets first (RLS-scoped read over network_assets) so the
	// per-asset classify/update loop below — which opens its own tenant txs via
	// ClassifyAsset/GetTagsForAsset — doesn't run inside an open cursor on the pool.
	type assetRow struct {
		id       uuid.UUID
		ipPtr    *string
		hostname *string
		fqdns    []string
	}
	var assets []assetRow
	query := `SELECT id, ip_address, hostname, fqdns FROM network_assets
		WHERE tenant_id = $1 AND deleted_at IS NULL`
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.Query(query, tenantID)
		if err != nil {
			return fmt.Errorf("failed to query assets: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var ipAddress, hostname sql.NullString
			var fqdns pq.StringArray
			if err := rows.Scan(&assetID, &ipAddress, &hostname, &fqdns); err != nil {
				continue
			}
			var ar assetRow
			ar.id = assetID
			if ipAddress.Valid {
				ar.ipPtr = &ipAddress.String
			}
			if hostname.Valid {
				ar.hostname = &hostname.String
			}
			ar.fqdns = []string(fqdns)
			assets = append(assets, ar)
		}
		return rows.Err()
	}); err != nil {
		return 0, err
	}

	updatedCount := 0
	for _, a := range assets {
		// Classify asset
		ownership, err := s.ClassifyAsset(tenantID, a.ipPtr, a.hostname, a.fqdns)
		if err != nil {
			continue
		}

		// Get tags from matching network spaces
		networkTags, _ := s.GetTagsForAsset(tenantID, a.ipPtr, a.hostname, a.fqdns)

		// RLS-scoped read of current tags + write of ownership/tags over network_assets, in one tenant tx.
		err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			var currentTagsJSON []byte
			_ = tx.QueryRow(`SELECT tags FROM network_assets WHERE id = $1 AND tenant_id = $2`, a.id, tenantID).Scan(&currentTagsJSON)
			var currentTags models.JSONB
			if len(currentTagsJSON) > 0 {
				_ = json.Unmarshal(currentTagsJSON, &currentTags)
			}
			// Merge tags
			mergedTags := mergeTags(currentTags, networkTags)
			tagsJSON, _ := json.Marshal(mergedTags)

			// Update both ownership and tags
			updateQuery := `UPDATE network_assets SET asset_ownership = $1, tags = $2, updated_at = NOW() WHERE id = $3 AND tenant_id = $4`
			_, e := tx.Exec(updateQuery, ownership, tagsJSON, a.id, tenantID)
			return e
		})
		if err != nil {
			continue
		}

		updatedCount++
	}

	return updatedCount, nil
}
