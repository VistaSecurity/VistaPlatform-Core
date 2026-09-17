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
	networkSpacesRaw, exists := config[NetworkSpacesSettingsKey]
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

// NetworkSpacesSettingsKey is the key inside `tenant_admin_settings.config`
// this feature owns.
//
// The row is ONE jsonb document shared by six features — `drift`, `identity`,
// `ai`, `discovery_auto_scan`, `onboarding_required` and this one — each owning
// a single top-level key. Naming the key once is what keeps the reader and the
// writer below from drifting to two spellings of it.
const NetworkSpacesSettingsKey = "network_spaces"

// SaveNetworkSpaces saves network spaces to tenant_admin_settings, merging into
// the shared config document rather than replacing it.
//
// # Why the merge happens in SQL and not in Go
//
// This used to SELECT the whole `config` into a map[string]interface{}, set its
// own key in Go, and write the WHOLE map back. That is a full-document replace
// wearing an update's clothes, and it cost two distinct things:
//
//   - Every sibling key made a lossy round trip on every save, concurrency or
//     not. encoding/json decodes each number into a float64, so any integer
//     past 2^53 came back changed: a stored 1758153600123456789 was rewritten
//     as 1758153600123456800 by a save that had nothing to do with it. Nothing
//     reported it; jsonb accepted the new number as readily as the old one.
//   - A sibling writer committing between the read and the write had its change
//     erased — or, once the `AND version = $n` guard was added, aborted THIS
//     save with "settings were modified by another process, please retry". That
//     guard protected nothing a user could act on: the version it compared
//     against was read microseconds earlier inside the same transaction, not
//     when the browser loaded the settings page, so it could only ever fire on
//     the sibling-writer race it was reporting instead of resolving.
//
// The other five writers merge inside their UPDATE, so the merge and the write
// are one statement and the window does not exist. This now does the same.
//
// `||` alone is the whole merge, and deliberately NOT the
// `jsonb_set(config || jsonb_build_object(...), ARRAY[...])` dance the drift
// writer beside this one performs. That dance is there because drift's path is
// TWO levels deep (`['drift','baseline_days']`) and jsonb_set creates only the
// LAST element of a path — with `drift` absent it would return its input
// unchanged and report success. This key is top-level, and `jsonb || jsonb`
// replaces exactly the named key and carries every other one forward, whether
// or not the key already existed.
//
// Two statements rather than one upsert, for the reason the drift writer
// records: `log_tenant_admin_settings_change` is an AFTER **UPDATE** trigger
// reading OLD.config/OLD.version, so it cannot fire on an INSERT. A single
// `INSERT … ON CONFLICT DO UPDATE` writes NO audit row for a tenant who has
// never opened the settings page — and the first time somebody defines their
// network spaces is the change most worth having a record of. So: seed the row
// if it is missing (a no-op if it is not), then UPDATE, which always fires
// because `version` always moves. Both run inside the one WithTenantTx.
func (s *NetworkSpaceService) SaveNetworkSpaces(tenantID, userID uuid.UUID, spaces []models.NetworkSpace) error {
	if spaces == nil {
		// A nil slice marshals to `null`, which would store a JSON null where
		// every reader expects an array.
		spaces = []models.NetworkSpace{}
	}
	spacesJSON, err := json.Marshal(spaces)
	if err != nil {
		return fmt.Errorf("failed to marshal network spaces: %w", err)
	}

	// RLS-scoped write over tenant_admin_settings. The seed and the merge form
	// one unit, so they run in one tenant tx.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// `updated_by` carries a foreign key to users ON DELETE SET NULL, so an
		// absent actor must be stored as NULL rather than as the nil UUID,
		// which no user row has.
		var actor any
		if userID != uuid.Nil {
			actor = userID
		}

		if _, err := tx.Exec(`
			INSERT INTO tenant_admin_settings (tenant_id, config, updated_by, created_at, updated_at)
			VALUES ($1, '{}'::jsonb, $2, NOW(), NOW())
			ON CONFLICT (tenant_id) DO NOTHING`,
			tenantID, actor); err != nil {
			return fmt.Errorf("failed to seed settings row: %w", err)
		}

		result, err := tx.Exec(`
			UPDATE tenant_admin_settings
			SET config = COALESCE(tenant_admin_settings.config, '{}'::jsonb)
			             || jsonb_build_object($2::text, $3::jsonb),
			    version = tenant_admin_settings.version + 1,
			    updated_by = $4,
			    updated_at = NOW()
			WHERE tenant_id = $1`,
			tenantID, NetworkSpacesSettingsKey, spacesJSON, actor)
		if err != nil {
			return fmt.Errorf("failed to update settings: %w", err)
		}
		// The seed above guarantees the row exists under this tenant's RLS
		// context, so zero rows here means the write did not land and must not
		// be reported as a save.
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to confirm the settings update: %w", err)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("failed to update settings: no tenant_admin_settings row for tenant %s", tenantID)
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
					err = tx.QueryRow(insertQuery, tenantID, ruleName, ruleDescription, conditionsJSON, space.IsActive, nullableUserID(userID)).Scan(&ruleID)
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
	// Materialize all tenant assets first (RLS-scoped read over assets) so the
	// per-asset classify/update loop below — which opens its own tenant txs via
	// ClassifyAsset/GetTagsForAsset — doesn't run inside an open cursor on the pool.
	type assetRow struct {
		id       uuid.UUID
		ipPtr    *string
		hostname *string
		fqdns    []string
	}
	var assets []assetRow
	// The address is the asset-level copy of its endpoints' (`primary_address`),
	// and the FQDNs are identifiers now — `ip_address` and `fqdns` have not been
	// columns on this table since phase 1, and this query failed outright.
	query := `SELECT a.id,
			 host(a.primary_address) AS ip_address,
			 a.hostname,
			 COALESCE(ARRAY(
				 SELECT i.value FROM asset_identifiers i
				  WHERE i.tenant_id = a.tenant_id AND i.asset_id = a.id AND i.kind = 'fqdn'
				  ORDER BY i.value
			 ), ARRAY[]::text[]) AS fqdns
		FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL`
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

		// RLS-scoped read of current tags + write of ownership/tags over assets, in one tenant tx.
		err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			var currentTagsJSON []byte
			_ = tx.QueryRow(`SELECT tags FROM assets WHERE id = $1 AND tenant_id = $2`, a.id, tenantID).Scan(&currentTagsJSON)
			var currentTags models.JSONB
			if len(currentTagsJSON) > 0 {
				_ = json.Unmarshal(currentTagsJSON, &currentTags)
			}
			// Merge tags
			mergedTags := mergeTags(currentTags, networkTags)
			tagsJSON, _ := json.Marshal(mergedTags)

			// Update both ownership and tags
			updateQuery := `UPDATE assets SET asset_ownership = $1, tags = $2, updated_at = NOW() WHERE id = $3 AND tenant_id = $4`
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
