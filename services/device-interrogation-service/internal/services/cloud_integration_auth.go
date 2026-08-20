package services

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// authorizeCloudIntegration returns the provider type for an integration the
// caller can use. It deliberately runs on the bypass connection because shared
// platform integrations are stored with tenant_id NULL and are not visible under
// the tenant RLS policy.
func authorizeCloudIntegration(ctx context.Context, bypassDB *sql.DB, tenantID, integrationID uuid.UUID, expectedType string) (string, error) {
	query := `
		SELECT integration_type
		FROM platform_integrations
		WHERE id = $1
		  AND (tenant_id = $2 OR (tenant_id IS NULL AND is_shared = true))
		  AND is_active = true
		  AND deleted_at IS NULL
	`
	args := []interface{}{integrationID, tenantID}
	if expectedType != "" {
		query += ` AND integration_type = $3`
		args = append(args, expectedType)
	}

	var integrationType string
	if err := bypassDB.QueryRowContext(ctx, query, args...).Scan(&integrationType); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("integration not found")
		}
		return "", fmt.Errorf("failed to authorize integration: %w", err)
	}
	return integrationType, nil
}
