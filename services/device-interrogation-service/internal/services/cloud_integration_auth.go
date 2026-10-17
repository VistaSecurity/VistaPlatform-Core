package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// authorizeCloudIntegration returns the provider type for an integration the
// caller can use. It deliberately runs on the bypass connection because shared
// platform integrations are stored with tenant_id NULL and are not visible under
// the tenant RLS policy.
//
// A disabled integration is refused. The "Enabled" switch on the integration
// (is_enabled) used to be stored and shown and read by nothing, so turning an
// integration off stopped neither its schedules nor a clicked Discover run.
func authorizeCloudIntegration(ctx context.Context, bypassDB *sql.DB, tenantID, integrationID uuid.UUID, expectedType string) (string, error) {
	query := `
		SELECT integration_type, COALESCE(is_enabled, true)
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
	var enabled bool
	if err := bypassDB.QueryRowContext(ctx, query, args...).Scan(&integrationType, &enabled); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("integration not found")
		}
		return "", fmt.Errorf("failed to authorize integration: %w", err)
	}
	if !enabled {
		return "", ErrCloudIntegrationDisabled
	}
	return integrationType, nil
}

// ErrCloudIntegrationDisabled is why a run of a switched-off integration is
// refused. Its text is what the job shows.
var ErrCloudIntegrationDisabled = errors.New("the integration is disabled; enable it under Discovery → Cloud to run discovery with it")

// cloudIntegrationSettings is the non-credential configuration an enumeration
// run needs from an integration.
//
// The `enumerate_compute` switch that used to live here is gone: compute,
// network and security-group enumeration are resource types selected per run
// like every other (asset-inventory ADR-0009 D3, cloud_lifecycle.go).
type cloudIntegrationSettings struct {
	// Environment is the integration's declared environment, used for any
	// network segment the enumeration creates.
	Environment string
}

// loadCloudIntegrationSettings reads the settings for an integration the caller
// is already authorized for.
//
// It runs on the bypass connection for the same reason every other integration
// read does: a shared platform integration has tenant_id NULL and is invisible
// under the tenant RLS policy. The tenant/shared predicate is spelled out here
// rather than relying on RLS, and the caller has already been through
// authorizeCloudIntegration.
func loadCloudIntegrationSettings(ctx context.Context, bypassDB *sql.DB, tenantID, integrationID uuid.UUID) (cloudIntegrationSettings, error) {
	// The default is what an integration with no stored value means, so it is
	// also what a read that finds nothing means.
	out := cloudIntegrationSettings{}

	var environment sql.NullString
	err := bypassDB.QueryRowContext(ctx, `
		SELECT environment
		FROM platform_integrations
		WHERE id = $1
		  AND (tenant_id = $2 OR (tenant_id IS NULL AND is_shared = true))
		  AND is_active = true
		  AND deleted_at IS NULL`, integrationID, tenantID).Scan(&environment)
	if err == sql.ErrNoRows {
		return out, fmt.Errorf("integration not found")
	}
	if err != nil {
		return out, fmt.Errorf("failed to load integration settings: %w", err)
	}
	out.Environment = environment.String
	return out, nil
}
