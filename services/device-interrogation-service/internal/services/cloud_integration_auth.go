package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

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

// EnumerateComputeConfigKey is the integration-config key that turns compute /
// network enumeration on or off for a cloud integration.
//
// It lives in `platform_integrations.config` rather than in a column because
// that map is the integration's settings bag, is already merged on update, and
// is already returned (unmasked, for a non-sensitive key) by GET — so the whole
// round trip exists. A column would have meant a schema change for a boolean.
const EnumerateComputeConfigKey = "enumerate_compute"

// cloudIntegrationSettings is the non-credential configuration an enumeration
// run needs from an integration.
type cloudIntegrationSettings struct {
	// EnumerateCompute reports whether this integration enumerates compute
	// instances, networks and subnets. DEFAULTS TO TRUE: an integration written
	// before this key existed carries no value at all, and the capability is
	// the point of the workstream — an operator who does not want the extra API
	// calls turns it off explicitly.
	EnumerateCompute bool
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
	out := cloudIntegrationSettings{EnumerateCompute: true}

	var configJSON sql.NullString
	var environment sql.NullString
	err := bypassDB.QueryRowContext(ctx, `
		SELECT config, environment
		FROM platform_integrations
		WHERE id = $1
		  AND (tenant_id = $2 OR (tenant_id IS NULL AND is_shared = true))
		  AND is_active = true
		  AND deleted_at IS NULL`, integrationID, tenantID).Scan(&configJSON, &environment)
	if err == sql.ErrNoRows {
		return out, fmt.Errorf("integration not found")
	}
	if err != nil {
		return out, fmt.Errorf("failed to load integration settings: %w", err)
	}
	out.Environment = environment.String

	if !configJSON.Valid || strings.TrimSpace(configJSON.String) == "" {
		return out, nil
	}
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON.String), &config); err != nil {
		// A config we cannot read is not a config that says "off". Reporting
		// the default here would be indistinguishable from a stored `true`, so
		// the error travels and the caller decides.
		return out, fmt.Errorf("failed to parse integration config: %w", err)
	}
	if v, ok := boolFromConfig(config[EnumerateComputeConfigKey]); ok {
		out.EnumerateCompute = v
	}
	return out, nil
}

// boolFromConfig reads a config value that may have been stored as a JSON bool
// or as a string.
//
// Both shapes occur: the API stores what the client sent, and the AWS
// credential decrypt path stringifies every non-string value it passes through
// (`fmt.Sprintf("%v", v)`), so a `false` that has been through it comes back as
// "false". Accepting only the bool would have read that as "not set" and
// silently turned the toggle back on.
func boolFromConfig(v interface{}) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(t))
		if err != nil {
			return false, false
		}
		return parsed, true
	default:
		return false, false
	}
}
