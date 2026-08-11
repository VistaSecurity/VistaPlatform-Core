package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Placeholder handlers for routes not yet implemented

// Flexible auth flow handlers live in auth_flow.go
// AuthInitiate, AuthMethods, AuthAuthenticate, AuthComplete are now implemented

// SSO authentication flow handlers are Enterprise (ee/sso/tenant_sso.go)
// SSOAuthorize, SSOCallback, SSOLink, SSOUnlink are implemented there

// SSO provider handlers are Enterprise (ee/sso/tenant_sso.go)
// ListSSOProviders is implemented there

// User management handlers have been moved to handlers/users.go
// These placeholder functions are no longer needed

func getCurrentTenantHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context (set by auth middleware)
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Fetch tenant from database. Note: there is no `status` column on
		// tenants — closest analogues are `payment_status` and
		// `onboarding_status`, neither of which the web-ui currently consumes
		// for this endpoint, so we omit it from the response.
		var tenant struct {
			ID             uuid.UUID       `json:"id"`
			Name           string          `json:"name"`
			Slug           string          `json:"slug"`
			Domain         *string         `json:"domain"`
			BillingEmail   *string         `json:"billing_email"`
			CustomBranding json.RawMessage `json:"custom_branding,omitempty"`
			UIConfig       json.RawMessage `json:"ui_config,omitempty"`
		}

		// COALESCE in jsonb space (not text) so the driver returns []byte and
		// scans cleanly into json.RawMessage. Casting to ::text returned a
		// string and broke the scan.
		err = db.QueryRow(`
			SELECT id, name, slug, domain, billing_email,
			       COALESCE(custom_branding, '{}'::jsonb),
			       COALESCE(ui_config, '{}'::jsonb)
			FROM tenants
			WHERE id = $1
		`, tenantID).Scan(
			&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain,
			&tenant.BillingEmail, &tenant.CustomBranding, &tenant.UIConfig,
		)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		if err != nil {
			// Log the underlying error so future failures are diagnosable
			// without an extra debugging round-trip — the previous swallowed
			// "Failed to fetch tenant" hid a missing-column error for years.
			log.Printf("getCurrentTenantHandler: query failed for tenant %s: %v", tenantID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tenant"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"tenant": tenant})
	}
}

func updateCurrentTenantHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context (set by auth middleware)
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Parse request body
		var req struct {
			Name           *string                `json:"name"`
			Domain         *string                `json:"domain"`
			BillingEmail   *string                `json:"billing_email"`
			CustomBranding map[string]interface{} `json:"custom_branding"`
			UIConfig       map[string]interface{} `json:"ui_config"`
			Settings       map[string]interface{} `json:"settings"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		// Build dynamic update query
		updates := []string{}
		args := []interface{}{}
		argIndex := 1

		if req.Name != nil {
			updates = append(updates, fmt.Sprintf("name = $%d", argIndex))
			args = append(args, *req.Name)
			argIndex++
		}
		if req.Domain != nil {
			updates = append(updates, fmt.Sprintf("domain = $%d", argIndex))
			args = append(args, *req.Domain)
			argIndex++
		}
		if req.BillingEmail != nil {
			updates = append(updates, fmt.Sprintf("billing_email = $%d", argIndex))
			args = append(args, *req.BillingEmail)
			argIndex++
		}
		if req.CustomBranding != nil {
			brandingJSON, _ := json.Marshal(req.CustomBranding)
			updates = append(updates, fmt.Sprintf("custom_branding = $%d", argIndex))
			args = append(args, brandingJSON)
			argIndex++
		}
		if req.UIConfig != nil {
			uiConfigJSON, _ := json.Marshal(req.UIConfig)
			updates = append(updates, fmt.Sprintf("ui_config = $%d", argIndex))
			args = append(args, uiConfigJSON)
			argIndex++
		}
		if req.Settings != nil {
			settingsJSON, _ := json.Marshal(req.Settings)
			updates = append(updates, fmt.Sprintf("settings = $%d", argIndex))
			args = append(args, settingsJSON)
			argIndex++
		}

		if len(updates) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
			return
		}

		// Add updated_at and tenant ID
		updates = append(updates, "updated_at = NOW()")
		args = append(args, tenantID)

		// Build and execute query
		query := fmt.Sprintf("UPDATE tenants SET %s WHERE id = $%d", joinStrings(updates, ", "), argIndex) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
		result, err := db.Exec(query, args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant"})
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Tenant updated successfully"})
	}
}

// Helper function to join strings
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

func getTenantUsageHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{"message": "Get tenant usage endpoint - to be implemented"})
	}
}

// Billing handlers have been moved to handlers/billing.go
// These placeholder functions are no longer needed

// SSO provider CRUD handlers are Enterprise (ee/sso/tenant_sso.go)
// CreateSSOProvider, UpdateSSOProvider, DeleteSSOProvider, TestSSOProvider are implemented there

// getSubscriptionTiersHandler returns subscription tiers (requires auth)
func getSubscriptionTiersHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`
			SELECT id, name, display_name, max_sensors, max_assets, max_users,
			       retention_days, price_cents, COALESCE(annual_price_cents, 0), billing_interval, features,
			       limits, is_active
			FROM subscription_tiers
			WHERE is_active = true
			  -- Standard plans only. Custom/enterprise plans and tenant-scoped
			  -- plans are private; a tenant's own plan surfaces via its billing
			  -- page (current-plan read path), not this selectable catalog.
			  AND COALESCE(is_custom, false) = false
			  AND owner_tenant_id IS NULL
			  AND (COALESCE(is_trial, false) = true OR (billing_method = 'stripe' AND COALESCE(price_cents, 0) > 0))
			ORDER BY price_cents ASC, name ASC
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch subscription tiers"})
			return
		}
		defer func() { _ = rows.Close() }()

		tiers := []gin.H{}
		for rows.Next() {
			var id, name, displayName, billingInterval string
			var maxSensors, maxAssets, maxUsers, retentionDays, priceCents sql.NullInt64
			var annualPriceCents int64
			var features, limits []byte
			var isActive bool
			if err := rows.Scan(&id, &name, &displayName, &maxSensors, &maxAssets, &maxUsers,
				&retentionDays, &priceCents, &annualPriceCents, &billingInterval, &features, &limits, &isActive); err != nil {
				continue
			}

			tier := gin.H{
				"id":                 id,
				"name":               name,
				"display_name":       displayName,
				"billing_interval":   billingInterval,
				"price_cents":        priceCents.Int64,
				"annual_price_cents": annualPriceCents,
				"is_active":          isActive,
			}

			if maxSensors.Valid {
				tier["max_sensors"] = maxSensors.Int64
			}
			if maxAssets.Valid {
				tier["max_assets"] = maxAssets.Int64
			}
			if maxUsers.Valid {
				tier["max_users"] = maxUsers.Int64
			}
			if retentionDays.Valid {
				tier["retention_days"] = retentionDays.Int64
			}
			// Parse JSONB fields
			if len(features) > 0 {
				var featuresMap map[string]interface{}
				if err := json.Unmarshal(features, &featuresMap); err == nil {
					tier["features"] = featuresMap
				}
			}
			if len(limits) > 0 {
				var limitsMap map[string]interface{}
				if err := json.Unmarshal(limits, &limitsMap); err == nil {
					tier["limits"] = limitsMap
				}
			}

			tiers = append(tiers, tier)
		}

		c.JSON(http.StatusOK, gin.H{"tiers": tiers})
	}
}

// getPublicTiersHandler returns subscription tiers (public, no auth required)
func getPublicTiersHandler(db *sql.DB) gin.HandlerFunc {
	return getPublicTiersHandlerWithStore(newBillingRepo(db))
}

// getPublicTiersHandlerWithStore is the store-backed implementation, exercised
// directly by the contract test.
func getPublicTiersHandlerWithStore(store tierStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := store.ListActiveTiers(c.Request.Context())
		if err != nil {
			log.Printf("Tiers query error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to fetch subscription tiers",
			})
			return
		}

		tiers := []gin.H{}
		for _, row := range rows {
			tier := gin.H{
				"id":                 row.ID.String(),
				"name":               row.Name,
				"display_name":       row.DisplayName,
				"billing_interval":   row.BillingInterval,
				"price_cents":        row.PriceCents.Int64,
				"annual_price_cents": row.AnnualPriceCents,
				"is_active":          row.IsActive,
			}

			if row.MaxSensors.Valid {
				tier["max_sensors"] = row.MaxSensors.Int64
			}
			if row.MaxAssets.Valid {
				tier["max_assets"] = row.MaxAssets.Int64
			}
			if row.MaxUsers.Valid {
				tier["max_users"] = row.MaxUsers.Int64
			}
			if row.RetentionDays.Valid {
				tier["retention_days"] = row.RetentionDays.Int64
			}
			// Parse JSONB fields
			if len(row.FeaturesJSON) > 0 {
				var featuresMap map[string]interface{}
				if err := json.Unmarshal(row.FeaturesJSON, &featuresMap); err == nil {
					tier["features"] = featuresMap
				}
			}
			if len(row.LimitsJSON) > 0 {
				var limitsMap map[string]interface{}
				if err := json.Unmarshal(row.LimitsJSON, &limitsMap); err == nil {
					tier["limits"] = limitsMap
				}
			}

			tiers = append(tiers, tier)
		}

		c.JSON(http.StatusOK, gin.H{"tiers": tiers})
	}
}

// Billing handlers have been moved to handlers/billing.go
// These placeholder functions are no longer needed

// Onboarding handlers have been moved to onboarding.go
// These placeholder functions are no longer needed
