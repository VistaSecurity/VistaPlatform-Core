package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
	"github.com/vistasecurity/vistaplatform/shared/storage"
)

// UIConfig represents tenant UI configuration
type UIConfig struct {
	Theme          string                 `json:"theme"`
	PrimaryColor   string                 `json:"primary_color"`
	SecondaryColor string                 `json:"secondary_color"`
	AccentColor    string                 `json:"accent_color"`
	Palette        string                 `json:"palette"` // "current", "blue", "purple", "green", "slate", "vista"
	Enhancements   map[string]bool        `json:"enhancements"`
	Layout         string                 `json:"layout"`
	Features       map[string]interface{} `json:"features"`
	CustomCSS      *string                `json:"custom_css,omitempty"`
}

// Branding represents tenant branding configuration
type Branding struct {
	LogoURL        *string `json:"logo_url,omitempty"`
	FaviconURL     *string `json:"favicon_url,omitempty"`
	CompanyName    *string `json:"company_name,omitempty"`
	PrimaryColor   string  `json:"primary_color"`
	SecondaryColor string  `json:"secondary_color"`
	AccentColor    string  `json:"accent_color"`
	CustomCSS      *string `json:"custom_css,omitempty"`
}

// Theme represents a UI theme
type Theme struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	PrimaryColor    string `json:"primary_color"`
	SecondaryColor  string `json:"secondary_color"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
}

// Palette identifiers a tenant may select. Single source of truth: the
// validator, the error message, and the stored-value normalizer all read this
// list, so adding a palette is a one-line change that cannot drift.
//
// A stored palette that is NOT in this list is normalized to defaultPalette on
// read (normalizePalette) rather than rejected. Renaming a palette would
// otherwise strand every tenant row still carrying the old identifier: the
// value round-trips through GET -> PUT, so a rejected read makes the whole
// branding form un-saveable until someone hand-edits jsonb.
var paletteNames = []string{"current", "blue", "purple", "green", "slate", "vista"}

const defaultPalette = "vista"

var validPalettes = func() map[string]bool {
	m := make(map[string]bool, len(paletteNames))
	for _, n := range paletteNames {
		m[n] = true
	}
	return m
}()

// normalizePalette maps an unrecognized (legacy or hand-edited) stored palette
// onto the default rather than surfacing a value the validator would reject.
func normalizePalette(p string) string {
	if p == "" || validPalettes[p] {
		return p
	}
	return defaultPalette
}

// Default UI configuration
var defaultUIConfig = UIConfig{
	Theme:          "light",
	PrimaryColor:   "#0066cc",
	SecondaryColor: "#00a86b",
	Palette:        defaultPalette,
	Layout:         "default",
	Features: map[string]interface{}{
		"show_sidebar": true,
		"compact_mode": false,
	},
}

// Available themes
var availableThemes = []Theme{
	{
		ID:              "light",
		Name:            "Light",
		Description:     "Light theme with bright colors",
		PrimaryColor:    "#0066cc",
		SecondaryColor:  "#00a86b",
		BackgroundColor: "#ffffff",
		TextColor:       "#333333",
	},
	{
		ID:              "dark",
		Name:            "Dark",
		Description:     "Dark theme for low-light environments",
		PrimaryColor:    "#4a9eff",
		SecondaryColor:  "#00d4aa",
		BackgroundColor: "#1a1a1a",
		TextColor:       "#ffffff",
	},
	{
		ID:              "auto",
		Name:            "Auto",
		Description:     "Automatically switch based on system preference",
		PrimaryColor:    "#0066cc",
		SecondaryColor:  "#00a86b",
		BackgroundColor: "auto",
		TextColor:       "auto",
	},
}

// GetTenantUIConfig handles GET /tenant/ui-config - Get tenant UI configuration
// Merges platform-wide UI config defaults (from platform_settings) with tenant-specific overrides (from tenants.ui_config)
func GetTenantUIConfig(db *sql.DB) gin.HandlerFunc {
	return GetTenantUIConfigWithStore(newTenantUIConfigRepo(db))
}

// GetTenantUIConfigWithStore is the store-backed implementation of
// GetTenantUIConfig, exercised directly by the contract test.
func GetTenantUIConfigWithStore(store tenantUIConfigStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
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

		// First, get platform-wide UI config defaults from platform_settings
		platformUIConfigJSON, err := store.GetPlatformUIConfigJSON(c.Request.Context())

		// Parse platform UI config (if exists)
		var platformConfig map[string]interface{}
		if err == nil && len(platformUIConfigJSON) > 0 {
			if err := json.Unmarshal(platformUIConfigJSON, &platformConfig); err != nil {
				platformConfig = make(map[string]interface{})
			}
		} else if err != sql.ErrNoRows {
			// Log error but continue (non-fatal)
			platformConfig = make(map[string]interface{})
		} else {
			platformConfig = make(map[string]interface{})
		}

		// Get tenant-specific UI config from database
		tenantUIConfigJSON, err := store.GetTenantUIConfigJSON(c.Request.Context(), tenantID)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch UI config"})
			return
		}

		// Parse tenant JSON config
		var tenantConfig map[string]interface{}
		if err := json.Unmarshal(tenantUIConfigJSON, &tenantConfig); err != nil {
			// If parsing fails, use empty config
			tenantConfig = make(map[string]interface{})
		}

		// Merge: platform defaults first, then tenant overrides
		mergedConfig := make(map[string]interface{})
		// Copy platform config first (defaults)
		for k, v := range platformConfig {
			mergedConfig[k] = v
		}
		// Override with tenant config (tenant-specific overrides)
		for k, v := range tenantConfig {
			mergedConfig[k] = v
		}

		// Merge with code defaults
		result := defaultUIConfig
		if theme, ok := mergedConfig["theme"].(string); ok && theme != "" {
			result.Theme = theme
		}
		if primaryColor, ok := mergedConfig["primary_color"].(string); ok && primaryColor != "" {
			result.PrimaryColor = primaryColor
		}
		if secondaryColor, ok := mergedConfig["secondary_color"].(string); ok && secondaryColor != "" {
			result.SecondaryColor = secondaryColor
		}
		if accentColor, ok := mergedConfig["accent_color"].(string); ok && accentColor != "" {
			result.AccentColor = accentColor
		}
		if palette, ok := mergedConfig["palette"].(string); ok && palette != "" {
			result.Palette = normalizePalette(palette)
		}
		if enhancements, ok := mergedConfig["enhancements"].(map[string]interface{}); ok {
			result.Enhancements = make(map[string]bool)
			for k, v := range enhancements {
				if boolVal, ok := v.(bool); ok {
					result.Enhancements[k] = boolVal
				}
			}
		}
		if layout, ok := mergedConfig["layout"].(string); ok && layout != "" {
			result.Layout = layout
		}
		if features, ok := mergedConfig["features"].(map[string]interface{}); ok {
			// Merge features
			for k, v := range features {
				result.Features[k] = v
			}
		}
		if customCSS, ok := mergedConfig["custom_css"].(string); ok && customCSS != "" {
			result.CustomCSS = &customCSS
		}

		c.JSON(http.StatusOK, gin.H{"config": result})
	}
}

// GetPublicPlatformUIConfig handles GET /platform/ui-config - Get platform UI defaults
// Returns platform UI config for unauthenticated clients (login screen).
func GetPublicPlatformUIConfig(db *sql.DB) gin.HandlerFunc {
	return GetPublicPlatformUIConfigWithStore(newTenantUIConfigRepo(db))
}

// GetPublicPlatformUIConfigWithStore is the store-backed implementation of
// GetPublicPlatformUIConfig, exercised directly by the contract test.
func GetPublicPlatformUIConfigWithStore(store tenantUIConfigStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		platformUIConfigJSON, err := store.GetPlatformUIConfigJSON(c.Request.Context())

		// Parse platform UI config (if exists)
		platformConfig := make(map[string]interface{})
		if err == nil && len(platformUIConfigJSON) > 0 {
			if err := json.Unmarshal(platformUIConfigJSON, &platformConfig); err != nil {
				platformConfig = make(map[string]interface{})
			}
		} else if err != sql.ErrNoRows {
			platformConfig = make(map[string]interface{})
		}

		// Merge with code defaults
		result := defaultUIConfig
		if theme, ok := platformConfig["theme"].(string); ok && theme != "" {
			result.Theme = theme
		}
		if primaryColor, ok := platformConfig["primary_color"].(string); ok && primaryColor != "" {
			result.PrimaryColor = primaryColor
		}
		if secondaryColor, ok := platformConfig["secondary_color"].(string); ok && secondaryColor != "" {
			result.SecondaryColor = secondaryColor
		}
		if accentColor, ok := platformConfig["accent_color"].(string); ok && accentColor != "" {
			result.AccentColor = accentColor
		}
		if palette, ok := platformConfig["palette"].(string); ok && palette != "" {
			result.Palette = normalizePalette(palette)
		}
		if enhancements, ok := platformConfig["enhancements"].(map[string]interface{}); ok {
			result.Enhancements = make(map[string]bool)
			for k, v := range enhancements {
				if boolVal, ok := v.(bool); ok {
					result.Enhancements[k] = boolVal
				}
			}
		}
		if layout, ok := platformConfig["layout"].(string); ok && layout != "" {
			result.Layout = layout
		}
		if features, ok := platformConfig["features"].(map[string]interface{}); ok {
			for k, v := range features {
				result.Features[k] = v
			}
		}
		if customCSS, ok := platformConfig["custom_css"].(string); ok && customCSS != "" {
			result.CustomCSS = &customCSS
		}

		c.JSON(http.StatusOK, gin.H{"config": result})
	}
}

// GetTenantUIConfigByID handles GET /tenant/:tenantId/ui-config - Get tenant UI config by tenant ID (platform admin)
func GetTenantUIConfigByID(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for platform_admin role
		userRole, exists := c.Get("role")
		if !exists || userRole != "platform_admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions. Platform admin role required."})
			return
		}

		// Get tenant ID from URL path
		tenantIDStr := c.Param("tenantId")
		if tenantIDStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID required"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get UI config from database
		var uiConfigJSON []byte
		err = db.QueryRow(`
			SELECT COALESCE(ui_config::text, '{}')
			FROM tenants
			WHERE id = $1
		`, tenantID).Scan(&uiConfigJSON)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch UI config"})
			return
		}

		// Parse JSON config
		var config map[string]interface{}
		if err := json.Unmarshal(uiConfigJSON, &config); err != nil {
			config = make(map[string]interface{})
		}

		// Merge with defaults
		result := defaultUIConfig
		if theme, ok := config["theme"].(string); ok && theme != "" {
			result.Theme = theme
		}
		if primaryColor, ok := config["primary_color"].(string); ok && primaryColor != "" {
			result.PrimaryColor = primaryColor
		}
		if secondaryColor, ok := config["secondary_color"].(string); ok && secondaryColor != "" {
			result.SecondaryColor = secondaryColor
		}
		if accentColor, ok := config["accent_color"].(string); ok && accentColor != "" {
			result.AccentColor = accentColor
		}
		if palette, ok := config["palette"].(string); ok && palette != "" {
			result.Palette = normalizePalette(palette)
		}
		if enhancements, ok := config["enhancements"].(map[string]interface{}); ok {
			result.Enhancements = make(map[string]bool)
			for k, v := range enhancements {
				if boolVal, ok := v.(bool); ok {
					result.Enhancements[k] = boolVal
				}
			}
		}
		if layout, ok := config["layout"].(string); ok && layout != "" {
			result.Layout = layout
		}
		if features, ok := config["features"].(map[string]interface{}); ok {
			for k, v := range features {
				result.Features[k] = v
			}
		}
		if customCSS, ok := config["custom_css"].(string); ok && customCSS != "" {
			result.CustomCSS = &customCSS
		}

		c.JSON(http.StatusOK, gin.H{"config": result})
	}
}

// UpdateTenantUIConfigByID handles PUT /tenant/:tenantId/ui-config - Update tenant UI config by tenant ID (platform admin)
func UpdateTenantUIConfigByID(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for platform_admin role
		userRole, exists := c.Get("role")
		if !exists || userRole != "platform_admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions. Platform admin role required."})
			return
		}

		// Get tenant ID from URL path
		tenantIDStr := c.Param("tenantId")
		if tenantIDStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID required"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Parse request body
		var req UIConfig
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		// Validate configuration
		if err := validateUIConfig(req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid configuration"})
			return
		}

		// Get existing config
		var existingConfigJSON []byte
		err = db.QueryRow(`
			SELECT COALESCE(ui_config::text, '{}')
			FROM tenants
			WHERE id = $1
		`, tenantID).Scan(&existingConfigJSON)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch existing config"})
			return
		}

		// Parse existing config
		var existingConfig map[string]interface{}
		if err := json.Unmarshal(existingConfigJSON, &existingConfig); err != nil {
			existingConfig = make(map[string]interface{})
		}

		// Merge with new values (partial update)
		if req.Theme != "" {
			existingConfig["theme"] = req.Theme
		}
		if req.PrimaryColor != "" {
			existingConfig["primary_color"] = req.PrimaryColor
		}
		if req.SecondaryColor != "" {
			existingConfig["secondary_color"] = req.SecondaryColor
		}
		if req.AccentColor != "" {
			existingConfig["accent_color"] = req.AccentColor
		}
		if req.Palette != "" {
			existingConfig["palette"] = req.Palette
		}
		if req.Enhancements != nil {
			existingConfig["enhancements"] = req.Enhancements
		}
		if req.Layout != "" {
			existingConfig["layout"] = req.Layout
		}
		if req.Features != nil {
			if existingFeatures, ok := existingConfig["features"].(map[string]interface{}); ok {
				// Merge features
				for k, v := range req.Features {
					existingFeatures[k] = v
				}
				existingConfig["features"] = existingFeatures
			} else {
				existingConfig["features"] = req.Features
			}
		}
		if req.CustomCSS != nil {
			existingConfig["custom_css"] = *req.CustomCSS
		}

		// Convert to JSON
		updatedConfigJSON, err := json.Marshal(existingConfig)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize config"})
			return
		}

		// Update database
		_, err = db.Exec(`
			UPDATE tenants
			SET ui_config = $1::jsonb, updated_at = NOW()
			WHERE id = $2
		`, updatedConfigJSON, tenantID)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update UI config"})
			return
		}

		// Return updated config
		var result UIConfig
		if theme, ok := existingConfig["theme"].(string); ok {
			result.Theme = theme
		} else {
			result.Theme = defaultUIConfig.Theme
		}
		if primaryColor, ok := existingConfig["primary_color"].(string); ok {
			result.PrimaryColor = primaryColor
		} else {
			result.PrimaryColor = defaultUIConfig.PrimaryColor
		}
		if secondaryColor, ok := existingConfig["secondary_color"].(string); ok {
			result.SecondaryColor = secondaryColor
		} else {
			result.SecondaryColor = defaultUIConfig.SecondaryColor
		}
		if accentColor, ok := existingConfig["accent_color"].(string); ok {
			result.AccentColor = accentColor
		}
		if palette, ok := existingConfig["palette"].(string); ok {
			result.Palette = normalizePalette(palette)
		}
		if enhancements, ok := existingConfig["enhancements"].(map[string]interface{}); ok {
			result.Enhancements = make(map[string]bool)
			for k, v := range enhancements {
				if boolVal, ok := v.(bool); ok {
					result.Enhancements[k] = boolVal
				}
			}
		}
		if layout, ok := existingConfig["layout"].(string); ok {
			result.Layout = layout
		} else {
			result.Layout = defaultUIConfig.Layout
		}
		if features, ok := existingConfig["features"].(map[string]interface{}); ok {
			result.Features = features
		} else {
			result.Features = defaultUIConfig.Features
		}
		if customCSS, ok := existingConfig["custom_css"].(string); ok && customCSS != "" {
			result.CustomCSS = &customCSS
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "UI configuration updated successfully",
			"config":  result,
		})
	}
}

// UpdateTenantUIConfig handles PUT /tenant/ui-config - Update tenant UI configuration
// Requires platform_admin role (platform admins set tenant design defaults)
// This version uses tenant ID from JWT context (for web-ui use)
func UpdateTenantUIConfig(db *sql.DB) gin.HandlerFunc {
	return UpdateTenantUIConfigWithStore(newTenantUIConfigRepo(db))
}

// UpdateTenantUIConfigWithStore is the store-backed implementation of
// UpdateTenantUIConfig, exercised directly by the contract test.
func UpdateTenantUIConfigWithStore(store tenantUIConfigStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for platform_admin role
		userRole, exists := c.Get("role")
		if !exists || userRole != "platform_admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions. Platform admin role required."})
			return
		}

		// Get tenant ID from context
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
		var req UIConfig
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		// Validate configuration
		if err := validateUIConfig(req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid configuration"})
			return
		}

		// Get existing config
		existingConfigJSON, err := store.GetTenantUIConfigJSON(c.Request.Context(), tenantID)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch existing config"})
			return
		}

		// Parse existing config
		var existingConfig map[string]interface{}
		if err := json.Unmarshal(existingConfigJSON, &existingConfig); err != nil {
			existingConfig = make(map[string]interface{})
		}

		// Merge with new values (partial update)
		if req.Theme != "" {
			existingConfig["theme"] = req.Theme
		}
		if req.PrimaryColor != "" {
			existingConfig["primary_color"] = req.PrimaryColor
		}
		if req.SecondaryColor != "" {
			existingConfig["secondary_color"] = req.SecondaryColor
		}
		if req.AccentColor != "" {
			existingConfig["accent_color"] = req.AccentColor
		}
		if req.Palette != "" {
			existingConfig["palette"] = req.Palette
		}
		if req.Enhancements != nil {
			existingConfig["enhancements"] = req.Enhancements
		}
		if req.Layout != "" {
			existingConfig["layout"] = req.Layout
		}
		if req.Features != nil {
			if existingFeatures, ok := existingConfig["features"].(map[string]interface{}); ok {
				// Merge features
				for k, v := range req.Features {
					existingFeatures[k] = v
				}
				existingConfig["features"] = existingFeatures
			} else {
				existingConfig["features"] = req.Features
			}
		}
		if req.CustomCSS != nil {
			existingConfig["custom_css"] = *req.CustomCSS
		}

		// Convert to JSON
		updatedConfigJSON, err := json.Marshal(existingConfig)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize config"})
			return
		}

		// Update database
		if err := store.UpdateTenantUIConfigJSON(c.Request.Context(), tenantID, updatedConfigJSON); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update UI config"})
			return
		}

		// Return updated config
		var result UIConfig
		if theme, ok := existingConfig["theme"].(string); ok {
			result.Theme = theme
		} else {
			result.Theme = defaultUIConfig.Theme
		}
		if primaryColor, ok := existingConfig["primary_color"].(string); ok {
			result.PrimaryColor = primaryColor
		} else {
			result.PrimaryColor = defaultUIConfig.PrimaryColor
		}
		if secondaryColor, ok := existingConfig["secondary_color"].(string); ok {
			result.SecondaryColor = secondaryColor
		} else {
			result.SecondaryColor = defaultUIConfig.SecondaryColor
		}
		if accentColor, ok := existingConfig["accent_color"].(string); ok {
			result.AccentColor = accentColor
		}
		if palette, ok := existingConfig["palette"].(string); ok {
			result.Palette = normalizePalette(palette)
		}
		if enhancements, ok := existingConfig["enhancements"].(map[string]interface{}); ok {
			result.Enhancements = make(map[string]bool)
			for k, v := range enhancements {
				if boolVal, ok := v.(bool); ok {
					result.Enhancements[k] = boolVal
				}
			}
		}
		if layout, ok := existingConfig["layout"].(string); ok {
			result.Layout = layout
		} else {
			result.Layout = defaultUIConfig.Layout
		}
		if features, ok := existingConfig["features"].(map[string]interface{}); ok {
			result.Features = features
		} else {
			result.Features = defaultUIConfig.Features
		}
		if customCSS, ok := existingConfig["custom_css"].(string); ok && customCSS != "" {
			result.CustomCSS = &customCSS
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "UI configuration updated successfully",
			"config":  result,
		})
	}
}

// GetUIThemes handles GET /ui/themes - Get available themes
func GetUIThemes(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context (optional, for filtering by tier)
		tenantIDStr := c.GetString("tenantID")

		var themes []Theme
		if tenantIDStr != "" {
			tenantID, err := uuid.Parse(tenantIDStr)
			if err == nil {
				// Get tenant's subscription tier
				var tierName string
				err = db.QueryRow(`
					SELECT st.name
					FROM tenants t
					JOIN subscription_tiers st ON t.subscription_tier_id = st.id
					WHERE t.id = $1
				`, tenantID).Scan(&tierName)

				if err == nil {
					// Filter themes by tier availability.
					// For now, all themes are available to all tiers;
					// can be enhanced to check the ui_themes table.
					themes = append(themes, availableThemes...)
				} else {
					// If tier lookup fails, return all themes
					themes = availableThemes
				}
			} else {
				themes = availableThemes
			}
		} else {
			// No tenant context, return all public themes
			themes = availableThemes
		}

		// Also check database for custom themes
		rows, err := db.Query(`
			SELECT name, display_name, description, theme_config
			FROM ui_themes
			WHERE is_active = true AND (is_public = true OR pricing_tier = 'all')
			ORDER BY name
		`)

		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var name, displayName, description string
				var themeConfigJSON []byte
				if err := rows.Scan(&name, &displayName, &description, &themeConfigJSON); err == nil {
					var themeConfig map[string]interface{}
					if err := json.Unmarshal(themeConfigJSON, &themeConfig); err == nil {
						theme := Theme{
							ID:              name,
							Name:            displayName,
							Description:     description,
							PrimaryColor:    getStringFromMap(themeConfig, "primary_color", "#0066cc"),
							SecondaryColor:  getStringFromMap(themeConfig, "secondary_color", "#00a86b"),
							BackgroundColor: getStringFromMap(themeConfig, "background_color", "#ffffff"),
							TextColor:       getStringFromMap(themeConfig, "text_color", "#333333"),
						}
						themes = append(themes, theme)
					}
				}
			}
		}

		c.JSON(http.StatusOK, gin.H{"themes": themes})
	}
}

// GetTenantBranding handles GET /tenant/branding - Get tenant branding configuration
func GetTenantBranding(db *sql.DB) gin.HandlerFunc {
	return GetTenantBrandingWithStore(newTenantBrandingRepo(db))
}

// GetTenantBrandingWithStore is the store-backed implementation of
// GetTenantBranding, exercised directly by the contract test.
func GetTenantBrandingWithStore(store tenantBrandingStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
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

		// Get branding from database
		brandingJSON, err := store.GetBrandingJSON(c.Request.Context(), tenantID)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch branding"})
			return
		}

		// Parse JSON branding
		var brandingMap map[string]interface{}
		if err := json.Unmarshal(brandingJSON, &brandingMap); err != nil {
			brandingMap = make(map[string]interface{})
		}

		// Build response
		result := Branding{
			PrimaryColor:   getStringFromMap(brandingMap, "primary_color", "#0066cc"),
			SecondaryColor: getStringFromMap(brandingMap, "secondary_color", "#00a86b"),
			AccentColor:    getStringFromMap(brandingMap, "accent_color", "#ff6b6b"),
		}
		if logoURL, ok := brandingMap["logo_url"].(string); ok && logoURL != "" {
			result.LogoURL = &logoURL
		}
		if faviconURL, ok := brandingMap["favicon_url"].(string); ok && faviconURL != "" {
			result.FaviconURL = &faviconURL
		}
		if companyName, ok := brandingMap["company_name"].(string); ok && companyName != "" {
			result.CompanyName = &companyName
		}
		if customCSS, ok := brandingMap["custom_css"].(string); ok && customCSS != "" {
			result.CustomCSS = &customCSS
		}

		c.JSON(http.StatusOK, gin.H{"branding": result})
	}
}

// UpdateTenantBranding handles PUT /tenant/branding - Update tenant branding

// whiteLabelFieldsRequested reports whether the update touches the white-label
// surface, as opposed to the palette.
//
// The Core/Enterprise line for branding is "theme your instance" vs "replace our
// identity with yours". Colors are Core: a single organization tinting its own
// deployment is ordinary self-service, and the palette is read on every page
// load, so gating it would degrade the product for non-paying users rather than
// withhold a paid capability. Logo, favicon, company name, and custom CSS are
// the white-label surface — that is what "custom_branding" is sold as.
//
// Note this deliberately gates on what the request CHANGES, not on what the
// tenant already has. An Enterprise tenant that lapses keeps its stored logo
// serving (the read path is ungated) and can still adjust colors; it just
// cannot set a new logo. Blanking their branding on downgrade would be a
// destructive surprise, and the read path has no entitlement check by design.
func whiteLabelFieldsRequested(req Branding) bool {
	return req.LogoURL != nil || req.FaviconURL != nil ||
		req.CompanyName != nil || req.CustomCSS != nil
}

// requireCustomBranding writes a 403 and reports whether it did. Mirrors
// compliance-engine's requireCustomPolicies. Fails OPEN when the entitlement
// lookup itself errors: a database hiccup must not lock a paying tenant out of
// its own branding, and the downside of a wrongly-permitted logo change is
// negligible next to a false denial.
func requireCustomBranding(c *gin.Context, limitSvc limitChecker, tenantID uuid.UUID) bool {
	if limitSvc == nil {
		return false
	}
	allowed, err := limitSvc.CheckFeatureAccess(tenantID, "custom_branding")
	if err != nil {
		log.Printf("requireCustomBranding: CheckFeatureAccess for tenant %s failed: %v", tenantID, err)
		return false
	}
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Custom branding requires an Enterprise subscription",
		})
		return true
	}
	return false
}

func UpdateTenantBranding(db *sql.DB) gin.HandlerFunc {
	return UpdateTenantBrandingWithStore(newTenantBrandingRepo(db), sharedservices.NewLimitEnforcementService(db))
}

// UpdateTenantBrandingWithStore is the store-backed implementation of
// UpdateTenantBranding, exercised directly by the contract test.
func UpdateTenantBrandingWithStore(store tenantBrandingStore, limitSvc limitChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
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
		var req Branding
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		// Validate branding
		if err := validateBranding(req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid branding"})
			return
		}

		// White-label fields are Enterprise; the palette is Core.
		if whiteLabelFieldsRequested(req) && requireCustomBranding(c, limitSvc, tenantID) {
			return
		}

		// Get existing branding
		existingBrandingJSON, err := store.GetBrandingJSON(c.Request.Context(), tenantID)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch existing branding"})
			return
		}

		// Parse existing branding
		var existingBranding map[string]interface{}
		if err := json.Unmarshal(existingBrandingJSON, &existingBranding); err != nil {
			existingBranding = make(map[string]interface{})
		}

		// Merge with new values (partial update)
		if req.LogoURL != nil {
			existingBranding["logo_url"] = *req.LogoURL
		}
		if req.FaviconURL != nil {
			existingBranding["favicon_url"] = *req.FaviconURL
		}
		if req.CompanyName != nil {
			existingBranding["company_name"] = *req.CompanyName
		}
		if req.PrimaryColor != "" {
			existingBranding["primary_color"] = req.PrimaryColor
		}
		if req.SecondaryColor != "" {
			existingBranding["secondary_color"] = req.SecondaryColor
		}
		if req.AccentColor != "" {
			existingBranding["accent_color"] = req.AccentColor
		}
		if req.CustomCSS != nil {
			existingBranding["custom_css"] = *req.CustomCSS
		}

		// Convert to JSON
		updatedBrandingJSON, err := json.Marshal(existingBranding)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize branding"})
			return
		}

		// Update database
		if err := store.UpdateBrandingJSON(c.Request.Context(), tenantID, updatedBrandingJSON); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update branding"})
			return
		}

		// Build response
		result := Branding{
			PrimaryColor:   getStringFromMap(existingBranding, "primary_color", "#0066cc"),
			SecondaryColor: getStringFromMap(existingBranding, "secondary_color", "#00a86b"),
			AccentColor:    getStringFromMap(existingBranding, "accent_color", "#ff6b6b"),
		}
		if logoURL, ok := existingBranding["logo_url"].(string); ok && logoURL != "" {
			result.LogoURL = &logoURL
		}
		if faviconURL, ok := existingBranding["favicon_url"].(string); ok && faviconURL != "" {
			result.FaviconURL = &faviconURL
		}
		if companyName, ok := existingBranding["company_name"].(string); ok && companyName != "" {
			result.CompanyName = &companyName
		}
		if customCSS, ok := existingBranding["custom_css"].(string); ok && customCSS != "" {
			result.CustomCSS = &customCSS
		}

		c.JSON(http.StatusOK, gin.H{
			"message":  "Branding updated successfully",
			"branding": result,
		})
	}
}

// UploadBrandingAsset handles POST /auth/tenant/branding/upload - Upload logo/favicon files
func UploadBrandingAsset(db *sql.DB) gin.HandlerFunc {
	return UploadBrandingAssetWithChecker(db, sharedservices.NewLimitEnforcementService(db))
}

// UploadBrandingAssetWithChecker is the injectable form of UploadBrandingAsset,
// so the contract test can supply an entitlement stub instead of a live pool.
func UploadBrandingAssetWithChecker(db *sql.DB, limitSvc limitChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
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

		// Logo/favicon uploads are wholly white-label — unlike the PUT, there is
		// no palette half here, so the gate is unconditional.
		if requireCustomBranding(c, limitSvc, tenantID) {
			return
		}

		// Get asset type (logo or favicon)
		assetType := c.PostForm("type")
		if assetType != "logo" && assetType != "favicon" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset type. Must be 'logo' or 'favicon'"})
			return
		}

		// Get uploaded file
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided"})
			return
		}

		// Validate file size (5MB limit)
		if file.Size > 5*1024*1024 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "File too large. Maximum size is 5MB"})
			return
		}

		// Validate the file by its MAGIC BYTES — not the attacker-controlled
		// Content-Type header or filename. SVG stays excluded (it can embed
		// JavaScript → stored XSS) and is rejected because it carries no raster
		// image magic. The previous code derived the on-disk extension from
		// filepath.Ext(file.Filename), which let a caller pass Content-Type:
		// image/png with filename="evil.svg" and persist a .svg asset.
		allowedTypes := map[string]bool{
			"image/png":    true,
			"image/jpeg":   true,
			"image/x-icon": true,
		}
		img, ok := sniffImageType(file)
		if !ok || !allowedTypes[img.MIME] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Only PNG, JPEG, and ICO are allowed"})
			return
		}
		contentType := img.MIME

		// Generate unique filename with asset type prefix. The extension is
		// server-authoritative (from the sniffed type), never from the caller.
		filename := fmt.Sprintf("%s-%s%s", assetType, uuid.New().String(), img.Ext)

		var assetURL string

		// Check if S3 storage is configured and enabled for tenant branding
		if IsTenantBrandingStorageEnabled() {
			assetURL, err = uploadTenantBrandingToS3(c, file, filename, contentType, &tenantID)
			if err != nil {
				if storageLogger != nil {
					storageLogger.WithError(err).Error("Failed to upload to S3, falling back to local storage")
				}
				// Fall back to local storage
				assetURL, err = uploadTenantBrandingToLocal(c, file, filename, tenantID)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
					return
				}
			}
		} else {
			// Use local storage (fallback for when S3 is not configured)
			assetURL, err = uploadTenantBrandingToLocal(c, file, filename, tenantID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("%s uploaded successfully", assetType),
			"url":     assetURL,
		})
	}
}

// uploadTenantBrandingToS3 uploads the file to S3 using the storage service
func uploadTenantBrandingToS3(c *gin.Context, file *multipart.FileHeader, filename, contentType string, tenantID *uuid.UUID) (string, error) {
	storageService := GetTenantStorageService()
	if storageService == nil {
		return "", fmt.Errorf("storage service not initialized")
	}

	// Open the file
	src, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = src.Close() }()

	// Read file content
	data, err := io.ReadAll(src)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Upload to S3
	result, err := storageService.Upload(
		c.Request.Context(),
		storage.ArtifactTypeTenantBranding,
		tenantID,
		filename,
		bytes.NewReader(data),
		contentType,
		int64(len(data)),
	)
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	return result.URL, nil
}

// uploadTenantBrandingToLocal saves the file to local filesystem
func uploadTenantBrandingToLocal(c *gin.Context, file *multipart.FileHeader, filename string, tenantID uuid.UUID) (string, error) {
	// Create uploads directory for tenant branding
	uploadDir := filepath.Join("uploads", "branding", tenantID.String())
	if err := os.MkdirAll(uploadDir, 0o750); err != nil {
		return "", fmt.Errorf("failed to create upload directory: %w", err)
	}

	// Open source file
	src, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() { _ = src.Close() }()

	// Create destination file
	filePath := filepath.Join(uploadDir, filename)
	dst, err := os.Create(filePath) //nolint:gosec // intentional — filename is server-generated as "{assetType}-{uuid}{ext}" (line 1017), uploadDir is a fixed tenant-scoped path
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() { _ = dst.Close() }()

	// Copy content
	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	// Return URL for the uploaded file
	return fmt.Sprintf("/uploads/branding/%s/%s", tenantID.String(), filename), nil
}

// validateUIConfig validates UI configuration
func validateUIConfig(config UIConfig) error {
	// Validate palette if provided
	if config.Palette != "" && !validPalettes[config.Palette] {
		return &ValidationError{
			Field:   "palette",
			Message: "Invalid palette. Must be one of: " + strings.Join(paletteNames, ", "),
		}
	}

	// Validate enhancement flags if provided
	if config.Enhancements != nil {
		validEnhancements := map[string]bool{
			"shadows":      true,
			"gradients":    true,
			"animations":   true,
			"typography":   true,
			"spacing":      true,
			"borders":      true,
			"hoverEffects": true,
		}
		for key := range config.Enhancements {
			if !validEnhancements[key] {
				return &ValidationError{Field: "enhancements", Message: fmt.Sprintf("Invalid enhancement key: %s", key)}
			}
		}
	}
	// Validate theme
	validThemes := map[string]bool{"light": true, "dark": true, "auto": true}
	if config.Theme != "" && !validThemes[config.Theme] {
		return &ValidationError{Field: "theme", Message: "Theme must be one of: light, dark, auto"}
	}

	// Validate colors (hex format)
	if config.PrimaryColor != "" && !isValidHexColor(config.PrimaryColor) {
		return &ValidationError{Field: "primary_color", Message: "Primary color must be a valid hex color"}
	}
	if config.SecondaryColor != "" && !isValidHexColor(config.SecondaryColor) {
		return &ValidationError{Field: "secondary_color", Message: "Secondary color must be a valid hex color"}
	}

	// Validate layout
	validLayouts := map[string]bool{"default": true, "compact": true, "wide": true}
	if config.Layout != "" && !validLayouts[config.Layout] {
		return &ValidationError{Field: "layout", Message: "Layout must be one of: default, compact, wide"}
	}

	// Validate custom CSS (basic sanitization - prevent obvious XSS)
	if config.CustomCSS != nil && *config.CustomCSS != "" {
		// Basic check for script tags
		if strings.Contains(strings.ToLower(*config.CustomCSS), "<script") {
			return &ValidationError{Field: "custom_css", Message: "Custom CSS cannot contain script tags"}
		}
	}

	return nil
}

// validateBranding validates branding configuration
func validateBranding(branding Branding) error {
	// Validate URLs (allow local upload paths)
	if branding.LogoURL != nil && *branding.LogoURL != "" {
		if !isValidBrandingAssetURL(*branding.LogoURL) {
			return &ValidationError{Field: "logo_url", Message: "Logo URL must be a valid URL"}
		}
	}
	if branding.FaviconURL != nil && *branding.FaviconURL != "" {
		if !isValidBrandingAssetURL(*branding.FaviconURL) {
			return &ValidationError{Field: "favicon_url", Message: "Favicon URL must be a valid URL"}
		}
	}

	// Validate colors
	if branding.PrimaryColor != "" && !isValidHexColor(branding.PrimaryColor) {
		return &ValidationError{Field: "primary_color", Message: "Primary color must be a valid hex color"}
	}
	if branding.SecondaryColor != "" && !isValidHexColor(branding.SecondaryColor) {
		return &ValidationError{Field: "secondary_color", Message: "Secondary color must be a valid hex color"}
	}
	if branding.AccentColor != "" && !isValidHexColor(branding.AccentColor) {
		return &ValidationError{Field: "accent_color", Message: "Accent color must be a valid hex color"}
	}

	// Validate custom CSS
	if branding.CustomCSS != nil && *branding.CustomCSS != "" {
		if strings.Contains(strings.ToLower(*branding.CustomCSS), "<script") {
			return &ValidationError{Field: "custom_css", Message: "Custom CSS cannot contain script tags"}
		}
	}

	return nil
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// isValidHexColor checks if a string is a valid hex color
func isValidHexColor(color string) bool {
	matched, _ := regexp.MatchString(`^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$`, color)
	return matched
}

// isValidURL checks if a string is a valid URL
func isValidURL(url string) bool {
	matched, _ := regexp.MatchString(`^https?://[^\s/$.?#].[^\s]*$`, url)
	return matched
}

// isValidBrandingAssetURL allows absolute URLs or local uploads paths.
func isValidBrandingAssetURL(url string) bool {
	if strings.HasPrefix(url, "/uploads/branding/") || strings.HasPrefix(url, "/uploads/platform-branding/") {
		return true
	}
	return isValidURL(url)
}

// getStringFromMap safely gets a string from a map
func getStringFromMap(m map[string]interface{}, key, defaultValue string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return defaultValue
}
