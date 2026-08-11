package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/shared/storage"
)

var storageConfigLogger *logrus.Logger

func init() {
	storageConfigLogger = logrus.New()
	storageConfigLogger.SetLevel(logrus.InfoLevel)
}

// StorageConfigResponse represents the response for storage configuration
type StorageConfigResponse struct {
	Config                 *storage.StorageConfig `json:"config"`
	AvailableIntegrations  []IntegrationSummary   `json:"available_integrations"`
	AvailableArtifactTypes []ArtifactTypeInfo     `json:"available_artifact_types"`
}

// IntegrationSummary provides a summary of an integration for selection
type IntegrationSummary struct {
	ID              uuid.UUID `json:"id"`
	IntegrationName string    `json:"integration_name"`
	Provider        string    `json:"provider"`
	Status          string    `json:"status"`
	Region          *string   `json:"region,omitempty"`
}

// ArtifactTypeInfo provides information about available artifact types
type ArtifactTypeInfo struct {
	Type        storage.ArtifactType `json:"type"`
	DisplayName string               `json:"display_name"`
	Description string               `json:"description"`
}

// storageStore is the narrow DB surface the storage-config handlers use. The
// concrete repo holds the SQL verbatim so the handlers are contract-testable over
// an in-memory stub (ADR-0001). Public Get/Update/TestStorage* (db) wrap the
// *WithStore variants — server wiring is unchanged. ErrNoRows sentinels are
// preserved (the handlers branch on them).
type storageStore interface {
	GetArtifactStorageConfigRaw(ctx context.Context) ([]byte, error)
	UpsertArtifactStorageConfig(ctx context.Context, configJSON []byte, updatedBy uuid.UUID) error
	ListAWSIntegrations(ctx context.Context) ([]IntegrationSummary, error)
	IntegrationExists(ctx context.Context, integrationID uuid.UUID) (bool, error)
	GetIntegrationStatus(ctx context.Context, integrationID uuid.UUID) (string, error)
}

// storageRepository runs the platform storage-config queries. The
// platform_settings reads/writes stay on db; the platform_integrations lookups
// (RLS-policied, read with no tenant predicate) use bypassDB (BYPASSRLS, Phase 4).
type storageRepository struct {
	db       *sql.DB
	bypassDB *sql.DB
}

func newStorageStore(db, bypassDB *sql.DB) storageStore {
	return &storageRepository{db: db, bypassDB: bypassDB}
}

func (r *storageRepository) GetArtifactStorageConfigRaw(ctx context.Context) ([]byte, error) {
	var settingValue []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT setting_value
		FROM platform_settings
		WHERE setting_key = 'artifact_storage_config'
	`).Scan(&settingValue)
	return settingValue, err
}

func (r *storageRepository) UpsertArtifactStorageConfig(ctx context.Context, configJSON []byte, updatedBy uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO platform_settings (setting_key, setting_value, description, updated_by, updated_at)
		VALUES ('artifact_storage_config', $1, 'Artifact storage configuration for S3 backends.', $2, NOW())
		ON CONFLICT (setting_key)
		DO UPDATE SET
			setting_value = EXCLUDED.setting_value,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()
	`, configJSON, updatedBy)
	return err
}

// RLS: cross-tenant — runs on the bypass role (Phase 4). platform_integrations
// is RLS-policied on tenant_id, but this reads PLATFORM-level AWS storage
// backends (tenant_id IS NULL / shared) with no tenant predicate, so it must
// see rows across the tenant scope.
func (r *storageRepository) ListAWSIntegrations(ctx context.Context) ([]IntegrationSummary, error) {
	rows, err := r.bypassDB.QueryContext(ctx, `
		SELECT id, integration_name, provider, status, region
		FROM platform_integrations
		WHERE integration_type = 'aws' AND is_active = true
		ORDER BY integration_name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var integrations []IntegrationSummary
	for rows.Next() {
		var i IntegrationSummary
		if err := rows.Scan(&i.ID, &i.IntegrationName, &i.Provider, &i.Status, &i.Region); err != nil {
			return nil, err
		}
		integrations = append(integrations, i)
	}
	return integrations, rows.Err()
}

// RLS: cross-tenant — runs on the bypass role (Phase 4). Existence check by id
// on RLS-policied platform_integrations with no tenant predicate (platform-level
// storage backend lookup); must resolve across the tenant scope.
func (r *storageRepository) IntegrationExists(ctx context.Context, integrationID uuid.UUID) (bool, error) {
	var exists bool
	err := r.bypassDB.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM platform_integrations
			WHERE id = $1 AND is_active = true AND integration_type = 'aws'
		)
	`, integrationID).Scan(&exists)
	return exists, err
}

// RLS: cross-tenant — runs on the bypass role (Phase 4). Status lookup by id on
// RLS-policied platform_integrations with no tenant predicate (platform-level
// storage backend); must resolve across the tenant scope.
func (r *storageRepository) GetIntegrationStatus(ctx context.Context, integrationID uuid.UUID) (string, error) {
	var status string
	err := r.bypassDB.QueryRowContext(ctx, `
		SELECT status FROM platform_integrations
		WHERE id = $1 AND is_active = true
	`, integrationID).Scan(&status)
	return status, err
}

func artifactTypeCatalog() []ArtifactTypeInfo {
	return []ArtifactTypeInfo{
		{Type: storage.ArtifactTypeTenantBranding, DisplayName: "Tenant Branding", Description: "Logos, favicons, and branding assets uploaded by tenants"},
		{Type: storage.ArtifactTypePlatformBranding, DisplayName: "Platform Branding", Description: "Platform-wide logos, favicons, and branding assets"},
		{Type: storage.ArtifactTypeSensorBinaries, DisplayName: "Sensor Binaries", Description: "Sensor installation binaries for various platforms"},
		{Type: storage.ArtifactTypeReports, DisplayName: "Reports", Description: "Generated reports (compliance, inventory, etc.)"},
		{Type: storage.ArtifactTypeAuditLogs, DisplayName: "Audit Logs", Description: "Archived audit logs for long-term retention"},
	}
}

// GetStorageConfig returns the current artifact storage configuration.
func GetStorageConfig(db, bypassDB *sql.DB) gin.HandlerFunc {
	return getStorageConfigWithStore(newStorageStore(db, bypassDB))
}

func getStorageConfigWithStore(store storageStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		settingValue, err := store.GetArtifactStorageConfigRaw(c.Request.Context())

		var config *storage.StorageConfig
		if errors.Is(err, sql.ErrNoRows) {
			config = storage.DefaultStorageConfig()
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve storage configuration",
			})
			return
		} else {
			config, err = storage.ParseStorageConfig(settingValue)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to parse storage configuration",
				})
				return
			}
		}

		integrations, err := store.ListAWSIntegrations(c.Request.Context())
		if err != nil {
			storageConfigLogger.WithError(err).Warn("Failed to fetch AWS integrations")
			integrations = []IntegrationSummary{}
		}

		c.JSON(http.StatusOK, StorageConfigResponse{
			Config:                 config,
			AvailableIntegrations:  integrations,
			AvailableArtifactTypes: artifactTypeCatalog(),
		})
	}
}

// UpdateStorageConfig updates the artifact storage configuration.
func UpdateStorageConfig(db, bypassDB *sql.DB) gin.HandlerFunc {
	return updateStorageConfigWithStore(newStorageStore(db, bypassDB))
}

func updateStorageConfigWithStore(store storageStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		var config storage.StorageConfig
		if err := c.ShouldBindJSON(&config); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		// Validate integration ID if provided
		if config.DefaultIntegrationID != nil {
			valid, err := store.IntegrationExists(c.Request.Context(), *config.DefaultIntegrationID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate integration"})
				return
			}
			if !valid {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid default_integration_id: integration not found or not active"})
				return
			}
		}

		// Validate per-artifact integration IDs
		for artType, artConfig := range config.ArtifactTypes {
			if artConfig.IntegrationID != nil {
				valid, err := store.IntegrationExists(c.Request.Context(), *artConfig.IntegrationID)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate integration"})
					return
				}
				if !valid {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration_id for artifact type " + string(artType)})
					return
				}
			}
		}

		configJSON, err := json.Marshal(config)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize configuration"})
			return
		}

		if err := store.UpsertArtifactStorageConfig(c.Request.Context(), configJSON, userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save storage configuration"})
			return
		}

		storageConfigLogger.WithFields(logrus.Fields{
			"user_id":        userID.String(),
			"integration_id": config.DefaultIntegrationID,
			"bucket":         config.DefaultBucket,
			"enabled_types":  getEnabledArtifactTypes(config),
		}).Info("Storage configuration updated")

		c.JSON(http.StatusOK, gin.H{
			"message": "Storage configuration updated successfully",
			"config":  config,
		})
	}
}

// TestStorageConnection tests connectivity for a specific artifact type.
func TestStorageConnection(db, bypassDB *sql.DB) gin.HandlerFunc {
	return testStorageConnectionWithStore(newStorageStore(db, bypassDB))
}

func testStorageConnectionWithStore(store storageStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			ArtifactType string `json:"artifact_type" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		settingValue, err := store.GetArtifactStorageConfigRaw(c.Request.Context())
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Storage not configured",
				"message": "Please configure storage settings first",
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve storage configuration"})
			return
		}

		config, err := storage.ParseStorageConfig(settingValue)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse storage configuration"})
			return
		}

		artConfig, ok := config.ArtifactTypes[storage.ArtifactType(req.ArtifactType)]
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown artifact type: " + req.ArtifactType})
			return
		}

		if !artConfig.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Artifact type not enabled",
				"message": "Enable " + req.ArtifactType + " before testing connection",
			})
			return
		}

		integrationID := artConfig.GetIntegrationID(config.DefaultIntegrationID)
		if integrationID == nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "No AWS integration configured",
				"message": "Please select an AWS integration for storage",
			})
			return
		}

		bucket := artConfig.GetBucket(config.DefaultBucket)
		if bucket == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "No S3 bucket configured",
				"message": "Please specify an S3 bucket",
			})
			return
		}

		status, err := store.GetIntegrationStatus(c.Request.Context(), *integrationID)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Integration not found",
				"message": "The configured AWS integration is not available",
				"success": false,
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to verify integration",
				"success": false,
			})
			return
		}

		if status != "connected" && status != "configured" {
			c.JSON(http.StatusOK, gin.H{
				"success":       false,
				"message":       "AWS integration is not in a connected state",
				"artifact_type": req.ArtifactType,
				"bucket":        bucket,
				"status":        status,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success":            true,
			"message":            "Storage configuration appears valid",
			"artifact_type":      req.ArtifactType,
			"bucket":             bucket,
			"integration_status": status,
		})
	}
}

func getEnabledArtifactTypes(config storage.StorageConfig) []string {
	var enabled []string
	for artType, artConfig := range config.ArtifactTypes {
		if artConfig.Enabled {
			enabled = append(enabled, string(artType))
		}
	}
	return enabled
}
