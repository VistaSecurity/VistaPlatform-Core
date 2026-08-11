package api

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
	"github.com/vistasecurity/vistaplatform/shared/storage"
)

var (
	tenantStorageService storage.ArtifactStorageService
	storageLogger        *logrus.Logger
)

// InitializeTenantStorageService sets up the storage service for tenant branding
func InitializeTenantStorageService(db *sql.DB) error {
	storageLogger = logrus.New()
	storageLogger.SetLevel(logrus.InfoLevel)

	masterKey := os.Getenv("ENCRYPTION_MASTER_KEY")
	if masterKey == "" {
		storageLogger.Warn("ENCRYPTION_MASTER_KEY not set, S3 storage will be disabled for tenant branding")
		return nil
	}

	// Create encryption service
	encSvc, err := encryption.NewService(masterKey)
	if err != nil {
		return fmt.Errorf("failed to create encryption service: %w", err)
	}

	// Create config and integration providers
	configProvider := storage.NewDatabaseConfigProvider(db)
	integrationProvider := storage.NewDatabaseIntegrationProvider(db, encSvc)

	// Create S3 storage service
	tenantStorageService = storage.NewS3StorageService(configProvider, integrationProvider, storageLogger)

	// Load initial config
	if err := tenantStorageService.Reload(context.Background()); err != nil {
		storageLogger.WithError(err).Warn("Failed to load initial storage config, S3 storage may not be available")
	}

	storageLogger.Info("Tenant storage service initialized")
	return nil
}

// GetTenantStorageService returns the tenant storage service
func GetTenantStorageService() storage.ArtifactStorageService {
	return tenantStorageService
}

// IsTenantBrandingStorageEnabled returns whether S3 storage is enabled for tenant branding
func IsTenantBrandingStorageEnabled() bool {
	if tenantStorageService == nil {
		return false
	}
	return tenantStorageService.IsEnabled(storage.ArtifactTypeTenantBranding)
}
