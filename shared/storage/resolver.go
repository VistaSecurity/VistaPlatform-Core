package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// DatabaseConfigProvider implements ConfigProvider using a database connection
type DatabaseConfigProvider struct {
	db *sql.DB
}

// NewDatabaseConfigProvider creates a new database-backed config provider
func NewDatabaseConfigProvider(db *sql.DB) *DatabaseConfigProvider {
	return &DatabaseConfigProvider{db: db}
}

// GetStorageConfig retrieves the storage configuration from the platform_settings table
func (p *DatabaseConfigProvider) GetStorageConfig(ctx context.Context) (*StorageConfig, error) {
	var settingValue []byte

	err := p.db.QueryRowContext(ctx, `
		SELECT setting_value
		FROM platform_settings
		WHERE setting_key = 'artifact_storage_config'
	`).Scan(&settingValue)

	if err == sql.ErrNoRows {
		// Return default config if not set
		return DefaultStorageConfig(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query storage config: %w", err)
	}

	config, err := ParseStorageConfig(settingValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse storage config: %w", err)
	}

	return config, nil
}

// DatabaseIntegrationProvider implements IntegrationProvider using a database connection
type DatabaseIntegrationProvider struct {
	db         *sql.DB
	encryption *encryption.Service
}

// NewDatabaseIntegrationProvider creates a new database-backed integration provider
func NewDatabaseIntegrationProvider(db *sql.DB, encryptionService *encryption.Service) *DatabaseIntegrationProvider {
	return &DatabaseIntegrationProvider{
		db:         db,
		encryption: encryptionService,
	}
}

// GetAWSCredentials retrieves and decrypts AWS credentials for the given integration
func (p *DatabaseIntegrationProvider) GetAWSCredentials(ctx context.Context, integrationID uuid.UUID) (*AWSCredentials, error) {
	var (
		integrationType     string
		encryptedConfigJSON []byte
	)

	err := p.db.QueryRowContext(ctx, `
		SELECT integration_type, encrypted_config
		FROM platform_integrations
		WHERE id = $1 AND is_active = true
	`, integrationID).Scan(&integrationType, &encryptedConfigJSON)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("integration not found: %s", integrationID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query integration: %w", err)
	}

	if integrationType != "aws" {
		return nil, fmt.Errorf("integration %s is not an AWS integration (type: %s)", integrationID, integrationType)
	}

	// Decrypt the configuration
	var encryptedConfig struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		Region          string `json:"region"`
		RoleARN         string `json:"role_arn"`
	}

	if err := json.Unmarshal(encryptedConfigJSON, &encryptedConfig); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted config: %w", err)
	}

	// Decrypt credentials
	accessKeyID, err := p.encryption.Decrypt(encryptedConfig.AccessKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt access key ID: %w", err)
	}

	secretAccessKey, err := p.encryption.Decrypt(encryptedConfig.SecretAccessKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret access key: %w", err)
	}

	return &AWSCredentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Region:          encryptedConfig.Region,
	}, nil
}
