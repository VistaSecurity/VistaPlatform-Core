package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

type CryptoConfigurationService struct {
	db *database.DB
}

func NewCryptoConfigurationService(db *database.DB) *CryptoConfigurationService {
	return &CryptoConfigurationService{
		db: db,
	}
}

// CryptoConfiguration represents a configured (but not necessarily in-use) crypto configuration
type CryptoConfiguration struct {
	ID                         uuid.UUID              `json:"id" db:"id"`
	TenantID                   uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	AssetID                    uuid.UUID              `json:"asset_id" db:"asset_id"`
	DeviceID                   *uuid.UUID             `json:"device_id,omitempty" db:"device_id"`
	Protocol                   string                 `json:"protocol" db:"protocol"`
	ConfiguredCipherSuites     []string               `json:"configured_cipher_suites" db:"configured_cipher_suites"`
	ConfiguredProtocolVersions []string               `json:"configured_protocol_versions" db:"configured_protocol_versions"`
	AlgorithmPreferences       map[string]interface{} `json:"algorithm_preferences" db:"algorithm_preferences"`
	Source                     string                 `json:"source" db:"source"`
	DiscoveryMethod            string                 `json:"discovery_method" db:"discovery_method"`
	ConfidenceScore            float64                `json:"confidence_score" db:"confidence_score"`
	DiscoveredAt               time.Time              `json:"discovered_at" db:"discovered_at"`
	LastVerifiedAt             time.Time              `json:"last_verified_at" db:"last_verified_at"`
	CreatedAt                  time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt                  time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt                  *time.Time             `json:"deleted_at,omitempty" db:"deleted_at"`
}

// CreateConfiguration creates a new crypto configuration record
func (s *CryptoConfigurationService) CreateConfiguration(
	tenantID, assetID uuid.UUID,
	protocol string,
	configuredCipherSuites []string,
	configuredProtocolVersions []string,
	source, discoveryMethod string,
	deviceID *uuid.UUID,
) (*CryptoConfiguration, error) {
	insertQuery := `
		INSERT INTO crypto_configurations (
			tenant_id, asset_id, device_id, protocol,
			configured_cipher_suites, configured_protocol_versions,
			algorithm_preferences, source, discovery_method,
			confidence_score, discovered_at, last_verified_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW(), NOW(), NOW()
		) RETURNING id, discovered_at, last_verified_at, created_at, updated_at
	`

	var configID uuid.UUID
	var discoveredAt, lastVerifiedAt, createdAt, updatedAt time.Time

	algorithmPreferencesJSON, _ := json.Marshal(map[string]interface{}{})
	confidenceScore := 1.0

	// RLS-scoped write over crypto_configurations — WithTenantTx sets app.tenant_id
	// so the INSERT's tenant_id satisfies the policy WITH CHECK.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(
			insertQuery,
			tenantID, assetID, deviceID, protocol,
			pq.Array(configuredCipherSuites), pq.Array(configuredProtocolVersions),
			algorithmPreferencesJSON, source, discoveryMethod,
			confidenceScore,
		).Scan(&configID, &discoveredAt, &lastVerifiedAt, &createdAt, &updatedAt)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create crypto configuration: %w", err)
	}

	return &CryptoConfiguration{
		ID:                         configID,
		TenantID:                   tenantID,
		AssetID:                    assetID,
		DeviceID:                   deviceID,
		Protocol:                   protocol,
		ConfiguredCipherSuites:     configuredCipherSuites,
		ConfiguredProtocolVersions: configuredProtocolVersions,
		AlgorithmPreferences:       map[string]interface{}{},
		Source:                     source,
		DiscoveryMethod:            discoveryMethod,
		ConfidenceScore:            confidenceScore,
		DiscoveredAt:               discoveredAt,
		LastVerifiedAt:             lastVerifiedAt,
		CreatedAt:                  createdAt,
		UpdatedAt:                  updatedAt,
	}, nil
}

// GetConfigurationsByAsset retrieves all configurations for an asset
func (s *CryptoConfigurationService) GetConfigurationsByAsset(
	tenantID, assetID uuid.UUID,
) ([]CryptoConfiguration, error) {
	query := `
		SELECT
			id, tenant_id, asset_id, device_id, protocol,
			configured_cipher_suites, configured_protocol_versions,
			algorithm_preferences, source, discovery_method,
			confidence_score, discovered_at, last_verified_at,
			created_at, updated_at, deleted_at
		FROM crypto_configurations
		WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL
		ORDER BY discovered_at DESC
	`

	var configurations []CryptoConfiguration
	// RLS-scoped read over crypto_configurations.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.Queryx(query, tenantID, assetID)
		if err != nil {
			return fmt.Errorf("failed to query configurations: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var config CryptoConfiguration
			var deviceID sql.NullString
			var deletedAt sql.NullTime
			var algorithmPreferencesJSON sql.NullString
			var cipherSuites, protocolVersions pq.StringArray

			err := rows.Scan(
				&config.ID, &config.TenantID, &config.AssetID, &deviceID, &config.Protocol,
				&cipherSuites, &protocolVersions,
				&algorithmPreferencesJSON, &config.Source, &config.DiscoveryMethod,
				&config.ConfidenceScore, &config.DiscoveredAt, &config.LastVerifiedAt,
				&config.CreatedAt, &config.UpdatedAt, &deletedAt,
			)
			if err != nil {
				continue
			}

			if deviceID.Valid {
				if id, err := uuid.Parse(deviceID.String); err == nil {
					config.DeviceID = &id
				}
			}
			if deletedAt.Valid {
				config.DeletedAt = &deletedAt.Time
			}
			if algorithmPreferencesJSON.Valid {
				_ = json.Unmarshal([]byte(algorithmPreferencesJSON.String), &config.AlgorithmPreferences)
			}
			config.ConfiguredCipherSuites = []string(cipherSuites)
			config.ConfiguredProtocolVersions = []string(protocolVersions)

			configurations = append(configurations, config)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return configurations, nil
}
