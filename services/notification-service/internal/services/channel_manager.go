package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// ChannelManager handles CRUD operations for notification channels
type ChannelManager struct {
	db            *sqlx.DB
	config        *config.Config
	emailResolver *email.EmailConfigResolver
	logger        *log.Logger
	cipher        *credentials.Cipher
}

// NewChannelManager creates a new channel manager.
//
// A notification channel's config is a credential store: a Slack incoming
// webhook URL is a bearer credential, PagerDuty's integration_key is an API
// key, and a generic webhook channel carries arbitrary auth headers. Every
// read decrypts and every write encrypts via cm.cipher — see decodeConfig /
// encodeConfig, which are the ONLY places this file touches the config JSON.
func NewChannelManager(db *sqlx.DB, cfg *config.Config, emailResolver *email.EmailConfigResolver) *ChannelManager {
	logger := log.New(log.Writer(), "[ChannelManager] ", log.LstdFlags)
	cipher, err := credentials.NewCipher("notification channel", cfg.EncryptionMasterKey, credentials.NotificationChannelPolicy)
	if err != nil {
		// A non-empty but unusable master key is a misconfiguration, not a dev
		// fallback. Degrade to passthrough rather than taking the service down,
		// but say so at the loudest level available here.
		logger.Printf("ERROR: credential encryption unavailable (%v) — channel credentials will be stored unencrypted", err)
		cipher = nil
	}
	return &ChannelManager{
		db:            db,
		config:        cfg,
		emailResolver: emailResolver,
		logger:        logger,
		cipher:        cipher,
	}
}

// decodeConfig unmarshals a channel's config column and decrypts its
// credential fields. A malformed blob yields an empty map (preserving the
// prior behavior — a bad row must not take down a channel listing), but a
// decrypt failure is logged: it means a tagged ciphertext would not open,
// which is a key problem an operator needs to see, not a missing field.
func (cm *ChannelManager) decodeConfig(configJSON []byte) map[string]interface{} {
	var cfg map[string]interface{}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return make(map[string]interface{})
	}
	decrypted, err := cm.cipher.DecryptMap(cfg)
	if err != nil {
		cm.logger.Printf("ERROR: failed to decrypt channel config: %v", err)
		return make(map[string]interface{})
	}
	if decrypted == nil {
		return make(map[string]interface{})
	}
	return decrypted
}

// encodeConfig encrypts a channel config's credential fields and marshals it
// for storage. Encryption is idempotent, so a read-modify-write cycle that
// never decrypted a field cannot double-encrypt it.
func (cm *ChannelManager) encodeConfig(cfg map[string]interface{}) ([]byte, error) {
	encrypted, err := cm.cipher.EncryptMap(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt channel config: %w", err)
	}
	out, err := json.Marshal(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	return out, nil
}

// GetTenantChannels gets all channels for a tenant
func (cm *ChannelManager) GetTenantChannels(ctx context.Context, tenantID uuid.UUID) ([]models.TenantNotificationChannel, error) {
	var channels []models.TenantNotificationChannel
	query := `
		SELECT id, tenant_id, channel_name, channel_type, config, enabled,
		       test_status, last_test_at, last_used_at, description,
		       created_by, created_at, updated_at
		FROM tenant_notification_channels
		WHERE tenant_id = $1
		ORDER BY channel_name ASC
	`

	// RLS-scoped: tenant_notification_channels carries a tenant_isolation policy.
	err := shareddatabase.WithTenantTx(ctx, cm.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, tenantID)
		if qErr != nil {
			return fmt.Errorf("failed to query tenant channels: %w", qErr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var channel models.TenantNotificationChannel
			var configJSON []byte
			var testStatus, description sql.NullString
			var lastTestAt, lastUsedAt sql.NullTime
			var createdBy sql.NullString

			err := rows.Scan(
				&channel.ID, &channel.TenantID, &channel.ChannelName, &channel.ChannelType,
				&configJSON, &channel.Enabled, &testStatus, &lastTestAt, &lastUsedAt,
				&description, &createdBy, &channel.CreatedAt, &channel.UpdatedAt,
			)
			if err != nil {
				continue
			}

			channel.Config = cm.decodeConfig(configJSON)

			if testStatus.Valid {
				channel.TestStatus = &testStatus.String
			}
			if lastTestAt.Valid {
				channel.LastTestAt = &lastTestAt.Time
			}
			if lastUsedAt.Valid {
				channel.LastUsedAt = &lastUsedAt.Time
			}
			if description.Valid {
				channel.Description = &description.String
			}
			if createdBy.Valid {
				if id, err := uuid.Parse(createdBy.String); err == nil {
					channel.CreatedBy = &id
				}
			}

			channels = append(channels, channel)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return channels, nil
}

// GetTenantChannelByID gets a specific tenant channel by ID
func (cm *ChannelManager) GetTenantChannelByID(ctx context.Context, tenantID, channelID uuid.UUID) (*models.TenantNotificationChannel, error) {
	var channel models.TenantNotificationChannel
	var configJSON []byte
	var testStatus, description sql.NullString
	var lastTestAt, lastUsedAt sql.NullTime
	var createdBy sql.NullString

	query := `
		SELECT id, tenant_id, channel_name, channel_type, config, enabled,
		       test_status, last_test_at, last_used_at, description,
		       created_by, created_at, updated_at
		FROM tenant_notification_channels
		WHERE id = $1 AND tenant_id = $2
	`

	// RLS-scoped: tenant_notification_channels carries a tenant_isolation policy.
	found := false
	err := shareddatabase.WithTenantTx(ctx, cm.db.DB, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, channelID, tenantID).Scan(
			&channel.ID, &channel.TenantID, &channel.ChannelName, &channel.ChannelType,
			&configJSON, &channel.Enabled, &testStatus, &lastTestAt, &lastUsedAt,
			&description, &createdBy, &channel.CreatedAt, &channel.UpdatedAt,
		)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get channel: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("channel not found")
	}

	channel.Config = cm.decodeConfig(configJSON)

	if testStatus.Valid {
		channel.TestStatus = &testStatus.String
	}
	if lastTestAt.Valid {
		channel.LastTestAt = &lastTestAt.Time
	}
	if lastUsedAt.Valid {
		channel.LastUsedAt = &lastUsedAt.Time
	}
	if description.Valid {
		channel.Description = &description.String
	}
	if createdBy.Valid {
		if id, err := uuid.Parse(createdBy.String); err == nil {
			channel.CreatedBy = &id
		}
	}

	return &channel, nil
}

// GetTenantChannelsByIDs gets multiple tenant channels by their IDs
func (cm *ChannelManager) GetTenantChannelsByIDs(ctx context.Context, tenantID uuid.UUID, channelIDs []uuid.UUID) ([]models.TenantNotificationChannel, error) {
	if len(channelIDs) == 0 {
		return []models.TenantNotificationChannel{}, nil
	}

	query, args, err := sqlx.In(`
		SELECT id, tenant_id, channel_name, channel_type, config, enabled,
		       test_status, last_test_at, last_used_at, description,
		       created_by, created_at, updated_at
		FROM tenant_notification_channels
		WHERE tenant_id = ? AND id IN (?)
		ORDER BY channel_name ASC
	`, tenantID, channelIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	query = cm.db.Rebind(query)

	// RLS-scoped: tenant_notification_channels carries a tenant_isolation policy.
	var channels []models.TenantNotificationChannel
	err = shareddatabase.WithTenantTx(ctx, cm.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, args...)
		if qErr != nil {
			return fmt.Errorf("failed to query channels: %w", qErr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var channel models.TenantNotificationChannel
			var configJSON []byte
			var testStatus, description sql.NullString
			var lastTestAt, lastUsedAt sql.NullTime
			var createdBy sql.NullString

			err := rows.Scan(
				&channel.ID, &channel.TenantID, &channel.ChannelName, &channel.ChannelType,
				&configJSON, &channel.Enabled, &testStatus, &lastTestAt, &lastUsedAt,
				&description, &createdBy, &channel.CreatedAt, &channel.UpdatedAt,
			)
			if err != nil {
				continue
			}

			channel.Config = cm.decodeConfig(configJSON)

			if testStatus.Valid {
				channel.TestStatus = &testStatus.String
			}
			if lastTestAt.Valid {
				channel.LastTestAt = &lastTestAt.Time
			}
			if lastUsedAt.Valid {
				channel.LastUsedAt = &lastUsedAt.Time
			}
			if description.Valid {
				channel.Description = &description.String
			}
			if createdBy.Valid {
				if id, err := uuid.Parse(createdBy.String); err == nil {
					channel.CreatedBy = &id
				}
			}

			channels = append(channels, channel)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return channels, nil
}

// CreateTenantChannel creates a new tenant channel
func (cm *ChannelManager) CreateTenantChannel(ctx context.Context, tenantID uuid.UUID, req *models.CreateChannelRequest, createdBy *uuid.UUID) (*models.TenantNotificationChannel, error) {
	configJSON, err := cm.encodeConfig(req.Config)
	if err != nil {
		return nil, err
	}

	channel := models.TenantNotificationChannel{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ChannelName: req.ChannelName,
		ChannelType: req.ChannelType,
		Config:      req.Config,
		Enabled:     req.Enabled,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if req.Description != nil {
		channel.Description = req.Description
	}

	query := `
		INSERT INTO tenant_notification_channels (
			id, tenant_id, channel_name, channel_type, config, enabled,
			description, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW()
		)
	`

	// RLS-scoped write: WithTenantTx sets app.tenant_id so the INSERT's tenant_id
	// satisfies the policy's WITH CHECK.
	err = shareddatabase.WithTenantTx(ctx, cm.db.DB, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			channel.ID, channel.TenantID, channel.ChannelName, channel.ChannelType,
			configJSON, channel.Enabled, channel.Description, channel.CreatedBy,
		)
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create channel: %w", err)
	}

	return &channel, nil
}

// UpdateTenantChannel updates a tenant channel
func (cm *ChannelManager) UpdateTenantChannel(ctx context.Context, tenantID, channelID uuid.UUID, req *models.UpdateChannelRequest, updatedBy *uuid.UUID) (*models.TenantNotificationChannel, error) {
	// Get existing channel
	channel, err := cm.GetTenantChannelByID(ctx, tenantID, channelID)
	if err != nil {
		return nil, err
	}

	// Update fields
	if req.ChannelName != nil {
		channel.ChannelName = *req.ChannelName
	}
	if req.Config != nil {
		channel.Config = req.Config
	}
	if req.Enabled != nil {
		channel.Enabled = *req.Enabled
	}
	if req.Description != nil {
		channel.Description = req.Description
	}
	channel.UpdatedAt = time.Now()

	configJSON, err := cm.encodeConfig(channel.Config)
	if err != nil {
		return nil, err
	}

	query := `
		UPDATE tenant_notification_channels
		SET channel_name = $1, config = $2, enabled = $3,
		    description = $4, updated_at = NOW()
		WHERE id = $5 AND tenant_id = $6
	`

	// RLS-scoped write: the USING + WITH CHECK confine the UPDATE to the caller's tenant.
	err = shareddatabase.WithTenantTx(ctx, cm.db.DB, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			channel.ChannelName, configJSON, channel.Enabled,
			channel.Description, channelID, tenantID,
		)
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update channel: %w", err)
	}

	return channel, nil
}

// DeleteTenantChannel deletes a tenant channel
func (cm *ChannelManager) DeleteTenantChannel(ctx context.Context, tenantID, channelID uuid.UUID) error {
	query := `DELETE FROM tenant_notification_channels WHERE id = $1 AND tenant_id = $2`
	// RLS-scoped: the policy's USING clause confines the DELETE to the caller's tenant.
	err := shareddatabase.WithTenantTx(ctx, cm.db.DB, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, channelID, tenantID)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to delete channel: %w", err)
	}
	return nil
}

// TestTenantChannel tests a tenant channel connectivity
func (cm *ChannelManager) TestTenantChannel(ctx context.Context, tenantID, channelID uuid.UUID) error {
	channel, err := cm.GetTenantChannelByID(ctx, tenantID, channelID)
	if err != nil {
		return err
	}

	// Use delivery service to send test notification
	testReq := &models.SendNotificationRequest{
		TenantID:         &tenantID,
		AlertSource:      "system",
		AlertType:        "test",
		Severity:         "info",
		Message:          "Test notification",
		NotificationType: "system",
		Metadata:         map[string]interface{}{"test": true},
	}

	// Create a test delivery service instance
	deliveryService := NewDeliveryService(cm.db, cm.config, cm.emailResolver)

	// Test the channel
	err = deliveryService.TestChannel(ctx, channel, testReq)

	// Update test status
	testStatus := "success"
	if err != nil {
		testStatus = "failed"
		cm.logger.Printf("Channel test failed: %v", err)
	}

	query := `
		UPDATE tenant_notification_channels
		SET test_status = $1, last_test_at = NOW()
		WHERE id = $2 AND tenant_id = $3
	`
	// RLS-scoped write: the policy confines the UPDATE to the caller's tenant.
	updateErr := shareddatabase.WithTenantTx(ctx, cm.db.DB, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, testStatus, channelID, tenantID)
		return e
	})
	if updateErr != nil {
		cm.logger.Printf("Failed to update test status: %v", updateErr)
	}

	return err
}

// Platform channel methods (similar structure but no tenant_id)

// GetPlatformChannels gets all platform channels
func (cm *ChannelManager) GetPlatformChannels() ([]models.PlatformNotificationChannel, error) {
	var channels []models.PlatformNotificationChannel
	query := `
		SELECT id, channel_name, channel_type, config, enabled,
		       test_status, last_test_at, last_used_at, description,
		       created_by, created_at, updated_at, updated_by
		FROM platform_notification_channels
		ORDER BY channel_name ASC
	`

	rows, err := cm.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query platform channels: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var channel models.PlatformNotificationChannel
		var configJSON []byte
		var testStatus, description sql.NullString
		var lastTestAt, lastUsedAt sql.NullTime
		var createdBy, updatedBy sql.NullString

		err := rows.Scan(
			&channel.ID, &channel.ChannelName, &channel.ChannelType,
			&configJSON, &channel.Enabled, &testStatus, &lastTestAt, &lastUsedAt,
			&description, &createdBy, &channel.CreatedAt, &channel.UpdatedAt, &updatedBy,
		)
		if err != nil {
			continue
		}

		channel.Config = cm.decodeConfig(configJSON)

		if testStatus.Valid {
			channel.TestStatus = &testStatus.String
		}
		if lastTestAt.Valid {
			channel.LastTestAt = &lastTestAt.Time
		}
		if lastUsedAt.Valid {
			channel.LastUsedAt = &lastUsedAt.Time
		}
		if description.Valid {
			channel.Description = &description.String
		}
		if createdBy.Valid {
			if id, err := uuid.Parse(createdBy.String); err == nil {
				channel.CreatedBy = &id
			}
		}
		if updatedBy.Valid {
			if id, err := uuid.Parse(updatedBy.String); err == nil {
				channel.UpdatedBy = &id
			}
		}

		channels = append(channels, channel)
	}

	return channels, nil
}

// GetPlatformChannelByID gets a specific platform channel by ID
func (cm *ChannelManager) GetPlatformChannelByID(channelID uuid.UUID) (*models.PlatformNotificationChannel, error) {
	var channel models.PlatformNotificationChannel
	var configJSON []byte
	var testStatus, description sql.NullString
	var lastTestAt, lastUsedAt sql.NullTime
	var createdBy, updatedBy sql.NullString

	query := `
		SELECT id, channel_name, channel_type, config, enabled,
		       test_status, last_test_at, last_used_at, description,
		       created_by, created_at, updated_at, updated_by
		FROM platform_notification_channels
		WHERE id = $1
	`

	err := cm.db.QueryRow(query, channelID).Scan(
		&channel.ID, &channel.ChannelName, &channel.ChannelType,
		&configJSON, &channel.Enabled, &testStatus, &lastTestAt, &lastUsedAt,
		&description, &createdBy, &channel.CreatedAt, &channel.UpdatedAt, &updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("channel not found")
		}
		return nil, fmt.Errorf("failed to get channel: %w", err)
	}

	channel.Config = cm.decodeConfig(configJSON)

	if testStatus.Valid {
		channel.TestStatus = &testStatus.String
	}
	if lastTestAt.Valid {
		channel.LastTestAt = &lastTestAt.Time
	}
	if lastUsedAt.Valid {
		channel.LastUsedAt = &lastUsedAt.Time
	}
	if description.Valid {
		channel.Description = &description.String
	}
	if createdBy.Valid {
		if id, err := uuid.Parse(createdBy.String); err == nil {
			channel.CreatedBy = &id
		}
	}
	if updatedBy.Valid {
		if id, err := uuid.Parse(updatedBy.String); err == nil {
			channel.UpdatedBy = &id
		}
	}

	return &channel, nil
}

// GetPlatformChannelsByIDs gets multiple platform channels by their IDs
func (cm *ChannelManager) GetPlatformChannelsByIDs(channelIDs []uuid.UUID) ([]models.PlatformNotificationChannel, error) {
	if len(channelIDs) == 0 {
		return []models.PlatformNotificationChannel{}, nil
	}

	query, args, err := sqlx.In(`
		SELECT id, channel_name, channel_type, config, enabled,
		       test_status, last_test_at, last_used_at, description,
		       created_by, created_at, updated_at, updated_by
		FROM platform_notification_channels
		WHERE id IN (?)
		ORDER BY channel_name ASC
	`, channelIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	query = cm.db.Rebind(query)
	rows, err := cm.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query channels: %w", err)
	}
	defer rows.Close()

	var channels []models.PlatformNotificationChannel
	for rows.Next() {
		var channel models.PlatformNotificationChannel
		var configJSON []byte
		var testStatus, description sql.NullString
		var lastTestAt, lastUsedAt sql.NullTime
		var createdBy, updatedBy sql.NullString

		err := rows.Scan(
			&channel.ID, &channel.ChannelName, &channel.ChannelType,
			&configJSON, &channel.Enabled, &testStatus, &lastTestAt, &lastUsedAt,
			&description, &createdBy, &channel.CreatedAt, &channel.UpdatedAt, &updatedBy,
		)
		if err != nil {
			continue
		}

		channel.Config = cm.decodeConfig(configJSON)

		if testStatus.Valid {
			channel.TestStatus = &testStatus.String
		}
		if lastTestAt.Valid {
			channel.LastTestAt = &lastTestAt.Time
		}
		if lastUsedAt.Valid {
			channel.LastUsedAt = &lastUsedAt.Time
		}
		if description.Valid {
			channel.Description = &description.String
		}
		if createdBy.Valid {
			if id, err := uuid.Parse(createdBy.String); err == nil {
				channel.CreatedBy = &id
			}
		}
		if updatedBy.Valid {
			if id, err := uuid.Parse(updatedBy.String); err == nil {
				channel.UpdatedBy = &id
			}
		}

		channels = append(channels, channel)
	}

	return channels, nil
}

// CreatePlatformChannel creates a new platform channel
func (cm *ChannelManager) CreatePlatformChannel(req *models.CreateChannelRequest, createdBy *uuid.UUID) (*models.PlatformNotificationChannel, error) {
	configJSON, err := cm.encodeConfig(req.Config)
	if err != nil {
		return nil, err
	}

	channel := models.PlatformNotificationChannel{
		ID:          uuid.New(),
		ChannelName: req.ChannelName,
		ChannelType: req.ChannelType,
		Config:      req.Config,
		Enabled:     req.Enabled,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if req.Description != nil {
		channel.Description = req.Description
	}

	query := `
		INSERT INTO platform_notification_channels (
			id, channel_name, channel_type, config, enabled,
			description, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, NOW(), NOW()
		)
	`

	_, err = cm.db.Exec(query,
		channel.ID, channel.ChannelName, channel.ChannelType,
		configJSON, channel.Enabled, channel.Description, channel.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel: %w", err)
	}

	return &channel, nil
}

// UpdatePlatformChannel updates a platform channel
func (cm *ChannelManager) UpdatePlatformChannel(channelID uuid.UUID, req *models.UpdateChannelRequest, updatedBy *uuid.UUID) (*models.PlatformNotificationChannel, error) {
	channel, err := cm.GetPlatformChannelByID(channelID)
	if err != nil {
		return nil, err
	}

	if req.ChannelName != nil {
		channel.ChannelName = *req.ChannelName
	}
	if req.Config != nil {
		channel.Config = req.Config
	}
	if req.Enabled != nil {
		channel.Enabled = *req.Enabled
	}
	if req.Description != nil {
		channel.Description = req.Description
	}
	channel.UpdatedAt = time.Now()
	channel.UpdatedBy = updatedBy

	configJSON, err := cm.encodeConfig(channel.Config)
	if err != nil {
		return nil, err
	}

	query := `
		UPDATE platform_notification_channels
		SET channel_name = $1, config = $2, enabled = $3,
		    description = $4, updated_at = NOW(), updated_by = $5
		WHERE id = $6
	`

	_, err = cm.db.Exec(query,
		channel.ChannelName, configJSON, channel.Enabled,
		channel.Description, updatedBy, channelID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update channel: %w", err)
	}

	return channel, nil
}

// DeletePlatformChannel deletes a platform channel
func (cm *ChannelManager) DeletePlatformChannel(channelID uuid.UUID) error {
	query := `DELETE FROM platform_notification_channels WHERE id = $1`
	_, err := cm.db.Exec(query, channelID)
	if err != nil {
		return fmt.Errorf("failed to delete channel: %w", err)
	}
	return nil
}

// TestPlatformChannel tests a platform channel connectivity
func (cm *ChannelManager) TestPlatformChannel(ctx context.Context, channelID uuid.UUID) error {
	channel, err := cm.GetPlatformChannelByID(channelID)
	if err != nil {
		return err
	}

	testReq := &models.SendNotificationRequest{
		TenantID:         nil, // Platform notification
		AlertSource:      "system",
		AlertType:        "test",
		Severity:         "info",
		Message:          "Test notification",
		NotificationType: "system",
		Metadata:         map[string]interface{}{"test": true},
	}

	deliveryService := NewDeliveryService(cm.db, cm.config, cm.emailResolver)
	err = deliveryService.TestChannel(ctx, channel, testReq)

	testStatus := "success"
	if err != nil {
		testStatus = "failed"
		cm.logger.Printf("Channel test failed: %v", err)
	}

	// platform_notification_channels has no RLS policy — global table, no tenant context.
	query := `
		UPDATE platform_notification_channels
		SET test_status = $1, last_test_at = NOW()
		WHERE id = $2
	`
	_, updateErr := cm.db.ExecContext(ctx, query, testStatus, channelID)
	if updateErr != nil {
		cm.logger.Printf("Failed to update test status: %v", updateErr)
	}

	return err
}
