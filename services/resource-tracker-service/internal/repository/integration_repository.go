package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// AWSIntegrationCredentials represents decrypted credentials for an AWS integration.
type AWSIntegrationCredentials struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Region       string
	AccountID    string
}

// IntegrationRepository loads platform integration credentials for downstream services.
type IntegrationRepository struct {
	db  *sql.DB
	enc *encryption.Service
	log *logrus.Logger
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used only by the
	// `// RLS: cross-tenant` platform-bootstrap lookups in this repository.
	bypassDB *sql.DB
}

// NewIntegrationRepository creates a repository capable of decrypting integration credentials.
func NewIntegrationRepository(db, bypassDB *sql.DB, masterKey string, log *logrus.Logger) (*IntegrationRepository, error) {
	if masterKey == "" {
		return nil, fmt.Errorf("ENCRYPTION_MASTER_KEY is required to read platform integrations")
	}

	enc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	return &IntegrationRepository{
		db:       db,
		enc:      enc,
		log:      log,
		bypassDB: bypassDB,
	}, nil
}

// GetLatestAWSIntegration returns the most recently updated active AWS integration.
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). This loads the
// platform-level AWS credential the cost-sync job runs under: it has no caller
// tenant (the query carries no tenant_id filter and selects the newest active
// integration platform-wide). Although platform_integrations is RLS-scoped, this
// platform-bootstrap lookup is assigned to bypassDB, not WithTenantTx.
func (r *IntegrationRepository) GetLatestAWSIntegration(ctx context.Context) (*AWSIntegrationCredentials, error) {
	query := `
		SELECT integration_name, config, account_id, region
		FROM platform_integrations
		WHERE integration_type = 'aws'
		  AND is_active = true
		  AND deleted_at IS NULL
		ORDER BY updated_at DESC
		LIMIT 1
	`

	var integrationName string
	var configJSON string
	var accountID sql.NullString
	var region sql.NullString

	err := r.bypassDB.QueryRowContext(ctx, query).Scan(&integrationName, &configJSON, &accountID, &region)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no active AWS platform integration found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS integration: %w", err)
	}

	var encryptedConfig map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &encryptedConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AWS integration config: %w", err)
	}

	decrypted, err := r.decryptConfig(encryptedConfig)
	if err != nil {
		return nil, err
	}

	creds := &AWSIntegrationCredentials{
		AccessKey:    decrypted["access_key_id"],
		SecretKey:    decrypted["secret_access_key"],
		SessionToken: decrypted["session_token"],
		Region:       region.String,
		AccountID:    accountID.String,
	}

	if creds.Region == "" {
		creds.Region = decrypted["region"]
	}

	if creds.AccessKey == "" || creds.SecretKey == "" {
		return nil, fmt.Errorf("AWS integration '%s' is missing access keys", integrationName)
	}

	return creds, nil
}

func (r *IntegrationRepository) decryptConfig(config map[string]interface{}) (map[string]string, error) {
	sensitiveKeys := []string{"access_key_id", "secret_access_key", "session_token", "api_token", "api_key", "password", "client_secret"}
	decrypted := make(map[string]string)

	for key, value := range config {
		raw := stringValue(value)
		if raw == "" {
			continue
		}

		if slices.Contains(sensitiveKeys, key) {
			plain, err := r.enc.Decrypt(raw)
			if err != nil {
				r.log.WithError(err).WithField("field", key).Error("Failed to decrypt integration credential")
				return nil, fmt.Errorf("failed to decrypt %s: %w", key, err)
			}
			decrypted[key] = plain
		} else {
			decrypted[key] = raw
		}
	}

	return decrypted, nil
}

func stringValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}
}
