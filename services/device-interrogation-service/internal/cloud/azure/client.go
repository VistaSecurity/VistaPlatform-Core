package azure

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// Client handles Azure API interactions for device interrogation
type Client struct {
	subscriptionID string
	credential     *azidentity.ClientSecretCredential
	integrationID  uuid.UUID
}

// NewClient creates a new Azure client from platform integration credentials.
//
// RLS: integration lookup by id must resolve both tenant-scoped and shared
// (tenant_id IS NULL) integrations, which the RLS policy excludes — so it runs on
// the BYPASSRLS connection (the integration id was authorized upstream by the
// tenant-scoped flow). Pre-flip bypassDB resolves to the same connection as db.
func NewClient(ctx context.Context, bypassDB *sql.DB, integrationID uuid.UUID, masterKey string) (*Client, error) {
	// Load integration from database
	query := `
		SELECT config, account_id, region
		FROM platform_integrations
		WHERE id = $1 AND integration_type = 'azure' AND is_active = true AND deleted_at IS NULL
	`

	var configJSON string
	var subscriptionID sql.NullString
	var region sql.NullString

	err := bypassDB.QueryRowContext(ctx, query, integrationID).Scan(&configJSON, &subscriptionID, &region)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no Azure integration found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load Azure integration: %w", err)
	}

	// Decrypt credentials
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	var encryptedConfig map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &encryptedConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Azure integration config: %w", err)
	}

	// Decrypt sensitive fields
	sensitiveKeys := []string{"client_id", "client_secret", "tenant_id", "subscription_id"}
	decrypted := make(map[string]string)

	for key, value := range encryptedConfig {
		raw := ""
		switch v := value.(type) {
		case string:
			raw = v
		case nil:
			continue
		default:
			raw = fmt.Sprintf("%v", v)
		}

		if raw == "" {
			continue
		}

		// Check if this is a sensitive key
		isSensitive := false
		for _, sk := range sensitiveKeys {
			if key == sk {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			plain, err := enc.Decrypt(raw)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt %s: %w", key, err)
			}
			decrypted[key] = plain
		} else {
			decrypted[key] = raw
		}
	}

	clientID := decrypted["client_id"]
	if clientID == "" {
		return nil, fmt.Errorf("missing client_id in Azure integration")
	}

	clientSecret := decrypted["client_secret"]
	if clientSecret == "" {
		return nil, fmt.Errorf("missing client_secret in Azure integration")
	}

	tenantID := decrypted["tenant_id"]
	if tenantID == "" {
		return nil, fmt.Errorf("missing tenant_id in Azure integration")
	}

	// Use subscription ID from integration or decrypted config
	subID := subscriptionID.String
	if subID == "" {
		subID = decrypted["subscription_id"]
	}
	if subID == "" {
		return nil, fmt.Errorf("missing subscription_id in Azure integration")
	}

	// Create Azure credential
	credential, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	return &Client{
		subscriptionID: subID,
		credential:     credential,
		integrationID:  integrationID,
	}, nil
}

// GetApplicationGatewayClient returns an Application Gateway client
func (c *Client) GetApplicationGatewayClient() (*armnetwork.ApplicationGatewaysClient, error) {
	client, err := armnetwork.NewApplicationGatewaysClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Application Gateway client: %w", err)
	}
	return client, nil
}

// GetLoadBalancerClient returns a Load Balancer client
func (c *Client) GetLoadBalancerClient() (*armnetwork.LoadBalancersClient, error) {
	client, err := armnetwork.NewLoadBalancersClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Load Balancer client: %w", err)
	}
	return client, nil
}

// GetKeyVaultVaultsClient returns a Key Vault management (vaults) client.
func (c *Client) GetKeyVaultVaultsClient() (*armkeyvault.VaultsClient, error) {
	client, err := armkeyvault.NewVaultsClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Vault vaults client: %w", err)
	}
	return client, nil
}

// GetKeyVaultKeysClient returns a Key Vault keys (management-plane) client.
func (c *Client) GetKeyVaultKeysClient() (*armkeyvault.KeysClient, error) {
	client, err := armkeyvault.NewKeysClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Vault keys client: %w", err)
	}
	return client, nil
}

// GetStorageAccountsClient returns a Storage account management client.
func (c *Client) GetStorageAccountsClient() (*armstorage.AccountsClient, error) {
	client, err := armstorage.NewAccountsClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Storage accounts client: %w", err)
	}
	return client, nil
}

// GetSQLServersClient returns a SQL servers management client.
func (c *Client) GetSQLServersClient() (*armsql.ServersClient, error) {
	client, err := armsql.NewServersClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL servers client: %w", err)
	}
	return client, nil
}

// GetSQLDatabasesClient returns a SQL databases management client.
func (c *Client) GetSQLDatabasesClient() (*armsql.DatabasesClient, error) {
	client, err := armsql.NewDatabasesClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL databases client: %w", err)
	}
	return client, nil
}

// GetSQLEncryptionProtectorsClient returns a SQL server encryption-protector
// client (reports TDE service-managed vs Azure Key Vault CMK per server).
func (c *Client) GetSQLEncryptionProtectorsClient() (*armsql.EncryptionProtectorsClient, error) {
	client, err := armsql.NewEncryptionProtectorsClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL encryption protectors client: %w", err)
	}
	return client, nil
}

// GetSubscriptionID returns the Azure subscription ID
func (c *Client) GetSubscriptionID() string {
	return c.subscriptionID
}
