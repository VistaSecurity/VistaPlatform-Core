package azure

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/cloudcredentials"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// Client handles Azure API interactions for device interrogation
type Client struct {
	subscriptionID string
	credential     *azidentity.ClientSecretCredential
	integrationID  uuid.UUID
	// armOptions is nil in every production path (Azure public cloud, the
	// SDK's own transport). WithCloud sets it so a test can point the whole
	// client — token and ARM calls alike — at a local server.
	armOptions *arm.ClientOptions
}

// Option adjusts where a Client reaches Azure. Production passes none.
type Option func(*clientOptions)

type clientOptions struct {
	cloud     *cloud.Configuration
	transport policy.Transporter
}

// WithCloud points the credential's token requests and every ARM client at
// cfg over transport. It exists for tests that stand up a local Microsoft
// Entra token endpoint and ARM endpoint; it changes WHERE the client connects,
// never HOW it authenticates, so a connection test built with it still runs
// the same credential construction discovery does.
func WithCloud(cfg cloud.Configuration, transport policy.Transporter) Option {
	return func(o *clientOptions) {
		o.cloud = &cfg
		o.transport = transport
	}
}

// SensitiveConfigKeys is the canonical list of Azure integration config keys
// that are stored ENCRYPTED. It is the single source of truth for the encrypt,
// decrypt and mask paths: the handler package builds its list from this slice
// rather than keeping a second copy that can drift.
//
// tenant_id and subscription_id are deliberately NOT here. A directory (tenant)
// ID and a subscription ID are identifiers, not credentials, and the
// integrations UI renders them as plain fields. They used to be on this
// (client-side) list but never on the handler's, so every integration saved
// through the UI stored them in plaintext and then failed here with
// "illegal base64" on every run: Azure discovery never executed.
//
// client_id stays: every existing row holds it encrypted, and dropping it here
// would hand Azure a ciphertext as the application ID.
//
// The list itself lives in shared/cloudcredentials so admin-service's
// platform-integration writer uses the same one.
var SensitiveConfigKeys = cloudcredentials.Azure

// DecryptConfigMap decrypts the sensitive fields of a stored Azure integration
// config. Non-sensitive fields are passed through untouched; a decrypt failure
// on a sensitive field is a hard error, so a key-management problem surfaces as
// such rather than as an unexplained Azure authentication failure.
func DecryptConfigMap(enc *encryption.Service, config map[string]interface{}) (map[string]string, error) {
	sensitive := make(map[string]bool, len(SensitiveConfigKeys))
	for _, k := range SensitiveConfigKeys {
		sensitive[k] = true
	}

	decrypted := make(map[string]string, len(config))
	for key, value := range config {
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
		if !sensitive[key] {
			decrypted[key] = raw
			continue
		}
		plain, err := enc.Decrypt(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt %s: %w", key, err)
		}
		decrypted[key] = plain
	}
	return decrypted, nil
}

// NewClient creates a new Azure client from platform integration credentials.
//
// RLS: integration lookup by id must resolve both tenant-scoped and shared
// (tenant_id IS NULL) integrations, which the RLS policy excludes — so it runs on
// the BYPASSRLS connection (the integration id was authorized upstream by the
// tenant-scoped flow). Pre-flip bypassDB resolves to the same connection as db.
func NewClient(ctx context.Context, bypassDB *sql.DB, integrationID uuid.UUID, masterKey string, opts ...Option) (*Client, error) {
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

	return NewClientFromStoredConfig(integrationID, configJSON, subscriptionID.String, masterKey, opts...)
}

// NewClientFromStoredConfig builds a Client from an integration row's stored
// (encrypted-at-rest) config JSON and its account_id column. NewClient is this
// plus the row lookup; it is split out so a test can feed it exactly what the
// integrations handler writes and prove the two agree on what is encrypted.
func NewClientFromStoredConfig(integrationID uuid.UUID, configJSON, accountSubscriptionID, masterKey string, opts ...Option) (*Client, error) {
	var o clientOptions
	for _, opt := range opts {
		opt(&o)
	}

	enc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	var encryptedConfig map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &encryptedConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Azure integration config: %w", err)
	}

	decrypted, err := DecryptConfigMap(enc, encryptedConfig)
	if err != nil {
		return nil, err
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

	// Use subscription ID from the integration row, then the config.
	subID := accountSubscriptionID
	if subID == "" {
		subID = decrypted["subscription_id"]
	}
	if subID == "" {
		return nil, fmt.Errorf("missing subscription_id in Azure integration")
	}

	// Create Azure credential
	var credOpts *azidentity.ClientSecretCredentialOptions
	var armOpts *arm.ClientOptions
	if o.cloud != nil {
		core := azcore.ClientOptions{Cloud: *o.cloud, Transport: o.transport}
		// Instance discovery only knows Microsoft's own authorities; a
		// non-public authority host is exactly the case the SDK documents
		// this switch for.
		credOpts = &azidentity.ClientSecretCredentialOptions{ClientOptions: core, DisableInstanceDiscovery: true}
		armOpts = &arm.ClientOptions{ClientOptions: core}
	}
	credential, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, credOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	return &Client{
		subscriptionID: subID,
		credential:     credential,
		integrationID:  integrationID,
		armOptions:     armOpts,
	}, nil
}

// SubscriptionCheck is what a connection test learned about the configured
// subscription.
type SubscriptionCheck struct {
	SubscriptionID string
	DisplayName    string
	State          string
}

// subscriptionsAPIVersion is the ARM Subscriptions API version the check uses.
const subscriptionsAPIVersion = "2022-12-01"

// CheckSubscription proves the integration can do what discovery does first:
// obtain a token with the configured client credentials (a client-credentials
// exchange with Microsoft Entra ID) and read the configured subscription from
// Azure Resource Manager. It is the cheapest ARM call that exercises both the
// credential and the subscription binding — a GET on the subscription itself,
// which any role assignment on the subscription (Reader included) permits.
//
// Errors are returned as the SDK produced them; the caller projects them onto
// something safe to show (they can quote the provider's response).
func (c *Client) CheckSubscription(ctx context.Context) (SubscriptionCheck, error) {
	cl, err := arm.NewClient("vistaplatform/device-interrogation-service", "v1.0.0", c.credential, c.armOptions)
	if err != nil {
		return SubscriptionCheck{}, fmt.Errorf("failed to create ARM client: %w", err)
	}
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(cl.Endpoint(), "subscriptions", url.PathEscape(c.subscriptionID)))
	if err != nil {
		return SubscriptionCheck{}, fmt.Errorf("failed to build subscription request: %w", err)
	}
	q := req.Raw().URL.Query()
	q.Set("api-version", subscriptionsAPIVersion)
	req.Raw().URL.RawQuery = q.Encode()
	req.Raw().Header.Set("Accept", "application/json")

	resp, err := cl.Pipeline().Do(req)
	if err != nil {
		return SubscriptionCheck{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return SubscriptionCheck{}, runtime.NewResponseError(resp)
	}
	var body struct {
		SubscriptionID string `json:"subscriptionId"`
		DisplayName    string `json:"displayName"`
		State          string `json:"state"`
	}
	if err := runtime.UnmarshalAsJSON(resp, &body); err != nil {
		return SubscriptionCheck{}, fmt.Errorf("unreadable subscription response: %w", err)
	}
	if body.SubscriptionID == "" {
		body.SubscriptionID = c.subscriptionID
	}
	return SubscriptionCheck{SubscriptionID: body.SubscriptionID, DisplayName: body.DisplayName, State: body.State}, nil
}

// GetApplicationGatewayClient returns an Application Gateway client
func (c *Client) GetApplicationGatewayClient() (*armnetwork.ApplicationGatewaysClient, error) {
	client, err := armnetwork.NewApplicationGatewaysClient(c.subscriptionID, c.credential, c.armOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create Application Gateway client: %w", err)
	}
	return client, nil
}

// GetLoadBalancerClient returns a Load Balancer client
func (c *Client) GetLoadBalancerClient() (*armnetwork.LoadBalancersClient, error) {
	client, err := armnetwork.NewLoadBalancersClient(c.subscriptionID, c.credential, c.armOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create Load Balancer client: %w", err)
	}
	return client, nil
}

// GetKeyVaultVaultsClient returns a Key Vault management (vaults) client.
func (c *Client) GetKeyVaultVaultsClient() (*armkeyvault.VaultsClient, error) {
	client, err := armkeyvault.NewVaultsClient(c.subscriptionID, c.credential, c.armOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Vault vaults client: %w", err)
	}
	return client, nil
}

// GetKeyVaultKeysClient returns a Key Vault keys (management-plane) client.
func (c *Client) GetKeyVaultKeysClient() (*armkeyvault.KeysClient, error) {
	client, err := armkeyvault.NewKeysClient(c.subscriptionID, c.credential, c.armOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Vault keys client: %w", err)
	}
	return client, nil
}

// GetStorageAccountsClient returns a Storage account management client.
func (c *Client) GetStorageAccountsClient() (*armstorage.AccountsClient, error) {
	client, err := armstorage.NewAccountsClient(c.subscriptionID, c.credential, c.armOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create Storage accounts client: %w", err)
	}
	return client, nil
}

// GetSQLServersClient returns a SQL servers management client.
func (c *Client) GetSQLServersClient() (*armsql.ServersClient, error) {
	client, err := armsql.NewServersClient(c.subscriptionID, c.credential, c.armOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL servers client: %w", err)
	}
	return client, nil
}

// GetSQLDatabasesClient returns a SQL databases management client.
func (c *Client) GetSQLDatabasesClient() (*armsql.DatabasesClient, error) {
	client, err := armsql.NewDatabasesClient(c.subscriptionID, c.credential, c.armOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL databases client: %w", err)
	}
	return client, nil
}

// GetSQLEncryptionProtectorsClient returns a SQL server encryption-protector
// client (reports TDE service-managed vs Azure Key Vault CMK per server).
func (c *Client) GetSQLEncryptionProtectorsClient() (*armsql.EncryptionProtectorsClient, error) {
	client, err := armsql.NewEncryptionProtectorsClient(c.subscriptionID, c.credential, c.armOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL encryption protectors client: %w", err)
	}
	return client, nil
}

// GetSubscriptionID returns the Azure subscription ID
func (c *Client) GetSubscriptionID() string {
	return c.subscriptionID
}
