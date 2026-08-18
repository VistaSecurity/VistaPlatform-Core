package aws

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// Authentication modes for an AWS integration's `config` JSONB.
//
// An ABSENT or empty auth_mode means AuthModeAccessKey — every integration row
// written before assume-role support existed carries no auth_mode at all, and
// must keep behaving exactly as it did.
const (
	AuthModeAccessKey  = "access_key"
	AuthModeAssumeRole = "assume_role"
)

// DefaultRoleSessionName is used when the integration does not name one. It has
// to be stable and identifying: it is what shows up in the customer's CloudTrail
// as the principal that read their account.
const DefaultRoleSessionName = "vistaplatform-discovery"

// DefaultRegion is used when neither the integration row nor its config names one.
const DefaultRegion = "us-east-1"

// SensitiveConfigKeys is the canonical list of AWS integration config keys that
// are stored ENCRYPTED. It is the single source of truth for the encrypt,
// decrypt and mask paths — the handler package appends its non-AWS keys to this
// slice rather than maintaining a second copy that can drift.
//
// assume_role_arn is deliberately NOT here: a role ARN is not a secret and the
// UI displays it. external_id IS here: it is a shared secret between us and the
// customer's role trust policy, and possession of it is half of the assume-role
// authorization decision.
var SensitiveConfigKeys = []string{
	"access_key_id",
	"secret_access_key",
	"session_token",
	"external_id",
}

// legacyPlaintextConfigKeys names the sensitive keys that were stored in
// PLAINTEXT before they were classified as sensitive. Rows written before that
// change still hold a plaintext value, so a decrypt failure on one of these is
// expected and falls back to treating the stored value as plaintext.
//
// This tolerance is scoped to exactly these keys on purpose. A decrypt failure
// on access_key_id / secret_access_key / session_token has never had a benign
// explanation and must still hard-fail — silently handing AWS a base64 blob as
// a secret key would turn a key-management bug into an unexplained auth error.
var legacyPlaintextConfigKeys = map[string]bool{
	"external_id": true,
}

// Client handles AWS API interactions for device interrogation
type Client struct {
	config        aws.Config
	accountID     string
	region        string
	integrationID uuid.UUID
}

// CredentialConfig is the credential-relevant projection of an AWS integration's
// decrypted `config` JSONB. It is what both the discovery path (NewClient) and
// the "Test Connection" path build their aws.Config from, so a green connection
// test proves the discovery path will authenticate the same way.
type CredentialConfig struct {
	AuthMode        string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	AssumeRoleARN   string
	ExternalID      string
	RoleSessionName string
	Region          string
}

// CredentialConfigFromMap projects a decrypted config map onto CredentialConfig.
func CredentialConfigFromMap(config map[string]interface{}) CredentialConfig {
	get := func(key string) string {
		v, ok := config[key]
		if !ok || v == nil {
			return ""
		}
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return CredentialConfig{
		AuthMode:        get("auth_mode"),
		AccessKeyID:     get("access_key_id"),
		SecretAccessKey: get("secret_access_key"),
		SessionToken:    get("session_token"),
		AssumeRoleARN:   get("assume_role_arn"),
		ExternalID:      get("external_id"),
		RoleSessionName: get("role_session_name"),
		Region:          get("region"),
	}
}

// ResolvedAuthMode normalizes AuthMode. Absent or empty means access_key.
func (c CredentialConfig) ResolvedAuthMode() string {
	if c.AuthMode == "" {
		return AuthModeAccessKey
	}
	return c.AuthMode
}

// HasStaticKeys reports whether a static access key pair is configured.
func (c CredentialConfig) HasStaticKeys() bool {
	return c.AccessKeyID != "" && c.SecretAccessKey != ""
}

// ResolvedRoleSessionName returns the configured session name or the default.
func (c CredentialConfig) ResolvedRoleSessionName() string {
	if c.RoleSessionName == "" {
		return DefaultRoleSessionName
	}
	return c.RoleSessionName
}

// Validate checks the credential fields the resolved auth mode actually needs.
//
// access_key mode requires BOTH keys (unchanged from before assume-role existed).
// assume_role mode requires assume_role_arn and requires NEITHER key — static
// keys are optional there and only decide which credential source the STS
// AssumeRole call itself is signed with.
func (c CredentialConfig) Validate() error {
	switch c.ResolvedAuthMode() {
	case AuthModeAccessKey:
		if c.AccessKeyID == "" {
			return fmt.Errorf("missing access_key_id in AWS integration")
		}
		if c.SecretAccessKey == "" {
			return fmt.Errorf("missing secret_access_key in AWS integration")
		}
	case AuthModeAssumeRole:
		if c.AssumeRoleARN == "" {
			return fmt.Errorf("missing assume_role_arn in AWS integration (auth_mode=assume_role)")
		}
	default:
		return fmt.Errorf("unsupported auth_mode %q (expected %q or %q)",
			c.AuthMode, AuthModeAccessKey, AuthModeAssumeRole)
	}
	return nil
}

// ValidateConfigMap validates a decrypted AWS integration config map. It is the
// single source of truth for what an AWS integration must carry, shared by the
// handler's create/update validation and by client construction.
func ValidateConfigMap(config map[string]interface{}) error {
	return CredentialConfigFromMap(config).Validate()
}

// assumeRoleOptions builds the stscreds option func for an assume-role config.
//
// ExternalID is set only when non-empty. A non-nil pointer to an empty string is
// NOT the same as omitting it: the SDK would then send ExternalId="" on the
// AssumeRole call, which AWS rejects for roles whose trust policy does not
// require an external id.
func assumeRoleOptions(c CredentialConfig) func(*stscreds.AssumeRoleOptions) {
	return func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = c.ResolvedRoleSessionName()
		if c.ExternalID != "" {
			o.ExternalID = aws.String(c.ExternalID)
		}
	}
}

// buildBaseConfig loads the aws.Config that credentials are resolved from.
//
// When static access keys are present they are used verbatim — including the
// session token, which is what makes temporary STS credentials work. When they
// are absent (only legal in assume_role mode) the SDK's ambient default chain is
// used: environment, shared config, IRSA web identity, IMDS.
func buildBaseConfig(ctx context.Context, c CredentialConfig) (aws.Config, error) {
	region := c.Region
	if region == "" {
		region = DefaultRegion
	}

	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if c.HasStaticKeys() {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				c.AccessKeyID,
				c.SecretAccessKey,
				c.SessionToken,
			),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to create AWS config: %w", err)
	}
	return cfg, nil
}

// BuildAWSConfig turns a decrypted integration credential config into an
// aws.Config. This is the ONE place AWS credentials are assembled; every caller
// (discovery, connection test) goes through it so a passing test proves the
// discovery path.
func BuildAWSConfig(ctx context.Context, c CredentialConfig) (aws.Config, error) {
	if err := c.Validate(); err != nil {
		return aws.Config{}, err
	}

	base, err := buildBaseConfig(ctx, c)
	if err != nil {
		return aws.Config{}, err
	}

	if c.ResolvedAuthMode() != AuthModeAssumeRole {
		return base, nil
	}

	// Chain: assume the customer's role using whatever the base config resolved
	// to — the configured static keys when present, otherwise the ambient chain
	// (env / IRSA / IMDS).
	provider := stscreds.NewAssumeRoleProvider(
		sts.NewFromConfig(base),
		c.AssumeRoleARN,
		assumeRoleOptions(c),
	)

	cfg := base
	cfg.Credentials = aws.NewCredentialsCache(provider)
	return cfg, nil
}

// DecryptConfigMap decrypts the sensitive fields of a stored AWS integration
// config. Non-sensitive fields are passed through untouched.
//
// Fields in legacyPlaintextConfigKeys fall back to the stored value on decrypt
// failure (rows predating their reclassification hold plaintext). Every other
// sensitive field hard-fails, so a genuine key-management problem surfaces as
// such instead of being handed to AWS as a credential.
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
			if legacyPlaintextConfigKeys[key] {
				// Written before this key was classified sensitive.
				decrypted[key] = raw
				continue
			}
			return nil, fmt.Errorf("failed to decrypt %s: %w", key, err)
		}
		decrypted[key] = plain
	}

	return decrypted, nil
}

// NewClient creates a new AWS client from platform integration credentials.
//
// RLS: the integration lookup is by id and must resolve BOTH tenant-scoped
// (tenant_id = caller) AND platform-level/shared (tenant_id IS NULL) integration
// rows. Because the policy `tenant_id = NULLIF(current_setting('app.tenant_id', true), ”)::uuid`
// excludes NULL-tenant rows, this read runs on the BYPASSRLS connection — the
// integration id was already authorized by the tenant-scoped discovery flow that
// created the job. Pre-flip bypassDB resolves to the same connection as db.
func NewClient(ctx context.Context, bypassDB *sql.DB, integrationID uuid.UUID, masterKey string) (*Client, error) {
	// Load integration from database (supports both platform-level and tenant-scoped integrations)
	query := `
		SELECT config, account_id, region
		FROM platform_integrations
		WHERE id = $1 AND integration_type = 'aws' AND is_active = true AND deleted_at IS NULL
	`

	var configJSON string
	var accountID sql.NullString
	var region sql.NullString

	err := bypassDB.QueryRowContext(ctx, query, integrationID).Scan(&configJSON, &accountID, &region)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("AWS integration not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS integration: %w", err)
	}

	// Decrypt credentials
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	var encryptedConfig map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &encryptedConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AWS integration config: %w", err)
	}

	decrypted, err := DecryptConfigMap(enc, encryptedConfig)
	if err != nil {
		return nil, err
	}

	credCfg := CredentialConfigFromMap(toAnyMap(decrypted))

	// The integration row's region column wins over the config's; fall back to
	// the config value, then the default.
	if region.String != "" {
		credCfg.Region = region.String
	}
	if credCfg.Region == "" {
		credCfg.Region = DefaultRegion
	}

	cfg, err := BuildAWSConfig(ctx, credCfg)
	if err != nil {
		return nil, err
	}

	return &Client{
		config:        cfg,
		accountID:     accountID.String,
		region:        credCfg.Region,
		integrationID: integrationID,
	}, nil
}

func toAnyMap(m map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// GetELBClient returns an ELB v2 client
func (c *Client) GetELBClient() *elasticloadbalancingv2.Client {
	return elasticloadbalancingv2.NewFromConfig(c.config)
}

// GetAPIGatewayClient returns an API Gateway v2 client
func (c *Client) GetAPIGatewayClient() *apigatewayv2.Client {
	return apigatewayv2.NewFromConfig(c.config)
}

// GetCloudFrontClient returns a CloudFront client
func (c *Client) GetCloudFrontClient() *cloudfront.Client {
	return cloudfront.NewFromConfig(c.config)
}

// GetACMClient returns an ACM (Certificate Manager) client
func (c *Client) GetACMClient() *acm.Client {
	return acm.NewFromConfig(c.config)
}

// GetKMSClient returns a KMS client
func (c *Client) GetKMSClient() *kms.Client {
	return kms.NewFromConfig(c.config)
}

// GetAccountID returns the AWS account ID
func (c *Client) GetAccountID() string {
	return c.accountID
}

// GetRegion returns the AWS region
func (c *Client) GetRegion() string {
	return c.region
}

// GetIntegrationID returns the platform integration ID
func (c *Client) GetIntegrationID() uuid.UUID {
	return c.integrationID
}

// GetConfig returns the AWS config (for creating region-specific clients)
func (c *Client) GetConfig() aws.Config {
	return c.config
}
