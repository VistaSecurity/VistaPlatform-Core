package aws

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// Client handles AWS API interactions for device interrogation
type Client struct {
	config        aws.Config
	accountID     string
	region        string
	integrationID uuid.UUID
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

	// Decrypt sensitive fields
	sensitiveKeys := []string{"access_key_id", "secret_access_key", "session_token"}
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

	accessKeyID := decrypted["access_key_id"]
	if accessKeyID == "" {
		return nil, fmt.Errorf("missing access_key_id in AWS integration")
	}

	secretAccessKey := decrypted["secret_access_key"]
	if secretAccessKey == "" {
		return nil, fmt.Errorf("missing secret_access_key in AWS integration")
	}

	// Use region from integration or default
	awsRegion := region.String
	if awsRegion == "" {
		if r, exists := decrypted["region"]; exists && r != "" {
			awsRegion = r
		} else {
			awsRegion = "us-east-1" // Default
		}
	}

	// Create AWS config
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(awsRegion),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			accessKeyID,
			secretAccessKey,
			"", // Session token if needed
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %w", err)
	}

	return &Client{
		config:        cfg,
		accountID:     accountID.String,
		region:        awsRegion,
		integrationID: integrationID,
	}, nil
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
