package gcp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

const (
	computeBaseURL  = "https://compute.googleapis.com/compute/v1"
	cloudKMSBaseURL = "https://cloudkms.googleapis.com/v1"
	storageBaseURL  = "https://storage.googleapis.com/storage/v1"
	sqlAdminBaseURL = "https://sqladmin.googleapis.com/v1"
	tokenURL        = "https://oauth2.googleapis.com/token"
	// cloud-platform.read-only grants read access across Compute, Cloud KMS,
	// Cloud Storage and Cloud SQL — the read-only superset this discovery client
	// needs. It supersedes the narrower compute.readonly scope.
	tokenScope = "https://www.googleapis.com/auth/cloud-platform.read-only"
)

// ServiceAccountKey represents a GCP service account key JSON file
type ServiceAccountKey struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	TokenURI     string `json:"token_uri"`
}

// Client handles GCP API interactions for device interrogation
type Client struct {
	projectID     string
	credentials   []byte
	serviceKey    *ServiceAccountKey
	integrationID uuid.UUID
	httpClient    *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

// NewClient creates a new GCP client from platform integration credentials.
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
		WHERE id = $1 AND integration_type = 'gcp' AND is_active = true AND deleted_at IS NULL
	`

	var configJSON string
	var projectID sql.NullString
	var region sql.NullString

	err := bypassDB.QueryRowContext(ctx, query, integrationID).Scan(&configJSON, &projectID, &region)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("GCP integration not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load GCP integration: %w", err)
	}

	// Decrypt credentials
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	var encryptedConfig map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &encryptedConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GCP integration config: %w", err)
	}

	// Decrypt sensitive fields
	sensitiveKeys := []string{"service_account_key", "credentials_json", "service_account_json"}
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

	// Get service account key JSON (try all known field names)
	credentialsJSON := decrypted["service_account_key"]
	if credentialsJSON == "" {
		credentialsJSON = decrypted["credentials_json"]
	}
	if credentialsJSON == "" {
		credentialsJSON = decrypted["service_account_json"]
	}
	if credentialsJSON == "" {
		return nil, fmt.Errorf("missing service account credentials in GCP integration")
	}

	// Parse the service account key
	var serviceKey ServiceAccountKey
	if err := json.Unmarshal([]byte(credentialsJSON), &serviceKey); err != nil {
		return nil, fmt.Errorf("invalid service account key JSON: %w", err)
	}

	if serviceKey.Type != "service_account" {
		return nil, fmt.Errorf("credentials type must be 'service_account', got '%s'", serviceKey.Type)
	}

	if serviceKey.PrivateKey == "" || serviceKey.ClientEmail == "" {
		return nil, fmt.Errorf("service account key missing required fields (private_key, client_email)")
	}

	// Use project ID from integration config, then service account key
	projID := projectID.String
	if projID == "" {
		if pid, ok := decrypted["project_id"]; ok && pid != "" {
			projID = pid
		}
	}
	if projID == "" {
		projID = serviceKey.ProjectID
	}
	if projID == "" {
		return nil, fmt.Errorf("missing project_id in GCP integration")
	}

	return &Client{
		projectID:     projID,
		credentials:   []byte(credentialsJSON),
		serviceKey:    &serviceKey,
		integrationID: integrationID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// getAccessToken returns a valid access token, refreshing if expired
func (c *Client) getAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (with 60s buffer)
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return c.accessToken, nil
	}

	// Parse the private key
	block, _ := pem.Decode([]byte(c.serviceKey.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("failed to decode private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	// Create JWT assertion
	now := time.Now()
	tokenURI := c.serviceKey.TokenURI
	if tokenURI == "" {
		tokenURI = tokenURL
	}

	claims := jwt.MapClaims{
		"iss":   c.serviceKey.ClientEmail,
		"scope": tokenScope,
		"aud":   tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedJWT, err := token.SignedString(rsaKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Exchange JWT for access token
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signedJWT},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request access token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed (%d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return c.accessToken, nil
}

// doRequest performs an authenticated GET request to the GCP Compute API
func (c *Client) doRequest(ctx context.Context, urlPath string) ([]byte, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed (%d): %s", resp.StatusCode, truncateBody(body))
	}

	return body, nil
}

// ValidateCredentials validates credentials by calling the GCP projects API
func (c *Client) ValidateCredentials(ctx context.Context) error {
	// Validate service account key structure
	var creds map[string]interface{}
	if err := json.Unmarshal(c.credentials, &creds); err != nil {
		return fmt.Errorf("invalid credentials JSON: %w", err)
	}

	requiredFields := []string{"type", "project_id", "private_key_id", "private_key", "client_email"}
	for _, field := range requiredFields {
		if _, ok := creds[field]; !ok {
			return fmt.Errorf("missing required field in credentials: %s", field)
		}
	}

	// Try to get an access token — this validates the private key and service account
	_, err := c.getAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("credential validation failed: %w", err)
	}

	// Verify project access by listing SSL policies (lightweight call)
	apiURL := fmt.Sprintf("%s/projects/%s/global/sslPolicies?maxResults=1", computeBaseURL, c.projectID)
	_, err = c.doRequest(ctx, apiURL)
	if err != nil {
		// Check if it's a permissions issue vs invalid project
		if strings.Contains(err.Error(), "403") {
			return fmt.Errorf("service account lacks compute.viewer permissions on project %s", c.projectID)
		}
		if strings.Contains(err.Error(), "404") {
			return fmt.Errorf("project %s not found or Compute Engine API not enabled", c.projectID)
		}
		return fmt.Errorf("failed to validate project access: %w", err)
	}

	return nil
}

// ListTargetHTTPSProxies lists all target HTTPS proxies in the project
func (c *Client) ListTargetHTTPSProxies(ctx context.Context) ([]TargetHTTPSProxy, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/global/targetHttpsProxies", computeBaseURL, c.projectID)

	var allProxies []TargetHTTPSProxy
	for apiURL != "" {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list target HTTPS proxies: %w", err)
		}

		var resp targetHTTPSProxyListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse target HTTPS proxies response: %w", err)
		}
		allProxies = append(allProxies, resp.Items...)
		apiURL = resp.NextPageToken
		if apiURL != "" {
			apiURL = fmt.Sprintf("%s/projects/%s/global/targetHttpsProxies?pageToken=%s", computeBaseURL, c.projectID, apiURL)
		}
	}
	return allProxies, nil
}

// ListTargetSSLProxies lists all target SSL proxies in the project
func (c *Client) ListTargetSSLProxies(ctx context.Context) ([]TargetSSLProxy, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/global/targetSslProxies", computeBaseURL, c.projectID)

	var allProxies []TargetSSLProxy
	for apiURL != "" {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list target SSL proxies: %w", err)
		}

		var resp targetSSLProxyListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse target SSL proxies response: %w", err)
		}
		allProxies = append(allProxies, resp.Items...)
		apiURL = resp.NextPageToken
		if apiURL != "" {
			apiURL = fmt.Sprintf("%s/projects/%s/global/targetSslProxies?pageToken=%s", computeBaseURL, c.projectID, apiURL)
		}
	}
	return allProxies, nil
}

// GetSSLPolicy retrieves an SSL policy by its full resource URL or name
func (c *Client) GetSSLPolicy(ctx context.Context, policyRef string) (*SSLPolicy, error) {
	// policyRef can be a full URL or just a name
	var apiURL string
	if strings.HasPrefix(policyRef, "https://") {
		apiURL = policyRef
	} else {
		apiURL = fmt.Sprintf("%s/projects/%s/global/sslPolicies/%s", computeBaseURL, c.projectID, policyRef)
	}

	body, err := c.doRequest(ctx, apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSL policy: %w", err)
	}

	var policy SSLPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse SSL policy: %w", err)
	}
	return &policy, nil
}

// ListSSLCertificates lists all global SSL certificates in the project
func (c *Client) ListSSLCertificates(ctx context.Context) ([]SSLCertificate, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/global/sslCertificates", computeBaseURL, c.projectID)

	var allCerts []SSLCertificate
	for apiURL != "" {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list SSL certificates: %w", err)
		}

		var resp sslCertificateListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse SSL certificates response: %w", err)
		}
		allCerts = append(allCerts, resp.Items...)
		apiURL = resp.NextPageToken
		if apiURL != "" {
			apiURL = fmt.Sprintf("%s/projects/%s/global/sslCertificates?pageToken=%s", computeBaseURL, c.projectID, apiURL)
		}
	}
	return allCerts, nil
}

// GetSSLCertificate retrieves an SSL certificate by URL or name
func (c *Client) GetSSLCertificate(ctx context.Context, certRef string) (*SSLCertificate, error) {
	var apiURL string
	if strings.HasPrefix(certRef, "https://") {
		apiURL = certRef
	} else {
		apiURL = fmt.Sprintf("%s/projects/%s/global/sslCertificates/%s", computeBaseURL, c.projectID, certRef)
	}

	body, err := c.doRequest(ctx, apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSL certificate: %w", err)
	}

	var cert SSLCertificate
	if err := json.Unmarshal(body, &cert); err != nil {
		return nil, fmt.Errorf("failed to parse SSL certificate: %w", err)
	}
	return &cert, nil
}

// ListGlobalForwardingRules lists all global forwarding rules in the project
func (c *Client) ListGlobalForwardingRules(ctx context.Context) ([]ForwardingRule, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/global/forwardingRules", computeBaseURL, c.projectID)

	var allRules []ForwardingRule
	for apiURL != "" {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list global forwarding rules: %w", err)
		}

		var resp forwardingRuleListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse forwarding rules response: %w", err)
		}
		allRules = append(allRules, resp.Items...)
		apiURL = resp.NextPageToken
		if apiURL != "" {
			apiURL = fmt.Sprintf("%s/projects/%s/global/forwardingRules?pageToken=%s", computeBaseURL, c.projectID, apiURL)
		}
	}
	return allRules, nil
}

// ListKMSLocations lists the Cloud KMS locations available to the project.
func (c *Client) ListKMSLocations(ctx context.Context) ([]KMSLocation, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/locations", cloudKMSBaseURL, c.projectID)

	var all []KMSLocation
	for apiURL != "" {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list KMS locations: %w", err)
		}
		var resp kmsLocationListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse KMS locations response: %w", err)
		}
		all = append(all, resp.Locations...)
		apiURL = ""
		if resp.NextPageToken != "" {
			apiURL = fmt.Sprintf("%s/projects/%s/locations?pageToken=%s", cloudKMSBaseURL, c.projectID, resp.NextPageToken)
		}
	}
	return all, nil
}

// ListKeyRings lists the key rings in a Cloud KMS location.
func (c *Client) ListKeyRings(ctx context.Context, location string) ([]KMSKeyRing, error) {
	base := fmt.Sprintf("%s/projects/%s/locations/%s/keyRings", cloudKMSBaseURL, c.projectID, location)
	apiURL := base

	var all []KMSKeyRing
	for apiURL != "" {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list key rings in %s: %w", location, err)
		}
		var resp kmsKeyRingListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse key rings response: %w", err)
		}
		all = append(all, resp.KeyRings...)
		apiURL = ""
		if resp.NextPageToken != "" {
			apiURL = fmt.Sprintf("%s?pageToken=%s", base, resp.NextPageToken)
		}
	}
	return all, nil
}

// ListCryptoKeys lists the crypto keys in a key ring. keyRingName is the full
// resource name (projects/{p}/locations/{loc}/keyRings/{kr}).
func (c *Client) ListCryptoKeys(ctx context.Context, keyRingName string) ([]KMSCryptoKey, error) {
	base := fmt.Sprintf("%s/%s/cryptoKeys", cloudKMSBaseURL, keyRingName)
	apiURL := base

	var all []KMSCryptoKey
	for apiURL != "" {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list crypto keys in %s: %w", keyRingName, err)
		}
		var resp kmsCryptoKeyListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse crypto keys response: %w", err)
		}
		all = append(all, resp.CryptoKeys...)
		apiURL = ""
		if resp.NextPageToken != "" {
			apiURL = fmt.Sprintf("%s?pageToken=%s", base, resp.NextPageToken)
		}
	}
	return all, nil
}

// ListStorageBuckets lists the Cloud Storage buckets in the project, including
// each bucket's default encryption configuration.
func (c *Client) ListStorageBuckets(ctx context.Context) ([]StorageBucket, error) {
	base := fmt.Sprintf("%s/b?project=%s", storageBaseURL, url.QueryEscape(c.projectID))
	apiURL := base

	var all []StorageBucket
	for apiURL != "" {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list storage buckets: %w", err)
		}
		var resp storageBucketListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse storage buckets response: %w", err)
		}
		all = append(all, resp.Items...)
		apiURL = ""
		if resp.NextPageToken != "" {
			apiURL = fmt.Sprintf("%s&pageToken=%s", base, url.QueryEscape(resp.NextPageToken))
		}
	}
	return all, nil
}

// ListSQLInstances lists the Cloud SQL instances in the project.
func (c *Client) ListSQLInstances(ctx context.Context) ([]SQLInstance, error) {
	base := fmt.Sprintf("%s/projects/%s/instances", sqlAdminBaseURL, c.projectID)
	apiURL := base

	var all []SQLInstance
	for apiURL != "" {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cloud SQL instances: %w", err)
		}
		var resp sqlInstanceListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse Cloud SQL instances response: %w", err)
		}
		all = append(all, resp.Items...)
		apiURL = ""
		if resp.NextPageToken != "" {
			apiURL = fmt.Sprintf("%s?pageToken=%s", base, url.QueryEscape(resp.NextPageToken))
		}
	}
	return all, nil
}

// GetServiceAccountEmail returns the service account email from credentials
func (c *Client) GetServiceAccountEmail() (string, error) {
	return c.serviceKey.ClientEmail, nil
}

// GetProjectID returns the GCP project ID
func (c *Client) GetProjectID() string {
	return c.projectID
}

// GetIntegrationID returns the integration UUID
func (c *Client) GetIntegrationID() uuid.UUID {
	return c.integrationID
}

// GetCredentials returns the service account credentials JSON
func (c *Client) GetCredentials() []byte {
	return c.credentials
}

// truncateBody truncates API error bodies for logging
func truncateBody(body []byte) string {
	s := string(body)
	if len(s) > 500 {
		return s[:500] + "..."
	}
	return s
}
