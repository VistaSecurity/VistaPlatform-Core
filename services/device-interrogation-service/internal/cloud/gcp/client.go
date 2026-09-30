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
	"github.com/vistasecurity/vistaplatform/shared/cloudcredentials"
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

	// computeBaseOverride replaces computeBaseURL for the enumeration calls.
	// Empty in every production path — NewClient never sets it — and set only
	// by a test pointing one client at a recorded-response server.
	computeBaseOverride string
	// tokenURLOverride replaces the token endpoint, and apiBaseOverride the
	// Cloud KMS, Cloud Storage and Cloud SQL Admin bases. Same rule: empty in
	// production, set only through WithEndpoints by a test.
	tokenURLOverride string
	apiBaseOverride  string

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
func NewClient(ctx context.Context, bypassDB *sql.DB, integrationID uuid.UUID, masterKey string, opts ...Option) (*Client, error) {
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

	return NewClientFromStoredConfig(integrationID, configJSON, projectID.String, masterKey, opts...)
}

// SensitiveConfigKeys is the canonical list of GCP integration config keys that
// are stored ENCRYPTED — the three names a service-account key JSON has been
// accepted under. It is the single source of truth for the encrypt, decrypt and
// mask paths: the handler package builds its list from this slice. The handler
// used to encrypt only service_account_json while its validator also accepted
// service_account_key and credentials_json, so an integration created under
// either of those names was stored in plaintext and then failed to decrypt here.
//
// The list itself lives in shared/cloudcredentials so admin-service's
// platform-integration writer uses the same one.
var SensitiveConfigKeys = cloudcredentials.GCP

// DecryptConfigMap decrypts the sensitive fields of a stored GCP integration
// config. Non-sensitive fields are passed through untouched; a decrypt failure
// on a sensitive field is a hard error.
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

// NewClientFromStoredConfig builds a Client from an integration row's stored
// (encrypted-at-rest) config JSON and its account_id column. NewClient is this
// plus the row lookup; it is split out so a test can feed it exactly what the
// integrations handler writes and prove the two agree on what is encrypted.
func NewClientFromStoredConfig(integrationID uuid.UUID, configJSON, accountProjectID, masterKey string, opts ...Option) (*Client, error) {
	c, err := newClientFromStoredConfig(integrationID, configJSON, accountProjectID, masterKey)
	if err != nil {
		return nil, err
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Option adjusts where a Client reaches Google. Production passes none.
type Option func(*Client)

// WithEndpoints points the token exchange and every Google API this client
// calls at a local server over hc. It exists for tests; it changes WHERE the
// client connects, never how it signs its assertion, so a test built with it
// runs the same credential construction discovery does.
func WithEndpoints(hc *http.Client, tokenEndpoint, apiBase string) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
		c.tokenURLOverride = tokenEndpoint
		c.computeBaseOverride = apiBase
		c.apiBaseOverride = apiBase
	}
}

// apiBase is def unless a test pointed the client elsewhere.
func (c *Client) apiBase(def string) string {
	if strings.TrimSpace(c.apiBaseOverride) != "" {
		return strings.TrimRight(c.apiBaseOverride, "/")
	}
	return def
}

func newClientFromStoredConfig(integrationID uuid.UUID, configJSON, accountProjectID, masterKey string) (*Client, error) {
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	var encryptedConfig map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &encryptedConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GCP integration config: %w", err)
	}

	decrypted, err := DecryptConfigMap(enc, encryptedConfig)
	if err != nil {
		return nil, err
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
	projID := accountProjectID
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
	tokenURI, err := c.tokenEndpoint()
	if err != nil {
		return "", err
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
		return "", newTokenError(resp.StatusCode, body)
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
		return nil, newAPIError(resp.StatusCode, body)
	}

	return body, nil
}

// googleTokenHosts are the hosts a service-account key's token_uri may name.
// Every key Google issues says https://oauth2.googleapis.com/token; older keys
// say accounts.google.com. The key is tenant-supplied JSON, and the platform
// POSTs a signed assertion to whatever it names and — through Test
// Connection — reports what came back, so an arbitrary URL there would turn
// the integration into a request the platform makes on the tenant's behalf.
var googleTokenHosts = map[string]bool{
	"oauth2.googleapis.com": true,
	"accounts.google.com":   true,
}

// tokenEndpoint is where the JWT assertion is exchanged: the key's token_uri
// when it names a Google OAuth host over https, Google's default when it names
// none, and an error otherwise.
func (c *Client) tokenEndpoint() (string, error) {
	if c.tokenURLOverride != "" {
		return c.tokenURLOverride, nil
	}
	raw := strings.TrimSpace(c.serviceKey.TokenURI)
	if raw == "" {
		return tokenURL, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !googleTokenHosts[strings.ToLower(u.Hostname())] || u.Port() != "" {
		return "", fmt.Errorf("the service account key's token_uri is not a Google OAuth endpoint; use the key file exactly as Google issued it")
	}
	return raw, nil
}

// TokenError is a refused token exchange: the OAuth error code and
// description Google returned, never the raw body.
type TokenError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *TokenError) Error() string {
	msg := fmt.Sprintf("token request failed (%d)", e.StatusCode)
	if e.Code != "" {
		msg += ": " + e.Code
	}
	if e.Description != "" {
		msg += ": " + e.Description
	}
	return msg
}

func newTokenError(status int, body []byte) *TokenError {
	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &parsed)
	return &TokenError{StatusCode: status, Code: parsed.Error, Description: parsed.ErrorDescription}
}

// APIError is a non-200 answer from a Google API. Error() keeps the historical
// text (status and a bounded body) so existing log lines and status-code
// checks read the same; Status and Message are Google's structured error, for
// callers that show it to a user.
type APIError struct {
	StatusCode int
	Status     string
	Message    string
	body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API request failed (%d): %s", e.StatusCode, e.body)
}

func newAPIError(status int, body []byte) *APIError {
	var parsed struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	return &APIError{StatusCode: status, Status: parsed.Error.Status, Message: parsed.Error.Message, body: truncateBody(body)}
}

// ProjectCheck is what a connection test learned: who the key authenticated
// as, and the project it read.
type ProjectCheck struct {
	ProjectID      string
	ServiceAccount string
}

// Stages of CheckProject, carried on its error.
const (
	CheckStageToken   = "token"
	CheckStageProject = "project"
)

// CheckError says which step of CheckProject failed.
type CheckError struct {
	Stage string
	Err   error
}

func (e *CheckError) Error() string { return e.Stage + ": " + e.Err.Error() }
func (e *CheckError) Unwrap() error { return e.Err }

// CheckProject proves the integration can do what discovery does first:
// exchange the service-account key for an access token (the JWT-bearer grant
// discovery uses) and read the configured project through the Compute API —
// listing at most one SSL policy, the cheapest read in the permission set the
// load-balancer collectors need (roles/compute.viewer).
func (c *Client) CheckProject(ctx context.Context) (ProjectCheck, error) {
	out := ProjectCheck{ProjectID: c.projectID, ServiceAccount: c.serviceKey.ClientEmail}
	if _, err := c.getAccessToken(ctx); err != nil {
		return out, &CheckError{Stage: CheckStageToken, Err: err}
	}
	apiURL := fmt.Sprintf("%s/projects/%s/global/sslPolicies?maxResults=1", c.computeEndpoint(), url.PathEscape(c.projectID))
	if _, err := c.doRequest(ctx, apiURL); err != nil {
		return out, &CheckError{Stage: CheckStageProject, Err: err}
	}
	return out, nil
}

// ListTargetHTTPSProxies lists all target HTTPS proxies in the project
func (c *Client) ListTargetHTTPSProxies(ctx context.Context) ([]TargetHTTPSProxy, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/global/targetHttpsProxies", c.computeEndpoint(), c.projectID)

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
			apiURL = fmt.Sprintf("%s/projects/%s/global/targetHttpsProxies?pageToken=%s", c.computeEndpoint(), c.projectID, apiURL)
		}
	}
	return allProxies, nil
}

// ListTargetSSLProxies lists all target SSL proxies in the project
func (c *Client) ListTargetSSLProxies(ctx context.Context) ([]TargetSSLProxy, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/global/targetSslProxies", c.computeEndpoint(), c.projectID)

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
			apiURL = fmt.Sprintf("%s/projects/%s/global/targetSslProxies?pageToken=%s", c.computeEndpoint(), c.projectID, apiURL)
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
		apiURL = fmt.Sprintf("%s/projects/%s/global/sslPolicies/%s", c.computeEndpoint(), c.projectID, policyRef)
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
	apiURL := fmt.Sprintf("%s/projects/%s/global/sslCertificates", c.computeEndpoint(), c.projectID)

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
			apiURL = fmt.Sprintf("%s/projects/%s/global/sslCertificates?pageToken=%s", c.computeEndpoint(), c.projectID, apiURL)
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
		apiURL = fmt.Sprintf("%s/projects/%s/global/sslCertificates/%s", c.computeEndpoint(), c.projectID, certRef)
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
	apiURL := fmt.Sprintf("%s/projects/%s/global/forwardingRules", c.computeEndpoint(), c.projectID)

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
			apiURL = fmt.Sprintf("%s/projects/%s/global/forwardingRules?pageToken=%s", c.computeEndpoint(), c.projectID, apiURL)
		}
	}
	return allRules, nil
}

// ListKMSLocations lists the Cloud KMS locations available to the project.
func (c *Client) ListKMSLocations(ctx context.Context) ([]KMSLocation, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/locations", c.apiBase(cloudKMSBaseURL), c.projectID)

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
			apiURL = fmt.Sprintf("%s/projects/%s/locations?pageToken=%s", c.apiBase(cloudKMSBaseURL), c.projectID, resp.NextPageToken)
		}
	}
	return all, nil
}

// ListKeyRings lists the key rings in a Cloud KMS location.
func (c *Client) ListKeyRings(ctx context.Context, location string) ([]KMSKeyRing, error) {
	base := fmt.Sprintf("%s/projects/%s/locations/%s/keyRings", c.apiBase(cloudKMSBaseURL), c.projectID, location)
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
	base := fmt.Sprintf("%s/%s/cryptoKeys", c.apiBase(cloudKMSBaseURL), keyRingName)
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
	base := fmt.Sprintf("%s/b?project=%s", c.apiBase(storageBaseURL), url.QueryEscape(c.projectID))
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
	base := fmt.Sprintf("%s/projects/%s/instances", c.apiBase(sqlAdminBaseURL), c.projectID)
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
