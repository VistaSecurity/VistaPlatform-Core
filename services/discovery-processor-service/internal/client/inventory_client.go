package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// HTTPStatusError is returned whenever inventory-service answers with a
// non-success status. It carries the status CODE rather than only a formatted
// message so callers can classify retryability on the protocol fact instead of
// grepping the error text.
//
// Why it exists: the batch poller used to decide "permanent vs transient" by
// substring-matching "400"/"401"/"403"/"404"/"invalid"/"validation" in
// err.Error(). That misfires on text that merely contains those substrings — a
// URL with :8400, a certificate-rotation failure reading "certificate is not
// valid for host" — and terminally rejected whole batches of retryable work.
type HTTPStatusError struct {
	// StatusCode is the HTTP status inventory-service returned.
	StatusCode int
	// Op names the call that failed (for the message only).
	Op string
	// Body is the (possibly truncated) response body, for diagnostics.
	Body string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("%s returned status %d: %s", e.Op, e.StatusCode, e.Body)
}

// InventoryClient handles HTTP calls to inventory-service
type InventoryClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewInventoryClient creates a new inventory client
func NewInventoryClient(cfg *config.Config) (*InventoryClient, error) {
	baseURL := cfg.InventoryServiceURL
	if baseURL == "" {
		// Use HTTPS with mTLS port if mTLS is enabled
		if cfg.UseMTLS {
			baseURL = "https://inventory-service:8443"
		} else {
			baseURL = sharedconfig.PeerURL("inventory-service", sharedconfig.MTLSEnabled())
		}
	} else {
		// Update URL to use HTTPS and port 8443 if mTLS is enabled
		if cfg.UseMTLS {
			baseURL = strings.Replace(baseURL, "http://", "https://", 1)
			baseURL = strings.Replace(baseURL, ":8080", ":8443", 1)
		}
	}

	var httpClient *http.Client
	var err error
	if cfg.UseMTLS {
		httpClient, err = sharedhttp.NewMTLSClient(
			cfg.ClientCertPath,
			cfg.ClientKeyPath,
			cfg.PlatformCACertPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create mTLS client: %w", err)
		}
		httpClient.Timeout = 30 * time.Second
	} else {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return &InventoryClient{
		baseURL:    baseURL,
		httpClient: httpClient,
	}, nil
}

// ExternalConnectionUpsert is the payload sent to inventory-service POST /external-connections.
// Mirrors models.ExternalConnectionUpsert in inventory-service.
type ExternalConnectionUpsert struct {
	SourceIP             string     `json:"source_ip"`
	SourceHostname       *string    `json:"source_hostname,omitempty"`
	DestIP               string     `json:"dest_ip"`
	DestHostname         *string    `json:"dest_hostname,omitempty"`
	DestPort             int        `json:"dest_port"`
	Protocol             string     `json:"protocol"`
	ProtocolVersion      *string    `json:"protocol_version,omitempty"`
	CipherSuite          *string    `json:"cipher_suite,omitempty"`
	KeyExchangeAlgorithm *string    `json:"key_exchange_algorithm,omitempty"`
	KeySize              *int       `json:"key_size,omitempty"`
	SupportedTLSVersions []string   `json:"supported_tls_versions,omitempty"`
	SensorID             *uuid.UUID `json:"sensor_id,omitempty"`

	// Certificate fields
	CertSubject            *string    `json:"cert_subject,omitempty"`
	CertIssuer             *string    `json:"cert_issuer,omitempty"`
	CertSAN                []string   `json:"cert_san,omitempty"`
	CertNotBefore          *time.Time `json:"cert_not_before,omitempty"`
	CertNotAfter           *time.Time `json:"cert_not_after,omitempty"`
	CertFingerprintSHA256  *string    `json:"cert_fingerprint_sha256,omitempty"`
	CertPublicKeyAlgorithm *string    `json:"cert_public_key_algorithm,omitempty"`
	CertPublicKeySize      *int       `json:"cert_public_key_size,omitempty"`
	CertSignatureAlgorithm *string    `json:"cert_signature_algorithm,omitempty"`
	CertValidationStatus   *string    `json:"cert_validation_status,omitempty"`
	CertPEM                *string    `json:"cert_pem,omitempty"`

	// Sensor-level certificate quality flags
	CertHasSCT        *bool   `json:"cert_has_sct,omitempty"`
	CertKnownBadCA    *string `json:"cert_known_bad_ca,omitempty"`
	CertNoSubject     bool    `json:"cert_no_subject,omitempty"`
	CertNoCommonName  bool    `json:"cert_no_common_name,omitempty"`
	CertIsEV          bool    `json:"cert_is_ev,omitempty"`
	CertLargeSANCount *int    `json:"cert_large_san_count,omitempty"`
	OCSPStatus        *string `json:"ocsp_status,omitempty"`
}

// UpsertExternalConnection calls POST /api/v2/inventory-service/external-connections
// to record a 3rd party TLS/crypto connection observed by a sensor.
func (c *InventoryClient) UpsertExternalConnection(tenantID uuid.UUID, req ExternalConnectionUpsert) error {
	url := fmt.Sprintf("%s/api/v2/inventory-service/external-connections", c.baseURL)
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal external connection upsert: %w", err)
	}
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Tenant-ID", tenantID.String())
	serviceauth.SignRequestFromEnv(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send external connection upsert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return &HTTPStatusError{
			StatusCode: resp.StatusCode,
			Op:         "inventory-service external-connections",
			Body:       string(body),
		}
	}
	return nil
}

// ImportFindingsRequest represents the request body for importing findings
type ImportFindingsRequest struct {
	Findings    []converter.IngestFinding `json:"findings"`
	AssetStatus *string                   `json:"asset_status,omitempty"` // "monitoring" or "pending_approval"
}

// ImportFindingsResponse represents the response from importing findings
type ImportFindingsResponse struct {
	Imported int `json:"imported"`
}

// ClassifyResponse is the response from POST network-segments/classify-asset
type ClassifyResponse struct {
	SegmentID   *string `json:"segment_id,omitempty"` // UUID string when segment matched
	SegmentName *string `json:"segment_name,omitempty"`
	Ownership   string  `json:"ownership"`
	NetworkType string  `json:"network_type"`
}

// CloudResourceHint identifies the cloud account/region/VPC a discovery came
// from. Present only for cloud-API discoveries, where it — not the address —
// is what ownership resolves from.
type CloudResourceHint struct {
	Provider    string
	Region      string
	VPCID       string
	Environment string
}

// ClassifyAsset calls POST /api/v2/inventory-service/network-segments/classify-asset with HMAC and X-Tenant-ID.
// cloud may be nil; when set, inventory-service classifies by cloud segment rather than by address.
func (c *InventoryClient) ClassifyAsset(tenantID uuid.UUID, ipAddress string, hostname *string, cloud *CloudResourceHint) (*ClassifyResponse, error) {
	url := fmt.Sprintf("%s/api/v2/inventory-service/network-segments/classify-asset", c.baseURL)
	reqBody := map[string]interface{}{"ip_address": ipAddress}
	if hostname != nil {
		reqBody["hostname"] = *hostname
	}
	if cloud != nil {
		reqBody["cloud_provider"] = cloud.Provider
		reqBody["cloud_region"] = cloud.Region
		reqBody["vpc_id"] = cloud.VPCID
		reqBody["environment"] = cloud.Environment
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{
			StatusCode: resp.StatusCode,
			Op:         "inventory-service classify-asset",
			Body:       string(body),
		}
	}
	var result ClassifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &result, nil
}

// ImportFindings calls the inventory-service API to import findings
// Note: Uses /api/v1 prefix for service-to-service calls with internal headers
func (c *InventoryClient) ImportFindings(tenantID, jobID uuid.UUID, findings []converter.IngestFinding, assetStatus string) (*ImportFindingsResponse, error) {
	// Use the same route as gateway: /api/v1/inventory-service/discovery/jobs/:id/import
	url := fmt.Sprintf("%s/api/v1/inventory-service/discovery/jobs/%s/import", c.baseURL, jobID.String())

	reqBody := ImportFindingsRequest{
		Findings: findings,
	}
	if assetStatus != "" {
		reqBody.AssetStatus = &assetStatus
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID.String())
	// Sign as internal service call (HMAC or legacy header fallback)
	serviceauth.SignRequestFromEnv(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{
			StatusCode: resp.StatusCode,
			Op:         "inventory-service import-findings",
			Body:       string(body),
		}
	}

	var result ImportFindingsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}
