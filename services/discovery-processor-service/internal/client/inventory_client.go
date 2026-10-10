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
	"github.com/vistasecurity/vistaplatform/shared/identity"
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
// ImportTimeout bounds every call this client makes to inventory-service,
// import included. It is exported because the import is chunked to fit inside
// it (processor.importChunkSize) and that relationship is load-bearing: a
// chunk that cannot finish in time fails the whole batch and gets its rows
// marked rejected, which is.
const ImportTimeout = 30 * time.Second

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
		httpClient.Timeout = ImportTimeout
	} else {
		httpClient = &http.Client{
			Timeout: ImportTimeout,
		}
	}

	return &InventoryClient{
		baseURL:    baseURL,
		httpClient: httpClient,
	}, nil
}

// ImportFindingsRequest represents the request body for importing findings.
//
// It carries no status. inventory-service classifies each finding and
// evaluates the tenant's auto-approval rules itself ( WP3); the
// per-finding results say what each landed as and which rule, if any,
// approved it.
type ImportFindingsRequest struct {
	Findings []converter.IngestFinding `json:"findings"`
}

// ImportFindingsResponse represents the response from importing findings
type ImportFindingsResponse struct {
	Results  []identity.IngestResult `json:"results,omitempty"`
	Imported int                     `json:"imported"`

	// AssetStatuses is index-aligned with the findings that were sent: entry i
	// is the asset_status the i-th finding's asset ACTUALLY has after the
	// import, empty when it landed on no asset. It is how this service learns
	// that a finding it sent as `pending_approval` was materialized anyway,
	// because the asset it matched was already being monitored.
	//
	// Absent from an inventory-service older than this field, which is why it
	// is a nil-safe slice and not a count: nil means "not told", and every
	// caller must leave the discovery row exactly as it was.
	AssetStatuses []string `json:"asset_statuses,omitempty"`
}

// ImportFindings calls the inventory-service API to import findings
// Note: Uses /api/v1 prefix for service-to-service calls with internal headers
func (c *InventoryClient) ImportFindings(tenantID, jobID uuid.UUID, findings []converter.IngestFinding) (*ImportFindingsResponse, error) {
	// Use the same route as gateway: /api/v1/inventory-service/discovery/jobs/:id/import
	url := fmt.Sprintf("%s/api/v1/inventory-service/discovery/jobs/%s/import", c.baseURL, jobID.String())

	reqBody := ImportFindingsRequest{
		Findings: findings,
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
