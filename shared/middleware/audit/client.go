package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// Client handles HTTP communication with audit-service
type Client struct {
	baseURL    string
	httpClient *http.Client
	retries    int
	signer     *serviceauth.Signer
}

// NewClient creates a new audit service client with standard HTTP client
func NewClient(baseURL string, timeout time.Duration, retries int) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		retries: retries,
	}
}

// NewClientWithHTTPClient creates a new audit service client with a custom HTTP client (for mTLS)
func NewClientWithHTTPClient(baseURL string, httpClient *http.Client, retries int) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
		retries:    retries,
	}
}

// NewClientWithSigner creates a new audit service client with HMAC request signing
func NewClientWithSigner(baseURL string, timeout time.Duration, retries int, signer *serviceauth.Signer) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		retries: retries,
		signer:  signer,
	}
}

// NewClientWithHTTPClientAndSigner creates a new audit service client with a custom HTTP client and HMAC signing
func NewClientWithHTTPClientAndSigner(baseURL string, httpClient *http.Client, retries int, signer *serviceauth.Signer) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
		retries:    retries,
		signer:     signer,
	}
}

// LogActivity sends an activity log to audit-service (POST request)
func (c *Client) LogActivity(ctx context.Context, logEntry *ActivityLogRequest) error {
	url := fmt.Sprintf("%s/api/v1/audit-service/activity-logs", c.baseURL)

	body, err := json.Marshal(logEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal activity log: %w", err)
	}

	var lastErr error
	for i := 0; i < c.retries; i++ {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		if c.signer != nil {
			c.signer.SignRequest(req)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if i < c.retries-1 {
				time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to send activity log after %d retries: %w", c.retries, err)
		}

		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		// Read error response
		respBody, _ := io.ReadAll(resp.Body)
		lastErr = fmt.Errorf("audit service returned status %d: %s", resp.StatusCode, string(respBody))

		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			// Client error, don't retry
			break
		}

		if i < c.retries-1 {
			time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
		}
	}

	return lastErr
}
