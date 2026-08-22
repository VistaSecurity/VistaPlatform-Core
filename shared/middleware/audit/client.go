package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
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

// NewClientForEnv builds an audit-service client that speaks whatever the
// service mesh is configured for, rather than assuming plaintext.
//
// This is the ONE place the audit transport is chosen. It exists because it was
// previously chosen twice: the gin middleware read the mesh settings and built
// an mTLS client, while NewJobLogger hand-rolled a bare &http.Client{}. Under
// serviceMtls.enabled every peer URL derives to https://<svc>:8443, so the
// hand-rolled client could not verify the Platform CA and every job-execution
// log from the platform agent worker failed with "certificate signed by unknown
// authority" — jobs ran with no execution log at all, and the only symptom was
// a warning line on the worker's stdout.
//
// Explicit arguments win; anything empty falls back to the environment the
// chart injects (USE_MTLS, CLIENT_CERT_PATH, CLIENT_KEY_PATH,
// PLATFORM_CA_CERT_PATH). With mTLS off, or with certs unconfigured, the result
// is the same plain client as before.
func NewClientForEnv(
	baseURL string,
	timeout time.Duration,
	retries int,
	signer *serviceauth.Signer,
	useMTLS bool,
	clientCertPath, clientKeyPath, platformCACertPath string,
) *Client {
	if !useMTLS && os.Getenv("USE_MTLS") == "true" {
		useMTLS = true
	}
	if clientCertPath == "" {
		clientCertPath = os.Getenv("CLIENT_CERT_PATH")
	}
	if clientKeyPath == "" {
		clientKeyPath = os.Getenv("CLIENT_KEY_PATH")
	}
	if platformCACertPath == "" {
		platformCACertPath = os.Getenv("PLATFORM_CA_CERT_PATH")
	}

	baseURL = auditPeerURL(baseURL, useMTLS)

	if useMTLS && clientCertPath != "" && clientKeyPath != "" && platformCACertPath != "" {
		httpClient, err := sharedhttp.NewMTLSClient(clientCertPath, clientKeyPath, platformCACertPath)
		if err == nil {
			httpClient.Timeout = timeout
			return NewClientWithHTTPClientAndSigner(baseURL, httpClient, retries, signer)
		}
		// Falling back to plaintext against an mTLS listener will not work — say
		// so loudly rather than leaving the caller to guess from handshake errors.
		log.Printf("[audit] mTLS client setup failed (%v); falling back to a plaintext client against %s", err, baseURL)
	}

	return NewClientWithSigner(baseURL, timeout, retries, signer)
}

// auditPeerURL moves a plaintext peer URL onto the mTLS listener. Backends serve
// their real API on https://<svc>:8443 when mTLS is active; :8080 is reduced to
// the kubelet health probe.
func auditPeerURL(baseURL string, useMTLS bool) string {
	if !useMTLS {
		return baseURL
	}
	baseURL = strings.Replace(baseURL, "http://", "https://", 1)
	return strings.Replace(baseURL, ":8080", ":8443", 1)
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

		_ = resp.Body.Close()

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
